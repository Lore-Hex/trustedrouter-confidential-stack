// Package shim serves a TLS-bound attestation endpoint and a loopback inference proxy.
package shim

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/Lore-Hex/trustedrouter-confidential-stack/internal/attest"
)

type Config struct {
	Listen, Upstream, TEE, EvidenceSource, TSMPath string
	CocoAAURL, DstackSocket                        string
	ListenerAudit, ProcNetDir                      string
	AllowRemoteUpstream, RequireTEE                bool
	TLSCert, TLSKey                                string
	TLSSANs, AllowPathPrefixes                     []string
	GPUEvidenceCommand                             string
	Workload                                       attest.Workload
	AttestationRate                                float64
	MaxRequestBytes                                int64
}

func DefaultConfig() Config {
	return Config{Listen: ":8443", Upstream: "http://127.0.0.1:8000", TEE: "auto", EvidenceSource: "auto", TSMPath: "/sys/kernel/config/tsm/report", CocoAAURL: "http://127.0.0.1:8006", DstackSocket: "/var/run/dstack.sock", ListenerAudit: "auto", ProcNetDir: "/proc/net", TLSSANs: []string{"localhost"}, AllowPathPrefixes: []string{"/v1/"}, AttestationRate: 2, MaxRequestBytes: 33554432}
}
func (c Config) validate() (*url.URL, error) {
	if c.TEE != "auto" && c.TEE != "none" && c.TEE != "sev-snp" && c.TEE != "tdx" {
		return nil, errors.New("invalid tee")
	}
	switch c.EvidenceSource {
	case "auto", "none", "configfs-tsm":
	case "coco-aa":
		if _, err := attest.ValidateCocoAAURL(c.CocoAAURL); err != nil {
			return nil, err
		}
		fallthrough
	case "dstack":
		// Neither platform agent says which TEE it runs in.
		if c.TEE != "sev-snp" && c.TEE != "tdx" {
			return nil, fmt.Errorf("evidence-source %s needs an explicit --tee sev-snp or tdx", c.EvidenceSource)
		}
	default:
		return nil, errors.New("invalid evidence-source")
	}
	if (c.TLSCert != "" || c.TLSKey != "") && c.TEE != "none" {
		return nil, errors.New("operator TLS keys require --tee=none")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return nil, errors.New("tls-cert and tls-key must be supplied together")
	}
	if c.AttestationRate <= 0 || math.IsNaN(c.AttestationRate) || math.IsInf(c.AttestationRate, 0) {
		return nil, errors.New("attestation-rate must be positive and finite")
	}
	if c.MaxRequestBytes <= 0 || c.MaxRequestBytes == math.MaxInt64 {
		return nil, errors.New("max-request-bytes must be positive and less than MaxInt64")
	}
	if len(c.AllowPathPrefixes) == 0 {
		return nil, errors.New("at least one allowed path prefix is required")
	}
	for _, p := range c.AllowPathPrefixes {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#") {
			return nil, errors.New("invalid allowed path prefix")
		}
	}
	u, err := url.Parse(c.Upstream)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("upstream must be an HTTP(S) origin")
	}
	// Do not trust DNS for the loopback boundary; normalize localhost to a literal.
	if strings.EqualFold(u.Hostname(), "localhost") {
		port := u.Port()
		u.Host = "127.0.0.1"
		if port != "" {
			u.Host = net.JoinHostPort("127.0.0.1", port)
		}
	}
	ip := net.ParseIP(u.Hostname())
	if !c.AllowRemoteUpstream && (ip == nil || !ip.IsLoopback()) {
		return nil, errors.New("non-loopback upstream requires --allow-remote-upstream")
	}
	return u, nil
}

// selectSource resolves --evidence-source. In auto mode a dstack socket wins,
// then the kernel TSM interface. coco-aa is never auto-selected: it is a network
// call and needs an explicit TEE type.
func selectSource(c Config) (attest.EvidenceSource, string, error) {
	exists := func(path string) (bool, error) {
		_, err := os.Stat(path)
		if err == nil {
			return true, nil
		}
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	switch c.EvidenceSource {
	case "none":
		return nil, "none", nil
	case "configfs-tsm":
		return attest.TSM{Path: c.TSMPath}, "configfs-tsm", nil
	case "coco-aa":
		return attest.CocoAA{BaseURL: c.CocoAAURL, Platform: c.TEE}, "coco-aa", nil
	case "dstack":
		return attest.Dstack{Socket: c.DstackSocket, Platform: c.TEE}, "dstack", nil
	}
	if ok, err := exists(c.DstackSocket); err != nil {
		return nil, "", fmt.Errorf("inspect dstack socket: %w", err)
	} else if ok {
		if c.TEE != "sev-snp" && c.TEE != "tdx" {
			return nil, "", errors.New("found a dstack socket: set --tee sev-snp or tdx to use it")
		}
		return attest.Dstack{Socket: c.DstackSocket, Platform: c.TEE}, "dstack", nil
	}
	if ok, err := exists(c.TSMPath); err != nil {
		return nil, "", fmt.Errorf("inspect TSM path: %w", err)
	} else if ok {
		return attest.TSM{Path: c.TSMPath}, "configfs-tsm", nil
	}
	return nil, "none", nil
}

func sourceFor(ctx context.Context, c Config, spki [32]byte, source attest.EvidenceSource) (attest.EvidenceSource, string, string, error) {
	if c.TEE == "none" {
		if c.RequireTEE {
			return nil, "", "", errors.New("require-tee cannot use tee none")
		}
		return nil, "none", "none", nil
	}
	name := "injected"
	if source == nil {
		var err error
		if source, name, err = selectSource(c); err != nil {
			return nil, "", "", err
		}
	}
	if source == nil {
		if c.RequireTEE || c.TEE != "auto" {
			return nil, "", "", errors.New("no working TEE evidence source")
		}
		return nil, "none", "none", nil
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, "", "", err
	}
	cpu, err := source.Collect(ctx, attest.ReportData(nonce, spki))
	if err != nil {
		return nil, "", "", fmt.Errorf("TEE self-test failed: %w", err)
	}
	if cpu == nil || len(cpu.Evidence) == 0 {
		return nil, "", "", errors.New("TEE self-test returned no evidence")
	}
	if cpu.TEE != "sev-snp" && cpu.TEE != "tdx" {
		return nil, "", "", errors.New("evidence source did not name a TEE")
	}
	if c.TEE != "auto" && cpu.TEE != c.TEE {
		return nil, "", "", errors.New("TEE provider does not match requested tee")
	}
	return source, cpu.TEE, name, nil
}
