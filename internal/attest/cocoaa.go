package attest

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxAgentResponse bounds what the shim will buffer from a platform agent.
const maxAgentResponse = 8 << 20

// CocoAA collects evidence from the Confidential Containers guest attestation
// agent's REST API (guest-components api-server-rest). Verified against its
// source: GET /aa/evidence?runtime_data=<URL-safe base64, no padding>&encoding=base64
// returns the evidence as opaque bytes; /aa/additional-evidence does the same
// for additional devices such as GPUs. The API is off unless the guest kernel
// command line carries agent.guest_components_rest_api=all.
//
// The agent does not report which TEE it runs in, so Platform is required.
type CocoAA struct {
	BaseURL  string
	Platform string
	Client   *http.Client
}

// ValidateCocoAAURL accepts only a plain http origin on a loopback literal. The
// agent listens inside the guest; any other address would leave the TEE.
func ValidateCocoAAURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("coco-aa-url must be an http origin")
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return nil, errors.New("coco-aa-url must be a loopback address")
	}
	u.Path = ""
	return u, nil
}

func agentClient(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: dial}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (s CocoAA) get(ctx context.Context, path string, runtimeData []byte) ([]byte, int, error) {
	base, err := ValidateCocoAAURL(s.BaseURL)
	if err != nil {
		return nil, 0, err
	}
	query := url.Values{"runtime_data": {base64.RawURLEncoding.EncodeToString(runtimeData)}, "encoding": {"base64"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+path+"?"+query.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}
	client := s.Client
	if client == nil {
		client = agentClient(nil)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, errors.New("attestation agent unreachable")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentResponse+1))
	if err != nil {
		return nil, resp.StatusCode, errors.New("attestation agent response unreadable")
	}
	if len(body) > maxAgentResponse {
		return nil, resp.StatusCode, errors.New("attestation agent response too large")
	}
	return body, resp.StatusCode, nil
}

func (s CocoAA) Collect(ctx context.Context, data [64]byte) (*CPU, error) {
	if s.Platform != "sev-snp" && s.Platform != "tdx" {
		return nil, errors.New("coco-aa needs an explicit tee: sev-snp or tdx")
	}
	body, status, err := s.get(ctx, "/aa/evidence", data[:])
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("attestation agent returned status %d", status)
	}
	if len(body) == 0 {
		return nil, errors.New("attestation agent returned no evidence")
	}
	return &CPU{Source: "coco-aa", Provider: "coco-aa", Evidence: body, TEE: s.Platform}, nil
}

// CollectGPU asks the agent for additional-device evidence. What the endpoint
// returns on a guest with no additional devices is not documented, so an
// empty body, "{}", "[]" and "null" are all treated as "no GPU evidence".
func (s CocoAA) CollectGPU(ctx context.Context, nonce [32]byte) ([]GPUEvidence, error) {
	body, status, err := s.get(ctx, "/aa/additional-evidence", nonce[:])
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound || status == http.StatusNotImplemented {
		return nil, errors.New("attestation agent offers no additional-device evidence")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("attestation agent returned status %d for additional evidence", status)
	}
	switch strings.TrimSpace(string(body)) {
	case "", "{}", "[]", "null":
		return nil, errors.New("attestation agent returned no additional-device evidence")
	}
	return []GPUEvidence{{Vendor: "nvidia", Format: "coco-additional-evidence", Nonce: fmt.Sprintf("%x", nonce[:]), Evidence: body}}, nil
}
