// Package checkendpoint checks channel-binding consistency, NOT hardware trust.
package checkendpoint

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"

	"github.com/Lore-Hex/trustedrouter-confidential-stack/internal/attest"
)

const Warning = "Channel binding is consistent. Hardware evidence was NOT verified by this tool."

type Result struct {
	TEE                      string `json:"tee"`
	ChannelBindingConsistent bool   `json:"channel_binding_consistent"`
	HardwareEvidenceVerified bool   `json:"hardware_evidence_verified"`
	Message                  string `json:"message"`
}

func Check(ctx context.Context, endpoint, expectTEE string) (Result, int, error) {
	fail := func(message string) (Result, int, error) { return Result{}, 1, errors.New(message) }
	if expectTEE != "any" && expectTEE != "none" && expectTEE != "sev-snp" && expectTEE != "tdx" {
		return fail("invalid expect-tee")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fail("endpoint must be an HTTPS origin")
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return fail("could not generate nonce")
	}
	// WebPKI is deliberately not used here: only the SPKI recorded from this live
	// connection is used to check the binding. Consistency does NOT authenticate
	// hardware; full vendor-signature and policy verification is a separate step.
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, DisableKeepAlives: false, TLSHandshakeTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var conn net.Conn
	var spki [32]byte
	recorded := false
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		conn = info.Conn
		if tc, ok := info.Conn.(*tls.Conn); ok {
			state := tc.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				spki = attest.SPKI(state.PeerCertificates[0])
				recorded = true
			}
		}
	}}
	// Prime the connection, fully drain it, then require the attestation request to
	// reuse that exact TLS connection. A closed/replaced connection fails closed.
	u.Path = "/healthz"
	req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, u.String(), nil)
	response, err := client.Do(req)
	if err != nil {
		// A bare "failed" hides the difference between a refused connection, a
		// dropped one (a timeout usually means a network policy) and a TLS
		// error. Transport errors carry addresses, never request content.
		return fail("TLS probe failed: " + err.Error())
	}
	n, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20+1))
	response.Body.Close()
	if readErr != nil || n > 1<<20 || !recorded {
		return fail("TLS probe did not yield a reusable connection")
	}
	reused := false
	trace = &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused && info.Conn == conn }}
	nonceHex := hex.EncodeToString(nonce[:])
	u.Path = attest.Path
	u.RawQuery = url.Values{"nonce": {nonceHex}}.Encode()
	req, _ = http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, u.String(), nil)
	response, err = client.Do(req)
	if err != nil {
		return fail("evidence request failed: " + err.Error())
	}
	defer response.Body.Close()
	if !reused {
		return fail("evidence request did not reuse the recorded TLS connection")
	}
	if response.StatusCode != 200 {
		return fail("evidence endpoint did not return 200")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 16<<20+1))
	if err != nil || len(payload) > 16<<20 {
		return fail("invalid evidence response size")
	}
	var evidence attest.Response
	if err = json.Unmarshal(payload, &evidence); err != nil {
		return fail("invalid evidence JSON")
	}
	if evidence.Protocol != attest.Protocol {
		return fail("protocol mismatch")
	}
	if evidence.Nonce != nonceHex {
		return fail("nonce mismatch")
	}
	if evidence.TLSSPKISHA256 != hex.EncodeToString(spki[:]) {
		return fail("TLS SPKI mismatch")
	}
	data := attest.ReportData(nonce, spki)
	if evidence.ReportData != hex.EncodeToString(data[:]) {
		return fail("report_data mismatch")
	}
	if evidence.TEE != "none" && evidence.TEE != "sev-snp" && evidence.TEE != "tdx" {
		return fail("invalid tee in evidence")
	}
	if expectTEE != "any" && evidence.TEE != expectTEE {
		return fail("unexpected tee")
	}
	result := Result{TEE: evidence.TEE, ChannelBindingConsistent: true, Message: "Channel binding is consistent. Endpoint is standard (tee=none)."}
	if evidence.TEE != "none" {
		result.Message = Warning
		return result, 3, nil
	}
	return result, 0, nil
}
func Run(ctx context.Context, endpoint, expectTEE string, asJSON bool, out, stderr io.Writer) int {
	result, code, err := Check(ctx, endpoint, expectTEE)
	if err != nil {
		result.Message = err.Error()
		fmt.Fprintln(stderr, err)
	}
	if code == 3 {
		fmt.Fprintln(stderr, `"hardware_evidence_verified": false`)
		fmt.Fprintln(stderr, Warning)
	}
	if asJSON {
		_ = json.NewEncoder(out).Encode(result)
	} else if err == nil {
		fmt.Fprintln(out, result.Message)
	}
	return code
}
