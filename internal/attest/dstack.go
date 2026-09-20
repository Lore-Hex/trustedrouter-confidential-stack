package attest

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
)

// Dstack collects evidence from the dstack guest agent, API v1
// (Dstack-TEE/dstack docs/guest-api-v1.md): HTTP over the unix socket
// /var/run/dstack.sock, JSON bodies, byte fields hex encoded.
//
// EXPERIMENTAL. v1 ships in dstack 0.6.0, a release candidate when this was
// written. TODO(verify against dstack 0.6.0 final): the JSON field names
// "report_data", "attestation", "nonce" and the shape of the AttestGpu reply.
//
// The versioned attestation is MessagePack and is passed through untouched,
// so Platform (the TEE type) must be given explicitly.
type Dstack struct {
	Socket   string
	Platform string
	Client   *http.Client
}

func (s Dstack) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	socket := s.Socket
	return agentClient(func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	})
}

func (s Dstack) post(ctx context.Context, path string, payload any) ([]byte, int, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	// The host part is ignored by the unix-socket dialer.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://dstack"+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, 0, errors.New("dstack guest agent unreachable")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentResponse+1))
	if err != nil {
		return nil, resp.StatusCode, errors.New("dstack guest agent response unreadable")
	}
	if len(body) > maxAgentResponse {
		return nil, resp.StatusCode, errors.New("dstack guest agent response too large")
	}
	return body, resp.StatusCode, nil
}

func (s Dstack) Collect(ctx context.Context, data [64]byte) (*CPU, error) {
	if s.Platform != "sev-snp" && s.Platform != "tdx" {
		return nil, errors.New("dstack needs an explicit tee: sev-snp or tdx")
	}
	body, status, err := s.post(ctx, "/v1/Attest", map[string]string{"report_data": hex.EncodeToString(data[:])})
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, errors.New("dstack guest agent has no v1 API: dstack 0.6.0 or later is required")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("dstack guest agent returned status %d", status)
	}
	var reply struct {
		Attestation string `json:"attestation"`
	}
	if err = json.Unmarshal(body, &reply); err != nil {
		return nil, errors.New("invalid dstack Attest reply")
	}
	evidence, err := hex.DecodeString(reply.Attestation)
	if err != nil || len(evidence) == 0 {
		return nil, errors.New("dstack Attest reply carried no attestation")
	}
	return &CPU{Source: "dstack", Provider: "dstack-v1", Evidence: evidence, TEE: s.Platform}, nil
}

type dstackBundle struct {
	Vendor   string `json:"vendor"`
	Format   string `json:"format"`
	Evidence string `json:"evidence"`
}

// decodeDstackBundles accepts a top-level list, or an object with exactly one
// list-valued field, because the reply's field name is not confirmed.
func decodeDstackBundles(body []byte) ([]dstackBundle, error) {
	var list []dstackBundle
	if json.Unmarshal(body, &list) == nil {
		return list, nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil {
		return nil, errors.New("invalid dstack AttestGpu reply")
	}
	found := false
	for _, raw := range object {
		var candidate []dstackBundle
		if json.Unmarshal(raw, &candidate) != nil {
			continue
		}
		if found {
			return nil, errors.New("ambiguous dstack AttestGpu reply")
		}
		found = true
		list = candidate
	}
	if !found {
		return nil, errors.New("dstack AttestGpu reply carried no bundle list")
	}
	return list, nil
}

func (s Dstack) CollectGPU(ctx context.Context, nonce [32]byte) ([]GPUEvidence, error) {
	nonceHex := hex.EncodeToString(nonce[:])
	body, status, err := s.post(ctx, "/v1/AttestGpu", map[string]string{"nonce": nonceHex})
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotImplemented {
		return nil, errors.New("this dstack image ships no GPU attestation")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("dstack guest agent returned status %d for AttestGpu", status)
	}
	bundles, err := decodeDstackBundles(body)
	if err != nil {
		return nil, err
	}
	out := make([]GPUEvidence, 0, len(bundles))
	for _, b := range bundles {
		evidence, err := hex.DecodeString(b.Evidence)
		if err != nil || len(evidence) == 0 || b.Vendor == "" || b.Format == "" {
			return nil, errors.New("incomplete dstack GPU evidence bundle")
		}
		out = append(out, GPUEvidence{Vendor: b.Vendor, Format: b.Format, Nonce: nonceHex, Evidence: evidence})
	}
	if len(out) == 0 {
		return nil, errors.New("dstack AttestGpu returned no evidence")
	}
	return out, nil
}
