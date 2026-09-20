// Package attest implements the tr-attestation/v0 transcript and evidence collection.
// It deliberately makes no hardware trust or acceptance-policy decisions.
package attest

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
)

const Protocol = "tr-attestation/v0"
const Path = "/.well-known/trustedrouter/attestation"

type CPU struct {
	Source   string `json:"source"`
	Provider string `json:"provider"`
	Evidence []byte `json:"evidence"`
	Aux      []byte `json:"aux"`
	// TEE is set by the evidence source and is not part of the wire format:
	// the response carries it once, at the top level.
	TEE string `json:"-"`
}

// GPUEvidence is an opaque, tagged bundle. The shim never parses GPU evidence;
// Vendor and Format tell a verifier which appraiser to use.
type GPUEvidence struct {
	Vendor   string `json:"vendor"`
	Format   string `json:"format"`
	Nonce    string `json:"nonce"`
	Evidence []byte `json:"evidence"`
}
type Workload struct {
	StackVersion  string `json:"stack_version"`
	Model         string `json:"model"`
	ModelRevision string `json:"model_revision"`
	EngineImage   string `json:"engine_image"`
}
type Response struct {
	Protocol      string        `json:"protocol"`
	TEE           string        `json:"tee"`
	Nonce         string        `json:"nonce"`
	TLSSPKISHA256 string        `json:"tls_spki_sha256"`
	ReportData    string        `json:"report_data"`
	CPU           *CPU          `json:"cpu"`
	GPUEvidence   []GPUEvidence `json:"gpu_evidence"`
	GPUError      *string       `json:"gpu_error"`
	Workload      Workload      `json:"workload"`
	Confidential  bool          `json:"confidential"`
}

// EvidenceSource collects CPU evidence carrying exactly the supplied report data
// and names the TEE it came from in CPU.TEE.
type EvidenceSource interface {
	Collect(context.Context, [64]byte) (*CPU, error)
}

// GPUEvidenceSource is implemented by sources whose platform agent can also
// collect GPU evidence against a caller-chosen nonce.
type GPUEvidenceSource interface {
	CollectGPU(context.Context, [32]byte) ([]GPUEvidence, error)
}

func ParseNonce(s string) ([32]byte, error) {
	var nonce [32]byte
	if len(s) != 64 {
		return nonce, errors.New("nonce must be 64 hex characters")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nonce, errors.New("nonce must be 64 hex characters")
	}
	copy(nonce[:], b)
	return nonce, nil
}
func SPKI(cert *x509.Certificate) [32]byte { return sha256.Sum256(cert.RawSubjectPublicKeyInfo) }

// ReportData lays out the 64-byte TEE user data field:
//
//	[0:32]  SHA-256 of the DER SubjectPublicKeyInfo (the plain key digest, the
//	        same convention existing key-pinning verifiers already enforce)
//	[32:64] SHA-256("tr-attestation/v0" || 0x00 || nonce)
func ReportData(nonce, spki [32]byte) [64]byte {
	var out [64]byte
	copy(out[:32], spki[:])
	h := sha256.New()
	h.Write([]byte(Protocol + "\x00"))
	h.Write(nonce[:])
	copy(out[32:], h.Sum(nil))
	return out
}
func GPUNonce(data [64]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(Protocol + "/gpu\x00"))
	h.Write(data[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func TEE(provider string) (string, error) {
	switch provider {
	case "sev_guest":
		return "sev-snp", nil
	case "tdx_guest":
		return "tdx", nil
	}
	return "", errors.New("unknown TSM provider")
}
