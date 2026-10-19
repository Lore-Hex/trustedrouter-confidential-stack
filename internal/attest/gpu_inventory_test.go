package attest

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestTaggedGPUAndSwitchBundles(t *testing.T) {
	var entries []map[string]string
	for _, kind := range []string{"gpu", "nvswitch"} {
		n := 8
		if kind == "nvswitch" {
			n = 4
		}
		for i := 0; i < n; i++ {
			entries = append(entries, map[string]string{"vendor": "nvidia", "format": "nvidia-v1", "evidence_b64": "AQ==", "device_type": kind, "device_id": fmt.Sprintf("%s-%d", kind, i)})
		}
	}
	wire, err := json.Marshal(map[string]any{"gpu_evidence": entries})
	if err != nil {
		t.Fatal(err)
	}
	nonce := strings.Repeat("a", 64)
	bundles, err := decodeHelperGPUs(wire, nonce)
	if err != nil || len(bundles) != 12 {
		t.Fatalf("bundles=%d err=%v", len(bundles), err)
	}
	for i, b := range bundles {
		if b.DeviceType != entries[i]["device_type"] || b.DeviceID != entries[i]["device_id"] || b.Nonce != nonce || string(b.Evidence) != "\x01" {
			t.Fatalf("lost device metadata at %d", i)
		}
	}
}

func TestGPUEnvelopeRejections(t *testing.T) {
	valid := GPUEvidence{Vendor: "nvidia", Format: "nvidia-v1", Nonce: strings.Repeat("a", 64), Evidence: []byte{1}, DeviceType: "gpu", DeviceID: "GPU-0"}
	for _, tc := range []struct {
		name   string
		change func(*GPUEvidence)
	}{
		{"missing-id", func(b *GPUEvidence) { b.DeviceID = "" }},
		{"missing-type", func(b *GPUEvidence) { b.DeviceType = "" }},
		{"unknown-type", func(b *GPUEvidence) { b.DeviceType = "nic" }},
		{"control-label", func(b *GPUEvidence) { b.DeviceID = "GPU-0\nsecret" }},
		{"oversized-label", func(b *GPUEvidence) { b.DeviceID = strings.Repeat("x", 129) }},
		{"empty-evidence", func(b *GPUEvidence) { b.Evidence = nil }},
		{"empty-vendor", func(b *GPUEvidence) { b.Vendor = "" }},
		{"empty-format", func(b *GPUEvidence) { b.Format = "" }},
		{"bad-nonce", func(b *GPUEvidence) { b.Nonce = "not-a-nonce" }},
		{"oversized-evidence", func(b *GPUEvidence) { b.Evidence = make([]byte, (8<<20)+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := valid
			tc.change(&b)
			if err := ValidateGPUEnvelopes([]GPUEvidence{b}); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
	legacy := valid
	legacy.DeviceID, legacy.DeviceType = "", ""
	for name, bundles := range map[string][]GPUEvidence{
		"empty": nil, "duplicate": {valid, valid}, "mixed": {valid, legacy}, "too-many": make([]GPUEvidence, 65),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateGPUEnvelopes(bundles); err == nil {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
	if err := ValidateGPUEnvelopes([]GPUEvidence{legacy}); err != nil {
		t.Fatalf("legacy aggregate rejected: %v", err)
	}
	wire, _ := json.Marshal(legacy)
	if strings.Contains(string(wire), "device_") {
		t.Fatal("legacy aggregate acquired an invented identity")
	}
}

func TestGPUHelperMalformedJSON(t *testing.T) {
	for _, wire := range []string{"{}", "null", "{", `{"gpu_evidence":[{"vendor":"nvidia","format":"v1","evidence_b64":"invalid"}]}`, `{"gpu_evidence":[]} {}`} {
		if _, err := decodeHelperGPUs([]byte(wire), strings.Repeat("0", 64)); err == nil {
			t.Fatalf("accepted malformed helper result %q", wire)
		}
	}
}

func FuzzGPUHelperEnvelopes(f *testing.F) {
	f.Add([]byte(`{"gpu_evidence":[{"vendor":"nvidia","format":"v1","evidence_b64":"AQ==","device_type":"gpu","device_id":"GPU-0"}]}`))
	f.Add([]byte(`{"gpu_evidence":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := decodeHelperGPUs(data, strings.Repeat("a", 64))
		if err == nil && ValidateGPUEnvelopes(out) != nil {
			t.Fatal("decoder accepted invalid envelopes")
		}
	})
}
