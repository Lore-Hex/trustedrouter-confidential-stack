package attest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testReportData() [64]byte {
	var data [64]byte
	for i := range data {
		data[i] = byte(i * 3) // includes bytes that are not URL- or UTF-8-safe
	}
	return data
}

func TestCocoAAEvidenceRequestShape(t *testing.T) {
	data := testReportData()
	var gpuNonce [32]byte
	gpuNonce[0], gpuNonce[31] = 0xFE, 0x01
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		if r.URL.Query().Get("encoding") != "base64" {
			t.Errorf("encoding parameter = %q", r.URL.Query().Get("encoding"))
		}
		raw, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("runtime_data"))
		if err != nil {
			t.Errorf("runtime_data is not unpadded URL-safe base64: %v", err)
		}
		switch r.URL.Path {
		case "/aa/evidence":
			if !bytes.Equal(raw, data[:]) {
				t.Error("CPU runtime_data is not the 64 report-data bytes")
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write([]byte("cpu-evidence"))
		case "/aa/additional-evidence":
			if !bytes.Equal(raw, gpuNonce[:]) {
				t.Error("GPU runtime_data is not the 32-byte gpu nonce")
			}
			w.Write([]byte(`{"nvidia":"bundle"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	source := CocoAA{BaseURL: server.URL, Platform: "sev-snp"}
	cpu, err := source.Collect(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	if cpu.Source != "coco-aa" || cpu.TEE != "sev-snp" || string(cpu.Evidence) != "cpu-evidence" || cpu.Aux != nil {
		t.Fatalf("bad CPU evidence: %+v", cpu)
	}
	bundles, err := source.CollectGPU(context.Background(), gpuNonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundles) != 1 || bundles[0].Vendor != "nvidia" || bundles[0].Format != "coco-additional-evidence" || bundles[0].Nonce != hex.EncodeToString(gpuNonce[:]) || string(bundles[0].Evidence) != `{"nvidia":"bundle"}` {
		t.Fatalf("bad GPU bundle: %+v", bundles)
	}
	if strings.Join(seen, ",") != "GET /aa/evidence,GET /aa/additional-evidence" {
		t.Fatalf("requests: %v", seen)
	}
}

func TestCocoAAFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		gpu    bool
	}{
		{"cpu non-200", 500, "boom", false},
		{"cpu empty", 200, "", false},
		{"cpu oversize", 200, strings.Repeat("x", maxAgentResponse+1), false},
		{"gpu 404", 404, "", true},
		{"gpu 501", 501, "", true},
		{"gpu empty object", 200, " {} ", true},
		{"gpu null", 200, "null", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			source := CocoAA{BaseURL: server.URL, Platform: "tdx"}
			var err error
			if tc.gpu {
				_, err = source.CollectGPU(context.Background(), [32]byte{1})
			} else {
				_, err = source.Collect(context.Background(), testReportData())
			}
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestCocoAARefusesNonLoopbackAndMissingPlatform(t *testing.T) {
	for _, raw := range []string{"http://10.0.0.1:8006", "http://example.com:8006", "https://127.0.0.1:8006", "http://127.0.0.1:8006/x", "http://user@127.0.0.1:8006", "http://127.0.0.1:8006?x=1"} {
		if _, err := ValidateCocoAAURL(raw); err == nil {
			t.Errorf("%s should be refused", raw)
		}
	}
	for _, raw := range []string{"http://127.0.0.1:8006", "http://127.0.0.1:8006/", "http://[::1]:8006"} {
		if _, err := ValidateCocoAAURL(raw); err != nil {
			t.Errorf("%s should be accepted: %v", raw, err)
		}
	}
	if _, err := (CocoAA{BaseURL: "http://127.0.0.1:8006"}).Collect(context.Background(), testReportData()); err == nil {
		t.Fatal("a source with no platform must not produce evidence")
	}
}

func TestCocoAADoesNotFollowRedirects(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("redirect was followed")
	}))
	defer elsewhere.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusFound)
	}))
	defer server.Close()
	if _, err := (CocoAA{BaseURL: server.URL, Platform: "tdx"}).Collect(context.Background(), testReportData()); err == nil {
		t.Fatal("a redirect must be an error")
	}
}

// fakeDstack serves the guest agent API on a unix socket. macOS limits unix
// socket paths to 104 bytes, so the socket lives in a short temp dir.
func fakeDstack(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ds")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "d.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return socket
}

func TestDstackAttestAndGPU(t *testing.T) {
	data := testReportData()
	var nonce [32]byte
	nonce[5] = 0x7F
	for _, shape := range []string{"list", "object"} {
		t.Run(shape, func(t *testing.T) {
			socket := fakeDstack(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("%s %s content-type %q", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
				}
				var body map[string]string
				json.NewDecoder(r.Body).Decode(&body)
				switch r.URL.Path {
				case "/v1/Attest":
					if body["report_data"] != hex.EncodeToString(data[:]) {
						t.Error("report_data is not the hex of the 64 bytes")
					}
					json.NewEncoder(w).Encode(map[string]string{"attestation": hex.EncodeToString([]byte("msgpack-attestation"))})
				case "/v1/AttestGpu":
					if body["nonce"] != hex.EncodeToString(nonce[:]) {
						t.Error("nonce is not the hex of the 32 bytes")
					}
					bundles := []map[string]string{{"vendor": "nvidia", "format": "nvidia-nvattest-collect-evidence-json-v1", "evidence": hex.EncodeToString([]byte("gpu"))}}
					if shape == "list" {
						json.NewEncoder(w).Encode(bundles)
					} else {
						json.NewEncoder(w).Encode(map[string]any{"evidence": bundles})
					}
				default:
					http.NotFound(w, r)
				}
			})
			source := Dstack{Socket: socket, Platform: "tdx"}
			cpu, err := source.Collect(context.Background(), data)
			if err != nil {
				t.Fatal(err)
			}
			if cpu.Source != "dstack" || cpu.Provider != "dstack-v1" || cpu.TEE != "tdx" || string(cpu.Evidence) != "msgpack-attestation" {
				t.Fatalf("bad CPU evidence: %+v", cpu)
			}
			bundles, err := source.CollectGPU(context.Background(), nonce)
			if err != nil {
				t.Fatal(err)
			}
			if len(bundles) != 1 || bundles[0].Format != "nvidia-nvattest-collect-evidence-json-v1" || string(bundles[0].Evidence) != "gpu" || bundles[0].Nonce != hex.EncodeToString(nonce[:]) {
				t.Fatalf("bad GPU bundle: %+v", bundles)
			}
		})
	}
}

func TestDstackFailures(t *testing.T) {
	socket := fakeDstack(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/AttestGpu":
			w.WriteHeader(http.StatusNotImplemented)
		default:
			http.NotFound(w, r) // an agent that predates v1
		}
	})
	_, err := (Dstack{Socket: socket, Platform: "tdx"}).Collect(context.Background(), testReportData())
	if err == nil || !strings.Contains(err.Error(), "0.6.0") {
		t.Fatalf("a pre-v1 agent must say which version is required, got %v", err)
	}
	_, err = (Dstack{Socket: socket, Platform: "tdx"}).CollectGPU(context.Background(), [32]byte{})
	if err == nil || !strings.Contains(err.Error(), "no GPU attestation") {
		t.Fatalf("501 must be reported as no GPU attestation, got %v", err)
	}
	if _, err = (Dstack{Socket: socket}).Collect(context.Background(), testReportData()); err == nil {
		t.Fatal("a source with no platform must not produce evidence")
	}
	if _, err = (Dstack{Socket: filepath.Join(filepath.Dir(socket), "absent.sock"), Platform: "tdx"}).Collect(context.Background(), testReportData()); err == nil {
		t.Fatal("a missing socket must be an error")
	}
}
