package checkendpoint

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lore-Hex/trustedrouter-confidential-stack/internal/attest"
	"github.com/Lore-Hex/trustedrouter-confidential-stack/internal/shim"
)

func TestStandardShim(t *testing.T) {
	c := shim.DefaultConfig()
	c.TEE = "none"
	s, e := shim.New(context.Background(), c, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	ts := httptest.NewUnstartedServer(s.HTTP.Handler)
	ts.TLS = s.HTTP.TLSConfig.Clone()
	ts.StartTLS()
	defer ts.Close()
	var out, stderr bytes.Buffer
	if code := Run(context.Background(), ts.URL, "none", true, &out, &stderr); code != 0 {
		t.Fatalf("code=%d %s", code, stderr.String())
	}
	if !strings.Contains(out.String(), `"hardware_evidence_verified":false`) {
		t.Fatal("missing honest JSON flag")
	}
}
func TestBindingFailuresAndTEE(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
	}{{"good", 0}, {"spki", 1}, {"nonce", 1}, {"report_data", 1}, {"protocol", 1}, {"tee", 3}, {"replaced-connection", 1}, {"expect-tee", 1}} {
		t.Run(tc.name, func(t *testing.T) {
			var spki [32]byte
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/healthz" {
					if tc.name == "replaced-connection" {
						w.Header().Set("Connection", "close")
					}
					w.WriteHeader(200)
					return
				}
				nonce, _ := attest.ParseNonce(r.URL.Query().Get("nonce"))
				data := attest.ReportData(nonce, spki)
				response := attest.Response{Protocol: attest.Protocol, TEE: "none", Nonce: r.URL.Query().Get("nonce"), TLSSPKISHA256: hex.EncodeToString(spki[:]), ReportData: hex.EncodeToString(data[:])}
				switch tc.name {
				case "spki":
					response.TLSSPKISHA256 = strings.Repeat("0", 64)
				case "nonce":
					response.Nonce = strings.Repeat("0", 64)
				case "report_data":
					response.ReportData = strings.Repeat("0", 128)
				case "protocol":
					response.Protocol = "wrong"
				case "tee":
					response.TEE = "sev-snp"
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			ts.StartTLS()
			defer ts.Close()
			cert, e := x509.ParseCertificate(ts.TLS.Certificates[0].Certificate[0])
			if e != nil {
				t.Fatal(e)
			}
			spki = attest.SPKI(cert)
			var out, stderr bytes.Buffer
			expect := "any"
			if tc.name == "expect-tee" {
				expect = "tdx"
			}
			code := Run(context.Background(), ts.URL, expect, true, &out, &stderr)
			if code != tc.code {
				t.Fatalf("code=%d want=%d stderr=%s", code, tc.code, stderr.String())
			}
			if code == 3 && (!strings.Contains(stderr.String(), Warning) || !strings.Contains(stderr.String(), `"hardware_evidence_verified": false`) || !strings.Contains(out.String(), Warning) || !strings.Contains(out.String(), `"hardware_evidence_verified":false`)) {
				t.Fatal("missing hardware warning")
			}
		})
	}
}
func TestRefusesPlainHTTP(t *testing.T) {
	_, code, _ := Check(context.Background(), "http://127.0.0.1", "any")
	if code != 1 {
		t.Fatal(code)
	}
}
