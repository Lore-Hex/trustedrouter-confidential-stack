package shim

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/trustedrouter-confidential-stack/internal/attest"
)

func testServer(t *testing.T, c Config, source attest.EvidenceSource, logs io.Writer) (*Server, *httptest.Server) {
	t.Helper()
	s, err := New(context.Background(), c, source, logs)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(s.HTTP.Handler)
	ts.TLS = s.HTTP.TLSConfig.Clone()
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return s, ts
}
func config(upstream string) Config {
	c := DefaultConfig()
	c.TEE = "none"
	// The audit reads the host's real socket table; tests that exercise it use
	// fixture directories instead (listeners_test.go).
	c.ListenerAudit = "off"
	c.TLSSANs = []string{"localhost", "127.0.0.1"}
	if upstream != "" {
		c.Upstream = upstream
	}
	return c
}
func get(t *testing.T, ts *httptest.Server, path string) *http.Response {
	t.Helper()
	r, e := ts.Client().Get(ts.URL + path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Body.Close() })
	return r
}
func TestSPKIAndNoneShape(t *testing.T) {
	_, ts := testServer(t, config(""), nil, nil)
	nonce := strings.Repeat("0", 64)
	r := get(t, ts, attest.Path+"?nonce="+nonce)
	var wire attest.Response
	if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
		t.Fatal(err)
	}
	spki := attest.SPKI(r.TLS.PeerCertificates[0])
	data := attest.ReportData([32]byte{}, spki)
	if wire.TLSSPKISHA256 != hex.EncodeToString(spki[:]) || wire.ReportData != hex.EncodeToString(data[:]) {
		t.Fatal("binding differs from live certificate")
	}
	if wire.TEE != "none" || wire.CPU != nil || wire.GPUEvidence != nil || wire.Confidential || wire.GPUError == nil || *wire.GPUError != "gpu evidence helper not configured" {
		t.Fatalf("bad standard response: %+v", wire)
	}
	if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Content-Type") != "application/json" {
		t.Fatal("bad headers")
	}
}
func TestNonceHandler(t *testing.T) {
	_, ts := testServer(t, config(""), nil, nil)
	for _, tc := range []struct {
		name, query, method string
		status              int
	}{{"absent", "", "GET", 400}, {"short", "?nonce=00", "GET", 400}, {"badhex", "?nonce=" + strings.Repeat("x", 64), "GET", 400}, {"duplicate", "?nonce=" + strings.Repeat("0", 64) + "&nonce=" + strings.Repeat("0", 64), "GET", 400}, {"post", "?nonce=" + strings.Repeat("0", 64), "POST", 405}, {"valid", "?nonce=" + strings.Repeat("0", 64), "GET", 200}} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, ts.URL+attest.Path+tc.query, nil)
			r, e := ts.Client().Do(req)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Body.Close()
			if r.StatusCode != tc.status || r.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d", r.StatusCode)
			}
		})
	}
}
func TestRateLimiter(t *testing.T) {
	l := newLimiter(2)
	now := l.last
	for i := 0; i < 5; i++ {
		if !l.allow(now) {
			t.Fatal("early limit")
		}
	}
	if l.allow(now) || l.allow(now.Add(499*time.Millisecond)) {
		t.Fatal("over burst")
	}
	if !l.allow(now.Add(500 * time.Millisecond)) {
		t.Fatal("not replenished")
	}
	if l.allow(now.Add(500 * time.Millisecond)) {
		t.Fatal("double spend")
	}
}
func TestRateHTTP(t *testing.T) {
	c := config("")
	c.AttestationRate = .0001
	_, ts := testServer(t, c, nil, nil)
	for i := 0; i < 6; i++ {
		r := get(t, ts, attest.Path+"?nonce="+strings.Repeat("0", 64))
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if i == 5 && (r.StatusCode != 429 || r.Header.Get("Retry-After") != "1") {
			t.Fatalf("status=%d", r.StatusCode)
		}
	}
}
func TestPathAndBody(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) }))
	defer up.Close()
	c := config(up.URL)
	c.MaxRequestBytes = 4
	_, ts := testServer(t, c, nil, nil)
	for _, tc := range []struct {
		path, body string
		length     int64
		status     int
	}{{"/v1/chat/completions", "ok", 2, 201}, {"/admin", "", 0, 404}, {"/v1", "", 0, 404}, {"/v1/../admin", "", 0, 404}, {"/v1%2fadmin", "", 0, 404}, {"/v1/chat/completions", "12345", 5, 413}, {"/v1/chat/completions", "12345", -1, 413}} {
		t.Run(tc.path+fmt.Sprint(tc.length), func(t *testing.T) {
			req, _ := http.NewRequest("POST", ts.URL+tc.path, strings.NewReader(tc.body))
			req.ContentLength = tc.length
			r, e := ts.Client().Do(req)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Body.Close()
			if r.StatusCode != tc.status {
				t.Fatalf("got %d", r.StatusCode)
			}
		})
	}
}
func TestCustomPrefix(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer up.Close()
	c := config(up.URL)
	c.AllowPathPrefixes = []string{"/custom/"}
	_, ts := testServer(t, c, nil, nil)
	if get(t, ts, "/custom/test").StatusCode != 200 || get(t, ts, "/v1/models").StatusCode != 404 {
		t.Fatal("custom allow-list not enforced")
	}
}
func TestSSEIncremental(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	defer finish()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer up.Close()
	defer finish()
	_, ts := testServer(t, config(up.URL), nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/v1/chat/completions", nil)
	r, e := ts.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	reader := bufio.NewReader(r.Body)
	line, e := reader.ReadString('\n')
	if e != nil || line != "data: first\n" {
		t.Fatalf("first chunk: %q %v", line, e)
	}
	finish()
	rest, e := io.ReadAll(reader)
	if e != nil || !strings.Contains(string(rest), "[DONE]") {
		t.Fatal("missing final chunk")
	}
}

type lockedBuffer struct {
	sync.Mutex
	b bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) { b.Lock(); defer b.Unlock(); return b.b.Write(p) }
func (b *lockedBuffer) String() string              { b.Lock(); defer b.Unlock(); return b.b.String() }
func TestPrivacyAndHeaders(t *testing.T) {
	var logs lockedBuffer
	headers := make(chan http.Header, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Clone()
		io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, "response-canary")
	}))
	defer up.Close()
	_, ts := testServer(t, config(up.URL), nil, &logs)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/chat/completions?secret=query-canary", strings.NewReader("body-canary"))
	req.Header.Set("Authorization", "Bearer header-canary")
	req.Header.Set("X-Forwarded-For", "secret")
	req.Header.Set("X-Forwarded-Arbitrary", "secret")
	r, e := ts.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	h := <-headers
	if h.Get("Authorization") != "Bearer header-canary" {
		t.Fatal("authorization changed")
	}
	for key := range h {
		if strings.HasPrefix(strings.ToLower(key), "x-forwarded-") {
			t.Fatal("forwarded header leaked")
		}
	}
	// Wait for the handler's deferred log write without racing its buffer.
	deadline := time.Now().Add(time.Second)
	for logs.String() == "" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	output := logs.String()
	for _, canary := range []string{"query-canary", "body-canary", "response-canary", "header-canary", "?secret"} {
		if strings.Contains(output, canary) {
			t.Fatalf("logged sensitive content: %s", canary)
		}
	}
	if !strings.Contains(output, `path="/v1/chat/completions"`) || !strings.Contains(output, "status=200") {
		t.Fatal("missing access log fields")
	}
}
func TestStartupGuards(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*Config)
	}{{"external-cert", func(c *Config) { c.TEE = "auto"; c.TLSCert = "cert"; c.TLSKey = "key" }}, {"require-none", func(c *Config) { c.RequireTEE = true }}, {"require-source-none", func(c *Config) { c.TEE = "auto"; c.EvidenceSource = "none"; c.RequireTEE = true }}, {"remote", func(c *Config) { c.Upstream = "http://example.com:8000" }}, {"invalid-tee", func(c *Config) { c.TEE = "mystery" }}, {"invalid-source", func(c *Config) { c.EvidenceSource = "mystery" }}} {
		t.Run(tc.name, func(t *testing.T) {
			c := config("")
			tc.modify(&c)
			if _, err := New(context.Background(), c, nil, nil); err == nil {
				t.Fatal("expected refusal")
			}
		})
	}
}
func TestHealth(t *testing.T) {
	for _, status := range []int{200, 500, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" {
					t.Error("wrong health path")
				}
				w.WriteHeader(status)
				fmt.Fprint(w, "private-detail")
			}))
			defer up.Close()
			_, ts := testServer(t, config(up.URL), nil, nil)
			r := get(t, ts, "/healthz")
			b, _ := io.ReadAll(r.Body)
			want := 503
			if status == 200 {
				want = 200
			}
			if r.StatusCode != want || len(b) != 0 {
				t.Fatal("health leaked detail or bad status")
			}
		})
	}
}

type fakeSource struct{}

func (fakeSource) Collect(_ context.Context, data [64]byte) (*attest.CPU, error) {
	return &attest.CPU{Provider: "sev_guest", Source: "configfs-tsm", Evidence: append([]byte("fake:"), data[:]...), TEE: "sev-snp"}, nil
}
func TestEvidenceBinding(t *testing.T) {
	c := config("")
	c.TEE = "sev-snp"
	c.RequireTEE = true
	_, ts := testServer(t, c, fakeSource{}, nil)
	r := get(t, ts, attest.Path+"?nonce="+strings.Repeat("1", 64))
	var result attest.Response
	if e := json.NewDecoder(r.Body).Decode(&result); e != nil {
		t.Fatal(e)
	}
	data, _ := hex.DecodeString(result.ReportData)
	if result.TEE != "sev-snp" || !bytes.Equal(result.CPU.Evidence, append([]byte("fake:"), data...)) || result.Confidential {
		t.Fatal("CPU binding or convenience flag incorrect")
	}
}
