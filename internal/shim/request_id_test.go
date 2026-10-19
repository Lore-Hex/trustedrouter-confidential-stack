package shim

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewRequestID(t *testing.T) {
	id, err := newRequestID(bytes.NewReader(bytes.Repeat([]byte{0xab}, 16)))
	if err != nil || id != strings.Repeat("ab", 16) {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if id, err := newRequestID(strings.NewReader("short")); err == nil || id != "" {
		t.Fatal("partial randomness accepted")
	}
}

func TestRequestIDAllResponses(t *testing.T) {
	ids := make(chan string, 10)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ids <- r.Header.Get(requestIDHeader)
		w.Header().Set(requestIDHeader, "engine-canary")
		w.WriteHeader(http.StatusEarlyHints)
		if r.URL.Path == "/health" {
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Trailer", requestIDHeader)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "data: failure\n\n")
		w.Header().Set(requestIDHeader, "trailer-canary")
	}))
	defer up.Close()
	c := config(up.URL)
	c.MaxRequestBytes = 4
	_, ts := testServer(t, c, nil, nil)
	seen := make(map[string]bool)
	for _, tc := range []struct {
		path, body string
		status     int
	}{
		{"/v1/chat/completions", "ok", 503},
		{"/v1/responses", "ok", 503},
		{"/v1/chat/completions", "too big", 413},
		{"/healthz", "", 200},
		{"/missing", "", 404},
		{"/.well-known/trustedrouter/attestation", "", 400},
	} {
		t.Run(tc.path+tc.body, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, ts.URL+tc.path, strings.NewReader(tc.body))
			req.Header.Set(requestIDHeader, "client-canary")
			// A client cannot strip the generated upstream ID as hop-by-hop.
			req.Header.Set("Connection", requestIDHeader)
			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatal(err)
			}
			id := resp.Header.Get(requestIDHeader)
			raw, err := hex.DecodeString(id)
			if resp.StatusCode != tc.status || len(resp.Header.Values(requestIDHeader)) != 1 || err != nil || len(raw) != 16 || seen[id] {
				t.Fatalf("status=%d id=%q repeated=%v", resp.StatusCode, id, seen[id])
			}
			seen[id] = true
			if strings.Contains(tc.path, "/v1/") && tc.status == 503 {
				if got := <-ids; got != id {
					t.Fatalf("upstream id %q != response id %q", got, id)
				}
			}
			if got := resp.Trailer.Get(requestIDHeader); got != "" {
				t.Fatalf("upstream trailer leaked: %q", got)
			}
		})
	}
}

func TestRequestIDUpstreamError(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	up.Close()
	_, ts := testServer(t, config(up.URL), nil, nil)
	resp := get(t, ts, "/v1/models")
	if resp.StatusCode != 502 || len(resp.Header.Get(requestIDHeader)) != 32 {
		t.Fatalf("status=%d id=%q", resp.StatusCode, resp.Header.Get(requestIDHeader))
	}
}
