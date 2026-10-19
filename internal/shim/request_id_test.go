package shim

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestRequestIDUnannouncedTrailers(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Trailer.Get(requestIDHeader) != "" {
			t.Error("client request ID trailer reached engine")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		w.Header().Set(http.TrailerPrefix+requestIDHeader, "unannounced-canary")
		w.Header().Set(http.TrailerPrefix+"X-Unrelated", "kept")
	}))
	defer up.Close()
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", http2), func(t *testing.T) {
			s, err := New(context.Background(), config(up.URL), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			ts := httptest.NewUnstartedServer(s.HTTP.Handler)
			ts.EnableHTTP2 = http2
			ts.StartTLS()
			defer ts.Close()
			req, _ := http.NewRequest("POST", ts.URL+"/v1/responses", io.NopCloser(strings.NewReader("{}")))
			req.Trailer = http.Header{requestIDHeader: {"client-trailer-canary"}}
			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			_, err = io.Copy(io.Discard, resp.Body)
			if err != nil || resp.Trailer.Get(requestIDHeader) != "" || resp.Trailer.Get("X-Unrelated") != "kept" {
				t.Fatalf("trailers=%v err=%v", resp.Trailer, err)
			}
			if (resp.ProtoMajor == 2) != http2 || len(resp.Header.Get(requestIDHeader)) != 32 {
				t.Fatalf("protocol=%s requestID=%q", resp.Proto, resp.Header.Get(requestIDHeader))
			}
		})
	}
}

func TestRequestIDPreservesUpgrade(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\nX-Request-Id: engine-upgrade-canary\r\n\r\n")
		_ = rw.Flush()
		line, err := rw.ReadString('\n')
		if err == nil {
			_, _ = fmt.Fprint(rw, line)
			_ = rw.Flush()
		}
	}))
	defer up.Close()
	_, ts := testServer(t, config(up.URL), nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/v1/realtime", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "test")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 101 || len(resp.Header.Get(requestIDHeader)) != 32 {
		t.Fatalf("status=%d id=%q", resp.StatusCode, resp.Header.Get(requestIDHeader))
	}
	rw, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatal("upgrade body is no longer bidirectional")
	}
	if _, err := io.WriteString(rw, "ping\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(rw).ReadString('\n'); err != nil || line != "ping\n" {
		t.Fatalf("upgrade echo=%q err=%v", line, err)
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
