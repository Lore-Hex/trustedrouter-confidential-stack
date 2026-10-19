package shim

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type unreadBody struct{ read bool }

func (b *unreadBody) Read([]byte) (int, error) {
	b.read = true
	return 0, errors.New("unexpected read")
}
func (*unreadBody) Close() error { return nil }

func TestAdmissionRejectsBeforeReading(t *testing.T) {
	c := config("")
	c.MaxInflight = 1
	s, err := New(context.Background(), c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.inflight <- struct{}{}
	body := &unreadBody{}
	r := httptest.NewRequest("POST", "https://localhost/v1/chat/completions", nil)
	r.Body = body
	r.ContentLength = -1
	w := httptest.NewRecorder()
	s.HTTP.Handler.ServeHTTP(w, r)
	if w.Code != 429 || w.Header().Get("Retry-After") != "1" || body.read || len(s.inflight) != 1 {
		t.Fatalf("status=%d read=%v slots=%d", w.Code, body.read, len(s.inflight))
	}
}

func TestAdmissionSlowHTTP1SenderGetsImmediate429(t *testing.T) {
	c := config("")
	c.MaxInflight = 1
	s, ts := testServer(t, c, nil, nil)
	s.inflight <- struct{}{}
	// Trust only this test server's certificate, as httptest.Client does.
	conn, err := tls.Dial("tcp", ts.Listener.Addr().String(), ts.Client().Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Deliberately never transmit the body and do not use Expect: 100-continue.
	_, err = io.WriteString(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Length: 32\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 429 || !resp.Close || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("status=%d close=%v", resp.StatusCode, resp.Close)
	}
}

func TestAdmissionStreamingAndCancellation(t *testing.T) {
	var calls atomic.Int32
	upstreamCancelled := make(chan struct{}, 1)
	finish := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			upstreamCancelled <- struct{}{}
		case <-finish:
		}
	}))
	defer up.Close()
	defer close(finish)
	c := config(up.URL)
	c.MaxInflight = 1
	s, ts := testServer(t, c, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "POST", ts.URL+"/v1/chat/completions", strings.NewReader("{}"))
	resp, err := ts.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if line, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil || line != "data: first\n" {
		t.Fatalf("stream line=%q err=%v", line, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := ts.Client().Get(ts.URL + "/v1/models")
			if err != nil {
				t.Error(err)
				return
			}
			defer res.Body.Close()
			if res.StatusCode != 429 || res.Header.Get("Retry-After") != "1" {
				t.Errorf("status=%d", res.StatusCode)
			}
		}()
	}
	wg.Wait()
	if get(t, ts, "/healthz").StatusCode != 200 {
		t.Fatal("health blocked by inference saturation")
	}
	if get(t, ts, "/.well-known/trustedrouter/attestation?nonce="+strings.Repeat("0", 64)).StatusCode != 200 {
		t.Fatal("attestation blocked by inference saturation")
	}
	if calls.Load() != 1 {
		t.Fatal("excess inference reached the engine")
	}
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for len(s.inflight) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(s.inflight) != 0 {
		t.Fatal("client cancellation leaked the admission slot")
	}
	select {
	case <-upstreamCancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("client cancellation did not cancel the upstream stream")
	}
}

func TestAdmissionReleasesOnFailures(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "17")
		w.WriteHeader(503)
		_, _ = io.WriteString(w, "engine overloaded")
	}))
	defer up.Close()
	c := config(up.URL)
	c.MaxInflight = 1
	c.MaxRequestBytes = 4
	s, err := New(context.Background(), c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body io.ReadCloser
		code int
	}{
		{io.NopCloser(strings.NewReader("too big")), 413},
		{&unreadBody{}, 400},
		{io.NopCloser(strings.NewReader("{}")), 503},
	} {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://localhost/v1/responses", nil)
			r.Body, r.ContentLength = tc.body, -1
			w := httptest.NewRecorder()
			s.HTTP.Handler.ServeHTTP(w, r)
			if w.Code != tc.code || len(s.inflight) != 0 {
				t.Fatalf("status=%d slots=%d", w.Code, len(s.inflight))
			}
			if tc.code == 503 && (w.Header().Get("Retry-After") != "17" || w.Body.String() != "engine overloaded") {
				t.Fatal("engine overload response was rewritten")
			}
		})
	}
	up.Close()
	w := httptest.NewRecorder()
	s.HTTP.Handler.ServeHTTP(w, httptest.NewRequest("GET", "https://localhost/v1/models", nil))
	if w.Code != 502 || len(s.inflight) != 0 {
		t.Fatalf("upstream failure status=%d slots=%d", w.Code, len(s.inflight))
	}
}

func TestAdmissionConfig(t *testing.T) {
	for _, n := range []int{-1, 0, 65537} {
		c := config("")
		c.MaxInflight = n
		if _, err := c.validate(); err == nil {
			t.Errorf("accepted max-inflight=%d", n)
		}
	}
	for _, n := range []int{1, 32, 65536} {
		c := config("")
		c.MaxInflight = n
		if _, err := c.validate(); err != nil {
			t.Errorf("rejected max-inflight=%d: %v", n, err)
		}
	}
}
