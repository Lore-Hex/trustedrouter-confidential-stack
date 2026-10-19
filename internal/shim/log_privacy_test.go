package shim

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccessLogClasses(t *testing.T) {
	for path, class := range map[string]string{
		"/.well-known/trustedrouter/attestation": "attestation",
		"/healthz":                               "health", "/v1/models": "models",
		"/v1/chat/completions": "chat_completions", "/v1/completions": "completions",
		"/v1/responses": "responses", "/v1/embeddings": "embeddings",
		"/v1/models/private-model-name": "other", "/v1/chat/completions/": "other",
	} {
		if got := routeClass(path); got != class {
			t.Errorf("routeClass(%q)=%q want %q", path, got, class)
		}
	}
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"} {
		if methodClass(method) != method {
			t.Errorf("lost standard method %q", method)
		}
	}
	if methodClass("secret-method") != "OTHER" || methodClass("get") != "OTHER" {
		t.Fatal("nonstandard method was not classified")
	}
}

func TestAccessLogAdversarialData(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Secret", "secret-header")
		w.WriteHeader(503)
		_, _ = io.WriteString(w, "secret-completion")
	}))
	defer up.Close()
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"POST", "/v1/secret-path", "secret-prompt", 503},
		{"secret-method", "/v1/chat/completions", "secret-prompt", 503},
		{"POST", "/private/secret-path", "secret-prompt", 404},
		{"GET", "/v1/../secret-path", "", 404},
		{"GET", "/v1/%2fsecret-path", "", 404},
		{"GET", "/v1/%73ecret-path", "", 503},
		{"GET", "/.well-known/trustedrouter/attestation", "", 400},
		{"POST", "/v1/chat/completions", strings.Repeat("secret-prompt", 10), 413},
	} {
		t.Run(tc.method+tc.path+tc.body, func(t *testing.T) {
			var logs bytes.Buffer
			c := config(up.URL)
			c.MaxRequestBytes = 64
			s, err := New(context.Background(), c, nil, &logs)
			if err != nil {
				t.Fatal(err)
			}
			logs.Reset()
			r := httptest.NewRequest(tc.method, "https://secret-host"+tc.path+"?private=secret-query", strings.NewReader(tc.body))
			r.Header.Set("Authorization", "Bearer secret-credential")
			r.Header.Set(requestIDHeader, "secret-request-id")
			r.RemoteAddr = "secret-client-address"
			w := httptest.NewRecorder()
			s.HTTP.Handler.ServeHTTP(w, r)
			line := logs.String()
			if strings.Contains(line, "secret") || strings.Contains(line, tc.path) || strings.Count(line, "\n") != 1 {
				t.Fatalf("private or unexpected log content: %q", line)
			}
			if w.Code != tc.status || !strings.Contains(line, "request_id="+w.Header().Get(requestIDHeader)) || !strings.Contains(line, "method="+methodClass(tc.method)) {
				t.Fatalf("status=%d log=%q", w.Code, line)
			}
		})
	}
}

func TestAccessLogUpstreamFailureIsContentFree(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	up.Close()
	var logs bytes.Buffer
	s, err := New(context.Background(), config(up.URL), nil, &logs)
	if err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	w := httptest.NewRecorder()
	s.HTTP.Handler.ServeHTTP(w, httptest.NewRequest("POST", "https://localhost/v1/secret-path?secret-query", strings.NewReader("secret-body")))
	if w.Code != 502 || strings.Contains(logs.String(), "secret") || strings.Contains(logs.String(), up.URL) || !strings.Contains(logs.String(), "route=other status=502") {
		t.Fatalf("status=%d log=%q", w.Code, logs.String())
	}
}
