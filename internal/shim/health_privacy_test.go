package shim

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealthDoesNotForwardCallerOrEngineData(t *testing.T) {
	for _, status := range []int{200, 401, 429, 500, 503} {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil || len(body) != 0 || r.Method != "GET" || r.URL.Path != "/health" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Private") != "" {
				t.Error("health forwarded caller data")
			}
			w.Header().Set("X-Private", "engine-private-header")
			w.Header().Set("Set-Cookie", "engine-private-cookie")
			w.Header().Set("Retry-After", "engine-private-value")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, "engine-private-body")
		}))
		_, server := testServer(t, config(upstream.URL), nil, io.Discard)
		request, err := http.NewRequest("GET", server.URL+"/healthz?private=caller-query", strings.NewReader("caller-private-body"))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer caller-private-auth")
		request.Header.Set("Cookie", "caller-private-cookie")
		request.Header.Set("X-Private", "caller-private-header")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		want := http.StatusServiceUnavailable
		if status == 200 {
			want = http.StatusOK
		}
		if err != nil || len(body) != 0 || response.StatusCode != want {
			t.Fatal("health leaked body or returned incorrect status")
		}
		for _, name := range []string{"X-Private", "Set-Cookie", "Retry-After"} {
			if response.Header.Get(name) != "" {
				t.Error("health leaked an upstream header")
			}
		}
		upstream.Close()
	}
}

func TestHealthNeverFollowsEngineRedirect(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer target.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer upstream.Close()
	_, server := testServer(t, config(upstream.URL), nil, io.Discard)
	response := get(t, server, "/healthz")
	if response.StatusCode != 503 || calls.Load() != 0 {
		t.Fatal("engine health redirect was followed")
	}
}

func TestHealthDeadlineCancelsEngineRequest(t *testing.T) {
	cancelled := make(chan struct{})
	finish := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			close(cancelled)
		case <-finish:
		}
	}))
	defer upstream.Close()
	defer close(finish)
	_, server := testServer(t, config(upstream.URL), nil, io.Discard)
	server.Client().Timeout = 5 * time.Second
	response := get(t, server, "/healthz")
	if response.StatusCode != 503 {
		t.Fatal("hung engine health did not fail closed")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("engine health request survived deadline")
	}
}
