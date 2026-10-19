package shim

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
)

const requestIDHeader = "X-Request-Id"

type requestIDKey struct{}

func newRequestID(random io.Reader) (string, error) {
	var id [16]byte
	if _, err := io.ReadFull(random, id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey{}).(string)
	return id
}

func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := newRequestID(rand.Reader)
		if err != nil {
			http.Error(w, "request identity unavailable", http.StatusServiceUnavailable)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id))
		w.Header().Set(requestIDHeader, id)
		next.ServeHTTP(&requestIDWriter{ResponseWriter: w, id: id}, r)
	})
}

// Enforce the shim's identity even on upstream informational responses and SSE.
type requestIDWriter struct {
	http.ResponseWriter
	id string
}

func (w *requestIDWriter) WriteHeader(status int) {
	w.Header().Set(requestIDHeader, w.id)
	w.ResponseWriter.WriteHeader(status)
}

func (w *requestIDWriter) Write(p []byte) (int, error) {
	w.Header().Set(requestIDHeader, w.id)
	return w.ResponseWriter.Write(p)
}

func (w *requestIDWriter) Flush() {
	w.Header().Set(requestIDHeader, w.id)
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *requestIDWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Transport populates response trailers only after the body reaches EOF.
// ReverseProxy closes this body before forwarding those trailers.
type requestIDBody struct {
	io.ReadCloser
	trailer http.Header
}

func (b *requestIDBody) Close() error {
	err := b.ReadCloser.Close()
	b.trailer.Del(requestIDHeader)
	return err
}
