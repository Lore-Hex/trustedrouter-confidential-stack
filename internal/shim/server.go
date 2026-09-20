package shim

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/trustedrouter-confidential-stack/internal/attest"
)

type Server struct {
	HTTP         *http.Server
	cfg          Config
	tee          string
	source       attest.EvidenceSource
	spki         [32]byte
	gpuCommand   []string
	evidenceMu   sync.Mutex
	limiter      *limiter
	proxy        *httputil.ReverseProxy
	healthClient *http.Client
	healthURL    string
	logger       *log.Logger
	audit        *listenerAudit
}

// New runs the evidence self-test before opening a listening socket. source is
// optional (nil selects configfs automatically); injection supports other backends.
func New(ctx context.Context, c Config, source attest.EvidenceSource, logs io.Writer) (*Server, error) {
	upstream, err := c.validate()
	if err != nil {
		return nil, err
	}
	command, err := attest.SplitCommand(c.GPUEvidenceCommand)
	if err != nil {
		return nil, err
	}
	cert, err := certificate(c)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	spki := attest.SPKI(leaf)
	source, tee, sourceName, err := sourceFor(ctx, c, spki, source)
	if err != nil {
		return nil, err
	}
	if logs == nil {
		logs = io.Discard
	}
	startup := log.New(logs, "", 0)
	startup.Printf("trcs shim evidence_source=%s tee=%s", sourceName, tee)
	audit, err := newListenerAudit(c.ListenerAudit, c.ProcNetDir, c.Listen, tee, startup.Printf)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil              // Do not send private loopback requests through environment proxies.
	transport.DisableKeepAlives = true // Go's Transport can retry on reused connections; never retry inference.
	s := &Server{cfg: c, source: source, tee: tee, spki: spki, gpuCommand: command, limiter: newLimiter(c.AttestationRate), logger: log.New(logs, "", 0), healthURL: upstream.String() + "/health", audit: audit}
	// The upstream origin is validated above; normalize its trailing slash.
	health := *upstream
	health.Path = "/health"
	s.healthURL = health.String()
	s.healthClient = &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	s.proxy = &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		for key := range pr.Out.Header {
			if strings.HasPrefix(strings.ToLower(key), "x-forwarded-") {
				pr.Out.Header.Del(key)
			}
		}
		pr.Out.Header.Del("Forwarded")
		pr.SetURL(upstream)
		// ReverseProxy removes hop-by-hop headers. Authorization is preserved.
	}, Transport: transport, FlushInterval: -1, ErrorLog: log.New(io.Discard, "", 0), ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}}
	s.HTTP = &http.Server{Addr: c.Listen, Handler: s.accessLog(http.HandlerFunc(s.handle)), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second, ErrorLog: log.New(io.Discard, "", 0), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}}
	return s, nil
}
func (s *Server) Serve(l net.Listener) error         { return s.HTTP.ServeTLS(l, "", "") }
func (s *Server) Shutdown(ctx context.Context) error { return s.HTTP.Shutdown(ctx) }
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case attest.Path:
		s.attestation(w, r)
		return
	case "/healthz":
		if !s.audit.ok(true) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, s.healthURL, nil)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		resp, err := s.healthClient.Do(req)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(200)
		return
	}
	// Reject noncanonical/encoded separators so upstream normalization cannot escape
	// the allow-list. Queries remain opaque and are never included in access logs.
	canonical := path.Clean(r.URL.Path)
	if strings.HasSuffix(r.URL.Path, "/") && canonical != "/" {
		canonical += "/"
	}
	if canonical != r.URL.Path || strings.Contains(r.URL.Path, "\\") || strings.Contains(strings.ToLower(r.URL.EscapedPath()), "%2f") || strings.Contains(strings.ToLower(r.URL.EscapedPath()), "%5c") {
		http.NotFound(w, r)
		return
	}
	allowed := false
	for _, prefix := range s.cfg.AllowPathPrefixes {
		if strings.HasPrefix(r.URL.Path, prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		http.NotFound(w, r)
		return
	}
	// The attestation endpoint stays up so an operator can still debug; nothing
	// is proxied while another process in the guest is reachable from outside.
	if !s.audit.ok(false) {
		http.Error(w, "listener audit failed", http.StatusServiceUnavailable)
		return
	}
	if r.ContentLength > s.cfg.MaxRequestBytes {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxRequestBytes+1))
		r.Body.Close()
		if int64(len(body)) > s.cfg.MaxRequestBytes {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.GetBody = nil
	}
	s.proxy.ServeHTTP(w, r)
}
func (s *Server) attestation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", 405)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query["nonce"]) != 1 {
		http.Error(w, "invalid nonce", 400)
		return
	}
	nonce, err := attest.ParseNonce(query.Get("nonce"))
	if err != nil {
		http.Error(w, "invalid nonce", 400)
		return
	}
	if !s.limiter.allow(time.Now()) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limited", 429)
		return
	}
	data := attest.ReportData(nonce, s.spki)
	result := attest.Response{Protocol: attest.Protocol, TEE: s.tee, Nonce: query.Get("nonce"), TLSSPKISHA256: hex.EncodeToString(s.spki[:]), ReportData: hex.EncodeToString(data[:]), Workload: s.cfg.Workload}
	gpuErr := "gpu evidence helper not configured"
	if s.source == nil && len(s.gpuCommand) > 0 {
		gpuErr = "gpu evidence not collected in standard mode"
	}
	result.GPUError = &gpuErr
	if s.source != nil {
		// Serialize the entire CPU/GPU generation to avoid racing device state.
		s.evidenceMu.Lock()
		defer s.evidenceMu.Unlock()
		if r.Context().Err() != nil {
			return
		}
		cpu, err := s.source.Collect(r.Context(), data)
		if err != nil || cpu == nil || len(cpu.Evidence) == 0 {
			http.Error(w, "CPU evidence unavailable", 503)
			return
		}
		if cpu.TEE != s.tee {
			http.Error(w, "CPU provider changed", 503)
			return
		}
		result.CPU = cpu
		// An explicit helper wins; otherwise ask the platform agent if it can.
		var bundles []attest.GPUEvidence
		gpuNonce := attest.GPUNonce(data)
		if len(s.gpuCommand) > 0 {
			bundles, err = attest.CollectGPUs(r.Context(), s.gpuCommand, gpuNonce)
		} else if agent, ok := s.source.(attest.GPUEvidenceSource); ok {
			bundles, err = agent.CollectGPU(r.Context(), gpuNonce)
		} else {
			err = errors.New("gpu evidence helper not configured")
		}
		if err != nil {
			gpuErr = err.Error()
		} else {
			result.GPUEvidence = bundles
			result.GPUError = nil
		}
		result.Confidential = len(result.GPUEvidence) > 0
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

type logWriter struct {
	http.ResponseWriter
	status, bytes int
}

func (w *logWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *logWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}
func (w *logWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *logWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &logWriter{ResponseWriter: w}
		defer func() {
			status := lw.status
			if status == 0 {
				status = 200
			}
			s.logger.Printf("%s method=%q path=%q status=%d bytes=%d duration=%s", start.UTC().Format(time.RFC3339Nano), r.Method, r.URL.Path, status, lw.bytes, time.Since(start))
		}()
		next.ServeHTTP(lw, r)
	})
}

// IsClosed reports the normal result of a graceful HTTP shutdown.
func IsClosed(err error) bool { return errors.Is(err, http.ErrServerClosed) }
