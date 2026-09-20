package shim

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/trustedrouter-confidential-stack/internal/attest"
)

const procHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func row(local, state string) string {
	return "   0: " + local + " 00000000:0000 " + state + " 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0\n"
}

func TestParseProcNet(t *testing.T) {
	v4 := procHeader +
		row("0100007F:1F40", "0A") + // 127.0.0.1:8000 listening: loopback
		row("0A00007F:1F41", "0A") + // 127.0.0.10:8001: still loopback (127/8)
		row("00000000:7531", "0A") + // 0.0.0.0:30001 listening: VIOLATION
		row("0500F40A:20FB", "0A") + // 10.244.0.5:8443 listening: VIOLATION
		row("00000000:9999", "01") // ESTABLISHED on the wildcard: not a listener
	ports, err := parseProcNet(strings.NewReader(v4), false)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := json.Marshal(ports); string(got) != "[30001,8443]" {
		t.Fatalf("v4 ports = %s", got)
	}
	v6 := procHeader +
		row("00000000000000000000000001000000:1F90", "0A") + // [::1]:8080 loopback
		row("0000000000000000FFFF00000100007F:1F91", "0A") + // [::ffff:127.0.0.1]:8081 loopback
		row("00000000000000000000000000000000:20FB", "0A") + // [::]:8443: VIOLATION
		row("B80D0120000000000000000001000000:01BB", "0A") // [2001:db8::1]:443: VIOLATION
	ports, err = parseProcNet(strings.NewReader(v6), true)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := json.Marshal(ports); string(got) != "[8443,443]" {
		t.Fatalf("v6 ports = %s", got)
	}
	for _, bad := range []string{row("ZZ00007F:1F40", "0A"), row("0100007F", "0A"), row("0100007F:GGGG", "0A"), row("01007F:1F40", "0A")} {
		if _, err := parseProcNet(strings.NewReader(procHeader+bad), false); err == nil {
			t.Errorf("malformed row accepted: %q", bad)
		}
	}
}

func procDir(t *testing.T, tcp, tcp6 string) string {
	t.Helper()
	dir := t.TempDir()
	if tcp != "" {
		os.WriteFile(filepath.Join(dir, "tcp"), []byte(tcp), 0600)
	}
	if tcp6 != "" {
		os.WriteFile(filepath.Join(dir, "tcp6"), []byte(tcp6), 0600)
	}
	return dir
}

func TestListenerAuditModes(t *testing.T) {
	var lines []string
	logf := func(format string, args ...any) { lines = append(lines, format) }
	clean := procHeader + row("0100007F:1F40", "0A") + row("00000000:20FB", "0A") // engine on loopback, shim on :8443
	dirty := clean + row("00000000:7531", "0A")

	// The shim's own wildcard listener is not a violation.
	audit, err := newListenerAudit("auto", procDir(t, clean, ""), ":8443", "sev-snp", logf)
	if err != nil || audit == nil || !audit.enforce || !audit.ok(true) {
		t.Fatalf("clean enforce: audit=%v err=%v", audit, err)
	}
	// auto + a TEE enforces; auto + none only warns.
	audit, _ = newListenerAudit("auto", procDir(t, dirty, ""), ":8443", "sev-snp", logf)
	if audit.ok(true) {
		t.Fatal("a foreign non-loopback listener must block serving under a TEE")
	}
	audit, _ = newListenerAudit("auto", procDir(t, dirty, ""), ":8443", "none", logf)
	if audit.enforce || !audit.ok(true) {
		t.Fatal("standard mode must warn, not block")
	}
	// A different own port makes 8443 foreign.
	audit, _ = newListenerAudit("enforce", procDir(t, clean, ""), ":9443", "none", logf)
	if audit.ok(true) {
		t.Fatal("own-port exclusion must use the configured listen port")
	}
	// tcp6 alone is enough to find a violation.
	audit, _ = newListenerAudit("enforce", procDir(t, "", procHeader+row("00000000000000000000000000000000:7531", "0A")), ":8443", "tdx", logf)
	if audit.ok(true) {
		t.Fatal("tcp6 listeners must be audited")
	}
	// Unreadable tables fail closed when enforcing.
	audit, _ = newListenerAudit("enforce", procDir(t, procHeader+row("garbage", "0A"), ""), ":8443", "tdx", logf)
	if audit.ok(true) {
		t.Fatal("an unparseable table must fail closed")
	}
	// No proc files (not Linux): fatal only when it would have enforced for a TEE.
	if _, err = newListenerAudit("auto", t.TempDir(), ":8443", "sev-snp", logf); err == nil {
		t.Fatal("a TEE with no audit available must refuse to start")
	}
	if audit, err = newListenerAudit("auto", t.TempDir(), ":8443", "none", logf); err != nil || audit != nil {
		t.Fatalf("standard mode without proc files must skip: %v %v", audit, err)
	}
	if audit, err = newListenerAudit("off", "/nonexistent", ":8443", "sev-snp", logf); err != nil || audit != nil {
		t.Fatal("off must disable the audit")
	}
	if _, err = newListenerAudit("sometimes", t.TempDir(), ":8443", "none", logf); err == nil {
		t.Fatal("invalid mode accepted")
	}
	if !(*listenerAudit)(nil).ok(true) {
		t.Fatal("a disabled audit must allow serving")
	}
}

// newUpstream is a loopback engine stand-in that answers 200 to everything.
func newUpstream(t *testing.T) string {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	t.Cleanup(up.Close)
	return up.URL
}

type gpuSource struct{ fakeSource }

func (gpuSource) CollectGPU(_ context.Context, nonce [32]byte) ([]attest.GPUEvidence, error) {
	return []attest.GPUEvidence{{Vendor: "nvidia", Format: "test", Nonce: hex.EncodeToString(nonce[:]), Evidence: []byte("gpu")}}, nil
}

func TestAuditThroughHandlerAndGPURouting(t *testing.T) {
	upstream := newUpstream(t)
	clean := procHeader + row("0100007F:1F40", "0A")
	dir := procDir(t, clean+row("00000000:7531", "0A"), "")
	var logs lockedBuffer
	c := config(upstream)
	c.TEE, c.RequireTEE, c.ListenerAudit, c.ProcNetDir = "sev-snp", true, "auto", dir
	server, ts := testServer(t, c, gpuSource{}, &logs)
	now := time.Now()
	server.audit.now = func() time.Time { return now }

	status := func(path string) (int, string) {
		r := get(t, ts, path)
		body, _ := io.ReadAll(r.Body)
		return r.StatusCode, strings.TrimSpace(string(body))
	}
	if code, _ := status("/healthz"); code != http.StatusServiceUnavailable {
		t.Fatalf("healthz with a foreign listener = %d", code)
	}
	if code, body := status("/v1/models"); code != http.StatusServiceUnavailable || body != "listener audit failed" {
		t.Fatalf("proxy with a foreign listener = %d %q", code, body)
	}
	// Evidence stays available for debugging, and carries the agent's GPU bundle.
	r := get(t, ts, attest.Path+"?nonce="+strings.Repeat("2", 64))
	var wire attest.Response
	if err := json.NewDecoder(r.Body).Decode(&wire); err != nil || r.StatusCode != 200 {
		t.Fatalf("attestation during a violation: %d %v", r.StatusCode, err)
	}
	data, _ := hex.DecodeString(wire.ReportData)
	var reportData [64]byte
	copy(reportData[:], data)
	wantNonce := attest.GPUNonce(reportData)
	if !wire.Confidential || wire.GPUError != nil || len(wire.GPUEvidence) != 1 || wire.GPUEvidence[0].Nonce != hex.EncodeToString(wantNonce[:]) || string(wire.GPUEvidence[0].Evidence) != "gpu" {
		t.Fatalf("GPU evidence routing: %+v", wire)
	}
	// Clearing the violation restores service; the proxy path honours the 5 s cache.
	os.WriteFile(filepath.Join(dir, "tcp"), []byte(clean), 0600)
	if code, _ := status("/v1/models"); code != http.StatusServiceUnavailable {
		t.Fatalf("proxy must not rescan inside the cache window, got %d", code)
	}
	now = now.Add(6 * time.Second)
	if code, _ := status("/v1/models"); code != http.StatusOK {
		t.Fatalf("proxy after the violation cleared = %d", code)
	}
	if code, _ := status("/healthz"); code != http.StatusOK {
		t.Fatalf("healthz after the violation cleared = %d", code)
	}
	out := logs.String()
	if strings.Count(out, "listener-audit state=violation") != 1 || strings.Count(out, "listener-audit state=clean") != 1 {
		t.Fatalf("expected exactly one log line per state change:\n%s", out)
	}
	if !strings.Contains(out, "non_loopback_listener_ports=[30001]") || !strings.Contains(out, "evidence_source=injected tee=sev-snp") {
		t.Fatalf("log content:\n%s", out)
	}
}
