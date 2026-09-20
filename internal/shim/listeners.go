package shim

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The listener audit enforces one rule inside the guest: the shim is the only
// process allowed to listen on a non-loopback address. A NetworkPolicy cannot
// enforce that in the confidential modes, because the host enforces it and the
// host is the adversary. Containers in a pod share one network namespace, so
// /proc/net/tcp{,6} read from the shim's container lists every listener in
// the pod, including the inference engine's.

const tcpListen = "0A"

// parseProcNet returns the ports of LISTEN sockets bound to a non-loopback
// address. Addresses are hex: IPv4 is one little-endian 32-bit word, IPv6 is
// four of them.
func parseProcNet(r io.Reader, v6 bool) ([]int, error) {
	var ports []int
	scanner := bufio.NewScanner(r)
	first := true
	for scanner.Scan() {
		if first { // header row
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != tcpListen {
			continue
		}
		addr, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			return nil, errors.New("malformed local address")
		}
		raw, err := hex.DecodeString(addr)
		want := 4
		if v6 {
			want = 16
		}
		if err != nil || len(raw) != want {
			return nil, errors.New("malformed local address")
		}
		for i := 0; i < len(raw); i += 4 { // each 32-bit word is little-endian
			raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			return nil, errors.New("malformed local port")
		}
		if net.IP(raw).IsLoopback() { // covers 127/8, ::1 and IPv4-mapped 127/8
			continue
		}
		ports = append(ports, int(port))
	}
	return ports, scanner.Err()
}

type listenerAudit struct {
	dir     string
	ownPort int
	enforce bool
	logf    func(string, ...any)
	now     func() time.Time

	mu      sync.Mutex
	checked time.Time
	foreign []int
	failed  bool
	state   string
}

// errAuditUnavailable means the platform has no /proc/net (not Linux).
var errAuditUnavailable = errors.New("listener audit unavailable: no proc net files")

func (a *listenerAudit) scan() ([]int, error) {
	seen := map[int]bool{}
	found := false
	for _, name := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(a.dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		found = true
		ports, err := parseProcNet(f, name == "tcp6")
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		for _, p := range ports {
			if p != a.ownPort {
				seen[p] = true
			}
		}
	}
	if !found {
		return nil, errAuditUnavailable
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// ok reports whether serving is allowed. It rescans at most once every five
// seconds unless force is set, and logs once per change of state. Only port
// numbers are ever logged.
func (a *listenerAudit) ok(force bool) bool {
	if a == nil {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if force || a.checked.IsZero() || now.Sub(a.checked) >= 5*time.Second {
		a.checked = now
		ports, err := a.scan()
		a.foreign, a.failed = ports, err != nil
		state := "clean"
		if err != nil {
			state = "unreadable"
		} else if len(ports) > 0 {
			state = fmt.Sprint(ports)
		}
		if state != a.state {
			a.state = state
			switch {
			case err != nil:
				a.logf("listener-audit state=unreadable enforce=%t", a.enforce)
			case len(ports) > 0:
				a.logf("listener-audit state=violation non_loopback_listener_ports=%v enforce=%t", ports, a.enforce)
			default:
				a.logf("listener-audit state=clean")
			}
		}
	}
	if !a.enforce {
		return true
	}
	return !a.failed && len(a.foreign) == 0
}

// newListenerAudit resolves the mode. "auto" enforces whenever a TEE is in
// use and only warns otherwise. An unavailable audit is fatal exactly when it
// would have been enforcing for a TEE: never claim a guarantee it cannot check.
func newListenerAudit(mode, dir, listen, tee string, logf func(string, ...any)) (*listenerAudit, error) {
	switch mode {
	case "off":
		return nil, nil
	case "auto":
		mode = "warn"
		if tee != "none" {
			mode = "enforce"
		}
	case "enforce", "warn":
	default:
		return nil, errors.New("listener-audit must be auto, enforce, warn or off")
	}
	_, portText, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, errors.New("listen must be host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return nil, errors.New("listen must carry a numeric port")
	}
	audit := &listenerAudit{dir: dir, ownPort: port, enforce: mode == "enforce", logf: logf, now: time.Now}
	if _, err := audit.scan(); errors.Is(err, errAuditUnavailable) {
		if audit.enforce && tee != "none" {
			return nil, errors.New("listener audit cannot run here (no proc net files) but a TEE is in use")
		}
		logf("listener-audit state=unavailable")
		return nil, nil
	}
	return audit, nil
}
