package attest

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode"
)

// SplitCommand parses a command and quoted arguments without invoking a shell.
// There is no expansion, command substitution, globbing or redirection.
func SplitCommand(s string) ([]string, error) {
	var args []string
	var b strings.Builder
	var quote rune
	escaped, started := false, false
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			started = true
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped = true
			started = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			started = true
			continue
		}
		if unicode.IsSpace(r) {
			if started {
				args = append(args, b.String())
				b.Reset()
				started = false
			}
			continue
		}
		b.WriteRune(r)
		started = true
	}
	if quote != 0 || escaped {
		return nil, errors.New("unterminated GPU helper quoting")
	}
	if started {
		args = append(args, b.String())
	}
	if len(args) > 0 && args[0] == "" {
		return nil, errors.New("empty GPU executable")
	}
	return args, nil
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 8<<20 {
		return 0, errors.New("GPU helper output too large")
	}
	return b.Buffer.Write(p)
}

// CollectGPUs runs the optional operator-supplied helper. The helper prints
// {"gpu_evidence":[{"vendor":"","format":"","evidence_b64":""}]}; entries
// may also carry device_type (gpu|nvswitch) and device_id. The shim adds the
// nonce but never treats envelope labels as authenticated vendor evidence.
func CollectGPUs(ctx context.Context, command []string, nonce [32]byte) ([]GPUEvidence, error) {
	if len(command) == 0 {
		return nil, errors.New("gpu evidence helper not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	// The only request-derived input is the protocol's GPU nonce.
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "TRCS_GPU_NONCE=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	nonceHex := hex.EncodeToString(nonce[:])
	cmd.Env = append(cmd.Env, "TRCS_GPU_NONCE="+nonceHex)
	var output limitedBuffer
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return nil, errors.New("gpu evidence helper failed")
	}
	return decodeHelperGPUs(output.Bytes(), nonceHex)
}

func decodeHelperGPUs(output []byte, nonceHex string) ([]GPUEvidence, error) {
	if len(output) > 8<<20 {
		return nil, errors.New("GPU helper output too large")
	}
	var wire struct {
		Bundles []struct {
			Vendor     string `json:"vendor"`
			Format     string `json:"format"`
			Evidence   []byte `json:"evidence_b64"`
			DeviceType string `json:"device_type"`
			DeviceID   string `json:"device_id"`
		} `json:"gpu_evidence"`
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	if err := decoder.Decode(&wire); err != nil {
		return nil, errors.New("invalid gpu evidence helper JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing gpu evidence helper output")
	}
	if len(wire.Bundles) == 0 {
		return nil, errors.New("gpu evidence helper returned no evidence")
	}
	out := make([]GPUEvidence, 0, len(wire.Bundles))
	for _, b := range wire.Bundles {
		if b.Vendor == "" || b.Format == "" || len(b.Evidence) == 0 {
			return nil, errors.New("incomplete gpu evidence bundle")
		}
		out = append(out, GPUEvidence{Vendor: b.Vendor, Format: b.Format, Nonce: nonceHex, Evidence: b.Evidence, DeviceType: b.DeviceType, DeviceID: b.DeviceID})
	}
	return out, ValidateGPUEnvelopes(out)
}

// ValidateGPUEnvelopes checks bounded, unambiguous transport labels only. It
// does not authenticate a nonce, device identity, complete hardware inventory,
// CC mode or firmware. Untagged legacy aggregates stay explicitly untagged.
func ValidateGPUEnvelopes(bundles []GPUEvidence) error {
	if len(bundles) == 0 || len(bundles) > 64 {
		return errors.New("invalid GPU evidence bundle count")
	}
	seen := make(map[string]bool)
	tagged := 0
	total := 0
	for _, b := range bundles {
		total += len(b.Evidence)
		if !validDeviceLabel(b.Vendor) || !validDeviceLabel(b.Format) || len(b.Evidence) == 0 || total > 8<<20 {
			return errors.New("invalid GPU evidence envelope")
		}
		if _, err := ParseNonce(b.Nonce); err != nil {
			return errors.New("invalid GPU evidence envelope nonce")
		}
		if b.DeviceType == "" && b.DeviceID == "" {
			continue
		}
		if (b.DeviceType != "gpu" && b.DeviceType != "nvswitch") || !validDeviceLabel(b.DeviceID) {
			return errors.New("invalid GPU evidence device label")
		}
		tagged++
		key := b.Vendor + "/" + b.DeviceType + "/" + b.DeviceID
		if seen[key] {
			return errors.New("duplicate GPU evidence device label")
		}
		seen[key] = true
	}
	if tagged != 0 && tagged != len(bundles) {
		return errors.New("mixed tagged and aggregate GPU evidence")
	}
	return nil
}

func validDeviceLabel(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.:", r)) {
			return false
		}
	}
	return true
}
