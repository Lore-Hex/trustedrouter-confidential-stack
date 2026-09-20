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
// {"gpu_evidence":[{"vendor":"","format":"","evidence_b64":""}]}; the shim adds
// the nonce and never inspects the evidence.
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
	var wire struct {
		Bundles []struct {
			Vendor   string `json:"vendor"`
			Format   string `json:"format"`
			Evidence []byte `json:"evidence_b64"`
		} `json:"gpu_evidence"`
	}
	decoder := json.NewDecoder(&output)
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
		out = append(out, GPUEvidence{Vendor: b.Vendor, Format: b.Format, Nonce: nonceHex, Evidence: b.Evidence})
	}
	return out, nil
}
