package attest

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestGPUBufferCopyBound(t *testing.T) {
	for _, size := range []int{8 << 20, (8 << 20) + 1} {
		var b limitedBuffer
		// Hide WriterTo to exercise io.Copy's destination-ReadFrom path.
		r := struct{ io.Reader }{bytes.NewReader(make([]byte, size))}
		_, err := io.Copy(&b, r)
		if (err == nil) != (size == 8<<20) || b.Len() > 8<<20 {
			t.Fatalf("size=%d buffered=%d err=%v", size, b.Len(), err)
		}
		if size == 8<<20 && b.Len() != size {
			t.Fatal("valid boundary output was truncated")
		}
	}
}

func TestGPUBufferChildOutputBound(t *testing.T) {
	if os.Getenv("TRCS_TEST_GPU_OVERSIZE_CHILD") == "1" {
		_, _ = os.Stdout.Write(make([]byte, 9<<20))
		os.Exit(0)
	}
	t.Setenv("TRCS_TEST_GPU_OVERSIZE_CHILD", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGPUBufferChildOutputBound$")
	var b limitedBuffer
	cmd.Stdout = &b
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err == nil || b.Len() > 8<<20 {
		t.Fatalf("helper exceeded output cap: buffered=%d err=%v", b.Len(), err)
	}
	if ctx.Err() != nil {
		t.Fatal("output cap did not stop collection before timeout")
	}
}
