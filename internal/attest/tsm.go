package attest

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ReportFS is the small configfs surface required to produce a report. Remove
// must be rmdir, never RemoveAll: configfs attributes are owned by the kernel.
type ReportFS interface {
	MkdirTemp(string, string) (string, error)
	WriteFile(string, []byte, fs.FileMode) error
	ReadFile(string) ([]byte, error)
	Remove(string) error
}
type OSReportFS struct{}

func (OSReportFS) MkdirTemp(p, s string) (string, error)             { return os.MkdirTemp(p, s) }
func (OSReportFS) WriteFile(p string, b []byte, m fs.FileMode) error { return os.WriteFile(p, b, m) }
func (OSReportFS) ReadFile(p string) ([]byte, error)                 { return os.ReadFile(p) }
func (OSReportFS) Remove(p string) error                             { return os.Remove(p) }

type TSM struct {
	Path string
	FS   ReportFS
}

func (s TSM) Collect(ctx context.Context, data [64]byte) (cpu *CPU, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	f := s.FS
	if f == nil {
		f = OSReportFS{}
	}
	dir, err := f.MkdirTemp(s.Path, "trcs-")
	if err != nil {
		return nil, fmt.Errorf("create TSM report: %w", err)
	}
	defer func() {
		if e := f.Remove(dir); e != nil && err == nil {
			cpu = nil
			err = fmt.Errorf("remove TSM report: %w", e)
		}
	}()
	generation := func() (uint64, error) {
		b, e := f.ReadFile(filepath.Join(dir, "generation"))
		if e != nil {
			return 0, e
		}
		return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	}
	before, err := generation()
	if err != nil {
		return nil, err
	}
	if err = f.WriteFile(filepath.Join(dir, "inblob"), data[:], 0600); err != nil {
		return nil, err
	}
	report, err := f.ReadFile(filepath.Join(dir, "outblob"))
	if err != nil {
		return nil, err
	}
	if len(report) == 0 {
		return nil, errors.New("empty TSM evidence")
	}
	provider, err := f.ReadFile(filepath.Join(dir, "provider"))
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(string(provider))
	tee, err := TEE(name)
	if err != nil {
		return nil, err
	}
	aux, err := f.ReadFile(filepath.Join(dir, "auxblob"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if len(aux) == 0 {
		aux = nil
	}
	after, err := generation()
	if err != nil {
		return nil, err
	}
	// Exactly one write must have occurred. Reject wraps, races and stale reports.
	if before == ^uint64(0) || after != before+1 {
		return nil, errors.New("TSM generation changed unexpectedly")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return &CPU{Source: "configfs-tsm", Provider: name, Evidence: report, Aux: aux, TEE: tee}, nil
}
