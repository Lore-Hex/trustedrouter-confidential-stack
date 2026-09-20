package attest

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestVectors(t *testing.T) {
	content, err := os.ReadFile("../../docs/attestation-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Protocol string `json:"protocol"`
		Vectors  []struct {
			Name, Nonce string
			SPKI        string `json:"tls_spki_sha256"`
			Report      string `json:"report_data"`
			GPU         string `json:"gpu_nonce"`
		} `json:"vectors"`
	}
	if err = json.Unmarshal(content, &file); err != nil {
		t.Fatal(err)
	}
	if file.Protocol != Protocol || len(file.Vectors) != 3 {
		t.Fatal("invalid vector file")
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			nonce, err := ParseNonce(v.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			spki, err := ParseNonce(v.SPKI)
			if err != nil {
				t.Fatal(err)
			}
			report := ReportData(nonce, spki)
			gpu := GPUNonce(report)
			if hex.EncodeToString(report[:]) != v.Report || hex.EncodeToString(gpu[:]) != v.GPU {
				t.Fatal("transcript mismatch")
			}
		})
	}
}
func TestNonce(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		ok          bool
	}{{"zero", strings.Repeat("0", 64), true}, {"upper", strings.Repeat("AB", 32), true}, {"empty", "", false}, {"short", strings.Repeat("0", 63), false}, {"long", strings.Repeat("0", 65), false}, {"nonhex", strings.Repeat("g", 64), false}, {"space", strings.Repeat(" ", 64), false}} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseNonce(tc.value)
			if (err == nil) != tc.ok {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

type fakeFS struct {
	generation uint64
	provider   string
	in         []byte
	removed    bool
	race       bool
	aux        []byte
	missingAux bool
	empty      bool
}

func (f *fakeFS) MkdirTemp(string, string) (string, error) { return "/report/fake", nil }
func (f *fakeFS) WriteFile(_ string, b []byte, _ fs.FileMode) error {
	f.in = append([]byte{}, b...)
	f.generation++
	if f.race {
		f.generation++
	}
	return nil
}
func (f *fakeFS) ReadFile(p string) ([]byte, error) {
	switch filepath.Base(p) {
	case "generation":
		return []byte(strconv.FormatUint(f.generation, 10)), nil
	case "provider":
		return []byte(f.provider + "\n"), nil
	case "outblob":
		if f.empty {
			return nil, nil
		}
		return append([]byte("report:"), f.in...), nil
	case "auxblob":
		if f.missingAux {
			return nil, fs.ErrNotExist
		}
		return f.aux, nil
	}
	return nil, fs.ErrNotExist
}
func (f *fakeFS) Remove(string) error { f.removed = true; return nil }
func TestTSM(t *testing.T) {
	for _, tc := range []struct {
		name, provider           string
		race, missing, empty, ok bool
	}{{"snp", "sev_guest", false, false, false, true}, {"tdx", "tdx_guest", false, true, false, true}, {"race", "sev_guest", true, false, false, false}, {"unknown", "mystery", false, false, false, false}, {"empty", "sev_guest", false, false, true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeFS{provider: tc.provider, race: tc.race, missingAux: tc.missing, empty: tc.empty}
			data := ReportData([32]byte{1}, [32]byte{2})
			cpu, err := (TSM{FS: f}).Collect(context.Background(), data)
			if (err == nil) != tc.ok {
				t.Fatalf("error=%v", err)
			}
			if !f.removed {
				t.Fatal("report directory leaked")
			}
			if tc.ok {
				if !bytes.Equal(cpu.Evidence, append([]byte("report:"), data[:]...)) || cpu.Aux != nil {
					t.Fatal("bad evidence")
				}
				want := map[string]string{"sev_guest": "sev-snp", "tdx_guest": "tdx"}[tc.provider]
				if cpu.TEE != want {
					t.Fatalf("tee %q, want %q", cpu.TEE, want)
				}
			}
		})
	}
}
func TestSplitCommand(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  []string
		ok    bool
	}{{`helper --arg "two words" 'literal $x'`, []string{"helper", "--arg", "two words", "literal $x"}, true}, {`helper escaped\ word`, []string{"helper", "escaped word"}, true}, {`helper ''`, []string{"helper", ""}, true}, {`helper "`, nil, false}, {`helper \`, nil, false}, {`""`, nil, false}} {
		t.Run(tc.input, func(t *testing.T) {
			args, err := SplitCommand(tc.input)
			if (err == nil) != tc.ok {
				t.Fatal(err)
			}
			a, _ := json.Marshal(args)
			b, _ := json.Marshal(tc.want)
			if tc.ok && !bytes.Equal(a, b) {
				t.Fatalf("%s != %s", a, b)
			}
		})
	}
}
func TestGPUHelper(t *testing.T) {
	if os.Getenv("TRCS_TEST_GPU_CHILD") == "1" {
		// Echo the nonce through the format tag so the parent can prove which
		// nonce the helper actually received.
		nonce := os.Getenv("TRCS_GPU_NONCE")
		os.Stdout.WriteString(`{"gpu_evidence":[{"vendor":"nvidia","format":"test-` + nonce + `","evidence_b64":"AQ=="}]}`)
		os.Exit(0)
	}
	t.Setenv("TRCS_TEST_GPU_CHILD", "1")
	t.Setenv("TRCS_GPU_NONCE", "stale")
	nonce := [32]byte{8}
	bundles, err := CollectGPUs(context.Background(), []string{os.Args[0], "-test.run=^TestGPUHelper$"}, nonce)
	if err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString(nonce[:])
	if len(bundles) != 1 || bundles[0].Vendor != "nvidia" || bundles[0].Format != "test-"+want || bundles[0].Nonce != want || !bytes.Equal(bundles[0].Evidence, []byte{1}) {
		t.Fatalf("bad bundle: %+v", bundles)
	}
}

// The first half of the report data is the plain key digest: a verifier that
// only knows the key-pinning convention must find the key there, unprefixed.
func TestReportDataLayout(t *testing.T) {
	var nonce, other, spki [32]byte
	for i := range spki {
		spki[i] = byte(0xA0 + i)
		nonce[i] = byte(i)
		other[i] = byte(255 - i)
	}
	a, b := ReportData(nonce, spki), ReportData(other, spki)
	if !bytes.Equal(a[:32], spki[:]) || !bytes.Equal(b[:32], spki[:]) {
		t.Fatal("bytes 0..31 must be the SPKI digest")
	}
	if bytes.Equal(a[32:], b[32:]) {
		t.Fatal("bytes 32..63 must depend on the nonce")
	}
	if bytes.Equal(a[32:], nonce[:]) {
		t.Fatal("the nonce half must be a domain-separated digest, not the raw nonce")
	}
}
