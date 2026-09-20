package preflight

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	output    string
	available bool
}

func (f fakeRunner) LookPath(string) (string, error) {
	if !f.available {
		return "", errors.New("missing")
	}
	return "nvidia-smi", nil
}
func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name != "nvidia-smi" || strings.Join(args, " ") != "conf-compute -f" {
		return nil, errors.New("unexpected command")
	}
	return []byte(f.output), nil
}
func write(t *testing.T, root, name, value string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(value), 0644); err != nil {
		t.Fatal(err)
	}
}
func fixture(t *testing.T, vendor, model, id string, guest bool) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "proc/cpuinfo", "vendor_id : "+vendor+"\nmodel name : "+model+"\n")
	write(t, root, "proc/sys/kernel/osrelease", "6.8.0-fixture")
	write(t, root, "sys/module/kvm_amd/parameters/sev_snp", "Y")
	write(t, root, "sys/kernel/iommu_groups/0/fixture", "")
	if guest {
		write(t, root, "dev/sev-guest", "")
		if err := os.MkdirAll(filepath.Join(root, "sys/kernel/config/tsm/report"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if id != "" {
		base := "sys/bus/pci/devices/0000:01:00.0/"
		write(t, root, base+"vendor", "0x10de")
		write(t, root, base+"class", "0x030200")
		write(t, root, base+"device", "0x"+id)
		if e := os.Symlink("../../drivers/nvidia", filepath.Join(root, base+"driver")); e != nil {
			t.Fatal(e)
		}
		if e := os.Symlink("../../iommu_groups/0", filepath.Join(root, base+"iommu_group")); e != nil {
			t.Fatal(e)
		}
	}
	return root
}
func TestFixtures(t *testing.T) {
	cases := []struct {
		name, vendor, model, id string
		guest                   bool
		cc                      string
		code                    int
		check, status           string
	}{{"amd-host", "AuthenticAMD", "AMD EPYC 9354", "2330", false, "", 0, "host.kvm.sev_snp", "PASS"}, {"milan", "AuthenticAMD", "AMD EPYC 7B13", "2330", false, "", 0, "cpu.family_advice", "WARN"}, {"intel-no-tdx", "GenuineIntel", "Xeon", "2330", false, "", 1, "host.kvm.tdx", "FAIL"}, {"snp-on", "AuthenticAMD", "EPYC 9354", "2330", true, "Current CC mode : ON", 0, "guest.gpu_cc_mode", "PASS"}, {"snp-off", "AuthenticAMD", "EPYC 9354", "2330", true, "Current CC mode : OFF", 1, "guest.gpu_cc_mode", "FAIL"}, {"a100", "AuthenticAMD", "EPYC 9354", "20b0", false, "", 1, "gpu.cc_architecture", "FAIL"}, {"no-gpu", "AuthenticAMD", "EPYC 9354", "", false, "", 1, "gpu.devices", "FAIL"}, {"unknown", "AuthenticAMD", "EPYC 9354", "abcd", false, "", 0, "gpu.cc_architecture", "WARN"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := fixture(t, tc.vendor, tc.model, tc.id, tc.guest)
			runner := fakeRunner{tc.cc, true}
			checks, err := Inspect(context.Background(), root, runner)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, c := range checks {
				if c.ID == tc.check {
					found = true
					if c.Status != tc.status {
						t.Fatalf("%+v", c)
					}
					if tc.name == "milan" && c.Finding != milanWarning {
						t.Fatal("advisory changed")
					}
				}
				if tc.guest && c.ID == "host.kvm.sev_snp" && c.Status != "SKIP" {
					t.Fatal("guest host check not skipped")
				}
			}
			if !found {
				t.Fatal("missing check")
			}
			var out, stderr bytes.Buffer
			if code := Run(context.Background(), root, false, runner, &out, &stderr); code != tc.code {
				t.Fatalf("code=%d stderr=%s", code, stderr.String())
			}
			for _, verdict := range []string{"Kubernetes confidential containers host", "inside a confidential VM"} {
				if !strings.Contains(out.String(), verdict) {
					t.Fatal("missing deployment verdict")
				}
			}
		})
	}
}
func TestCCParsing(t *testing.T) {
	for _, tc := range []struct{ output, status string }{{"Mode: on", "PASS"}, {"Mode: off", "FAIL"}, {"Configuration: UNKNOWN", "WARN"}, {"ON", "WARN"}, {"Mode: ON\nOther: OFF", "FAIL"}, {"  unexpected  status  \nignored detail", "WARN"}} {
		t.Run(tc.output, func(t *testing.T) {
			root := fixture(t, "AuthenticAMD", "EPYC 9354", "2331", true)
			checks, e := Inspect(context.Background(), root, fakeRunner{tc.output, true})
			if e != nil {
				t.Fatal(e)
			}
			for _, c := range checks {
				if c.ID == "guest.gpu_cc_mode" && c.Status != tc.status {
					t.Fatalf("%+v", c)
				}
				if c.ID == "guest.gpu_cc_mode" && tc.status == "WARN" && c.Finding != strings.SplitN(tc.output, "\n", 2)[0] {
					t.Fatalf("raw first line changed: %q", c.Finding)
				}
			}
		})
	}
}
func TestInternalError(t *testing.T) {
	var out bytes.Buffer
	if code := Run(context.Background(), filepath.Join(t.TempDir(), "missing"), true, nil, &out, &out); code != 2 {
		t.Fatal(code)
	}
}
func TestDeviceTable(t *testing.T) {
	if len(supported) != 23 || len(ampere) != 9 {
		t.Fatal("device table differs from specified snapshot")
	}
	for _, id := range []string{"2321", "233b", "2348", "2909", "29bc"} {
		if supported[id] == "" {
			t.Fatal(id)
		}
	}
}
