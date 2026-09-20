// Package preflight reports node facts. It does not implement relying-party policy.
package preflight

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"
)

type Check struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Finding     string `json:"finding"`
	Remediation string `json:"remediation"`
}
type Runner interface {
	LookPath(string) (string, error)
	Run(context.Context, string, ...string) ([]byte, error)
}
type OSRunner struct{}

func (OSRunner) LookPath(s string) (string, error) { return exec.LookPath(s) }
func (OSRunner) Run(ctx context.Context, s string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, s, args...).Output()
}

type device struct{ id, slot, driver, group string }

const milanWarning = "A software-only SEV-SNP key-extraction attack on EPYC Milan was published in May 2026 (arXiv:2605.12990). Relying parties may refuse Milan for confidential tiers."

var milan = regexp.MustCompile(`EPYC 7[0-9A-Z]{2}3`)

// Source: pci.ids snapshot 2026.09.18. Deliberately do not extrapolate device IDs.
var supported = map[string]string{
	"2321": "Hopper H100L 94GB", "2322": "Hopper H800 PCIe", "2324": "Hopper H800", "2328": "Hopper H20B", "2329": "Hopper H20", "232c": "Hopper H20 HBM3e", "2330": "Hopper H100 SXM5 80GB", "2331": "Hopper H100 PCIe", "2335": "Hopper H200 SXM 141GB", "2336": "Hopper H100", "2337": "Hopper H100 SXM5 64GB", "2338": "Hopper H100 SXM5 96GB", "2339": "Hopper H100 SXM5 94GB", "233a": "Hopper H800L 94GB", "233b": "Hopper H200 NVL", "233d": "Hopper H100 96GB", "2342": "Hopper GH200 120GB/480GB", "2348": "Hopper GH200 144G HBM3e",
	"2901": "Blackwell B200", "2909": "Blackwell HGX B200 168GB", "2920": "Blackwell B100", "2941": "Blackwell HGX GB200", "29bc": "Blackwell B100",
}
var ampere = map[string]bool{"20b0": true, "20b1": true, "20b2": true, "20b3": true, "20b5": true, "20f1": true, "20f3": true, "20f5": true, "20f6": true}

func Inspect(ctx context.Context, root string, runner Runner) (checks []Check, err error) {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("root is not an accessible directory")
	}
	if runner == nil {
		runner = OSRunner{}
	}
	p := func(s string) string { return filepath.Join(root, strings.TrimPrefix(s, "/")) }
	read := func(s string) string {
		b, e := os.ReadFile(p(s))
		if e != nil && !os.IsNotExist(e) && err == nil {
			err = e
		}
		return strings.TrimSpace(string(b))
	}
	exists := func(s string) bool {
		_, e := os.Stat(p(s))
		if e != nil && !os.IsNotExist(e) && err == nil {
			err = e
		}
		return e == nil
	}
	add := func(id, status, finding, remediation string) {
		checks = append(checks, Check{id, status, strings.NewReplacer("\n", " ", "\r", " ").Replace(finding), remediation})
	}
	cpu := read("/proc/cpuinfo")
	vendor, model := "unknown", "unknown"
	for _, line := range strings.Split(cpu, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "vendor_id":
			vendor = strings.TrimSpace(value)
		case "model name":
			model = strings.TrimSpace(value)
		}
	}
	add("cpu.vendor", "INFO", vendor, "Compare hardware identity with relying-party policy.")
	add("cpu.model", "INFO", model, "Compare CPU family and TCB with relying-party policy.")
	if milan.MatchString(model) {
		add("cpu.family_advice", "WARN", milanWarning, "Use a platform accepted by your relying party.")
	} else {
		add("cpu.family_advice", "SKIP", "No Milan family advisory matched.", "Keep relying-party CPU policy current.")
	}
	snp, tdx := exists("/dev/sev-guest"), exists("/dev/tdx_guest")
	guest := snp || tdx
	for _, entry := range []struct{ id, vendor, file string }{{"host.kvm.sev_snp", "AuthenticAMD", "/sys/module/kvm_amd/parameters/sev_snp"}, {"host.kvm.tdx", "GenuineIntel", "/sys/module/kvm_intel/parameters/tdx"}} {
		if guest || vendor != entry.vendor {
			add(entry.id, "SKIP", "Not an applicable host check.", "Run on the host to inspect KVM configuration.")
			continue
		}
		value := read(entry.file)
		status := "FAIL"
		finding := "KVM confidential guest support is not enabled."
		if value == "Y" || value == "1" {
			status = "PASS"
			finding = "KVM confidential guest support is enabled."
		}
		add(entry.id, status, finding, "Enable supported CPU firmware and KVM confidential virtualization settings.")
	}
	groups, e := os.ReadDir(p("/sys/kernel/iommu_groups"))
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	if len(groups) > 0 {
		add("host.iommu", "PASS", "IOMMU groups are present.", "Confirm GPU passthrough isolation.")
	} else {
		add("host.iommu", "FAIL", "No IOMMU groups found.", "Enable IOMMU on the host; guest visibility may be limited.")
	}
	kernel := read("/proc/sys/kernel/osrelease")
	if kernel == "" {
		kernel = "unavailable"
	}
	add("host.kernel", "INFO", kernel, "Confirm kernel support for your selected evidence source.")
	finding := "No confidential guest device found."
	status := "INFO"
	if snp {
		finding = "inside an AMD SEV-SNP guest"
		status = "PASS"
	}
	if tdx {
		finding = "inside an Intel TDX guest"
		status = "PASS"
	}
	if exists("/sys/kernel/config/tsm/report") {
		finding += "; configfs-tsm report path present"
	} else {
		finding += "; configfs-tsm report path absent"
	}
	add("guest.tee", status, finding, "The shim's configfs-tsm source requires an accessible /sys/kernel/config/tsm/report.")
	entries, e := os.ReadDir(p("/sys/bus/pci/devices"))
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	var devices []device
	for _, entry := range entries {
		base := "/sys/bus/pci/devices/" + entry.Name()
		v := strings.ToLower(read(base + "/vendor"))
		class := strings.ToLower(read(base + "/class"))
		if v != "0x10de" || (!strings.HasPrefix(class, "0x0302") && !strings.HasPrefix(class, "0x0300")) {
			continue
		}
		linkName := func(name string) string {
			target, e := os.Readlink(p(base + "/" + name))
			if e != nil {
				return "none"
			}
			return filepath.Base(target)
		}
		devices = append(devices, device{strings.TrimPrefix(strings.ToLower(read(base+"/device")), "0x"), entry.Name(), linkName("driver"), linkName("iommu_group")})
	}
	if len(devices) == 0 {
		add("gpu.devices", "FAIL", "No NVIDIA display or 3D controller found.", "Attach a supported NVIDIA GPU.")
		add("gpu.cc_architecture", "SKIP", "No GPU to inspect.", "Attach a supported NVIDIA GPU.")
	} else {
		var facts, architectures []string
		architectureStatus := "PASS"
		for _, d := range devices {
			facts = append(facts, fmt.Sprintf("%s device=%s driver=%s iommu_group=%s", d.slot, d.id, d.driver, d.group))
			if name, ok := supported[d.id]; ok {
				architectures = append(architectures, d.id+" "+name+": architecture supports NVIDIA Confidential Computing; confirm this SKU, VBIOS and driver against NVIDIA's support matrix")
			} else if ampere[d.id] {
				architectureStatus = "FAIL"
				architectures = append(architectures, d.id+": architecture predates NVIDIA Confidential Computing")
			} else {
				if architectureStatus != "FAIL" {
					architectureStatus = "WARN"
				}
				architectures = append(architectures, d.id+": unknown GPU device id")
			}
		}
		add("gpu.devices", "PASS", strings.Join(facts, "; "), "Confirm the bound driver and IOMMU group for the deployment path.")
		add("gpu.cc_architecture", architectureStatus, strings.Join(architectures, "; "), "Consult NVIDIA's support matrix for this exact SKU, VBIOS and driver.")
	}
	executable, lookErr := runner.LookPath("nvidia-smi")
	if !guest || lookErr != nil {
		add("guest.gpu_cc_mode", "SKIP", "Requires a confidential guest and nvidia-smi on PATH.", "Run this check inside the confidential guest with NVIDIA tools installed.")
	} else {
		timeout, cancel := context.WithTimeout(ctx, 5*time.Second)
		output, runErr := runner.Run(timeout, executable, "conf-compute", "-f")
		cancel()
		status := "WARN"
		first := strings.TrimSuffix(strings.SplitN(string(output), "\n", 2)[0], "\r")
		finding := first
		// Match whole values after a colon, not substrings such as 'configuration'.
		on, off := false, false
		for _, line := range strings.Split(string(output), "\n") {
			_, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			words := strings.Fields(strings.ToUpper(strings.TrimSpace(value)))
			if len(words) > 0 {
				on = on || words[0] == "ON"
				off = off || words[0] == "OFF"
			}
		}
		if runErr == nil && off {
			status = "FAIL"
			finding = "GPU confidential-computing mode: OFF"
		} else if runErr == nil && on {
			status = "PASS"
			finding = "GPU confidential-computing mode: ON"
		} else if finding == "" {
			finding = "nvidia-smi did not report a recognized CC mode"
		}
		add("guest.gpu_cc_mode", status, finding, "Enable GPU confidential-computing mode using the supported platform procedure.")
	}
	return checks, err
}
func Run(ctx context.Context, root string, asJSON bool, runner Runner, out, stderr io.Writer) int {
	checks, err := Inspect(ctx, root, runner)
	if err != nil {
		fmt.Fprintln(stderr, "preflight internal error:", err)
		return 2
	}
	code := 0
	for _, c := range checks {
		if c.Status == "FAIL" {
			code = 1
		}
	}
	if asJSON {
		_ = json.NewEncoder(out).Encode(checks)
		return code
	}
	table := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "CHECK\tSTATUS\tFINDING")
	for _, c := range checks {
		fmt.Fprintf(table, "%s\t%s\t%s\n\t\tRemediation: %s\n", c.ID, c.Status, c.Finding, c.Remediation)
	}
	table.Flush()
	hostOK, guestOK, guestDetected := true, true, false
	for _, c := range checks {
		if c.ID == "guest.tee" && c.Status == "PASS" {
			guestDetected = true
		}
		if c.Status == "FAIL" {
			if strings.HasPrefix(c.ID, "host.") || strings.HasPrefix(c.ID, "gpu.") {
				hostOK = false
			}
			if strings.HasPrefix(c.ID, "guest.") || strings.HasPrefix(c.ID, "gpu.") {
				guestOK = false
			}
		}
	}
	hostVerdict := "No failing host checks; runtime, passthrough and evidence integration still need validation."
	if !hostOK {
		hostVerdict = "Host checks failed; resolve the findings before deploying confidential containers."
	} else if guestDetected {
		hostVerdict = "Host KVM checks were skipped inside this guest; run preflight on the Kubernetes node."
	}
	guestVerdict := "Guest and GPU facts are compatible; verify evidence availability and relying-party policy."
	if !guestDetected {
		guestVerdict = "This is not a detected confidential guest; run preflight inside the intended confidential VM."
	} else if !guestOK {
		guestVerdict = "Guest or GPU checks failed; resolve the findings before serving confidential traffic."
	}
	fmt.Fprintln(out, "\nKubernetes confidential containers host:", hostVerdict, "These checks do not establish attestation or custody.")
	fmt.Fprintln(out, "\ninside a confidential VM:", guestVerdict, "These checks do not verify hardware signatures.")
	return code
}
