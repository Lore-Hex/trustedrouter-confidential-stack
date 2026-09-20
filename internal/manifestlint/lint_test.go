package manifestlint

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// bare has no confidential-containers annotations; good carries both.
const bare = `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test"},"spec":{"runtimeClassName":"kata-test","automountServiceAccountToken":false,"containers":[{"name":"shim","image":"shim@sha256:abc","args":["shim","--require-tee"]},{"name":"inference","image":"engine@sha256:def","args":["--model","test","--host","127.0.0.1"],"env":[{"name":"VLLM_NO_USAGE_STATS","value":"1"},{"name":"DO_NOT_TRACK","value":"1"}]}]}}`
const good = `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test","annotations":{"io.katacontainers.config.hypervisor.kernel_params":"agent.guest_components_rest_api=all","io.katacontainers.config.hypervisor.cc_init_data":"H4sIAAAA"}},"spec":{"runtimeClassName":"kata-test","automountServiceAccountToken":false,"containers":[{"name":"shim","image":"shim@sha256:abc","args":["shim","--require-tee"]},{"name":"inference","image":"engine@sha256:def","args":["--model","test","--host","127.0.0.1"],"env":[{"name":"VLLM_NO_USAGE_STATS","value":"1"},{"name":"DO_NOT_TRACK","value":"1"}]}]}}`

func doc(t *testing.T, s string) map[string]any {
	t.Helper()
	var d map[string]any
	if e := json.Unmarshal([]byte(s), &d); e != nil {
		t.Fatal(e)
	}
	return d
}
func TestRules(t *testing.T) {
	for _, tc := range []struct{ rule, bad, pass string }{{"R1", `{"kind":"Ingress","metadata":{"name":"bad"}}`, `{"kind":"Service","metadata":{"name":"good"}}`}, {"R2", strings.Replace(good, "shim@sha256:abc", "shim:latest", 1), good}, {"R3", strings.Replace(good, "kata-test", "runc", 1), good}, {"R4", strings.Replace(good, `"automountServiceAccountToken":false`, `"hostPID":true,"automountServiceAccountToken":false`, 1), good}, {"R5", strings.Replace(good, `"automountServiceAccountToken":false`, `"automountServiceAccountToken":true`, 1), good}, {"R6", strings.Replace(good, `"--require-tee"`, `"--tls-key=secret"`, 1), good}, {"R7", `{"kind":"Service","metadata":{"name":"bad"},"spec":{"type":"ExternalName"}}`, `{"kind":"Service","metadata":{"name":"good"},"spec":{"type":"ClusterIP"}}`}, {"R8", strings.Replace(good, "127.0.0.1", "0.0.0.0", 1), good}} {
		t.Run(tc.rule, func(t *testing.T) {
			for _, v := range Lint(doc(t, tc.pass), "coco") {
				if v.Rule == tc.rule {
					t.Fatalf("passing document: %+v", v)
				}
			}
			found := false
			for _, v := range Lint(doc(t, tc.bad), "coco") {
				found = found || v.Rule == tc.rule
			}
			if !found {
				t.Fatal("did not catch violation")
			}
		})
	}
}
func TestR4Variants(t *testing.T) {
	for _, fragment := range []string{`"hostNetwork":true`, `"hostIPC":true`, `"volumes":[{"name":"host","hostPath":{"path":"/"}}]`, `"initContainers":[{"name":"init","image":"x@sha256:y","securityContext":{"privileged":true}}]`, `"initContainers":[{"name":"init","image":"x@sha256:y","securityContext":{"allowPrivilegeEscalation":true}}]`, `"initContainers":[{"name":"init","image":"x@sha256:y","securityContext":{"capabilities":{"add":["SYS_ADMIN"]}}}]`} {
		t.Run(fragment, func(t *testing.T) {
			bad := strings.Replace(good, `"runtimeClassName"`, fragment+`,"runtimeClassName"`, 1)
			found := false
			for _, v := range Lint(doc(t, bad), "standard") {
				found = found || v.Rule == "R4"
			}
			if !found {
				t.Fatal("unsafe setting accepted")
			}
		})
	}
}
func TestR8Variants(t *testing.T) {
	for _, bad := range []string{strings.Replace(good, `"--host","127.0.0.1"`, `"--host=0.0.0.0"`, 1), strings.Replace(good, `"--model"`, `"--enable-log-requests","--model"`, 1), strings.Replace(good, `"VLLM_NO_USAGE_STATS","value":"1"`, `"VLLM_NO_USAGE_STATS","value":"0"`, 1), strings.Replace(good, `"DO_NOT_TRACK","value":"1"`, `"DO_NOT_TRACK","value":"0"`, 1)} {
		found := false
		for _, v := range Lint(doc(t, bad), "standard") {
			found = found || v.Rule == "R8"
		}
		if !found {
			t.Fatal("unsafe inference config accepted")
		}
	}
	if v := Lint(doc(t, strings.Replace(good, `"--host","127.0.0.1"`, `"--host=127.0.0.1"`, 1)), "coco"); len(v) != 0 {
		t.Fatal(v)
	}
}
func TestStreamAndPreflight(t *testing.T) {
	var out bytes.Buffer
	if code := Run(strings.NewReader(good+"\n"+good), &out, "coco"); code != 0 {
		t.Fatal(out.String())
	}
	skip := `{"kind":"Pod","metadata":{"labels":{"trcs.trustedrouter.com/component":"preflight"}},"spec":{"hostPID":true}}`
	if len(Lint(doc(t, skip), "coco")) != 0 {
		t.Fatal("preflight not skipped")
	}
	for _, kind := range []string{"Ingress", "Gateway", "HTTPRoute", "IngressRoute"} {
		out.Reset()
		if code := Run(strings.NewReader(`{"kind":"`+kind+`","metadata":{"name":"x"}}`), &out, "standard"); code != 0 || !strings.Contains(out.String(), "warning:") {
			t.Fatal("standard routing must warn")
		}
	}
}

func rules(t *testing.T, document, mode string) (errors, warnings map[string]int) {
	t.Helper()
	errors, warnings = map[string]int{}, map[string]int{}
	for _, v := range Lint(doc(t, document), mode) {
		if v.Warning {
			warnings[v.Rule]++
		} else {
			errors[v.Rule]++
		}
	}
	return errors, warnings
}

const kernelParams = `"io.katacontainers.config.hypervisor.kernel_params":"agent.guest_components_rest_api=all"`
const initData = `"io.katacontainers.config.hypervisor.cc_init_data":"H4sIAAAA"`

func withAnnotations(document, annotations string) string {
	return strings.Replace(document, `"metadata":{"name":"test"}`, `"metadata":{"name":"test","annotations":{`+annotations+`}}`, 1)
}

func TestR8PerEngine(t *testing.T) {
	sglang := func(args string) string {
		return strings.Replace(good, `"args":["--model","test","--host","127.0.0.1"],"env":[{"name":"VLLM_NO_USAGE_STATS","value":"1"},{"name":"DO_NOT_TRACK","value":"1"}]`, `"command":["python3","-m","sglang.launch_server"],"args":[`+args+`]`, 1)
	}
	for _, tc := range []struct {
		name, document string
		bad            bool
	}{
		{"sglang loopback, no telemetry env needed", sglang(`"--model-path","m","--host","127.0.0.1","--port","8000"`), false},
		{"sglang host missing", sglang(`"--model-path","m","--port","8000"`), true},
		{"sglang wildcard host", sglang(`"--model-path","m","--host","0.0.0.0"`), true},
		{"sglang request logging", sglang(`"--model-path","m","--host","127.0.0.1","--log-requests"`), true},
		{"vllm request logging", strings.Replace(good, `"--host","127.0.0.1"`, `"--host","127.0.0.1","--enable-log-requests"`, 1), true},
		{"vllm telemetry opt-out missing", strings.Replace(good, `{"name":"DO_NOT_TRACK","value":"1"}`, `{"name":"DO_NOT_TRACK","value":"0"}`, 1), true},
		{"custom engine is not judged", strings.Replace(good, `"args":["--model","test","--host","127.0.0.1"]`, `"args":["/srv/server.py"]`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if errors, _ := rules(t, tc.document, "standard"); (errors["R8"] > 0) != tc.bad {
				t.Fatalf("R8 errors = %d, want bad=%t", errors["R8"], tc.bad)
			}
		})
	}
}

func TestR9EvidenceAPIAndInitData(t *testing.T) {
	errors, warnings := rules(t, bare, "coco")
	if errors["R9"] != 1 || warnings["R9"] != 1 {
		t.Fatalf("bare pod: R9 errors=%d warnings=%d, want 1 and 1", errors["R9"], warnings["R9"])
	}
	errors, warnings = rules(t, withAnnotations(bare, kernelParams), "coco")
	if errors["R9"] != 0 || warnings["R9"] != 1 {
		t.Fatalf("no init-data must be a warning that names the evidence factory: %d %d", errors["R9"], warnings["R9"])
	}
	for _, v := range Lint(doc(t, withAnnotations(bare, kernelParams)), "coco") {
		if v.Rule == "R9" && !strings.Contains(v.Message, "evidence factory") {
			t.Fatalf("warning text: %s", v.Message)
		}
	}
	errors, warnings = rules(t, withAnnotations(bare, kernelParams+","+initData), "coco")
	if errors["R9"] != 0 || warnings["R9"] != 0 {
		t.Fatalf("fully annotated pod still flagged: %d %d", errors["R9"], warnings["R9"])
	}
	if errors, warnings = rules(t, bare, "standard"); errors["R9"]+warnings["R9"] != 0 {
		t.Fatal("R9 must not apply in standard mode")
	}
	// Workload controllers carry the annotations on the pod template.
	deployment := `{"kind":"Deployment","metadata":{"name":"d"},"spec":{"template":{"metadata":{"annotations":{` + kernelParams + `,` + initData + `}},"spec":` + bare[strings.Index(bare, `"spec":`)+len(`"spec":`):len(bare)-1] + `}}}`
	if errors, warnings = rules(t, deployment, "coco"); errors["R9"]+warnings["R9"] != 0 {
		t.Fatalf("template annotations not read: %d %d", errors["R9"], warnings["R9"])
	}
}

func TestR10HostProvidedCache(t *testing.T) {
	pvc := strings.Replace(bare, `"automountServiceAccountToken":false`, `"automountServiceAccountToken":false,"volumes":[{"name":"models","persistentVolumeClaim":{"claimName":"weights"}}]`, 1)
	if errors, _ := rules(t, withAnnotations(pvc, kernelParams+","+initData), "coco"); errors["R10"] != 1 {
		t.Fatal("a PVC in coco mode must be refused")
	}
	allowed := withAnnotations(pvc, kernelParams+","+initData+`,"trcs.trustedrouter.com/allow-host-provided-cache":"true"`)
	if errors, _ := rules(t, allowed, "coco"); errors["R10"] != 0 {
		t.Fatal("the explicit annotation must allow it")
	}
	if errors, _ := rules(t, pvc, "standard"); errors["R10"] != 0 {
		t.Fatal("R10 must not apply in standard mode")
	}
	emptyDir := strings.Replace(pvc, `"persistentVolumeClaim":{"claimName":"weights"}`, `"emptyDir":{}`, 1)
	if errors, _ := rules(t, withAnnotations(emptyDir, kernelParams+","+initData), "coco"); errors["R10"] != 0 {
		t.Fatal("an emptyDir lives inside the guest and must pass")
	}
}

// A pod without the shim is a client or helper: it needs neither a Kata
// RuntimeClass nor the evidence-API annotations, but its images stay pinned.
func TestWorkloadOnlyRulesSkipHelperPods(t *testing.T) {
	helper := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"check"},"spec":{"automountServiceAccountToken":false,"containers":[{"name":"check-endpoint","image":"shim@sha256:abc"}]}}`
	if errors, warnings := rules(t, helper, "coco"); len(errors)+len(warnings) != 0 {
		t.Fatalf("helper pod flagged: %v %v", errors, warnings)
	}
	unpinned := strings.Replace(helper, "shim@sha256:abc", "shim:latest", 1)
	if errors, _ := rules(t, unpinned, "coco"); errors["R2"] != 1 {
		t.Fatal("helper pod images must still be digest-pinned in coco mode")
	}
	if errors, _ := rules(t, strings.Replace(bare, "kata-test", "runc", 1), "coco"); errors["R3"] != 1 {
		t.Fatal("the workload pod must still need a Kata RuntimeClass")
	}
}
