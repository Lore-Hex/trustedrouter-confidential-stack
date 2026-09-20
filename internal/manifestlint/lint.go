// Package manifestlint checks JSON Kubernetes resources without YAML dependencies.
package manifestlint

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type Violation struct {
	Rule, Resource, Message string
	Warning                 bool
}

func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func array(v any) []any           { a, _ := v.([]any); return a }
func str(v any) string            { s, _ := v.(string); return s }
func truth(v any) bool            { b, _ := v.(bool); return b }
func at(m map[string]any, keys ...string) any {
	var v any = m
	for _, key := range keys {
		v = object(v)[key]
	}
	return v
}
func texts(v any) []string {
	var result []string
	for _, s := range array(v) {
		result = append(result, str(s))
	}
	return result
}
func hasFlag(args []string, flag string) bool {
	for _, arg := range args {
		if arg == flag || strings.HasPrefix(arg, flag+"=") {
			return true
		}
	}
	return false
}
func flagValue(args []string, flag string) (string, bool) {
	var result string
	found := false
	for i, arg := range args {
		if arg == flag {
			found = true
			result = ""
			if i+1 < len(args) {
				result = args[i+1]
			}
		} else if strings.HasPrefix(arg, flag+"=") {
			found = true
			result = strings.TrimPrefix(arg, flag+"=")
		}
	}
	return result, found
}

func Lint(document map[string]any, mode string) []Violation {
	if at(document, "metadata", "labels", "trcs.trustedrouter.com/component") == "preflight" {
		return nil
	}
	kind := str(document["kind"])
	if kind == "List" {
		var out []Violation
		for _, item := range array(document["items"]) {
			out = append(out, Lint(object(item), mode)...)
		}
		return out
	}
	resource := kind + "/" + str(at(document, "metadata", "name"))
	var result []Violation
	add := func(rule, message string, warning bool) {
		result = append(result, Violation{rule, resource, message, warning})
	}
	switch kind {
	case "Ingress", "Gateway", "HTTPRoute", "IngressRoute":
		add("R1", "TLS-terminating routing resources are forbidden", mode == "standard")
	}
	if kind == "Service" && at(document, "spec", "type") == "ExternalName" {
		add("R7", "ExternalName services are forbidden", false)
	}
	var spec map[string]any
	switch kind {
	case "Pod":
		spec = object(document["spec"])
	case "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job":
		spec = object(at(document, "spec", "template", "spec"))
	case "CronJob":
		spec = object(at(document, "spec", "jobTemplate", "spec", "template", "spec"))
	}
	if spec == nil {
		return result
	}
	// The workload is the pod that carries the shim. Client and helper pods
	// (the Helm test, for one) need neither a confidential VM nor the evidence API.
	workload := false
	for _, entry := range append(append([]any{}, array(spec["containers"])...), array(spec["initContainers"])...) {
		if str(object(entry)["name"]) == "shim" {
			workload = true
		}
	}
	if mode == "coco" && workload && !strings.HasPrefix(str(spec["runtimeClassName"]), "kata-") {
		add("R3", "runtimeClassName must start with kata-", false)
	}
	unsafe := truth(spec["hostNetwork"]) || truth(spec["hostPID"]) || truth(spec["hostIPC"])
	for _, v := range array(spec["volumes"]) {
		if _, ok := object(v)["hostPath"]; ok {
			unsafe = true
		}
	}
	containers := append(append([]any{}, array(spec["containers"])...), array(spec["initContainers"])...)
	containers = append(containers, array(spec["ephemeralContainers"])...)
	for _, entry := range containers {
		c := object(entry)
		name := str(c["name"])
		args := texts(c["args"])
		command := texts(c["command"])
		allArgs := append(append([]string{}, command...), args...)
		if mode == "coco" && !strings.Contains(str(c["image"]), "@sha256:") {
			add("R2", name+" image must be digest-pinned", false)
		}
		security := object(c["securityContext"])
		if truth(security["privileged"]) || truth(security["allowPrivilegeEscalation"]) || len(array(at(security, "capabilities", "add"))) > 0 {
			unsafe = true
		}
		if mode == "coco" && name == "shim" {
			require := hasFlag(allArgs, "--require-tee")
			if value, found := flagValue(allArgs, "--require-tee"); found && (value == "false" || value == "0") {
				require = false
			}
			if !require || hasFlag(allArgs, "--tls-cert") || hasFlag(allArgs, "--tls-key") {
				add("R6", "shim requires --require-tee and must not supply TLS certificate/key flags", false)
			}
		}
		if name == "inference" {
			env := map[string]string{}
			for _, e := range array(c["env"]) {
				m := object(e)
				env[str(m["name"])] = str(m["value"])
			}
			host, hostSet := flagValue(allArgs, "--host")
			sglang := false
			for _, a := range allArgs {
				if strings.Contains(a, "sglang.launch_server") {
					sglang = true
				}
			}
			switch {
			case sglang:
				// SGLang binds 127.0.0.1 by default, but an explicit loopback bind is
				// required so a changed default cannot silently expose the engine.
				if !hostSet || host != "127.0.0.1" || hasFlag(allArgs, "--log-requests") {
					add("R8", "SGLang inference must pass --host 127.0.0.1 and must not enable --log-requests", false)
				}
			case hasFlag(allArgs, "--model") || hasFlag(allArgs, "serve"):
				if !hostSet || host != "127.0.0.1" || hasFlag(allArgs, "--enable-log-requests") || env["VLLM_NO_USAGE_STATS"] != "1" || env["DO_NOT_TRACK"] != "1" {
					add("R8", "vLLM inference must bind 127.0.0.1, disable request logging and set both telemetry opt-out variables to 1", false)
				}
			}
		}
	}
	if mode == "coco" && workload {
		annotations := object(at(document, "metadata", "annotations"))
		if kind != "Pod" {
			annotations = object(at(document, "spec", "template", "metadata", "annotations"))
			if kind == "CronJob" {
				annotations = object(at(document, "spec", "jobTemplate", "spec", "template", "metadata", "annotations"))
			}
		}
		// R9: the shim's coco-aa evidence source needs the in-guest REST API, which
		// the guest kernel command line enables. Without init-data the evidence says
		// only "a Kata guest": any other pod could mint it (an evidence factory).
		if !strings.Contains(str(annotations["io.katacontainers.config.hypervisor.kernel_params"]), "agent.guest_components_rest_api=all") {
			add("R9", "pod annotation io.katacontainers.config.hypervisor.kernel_params must contain agent.guest_components_rest_api=all", false)
		}
		if str(annotations["io.katacontainers.config.hypervisor.cc_init_data"]) == "" {
			add("R9", "no io.katacontainers.config.hypervisor.cc_init_data annotation: until init-data binds this pod definition into the hardware report, this deployment is an evidence factory (see docs/architecture.md)", true)
		}
		// R10: a PersistentVolumeClaim is storage the host provides, and the host is
		// the adversary: cached weights could be altered between runs.
		if str(annotations["trcs.trustedrouter.com/allow-host-provided-cache"]) != "true" {
			for _, v := range array(spec["volumes"]) {
				if _, ok := object(v)["persistentVolumeClaim"]; ok {
					add("R10", "PersistentVolumeClaim volumes are host-provided storage; forbidden in coco mode unless explicitly allowed", false)
					break
				}
			}
		}
	}
	if unsafe {
		add("R4", "host access, privilege escalation and added capabilities are forbidden", false)
	}
	if value, ok := spec["automountServiceAccountToken"].(bool); !ok || value {
		add("R5", "automountServiceAccountToken must be false", false)
	}
	return result
}
func Run(input io.Reader, output io.Writer, mode string) int {
	if mode != "standard" && mode != "coco" {
		fmt.Fprintln(output, "mode must be standard or coco")
		return 1
	}
	decoder := json.NewDecoder(input)
	code := 0
	for {
		var document map[string]any
		if err := decoder.Decode(&document); err == io.EOF {
			break
		} else if err != nil {
			fmt.Fprintln(output, "invalid JSON manifest stream")
			return 1
		}
		for _, v := range Lint(document, mode) {
			message := v.Message
			if v.Warning {
				message = "warning: " + message
			} else {
				code = 1
			}
			fmt.Fprintf(output, "%s %s: %s\n", v.Rule, v.Resource, message)
		}
	}
	return code
}
