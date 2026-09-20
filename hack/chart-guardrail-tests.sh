#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
chart=charts/confidential-inference
base=examples/values-coco-snp.yaml
count=0
fails() {
  local name=$1 expected=$2
  shift 2
  if helm template guard "$chart" -f "$base" "$@" > "$tmp/out" 2> "$tmp/error"; then
    printf 'FAIL guardrail %s: render unexpectedly succeeded\n' "$name" >&2
    exit 1
  fi
  if ! grep -Fq "$expected" "$tmp/error"; then
    printf 'FAIL guardrail %s: wrong failure\n' "$name" >&2
    cat "$tmp/error" >&2
    exit 1
  fi
  count=$((count + 1))
  printf 'PASS guardrail %s\n' "$name"
}
fails inference-digest 'digest-pinned images' --set-string inference.image.digest=
fails shim-digest 'digest-pinned images' --set-string shim.image.digest=
fails runtime-class 'requires tee.coco.runtimeClassName' --set-string tee.coco.runtimeClassName=
fails runtime-prefix 'must start with kata-' --set-string tee.coco.runtimeClassName=runc
fails gpu-resource 'requires explicit inference.gpu.resourceName' --set-string inference.gpu.resourceName=
fails coco-external-tls 'allowed only in mode none' --set-string shim.tls.existingSecret=external
fails multi-gpu 'single-GPU passthrough' --set inference.gpu.count=2
fails pvc-claim 'requires inference.cache.existingClaim' --set inference.cache.type=pvc --set tee.coco.allowHostProvidedCache=true
fails host-provided-cache 'host-provided storage' --set inference.cache.type=pvc --set-string inference.cache.existingClaim=weights
fails platform-missing 'requires tee.coco.platform' --set-string tee.coco.platform=
fails platform-runtime-mismatch 'disagrees with a tdx runtimeClassName' --set-string tee.coco.runtimeClassName=kata-qemu-nvidia-gpu-tdx
# The values schema rejects this before the template guardrail can.
fails unknown-engine "must be one of 'vllm', 'sglang'" --set-string inference.engine=tgi
helm template guard "$chart" -f "$base" --set inference.gpu.count=2 --set tee.coco.allowMultiGpu=true > /dev/null
helm template guard "$chart" --set shim.tls.existingSecret=external > /dev/null
helm template guard "$chart" -f "$base" --set inference.cache.type=pvc --set-string inference.cache.existingClaim=weights \
  --set tee.coco.allowHostProvidedCache=true > "$tmp/pvc.yaml"
grep -Fq 'trcs.trustedrouter.com/allow-host-provided-cache: "true"' "$tmp/pvc.yaml"

# Rendered-manifest assertions: the properties the design depends on.
render() { helm template guard "$chart" "$@" > "$tmp/render.yaml"; }
expect() {
  if ! grep -Fq -- "$2" "$tmp/render.yaml"; then printf 'FAIL render %s: missing %s\n' "$1" "$2" >&2; exit 1; fi
}
refuse() {
  if grep -Fq -- "$2" "$tmp/render.yaml"; then printf 'FAIL render %s: unexpected %s\n' "$1" "$2" >&2; exit 1; fi
}
render
expect default-engine 'image: "vllm/vllm-openai:v0.29.0"'
expect vllm-telemetry 'name: VLLM_NO_USAGE_STATS'
expect engine-liveness "urllib.request.urlopen('http://127.0.0.1:8000/health'"
expect shim-liveness-is-tcp 'tcpSocket:'
expect listener-audit '--listener-audit=auto'
refuse ingress-only-by-default '- Egress'
render --set networkPolicy.egress.enabled=true
expect egress-opt-in '- Egress'
render --set-string inference.engine=sglang --set-string inference.apiKeySecret=engine-key --set inference.gpu.count=2
expect sglang-image 'image: "lmsysorg/sglang:v0.5.20"'
expect sglang-command 'command: [python3, -m, sglang.launch_server]'
expect sglang-model-flag '- --model-path'
expect sglang-tp '- --tp-size'
# shellcheck disable=SC2016  # a literal Kubernetes $(VAR) reference, not a shell expansion
expect sglang-api-key '- $(TRCS_ENGINE_API_KEY)'
refuse sglang-no-vllm-env 'name: VLLM_NO_USAGE_STATS'
render -f "$base"
expect coco-source '--evidence-source=coco-aa'
expect coco-platform '--tee=sev-snp'
expect coco-require '--require-tee'
expect coco-kernel-params 'agent.guest_components_rest_api=all'
# The shim's liveness probe must never depend on the engine: exactly one
# /healthz httpGet per probe kind that is allowed to (readiness, startup).
if [[ "$(grep -c 'path: /healthz' "$tmp/render.yaml")" != 2 ]]; then
  printf 'FAIL render: /healthz must back readiness and startup only\n' >&2; exit 1
fi
printf 'PASS %d guardrail rejection tests, 3 permitted overrides and the rendered-manifest assertions\n' "$count"
