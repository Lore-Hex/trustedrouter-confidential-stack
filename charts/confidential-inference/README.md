# confidential-inference chart

This chart runs one engine and one TLS shim in a single pod. The engine binds
127.0.0.1:8000; the shim serves HTTPS on 8443. Replicas are fixed at one and the
Deployment strategy is Recreate so an update does not double-allocate a GPU.

```sh
helm install trcs charts/confidential-inference -f examples/values-dev-gpu.yaml
trcs check-endpoint https://<provider-host>:443 --expect-tee none
```

Mode `none` reaches **standard; the operator of this cluster can read all
traffic**. Mode `coco` is an unvalidated hardware integration configuration. It
can reach `attested` only after a relying party verifies CPU/GPU evidence,
measurements, current TCB policy and channel binding. `attested+custody` also
requires a custody allow list. See [the threat model](../../docs/threat-model.md)
and [the protocol](../../docs/attestation-protocol.md).

## Engines

`inference.engine` is `vllm` (default) or `sglang`. The shim does not care
which: it proxies any OpenAI-compatible server on loopback.

vLLM is the default for two reasons. It supports more models and hardware, and
it has a working security process: it published more than fifty advisories in
the twelve months to September 2026 and fixed them. SGLang is often faster on
DeepSeek-class mixture-of-experts models and on prefix-heavy traffic, and is a
reasonable choice for those. It has published no security advisories, while
researchers have reported unauthenticated remote code execution in its network
transports. Inside a TEE, code execution in the engine is the attack that
matters most, so treat that as a real cost.

Both engines crash sometimes. The chart is built for it:

- The engine has its own liveness probe, run inside its container, so a hung
  engine is restarted **without restarting the shim**. The shim's TLS key, and
  therefore every relying party's attestation of it, survives engine restarts.
- The shim's liveness probe is a plain TCP check. `/healthz` reflects the engine
  and backs only readiness and startup, so an engine outage takes the pod out of
  rotation but never rotates the attested key.

## Confidential mode

`tee.mode: coco` requires `tee.coco.platform` (`sev-snp` or `tdx`) and a matching
Kata RuntimeClass, both image digests, and an explicit GPU resource name. The
shim then reads evidence from the Confidential Containers guest attestation
agent and refuses to start without it. Multi-GPU needs an explicit opt-in
because it takes every GPU in the node and exists only on some platforms.

Two pod annotations matter and both belong in `tee.coco.podAnnotations`: the
`kernel_params` annotation that enables the in-guest evidence API, and
`cc_init_data`, which binds the pod definition into the hardware report. The
chart warns at install time when init-data is missing. See
[the Kubernetes guide](../../docs/kubernetes-coco.md).

A PersistentVolumeClaim model cache is refused in confidential mode unless
`tee.coco.allowHostProvidedCache` is set: the volume is host-provided storage,
and the host could alter cached weights between runs.

The all-zero shim digests in the examples are placeholders and deliberately
cannot pull. None of this has been validated on hardware yet.

## Network policy

Ingress is restricted to the shim's port. Egress restriction is opt-in
(`networkPolicy.egress.enabled`), because some CNIs, kind's among them, drop the
reply packets of inbound connections once an egress policy exists. That leaves
the endpoint reachable by kubelet probes and nothing else. In confidential mode
remember that any NetworkPolicy is enforced by the host, which is the adversary:
it keeps third parties out, not the operator. The shim's listener audit is the
control that holds inside the guest.

## Values

| Value | Default | Meaning |
|---|---|---|
| `nameOverride` | `""` | Override the application name in labels and the generated full name. |
| `fullnameOverride` | `""` | Override resource names. |
| `labels.chart` | `true` | Emit helm.sh/chart labels; disabled in the generated Kustomize base. |
| `labels.managedBy` | `true` | Emit app.kubernetes.io/managed-by labels; disabled in the generated base. |
| `tee.mode` | `"none"` | none reaches standard only; coco requires guest evidence and external verification. |
| `tee.coco.platform` | `""` | Required in coco: sev-snp or tdx. The guest attestation agent does not say which TEE it runs in, and this must agree with the RuntimeClass. |
| `tee.coco.runtimeClassName` | `""` | Required in coco; must start with kata-. The NVIDIA reference architecture provides kata-qemu-nvidia-gpu-snp and kata-qemu-nvidia-gpu-tdx. |
| `tee.coco.allowMultiGpu` | `false` | Acknowledge more than one GPU. Multi-GPU passthrough takes every GPU in the node and exists only on the platforms NVIDIA lists. |
| `tee.coco.allowHostProvidedCache` | `false` | Allow a PersistentVolumeClaim model cache in coco mode. It is host-provided storage, and the host could alter cached weights between runs. |
| `tee.coco.podAnnotations` | `{}` | Merged over podAnnotations in coco. Must contain the kernel_params annotation that enables the in-guest evidence API, and should contain cc_init_data. See docs/kubernetes-coco.md. |
| `inference.engine` | `"vllm"` | vllm or sglang. Selects the default image, the launch command and the argument names. |
| `inference.image.repository` | `""` | Engine image repository. Empty follows the engine: vllm/vllm-openai or lmsysorg/sglang. |
| `inference.image.tag` | `""` | Engine image tag, ignored when digest is set. Empty follows the engine: v0.29.0 for vLLM, v0.5.20 for SGLang. |
| `inference.image.digest` | `""` | sha256 digest, required in coco. The provided v0.29.0 example digest is amd64 only. |
| `inference.image.pullPolicy` | `"IfNotPresent"` | Kubernetes image pull policy. |
| `inference.model` | `"Qwen/Qwen2.5-7B-Instruct"` | Model ID passed with --model (vLLM) or --model-path (SGLang) and exposed as an untrusted workload hint. |
| `inference.revision` | `""` | Optional pinned model revision passed with --revision; pin a commit for a reproducible workload. |
| `inference.servedModelName` | `""` | Optional public API model name passed with --served-model-name. |
| `inference.command` | `[]` | Override the engine image entrypoint. |
| `inference.args` | `[]` | Full argument override; when nonempty, replaces generated model/host/port/download arguments and extraArgs. |
| `inference.extraArgs` | `[]` | Append engine arguments to the generated defaults. Local lint rejects non-loopback binding and request logging. |
| `inference.hfTokenSecret` | `""` | Optional existing Secret name containing the HF_TOKEN key. |
| `inference.apiKeySecret` | `""` | Optional existing Secret name containing the VLLM_API_KEY key. vLLM reads it from the environment; for SGLang the chart passes it with --api-key. |
| `inference.gpu.resourceName` | `""` | Empty resolves to nvidia.com/gpu in mode none. Coco requires an explicit name: nvidia.com/pgpu on the current NVIDIA reference architecture; confirm with kubectl describe node. |
| `inference.gpu.count` | `1` | GPU requests and limits; more than one also sets tensor parallelism. Zero disables GPU resource entries for CPU and stub tests. |
| `inference.cache.type` | `"emptyDir"` | emptyDir or pvc. Model cache is mounted at /models. |
| `inference.cache.existingClaim` | `""` | Existing PVC name, required when cache.type=pvc; no claim is created by this chart. |
| `inference.cache.sizeLimit` | `""` | Optional emptyDir size limit for the model cache. |
| `inference.shmSizeLimit` | `"8Gi"` | Memory-backed /dev/shm size limit. |
| `inference.securityContext` | `{}` | Additional engine security context. runAsNonRoot is unset because the vLLM image runs as root. Mandatory restrictions are merged over this map. |
| `inference.extraVolumeMounts` | `[]` | Additional mounts on the engine container. |
| `inference.livenessProbe.enabled` | `true` | Exec probe inside the engine container, so a hung engine restarts without restarting the shim and rotating the attested key. |
| `inference.livenessProbe.command` | `[]` | Replace the default python3 health check for an image without python3. |
| `inference.livenessProbe.initialDelaySeconds` | `60` | Also periodSeconds 30, timeoutSeconds 10, failureThreshold 4. |
| `shim.image.repository` | `"ghcr.io/lore-hex/trcs"` | Shim and Helm test image repository. |
| `shim.image.tag` | `""` | Defaults to Chart.appVersion when empty; ignored when digest is set. |
| `shim.image.digest` | `""` | sha256 digest, required in coco. Replace the example all-zero placeholder with a real release digest. |
| `shim.image.pullPolicy` | `"IfNotPresent"` | Kubernetes image pull policy for shim and Helm test. |
| `shim.evidenceSource` | `"auto"` | Standard mode only: auto, none or configfs-tsm. Coco mode always uses the guest attestation agent with --require-tee. |
| `shim.tsmPath` | `"/sys/kernel/config/tsm/report"` | Guest-accessible configfs TSM report directory. The shim UID must be able to create reports here. |
| `shim.cocoAAURL` | `"http://127.0.0.1:8006"` | Confidential Containers guest attestation agent origin. Loopback only. |
| `shim.listenerAudit` | `"auto"` | auto, enforce, warn or off. auto enforces whenever a TEE is in use: the shim refuses to serve while another process in the pod listens on a non-loopback address. |
| `shim.extraVolumeMounts` | `[]` | Additional mounts on the shim container. |
| `shim.gpuEvidenceCmd` | `""` | Optional executable plus quoted args available inside the shim container; overrides GPU evidence from the platform agent. Receives only TRCS_GPU_NONCE as request-derived input. |
| `shim.allowPathPrefixes` | `["/v1/"]` | Repeatable API path allow-list; health and attestation are separate. |
| `shim.attestationRate` | `2` | Global attestation token refill rate per second; fixed burst is five. |
| `shim.maxRequestBytes` | `33554432` | Maximum accepted proxied request body size, including chunked bodies. |
| `shim.tls.existingSecret` | `""` | Existing kubernetes.io/tls Secret (tls.crt and tls.key), allowed only in mode none. Otherwise keys are generated in memory. |
| `shim.tls.sans` | `["localhost"]` | DNS/IP SANs for the generated self-signed certificate. |
| `shim.startupProbe.failureThreshold` | `360` | Startup failures allowed while the engine downloads/loads the model. |
| `shim.startupProbe.periodSeconds` | `10` | Seconds between HTTPS health startup checks. |
| `service.type` | `"ClusterIP"` | ClusterIP, NodePort or LoadBalancer. Use a layer-4 load balancer with TLS pass-through. |
| `service.port` | `443` | External TCP service port targeting shim port 8443. |
| `service.nodePort` | `null` | Optional explicit node port for NodePort/LoadBalancer; null lets Kubernetes allocate it. |
| `service.annotations` | `{}` | Service annotations; operator is responsible for keeping the load balancer in TCP pass-through mode. |
| `networkPolicy.enabled` | `true` | Create a policy selecting workload pods (not the Helm test pod). Ingress is restricted to TCP 8443. |
| `networkPolicy.egress.enabled` | `false` | Opt-in egress restriction to DNS plus HTTPS. Some CNIs drop inbound reply packets once an egress policy exists; test before enabling. |
| `networkPolicy.egress.cidrs` | `["0.0.0.0/0"]` | CIDRs allowed for TCP 443 egress when egress restriction is enabled. |
| `podAnnotations` | `{}` | Workload pod annotations. coco annotations take precedence on duplicate keys. |
| `nodeSelector` | `{}` | Workload node selection; coco examples require amd64 because the supplied engine digest is amd64. |
| `tolerations` | `[]` | Workload pod tolerations. |
| `affinity` | `{}` | Workload pod affinity rules. |
| `extraVolumes` | `[]` | Additional pod volumes. Manifest lint rejects hostPath; do not use it to expose host data. |

## CLI and helper contract

Every shim flag also accepts `TRCS_<UPPER_SNAKE>`; flags override environment
values. `TRCS_TLS_SAN` and `TRCS_ALLOW_PATH_PREFIX` accept comma-separated lists;
repeatable CLI flags replace the corresponding environment list. The chart
uses flags for reproducible configuration. GPU helper commands accept simple
quotes/backslash escapes, but no shell expansion, pipes or redirection.

The helper has a 10-second timeout and receives `TRCS_GPU_NONCE=<32-byte hex>`.
It prints exactly one JSON object:

```json
{"gpu_evidence":[{"vendor":"nvidia","format":"nvidia-nvattest-collect-evidence-json-v1","evidence_b64":"AQ=="}]}
```

Those sample bytes are illustrative only. Each bundle is opaque to the shim:
`vendor` and `format` tell the verifier which appraiser to use, and the shim
adds the derived nonce. The helper must obtain the evidence from hardware using
that nonce. The shim never forwards request bodies, headers or query strings to
the helper, does not verify signatures, and does not apply acceptance policy.
When no helper is configured, GPU evidence comes from the platform agent if the
evidence source can provide it (`coco-aa`, `dstack`).

`trcs preflight --json` reports node facts, not acceptance decisions. The
privileged diagnostic Job in `deploy/preflight-job.yaml` is separate, opt-in,
and never installed by this chart.
