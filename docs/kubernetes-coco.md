# Kubernetes confidential containers path

> **Not yet validated on hardware by this project.** Everything on this page is
> assembled from the upstream documentation it links to. The chart renders the
> manifests described here and the policy linter checks them, but nobody has yet
> run this repository's workload on a real SEV-SNP or TDX node with a GPU in
> confidential mode. Treat it as a starting point for someone who has the
> hardware, and please report what you find.

In this path each inference pod runs inside its own confidential VM, started by
Kata Containers, with the GPU passed through in confidential-computing mode.
You own the hosts. The trust boundary is the pod's VM, so the cluster
administrator, the kubelet and the host kernel are all outside it.

## 1. Base layers (upstream, all Helm)

NVIDIA publishes a supported reference architecture for this, generally
available since version 1.0.0 (April 2026). Follow it exactly; it is the part
that touches firmware, kernels and drivers.
[NVIDIA Confidential Containers deployment guide](https://docs.nvidia.com/datacenter/cloud-native/confidential-containers/latest/confidential-containers-deploy.html)

As of reference architecture 1.1.0 the moving parts are:

| Layer | What | Version NVIDIA lists |
|---|---|---|
| Host | Ubuntu 25.10 or 26.04, kernel 6.17+, containerd, Kubernetes 1.32+ | |
| Kata Containers | `oci://ghcr.io/kata-containers/kata-deploy-charts/kata-deploy` with NVIDIA's GPU values file | 4.0.0 |
| NVIDIA GPU Operator | `nvidia/gpu-operator` with `sandboxWorkloads.enabled=true`, `sandboxWorkloads.mode=kata`, `nfd.enabled=true`, `nfd.nodefeaturerules=true` | v26.3.1 |
| Node label | `nvidia.com/gpu.workload.config=vm-passthrough` | |

When the node is ready the GPU Operator labels it `nvidia.com/cc.ready.state=true`
and the cluster has these RuntimeClasses:

| RuntimeClass | Use |
|---|---|
| `kata-qemu-nvidia-gpu-snp` | AMD SEV-SNP hosts |
| `kata-qemu-nvidia-gpu-tdx` | Intel TDX hosts |
| `kata-qemu-nvidia-gpu` | Kata isolation without a TEE. **Not confidential.** |

Run `trcs preflight` on the node before you start. It catches the common
blockers (TEE not enabled in the kernel, IOMMU off, a GPU generation without
confidential computing) in a few seconds.

Remember the two NVIDIA conditions from `hardware.md`: every GPU in the node is
in confidential mode, and a multi-GPU workload takes all of them. Also read the
licensing note there.

## 2. This repository's chart, in `coco` mode

```
helm install inference charts/confidential-inference \
  --namespace tr-inference --create-namespace \
  -f examples/values-coco-snp.yaml
```

What `tee.mode: coco` changes relative to `standard`:

| Setting | Why |
|---|---|
| `runtimeClassName` from `tee.coco.runtimeClassName` | Runs the pod in a confidential VM. No default: you must choose SNP or TDX. |
| Both images pinned by digest, enforced at render time | A tag can be repointed by whoever controls the registry. The workload policy pins digests, so the manifest must too. |
| `--require-tee` on the shim | The shim exits at startup unless it can obtain real evidence, so a misconfigured pod never silently serves as `standard`. |
| Operator-supplied TLS secret refused | A key that arrives through a Kubernetes Secret is visible to the host. The shim generates its key inside the guest. |
| GPU resource name required explicitly | The passthrough resource name depends on your GPU Operator configuration. Check `kubectl describe node` for the `nvidia.com/…` resource your nodes advertise (`nvidia.com/pgpu` on the current reference architecture). |
| `tee.coco.platform` required | The guest attestation agent does not say which TEE it runs in. The chart refuses a platform that disagrees with the RuntimeClass. |
| PersistentVolumeClaim model cache refused | The volume is host-provided storage and the host could alter cached weights between runs. An `emptyDir` lives inside the guest. |
| Listener audit enforced | The shim refuses to serve while any other process in the pod listens on a non-loopback address. A NetworkPolicy cannot do this job here, because the host enforces it. |
| One GPU unless `tee.coco.allowMultiGpu` | Multi-GPU is supported only on the platforms NVIDIA lists, and takes every GPU in the node. |

Two pod annotations matter, and both go in `tee.coco.podAnnotations`:

1. **Enable the in-guest evidence API.** The shim's `coco-aa` evidence source asks
   the guest attestation agent for evidence at `http://127.0.0.1:8006/aa/evidence`.
   That API is off by default and is enabled by a kernel parameter:

   ```yaml
   io.katacontainers.config.hypervisor.kernel_params: "agent.guest_components_rest_api=all"
   ```

   The kernel command line is part of the launch measurement, so a verifier's
   accepted measurements must be the ones computed *with* this parameter.
   [Confidential Containers: get attestation](https://confidentialcontainers.org/docs/features/get-attestation/)

2. **Bind the pod definition with init-data.** Without this, the evidence says
   only "a Kata guest", and you have built an evidence factory (see
   `architecture.md`). Init-data is a small document containing the Kata agent
   policy generated from your *rendered* manifest. It travels in the
   `io.katacontainers.config.hypervisor.cc_init_data` annotation, and its digest
   appears in the hardware report (`HOST_DATA` on SEV-SNP, `MRCONFIGID` on TDX).
   [Confidential Containers: init-data](https://confidentialcontainers.org/docs/features/initdata/)

## 3. Render, seal, apply

Because the policy is computed from the final manifest, the order is:

```
helm template …  ->  generate the agent policy from the rendered YAML (genpolicy)
                 ->  wrap it as init-data and add the annotation
                 ->  trcs lint-manifests --mode coco
                 ->  kubectl apply
                 ->  publish the init-data digest to your relying party
```

- Use `genpolicy` from Kata Containers **4.1.0 or later**. The Confidential
  Containers 0.22.0 release notes require this because of CVE-2026-77176.
- Generate the policy on a machine you trust, not on the cluster.
- The default policy denies `kubectl exec` and log streaming for the pod. Keep it
  that way. The shim and the engine are configured not to log request content,
  but the policy is what makes that a guarantee rather than a promise.
- The generated bases in `kustomize/coco-snp` and `kustomize/coco-tdx` give you a
  plain-YAML starting point for the same flow if you prefer not to use Helm, and
  `hack/gen-kustomize.sh` renders one for your own values. Rendered YAML
  is also easier to audit than templates, and it is the rendered YAML that gets
  measured.

This repository does not yet automate the sealing step. It is the next thing on
the roadmap, and it needs hardware to test against.

## 4. Verify from outside

```
trcs check-endpoint https://<service-address>:443 --expect-tee sev-snp
```

checks that the evidence is bound to the TLS key of the connection it arrived
on. It exits with status 3 and says so explicitly, because it does **not**
verify the hardware signatures or apply any policy. Full verification is the
relying party's job.

## What can go wrong that is specific to this path

| Symptom | Likely cause |
|---|---|
| Pod stuck `ContainerCreating` | RuntimeClass missing, node not labelled for passthrough, or GPUs not in confidential mode (`nvidia.com/cc.ready.state`) |
| Shim exits immediately with a TEE error | The evidence API kernel parameter is missing, or the annotation is not on the allow list in your Kata configuration |
| Model download fills guest memory | An `emptyDir` inside a confidential guest is backed by guest memory. Size the guest (`io.katacontainers.config.hypervisor.default_memory`) for the model cache plus the engine's host memory, or use a block-backed volume |
| Probes fail but the service works | The kubelet probes over HTTPS from the host; make sure nothing in front of the pod terminates TLS |
