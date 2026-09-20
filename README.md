# TrustedRouter Confidential Stack

Run an OpenAI-compatible inference endpoint on your own GPUs, and give buyers
hardware evidence of what is running and where their TLS connection ends.

This is the supply-side kit for the [TrustedRouter token exchange](https://trustedrouter.com/token-exchange):
free, Apache-2.0, and built on upstream projects (vLLM, Kata Containers,
Confidential Containers, the NVIDIA GPU Operator, dstack) rather than
replacing them.

> ## Status: alpha. Read this before you rely on it.
>
> **Nothing in this repository has yet been run on real confidential-computing
> hardware.** `standard` mode is tested end to end in CI. The confidential
> modes are wired, linted and unit tested against fakes, and documented from
> upstream sources, but unproven on an SEV-SNP or TDX machine with a GPU in
> confidential mode. Do not describe an endpoint as confidential on the
> strength of this alpha.
>
> | Piece | State |
> |---|---|
> | Helm chart and Kustomize bases, `standard` mode | Installed and exercised end to end on a kind cluster in CI: channel binding, streaming, Helm test |
> | `trcs shim`: TLS inside the workload, evidence endpoint, streaming proxy, listener audit | Unit and integration tested |
> | `trcs preflight`: is this machine capable? | Tested against fixture trees, not yet against real hosts |
> | `trcs check-endpoint`: is the evidence bound to this TLS connection? | Tested. It deliberately does **not** verify hardware signatures |
> | CPU evidence (`configfs-tsm`, `coco-aa`, `dstack` sources) | Implemented against fakes. **Not hardware tested** |
> | GPU evidence | Passed through as opaque, tagged bundles from the platform agent or an operator-supplied helper. **Not hardware tested** |
> | Kubernetes confidential-containers mode | Renders and lints. **Not hardware tested** |
> | Sealing a rendered manifest into measured init-data | Documented, not automated |
> | Relying-party verifier and policy | Not in this repository (it belongs to the TrustedRouter gateway) |

## Why this exists

The exchange lets buyers require a *verified confidential provider route*:
protection that continues through model execution, not just up to the gateway.
Very few providers can offer that today, because assembling a CPU TEE, a GPU in
confidential mode, an attestation flow and an inference server is weeks of
work. This repository is that work, done once, in the open.

What a buyer gets from an endpoint built this way:

1. **Proof of where TLS ends.** The TLS key is generated inside the protected
   workload and bound into the hardware evidence, so a proxy or a relay in
   front of it is detected.
2. **Proof of what ran.** The model, revision, engine image and flags are part
   of what is measured. On a marketplace that matters as much as privacy: it
   makes serving a cheaper model than the one you were paid for detectable.

## What it does not give you

Hardware TEEs do not protect against an operator who has physical access to
the server and is willing to use it. Inexpensive memory-bus interposers
(TEE.fail in 2025, DDRop in September 2026) read protected memory and forge
attestation, and the CPU vendors consider that out of scope. The answer is
custody, not cryptography: rent confidential GPU VMs from a cloud, or run in an
audited facility, and label routes honestly. Read [the threat model](docs/threat-model.md)
before you sell or buy anything on the strength of an attestation.

| Tier | Means |
|---|---|
| `standard` | API-conformant. The operator can read traffic. |
| `attested` | Fresh CPU and GPU evidence bound to the TLS key, measured workload accepted by policy. Protects against everyone except an operator with physical access. |
| `attested+custody` | The same, on hardware the operator cannot physically touch. |

## What is in the box

| | |
|---|---|
| `charts/confidential-inference` | Helm chart: an inference engine (vLLM by default, SGLang supported) plus the shim in one pod. TLS terminates in the pod, there is no Ingress by design, an engine crash never rotates the attested key, and guardrails refuse unsafe confidential configurations at render time |
| `kustomize/` | The same manifests as plain YAML, **generated** from the chart and checked for drift in CI: a standard base plus SEV-SNP and TDX bases. One command renders a base for your own values |
| `trcs` | One small static Go binary, standard library only: `shim`, `preflight`, `check-endpoint`, `lint-manifests` |
| `docs/` | [Threat model](docs/threat-model.md), [protocol](docs/attestation-protocol.md), [architecture](docs/architecture.md), [hardware](docs/hardware.md), [Kubernetes confidential containers](docs/kubernetes-coco.md) |

Helm is the source of truth. The Kustomize base is rendered from it so the two
can never disagree, and because rendered YAML is what actually gets measured.

## Quick start: `standard` mode, any Kubernetes cluster with an NVIDIA GPU

```
helm install inference charts/confidential-inference \
  --namespace tr-inference --create-namespace \
  -f examples/values-dev-gpu.yaml

kubectl -n tr-inference port-forward svc/inference-confidential-inference 8443:443 &
trcs check-endpoint https://localhost:8443 --expect-tee none
```

Then check API conformance with
[trustedrouter-provider-check](https://github.com/Lore-Hex/trustedrouter-provider-check)
and apply at [trustedrouter.com/providers/marketplace](https://trustedrouter.com/providers/marketplace).

No cluster handy? `make e2e-kind` brings up the whole thing on a laptop with a
stub model server.

## Going confidential

Start with `trcs preflight` on the machine. Then pick the path that matches
what you own:

| You have | Path |
|---|---|
| Bare-metal Kubernetes nodes with H100, H200, B200 or newer | [Kubernetes confidential containers](docs/kubernetes-coco.md) |
| A single server or VM host, or a Google Cloud TDX VM | dstack, with the compose file in `deploy/dstack/` |
| Neither | Rent a confidential GPU VM; see [hardware](docs/hardware.md) |

NVIDIA states that confidential computing is a licensed feature for production
use. The software here is free; check with NVIDIA about the GPU feature.

## Roadmap

1. Hardware validation of all three confidential paths, with the results
   published here.
2. GPU evidence through NVIDIA's attestation tooling.
3. A `seal` command: rendered manifest to agent policy to init-data to the
   digest a relying party needs.
4. Published reference measurements for the images this repository releases.
5. Evidence through Azure confidential VMs (vTPM based).
6. Request-body encryption to an attested key, so the binding survives
   TLS-terminating load balancers and tunnels.

## Development

```
make all        # format check, vet, tests, chart lint, render, manifest policy, kustomize drift
make e2e-kind   # full standard-mode install on kind
```

The Go code uses the standard library only, and a test enforces it. The shim
is the one component that sits inside the trust boundary; it should stay small
enough to audit in an afternoon.

## Security

See [SECURITY.md](SECURITY.md). Please report vulnerabilities privately.

## License

Apache-2.0. Copyright 2026 Lore Hex Corp.
