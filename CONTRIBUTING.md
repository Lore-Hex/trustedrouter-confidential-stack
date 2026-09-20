# Contributing

Contributions use Apache-2.0 inbound = outbound. No DCO sign-off or separate
contributor agreement is required. See LICENSE and NOTICE.

Read [the threat model](docs/threat-model.md) and
[the protocol](docs/attestation-protocol.md) before changing security behavior.
The Go code must use only the standard library: the shim is security-critical
and its dependency surface must remain small enough to audit. A test checks
`go list -deps ./...` and fails on every non-stdlib, non-self package.

Install Go 1.23+, Helm 4, yq 4, Kustomize 5, ShellCheck and Python 3. Install
kubeconform for Kubernetes schema checks. Run:

```sh
make all
```

For offline work, use `KUBECONFORM=skip make all`; this skips schema downloads,
not the local manifest-policy checks. CI runs kubeconform with strict schemas.
Run `make e2e-kind` separately with Docker, kind and kubectl available. It builds
the local image, uses the stdlib Python stub, tests TLS binding and incremental
SSE delivery, and removes its isolated cluster afterward.

The Kustomize base is generated. Edit the chart or
`kustomize/helm-values-for-base.yaml`, then run `make kustomize` and review the
diff. `make kustomize-check` detects drift and validates every overlay.
Overlays are maintained by hand. `make guardrail-tests` checks rejected chart
configurations and explicitly permitted overrides.

Do not log inference bodies, headers or query strings, including in error
paths. Do not turn channel-binding consistency into a hardware-validation
claim. Keep hardware acceptance policy with the relying party. The configfs
source is tested with a fake filesystem; actual CPU/GPU hardware integration
must be separately demonstrated. Never guess vendor flags, runtime annotations
or model-specific GPU resources: verify their source or require an explicit
operator-supplied value with `TODO(verify)` documentation.

Release automation is untested until the first tag. The release owner must
validate registry permissions, signing, image digests and chart publication.
The all-zero shim digests in examples are placeholders, not published images.
