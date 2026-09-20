# Attested endpoint protocol, v0

Identifier: `tr-attestation/v0`

This is the contract between a provider endpoint running this stack and a
relying party (normally the TrustedRouter gateway, but anyone may verify).
It answers one question: **is the TLS connection I am using terminated inside
the hardware-protected workload I think it is?**

The protocol is deliberately small. It carries evidence; it does not judge it.
Acceptance policy belongs to the relying party (see `threat-model.md`).

Status: v0 is a draft and may change incompatibly until v1. The `protocol`
field lets both sides detect a mismatch.

## 1. Transport

- The endpoint speaks HTTPS only, TLS 1.3 preferred, TLS 1.2 minimum.
- In confidential modes the TLS private key is generated in memory inside the
  TEE when the shim starts, is never written to storage, and is never supplied
  from outside (a key delivered through a Kubernetes Secret is visible to the
  host, which would defeat the binding). The certificate is self-signed.
- The relying party does **not** rely on WebPKI for confidentiality. It relies
  on the binding in section 3. It may additionally require a WebPKI certificate
  to establish who operates a hostname; that is a separate question.
- In `standard` mode the operator may supply an ordinary certificate and key.

## 2. Evidence request

```
GET /.well-known/trustedrouter/attestation?nonce=<64 hex characters>
```

- `nonce` is 32 bytes chosen freshly at random by the relying party for every
  request, hex encoded. Any other length is rejected with `400`.
- The endpoint is unauthenticated so that anyone can verify a provider, and is
  rate limited because each request costs a call into the security processor.
  `429` with `Retry-After` when limited.
- The response carries `Cache-Control: no-store`.

## 3. Binding

Let `spki` be the 32-byte SHA-256 digest of the DER-encoded
SubjectPublicKeyInfo of the certificate the server presents on this connection.

```
report_data[0:32]  = spki
report_data[32:64] = SHA-256( "tr-attestation/v0" || 0x00 || nonce )
gpu_nonce          = SHA-256( "tr-attestation/v0/gpu" || 0x00 || report_data )      (32 bytes)
```

`report_data` is placed in the 64-byte user-data field of the CPU TEE report
(`REPORT_DATA` on AMD SEV-SNP, `REPORTDATA` on Intel TDX). `gpu_nonce` is the
nonce given to the GPUs when their evidence is requested. One fresh
relying-party nonce therefore covers the CPU evidence, the GPU evidence and the
TLS key, and none of them can be replayed from another session.

The first half is deliberately the plain key digest, with no prefix. That is the
convention already used by at least one production confidential-inference
provider (the first 32 bytes of the report data are the SHA-256 of the
enclave's TLS public key), and it is what TrustedRouter's gateway already
enforces when it pins a provider's key. A verifier that knows only that
convention can still pin the key correctly. A verifier that knows this protocol
also gets freshness from the second half.

Golden test vectors are in `attestation-vectors.json`.

## 4. Response

`200 OK`, `Content-Type: application/json`:

```json
{
  "protocol": "tr-attestation/v0",
  "tee": "sev-snp",
  "nonce": "<hex, echoed>",
  "tls_spki_sha256": "<hex>",
  "report_data": "<hex, 64 bytes>",
  "cpu": {
    "source": "configfs-tsm",
    "provider": "sev_guest",
    "evidence": "<base64: SNP attestation report, or TDX quote>",
    "aux": "<base64: certificate table when the platform supplies one, else null>"
  },
  "gpu_evidence": [
    {
      "vendor": "nvidia",
      "format": "nvidia-nvattest-collect-evidence-json-v1",
      "nonce": "<hex gpu_nonce>",
      "evidence": "<base64: the vendor tool's evidence, byte for byte>"
    }
  ],
  "gpu_error": null,
  "workload": {
    "stack_version": "0.1.0",
    "model": "Qwen/Qwen2.5-7B-Instruct",
    "model_revision": "<commit>",
    "engine_image": "vllm/vllm-openai@sha256:…"
  },
  "confidential": true
}
```

Field rules:

| Field | Rule |
|---|---|
| `tee` | `sev-snp`, `tdx`, or `none`. |
| `cpu` | `null` when `tee` is `none`. `source` says how the evidence was obtained and therefore how to parse it: `configfs-tsm` (the Linux TSM report ABI, kernel 6.7+: `evidence` is the raw SEV-SNP report or TDX quote), `coco-aa` (the Confidential Containers guest attestation agent: `evidence` is that agent's evidence document), or `dstack` (the dstack guest agent: `evidence` is its versioned attestation). `provider` is the kernel's TSM provider name, or the source name where there is none. |
| `gpu_evidence` | A list of opaque, tagged bundles. The shim never parses GPU evidence; `vendor` and `format` tell the verifier which appraiser to use. `null` when GPU evidence could not be collected, with the reason in `gpu_error`. |
| `workload` | **Hints only.** A verifier must take workload identity from measured values inside the evidence, never from this object. It exists for humans and dashboards. |
| `confidential` | Convenience flag, true only when `tee` is not `none` and both CPU evidence and at least one GPU evidence bundle are present. **A verifier must ignore it.** |

When `tee` is `none` the response is still `200` with `cpu: null`,
`gpu_evidence: null`, `confidential: false`. A `standard` endpoint is an honest
endpoint that says so.

## 5. Verification procedure

A relying party must, in order:

1. Generate a fresh 32-byte nonce.
2. Open a TLS connection and record `spki` from the certificate actually
   presented on that connection.
3. Request the evidence on **that same connection**.
4. Check `protocol`, check `nonce` is the one sent, check `tls_spki_sha256`
   equals the recorded `spki`.
5. Recompute `report_data` from its own nonce and its own recorded `spki`. Do not
   use the value in the response except to compare. (A verifier that only pins
   keys may check bytes 0 to 31 alone, and then gets no freshness guarantee.)
6. Verify the CPU evidence signature chain to the vendor root (AMD: ARK, ASK,
   VCEK or VLEK. Intel: PCK chain and quoting-enclave identity), with revocation.
7. Check that the user-data field inside the verified evidence equals the
   recomputed `report_data`.
8. Apply platform policy: TCB and firmware minimums, debug disabled, CPU
   family allow and deny lists, platform allow list for the custody tier.
9. Apply workload policy against **measured** values: launch measurement in the
   accepted set, and for Confidential Containers the init-data digest matching
   an accepted workload definition.
10. Recompute `gpu_nonce`. For every bundle, select an appraiser by `vendor` and
    `format`, verify the report signature and
    certificate chain (NVIDIA Remote Attestation Service or a local verifier
    with current reference measurements), check the nonce, and check the GPU
    reports confidential-computing mode on with an accepted VBIOS and driver.
11. Pin `spki`. Send inference traffic only over connections presenting that
    key.
12. Repeat from step 1 whenever the presented key changes, and at least every
    `max_evidence_age` (suggested: 10 minutes).

A failure at any step means the route is not `attested`. It may still be served
as `standard` if the buyer's policy allows that tier.

## 6. What the binding does and does not prove

It proves that the holder of the TLS private key could obtain a hardware-signed
report containing a digest of that key and of the relying party's nonce. With
step 9, it proves that holder is the measured workload.

It does not prove the hardware is physically intact. See `threat-model.md`.

## 7. Operating behind proxies and tunnels

Anything that terminates TLS in front of the workload (an ingress controller, a
cloud HTTP load balancer, a tunnel service) breaks step 4, by design: the
relying party would be talking to the proxy's key. Use layer-4 pass-through.
The Helm chart ships no `Ingress` for this reason.

Application-layer encryption of request bodies to an attested key, which would
survive TLS-terminating intermediaries, is a candidate for v1.
