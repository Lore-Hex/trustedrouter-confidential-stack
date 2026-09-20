# Threat model

This document says what the stack protects, from whom, and where it stops.
It is written for two readers: a provider deciding whether to run this, and a
buyer deciding what a "confidential" label on a TrustedRouter route is worth.

If a claim here and a claim in marketing copy ever disagree, this file is the
one to believe.

## What is being protected

1. **Prompts and completions in use.** The content of inference requests while
   they are being processed on someone else's GPUs.
2. **The identity of what ran.** Which model, which revision, which inference
   engine and flags actually served a request. On a marketplace, a provider has
   an economic reason to serve a smaller or more heavily quantized model than
   the one it is paid for. Attested workload identity makes that detectable.

Not in scope for v0: secrecy of model weights (the stack serves openly
published weights), availability, and billing integrity.

## Parties

| Party | Role | Trusted for |
|---|---|---|
| Buyer | Sends inference requests through TrustedRouter | — |
| TrustedRouter gateway | Open-source proxy running in an attested enclave; the relying party that verifies provider evidence | Verifying evidence and enforcing policy. Its own attestation is published at trust.trustedrouter.com. |
| Provider (operator) | Owns or rents the GPUs and runs this stack | **Nothing about confidentiality.** The operator is treated as an adversary. |
| Custodian | Whoever has hands on the hardware. Sometimes the operator, sometimes a cloud or colocation facility | Physical integrity of the machine (see "Physical access") |
| AMD / Intel / NVIDIA | Hardware roots of trust | Correct TEE implementation, honest endorsement keys, timely TCB updates |

## Adversaries and outcomes

| Adversary | `standard` mode | Confidential modes |
|---|---|---|
| Network attacker between gateway and provider | Protected **only if** the operator installs a publicly trusted certificate. With the default self-signed certificate nothing authenticates the key, so an active attacker can impersonate the endpoint. | Protected. TLS terminates inside the TEE and the TLS key is bound into the hardware evidence, so a relay or a terminating proxy is detected. |
| Provider's cluster admin, host root, hypervisor, or anyone who compromises them (software only) | **Not protected.** They can read everything. | Protected, provided the platform's TCB is current and the platform is not on the relying party's deny list (see "Known attacks"). |
| Provider substituting a different model or engine configuration | Not detectable except by spot checks | Detectable. The workload definition is measured and the verifier compares it to policy. |
| Operator with **physical access** to the server | Not protected | **Not protected by the TEE alone.** See next section. |
| Side channels (timing, response length, shared-cache and power channels) | Out of scope | Out of scope. Streaming responses leak token count and timing through TLS record sizes even when content is encrypted. |
| Bugs or backdoors in TEE firmware, GPU firmware, or vendor key infrastructure | Out of scope | Out of scope; tracked through TCB policy. |
| A malicious or compromised release of this repository's images | Mitigated by digest pinning, reproducible builds and signed releases | Same, plus the image digests are part of what is measured. |

## Physical access is the limit of hardware TEEs

Confidential computing on commodity servers encrypts memory but, for
performance, does not give each memory write an integrity and freshness
guarantee. A series of published attacks exploits that with inexpensive
hardware placed between the CPU and a DIMM:

- **TEE.fail** (October 2025): a DDR5 interposer built for under $1,000
  extracted attestation signing keys, forged Intel TDX quotes that verified at
  the highest trust level, and showed the same keys undermine the trust chain
  used for NVIDIA GPU confidential computing.
  [tee.fail](https://tee.fail/) ·
  [coverage](https://thehackernews.com/2025/10/new-teefail-side-channel-attack.html)
- **DDRop** (14 September 2026): an active DDR5 interposer costing under $200
  replays stale ciphertext to force a protected VM into debug mode, read its
  memory in plaintext, and forge attestation. It works against Intel TDX,
  Scalable SGX and AMD SEV-SNP, deterministically, in under two minutes.
  Intel and AMD both responded that physical attacks are outside their threat
  model and that no mitigation is planned.
  [The Register](https://www.theregister.com/security/2026/09/14/new-hardware-device-can-ram-into-encrypted-memory-expose-your-data/5296377)

The consequence for a marketplace is direct. **If the party you do not trust
is also the party holding the screwdriver, remote attestation does not protect
you from them.** It still protects you from everyone else: remote attackers,
a compromised host OS, a curious administrator, accidental logging, and a
provider who would cheat only if it were free.

The mitigation is custody, not cryptography:

1. **Separate operation from custody.** A provider who *rents* confidential
   GPU VMs from a cloud has no physical access, and the cloud has no logical
   access. Neither party alone can mount these attacks.
2. **An accountable operator in an audited facility.** Where the operator does
   own the hardware, three things together stand in for the cloud's separation:
   - a direct relationship and a contract with the operator's leadership, with
     a right to audit and a duty to report physical incidents;
   - an ISO/IEC 27001 certification (or equivalent) whose **scope statement
     covers the facility and the servers**, with the physical controls of
     Annex A.7 (perimeter, entry, monitoring, equipment protection and
     maintenance) checked by TrustedRouter against the Statement of
     Applicability rather than taken from a logo;
   - the hardware identity of each audited machine (SEV-SNP chip ID, TDX
     platform ID) on the relying party's allow list, so that valid evidence
     from a machine *outside* the audited cage is refused.
3. **Say which one a route is.** TrustedRouter labels the tiers separately (below)
   so a buyer can require the stronger one.

## The network inside the guest

A Kubernetes NetworkPolicy, a security group and a host firewall are all
enforced by the host, which in the confidential modes is the adversary. They
keep third parties out. They do nothing against the operator, who can reach
any port the pod opens.

So the rule inside the guest is simple: **the shim is the only process allowed
to listen on a non-loopback address.** Inference engines are large programs
that open extra sockets for distributed and disaggregated serving, and those
sockets have carried unauthenticated remote-code-execution bugs
([ShadowMQ](https://www.oligo.security/blog/shadowmq-how-code-reuse-spread-critical-vulnerabilities-across-the-ai-ecosystem)).
Code execution inside the guest is the one attack that defeats everything
else, because the attacker can then ask for genuine evidence over a key of
their choosing. The shim therefore audits the pod's listening sockets and
refuses to serve while anything else is reachable from outside.

## Software-only attacks and why policy must be agile

Not every break needs a screwdriver. **BadFuse** (May 2026) is a software-only
chain that achieves code execution on the AMD secure processor of EPYC *Milan*
parts and extracts the hardware root seed, letting an attacker forge SEV-SNP
attestation reports for any firmware version.
[arXiv:2605.12990](https://arxiv.org/abs/2605.12990). A host operator is exactly
the party positioned to run it. A relying party that takes this seriously stops
accepting Milan for confidential routes, and no firmware update on the provider
side can change that.

New results of this kind arrive several times a year. Therefore:

- **All acceptance policy lives with the relying party**, not in this
  repository's chart: minimum TCB and firmware versions, CPU family allow and
  deny lists, accepted GPU VBIOS and driver versions, certificate revocation,
  maximum evidence age, and platform allow lists.
- This stack's job is to produce complete, fresh, channel-bound evidence.
  It deliberately does not decide whether that evidence is good enough.
- The preflight tool reports facts about a node. When it warns about a CPU
  family, that is advice about what verifiers are likely to reject, not a
  security decision.

## Tiers

| Tier | What is verified | Protects against | Does not protect against |
|---|---|---|---|
| `standard` | API conformance only | Network attackers, when the endpoint presents a publicly trusted certificate | The provider |
| `attested` | Fresh CPU TEE evidence and GPU evidence, bound to the TLS key; measured workload matches policy; platform passes TCB policy | Remote attackers, compromised or curious host software and administrators, model substitution | An operator with physical access and intent |
| `attested+custody` | Everything in `attested`, plus the platform identity is on a custody allow list: a cloud-rented confidential GPU VM, or a machine in a facility whose physical controls TrustedRouter has verified, run by an operator under contract | The above, plus the operator acting alone | Collusion between operator and custodian; vendor compromise; side channels |

## What this stack does not claim

- It does not claim protection from the operator in `standard` mode. That mode
  exists so providers can bring up and test an endpoint on any hardware.
- It does not claim that a green attestation check means "nobody can see your
  data". It means the specific things in the `attested` row above.
- It does not claim hardware validation it has not had. See the status table in
  the README for exactly what has and has not been run on real TEE hardware.
