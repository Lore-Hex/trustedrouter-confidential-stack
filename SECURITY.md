# Security Policy

## Reporting a vulnerability

Use GitHub's **[private vulnerability reporting](../../security/advisories/new)**
for this repository. Reports stay visible only to maintainers while they are
investigated, and the same thread carries the fix and any advisory.

Please do not open a public issue for a suspected vulnerability, and do not
include real prompts, keys or other user data in a report.

Include what you can: the affected version or commit, the deployment mode
(`standard`, Kubernetes confidential containers, dstack), reproduction steps,
and the impact you believe it has. A partial report sent early is more useful
than a complete one sent late.

## What to expect

- Acknowledgement within 72 hours.
- An assessment of severity and affected components within 5 business days.
- Notification when a fix ships, and credit in the advisory unless you ask us
  not to.

There is no bug bounty programme.

## Scope

[docs/threat-model.md](docs/threat-model.md) defines what this stack claims and
what it does not. Three limits are stated there and are not vulnerabilities in
themselves: `standard` mode does not protect against the operator; hardware
attestation alone does not protect against an operator with physical access;
and `trcs check-endpoint` checks channel binding only, not hardware signatures.

Anything that lets a party outside the TEE read request content, obtain the
shim's TLS key, mint evidence for a key it controls, or make the stack report
more protection than it provides is in scope and is treated as critical.

This is alpha software. Fixes target the latest release and the main branch.
