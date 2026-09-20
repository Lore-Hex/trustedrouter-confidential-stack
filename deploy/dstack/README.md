# dstack path

[dstack](https://github.com/Dstack-TEE/dstack) (Apache-2.0, a Confidential
Computing Consortium project) runs a Docker Compose application inside a
confidential VM that it builds and measures. It is the practical route when
you have a single server or a VM host rather than a Kubernetes cluster, and it
also runs on Google Cloud TDX VMs. The production path is Intel TDX.

`docker-compose.yaml` here is the same two containers the Helm chart deploys:
the inference engine on loopback, and the shim in front of it. The shim reads
evidence from the dstack guest agent on `/var/run/dstack.sock`.

**The compose file is what gets measured.** dstack records its hash in the
runtime event log, and that hash is what a relying party accepts. So images
are pinned by digest and nothing is filled in at deploy time. If you change the
model or a flag, you have a new measurement to publish.

Status: this project has not run this path yet. The `dstack` evidence source
targets the guest agent API v1, which ships in dstack 0.6.0 (a release
candidate when this was written), and is marked experimental in `trcs shim
--help`. GPU evidence comes from the agent's `AttestGpu` call when the dstack
image includes NVIDIA's attestation tool.
