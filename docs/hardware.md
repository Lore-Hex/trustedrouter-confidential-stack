# Hardware and host requirements

Confidential inference needs three things from hardware, and no software in
this repository can substitute for any of them.

## 1. A GPU that supports NVIDIA Confidential Computing

Confidential computing arrived with the Hopper architecture. As of NVIDIA's
Confidential Containers reference architecture 1.1.0 (August 2026) the
supported parts are:

| GPU | Single GPU | Multi-GPU |
|---|---|---|
| H100, H200 | yes | yes, in Protected PCIe mode |
| B200 | yes | yes |
| HGX B300 | yes | yes |
| RTX PRO 6000 Blackwell Server Edition | yes | not listed |

Source: [NVIDIA release notes](https://docs.nvidia.com/datacenter/cloud-native/confidential-containers/latest/release-notes.html).
A100, L40S, L4 and consumer cards do not support it: the feature needs hardware that first shipped with Hopper.

Two conditions from the same document that surprise people:

- **Every GPU in the host must be in confidential mode.** A mixed node is not
  supported.
- **Multi-GPU means all of the node's GPUs go to one VM.**

On Hopper, Protected PCIe mode leaves NVLink traffic between GPUs unencrypted
inside the chassis. Blackwell encrypts it.

### Licensing

NVIDIA states that "the NVIDIA Confidential Computing capability is a licensed
feature for production use cases" and that you "must have a valid NVIDIA
Confidential Computing license"
([source](https://docs.nvidia.com/datacenter/cloud-native/confidential-containers/latest/licensing.html)).
This stack is free and open source. The GPU feature it depends on is not
necessarily free in production. Talk to NVIDIA before you sell capacity.

## 2. A CPU with a confidential-VM TEE, enabled

| Vendor | Technology | NVIDIA-validated generations |
|---|---|---|
| AMD | SEV-SNP | EPYC Milan, Genoa |
| Intel | TDX | Emerald Rapids, Granite Rapids |

**About Milan.** NVIDIA validates it, but a software-only attack published in
May 2026 extracts the key material that signs Milan attestation reports
([arXiv:2605.12990](https://arxiv.org/abs/2605.12990)). Expect relying parties
to refuse Milan for confidential tiers. `trcs preflight` warns about it.

The TEE must be enabled in firmware (SEV-SNP or TDX, IOMMU, SR-IOV/ACS as your
platform requires). Those settings are vendor specific; follow your server
vendor's guide and NVIDIA's deployment guide.

## 3. A host kernel that can launch confidential guests

| Feature | Upstream since | Notes |
|---|---|---|
| SEV-SNP host (KVM) | Linux 6.11 | |
| TDX host (KVM) | Linux 6.16 | Ubuntu 25.10 ships it without extra repositories |

NVIDIA validates Ubuntu 25.10 and 26.04 with kernel 6.17 or later, Kubernetes
1.32 or later, and containerd only.

## Check a machine

```
trcs preflight
```

reports, for the machine it runs on: CPU vendor and family advice, whether the
kernel has SEV-SNP or TDX host support switched on, IOMMU state, NVIDIA devices
and which driver they are bound to, whether each GPU's architecture supports
confidential computing, and, inside a guest, whether the GPU is actually in
confidential mode. It reports facts. It does not decide whether a verifier will
accept the machine.

## If you do not own suitable hardware

Rent it. A confidential GPU VM from a cloud gives you the hardware and also the
stronger custody story described in `threat-model.md`, because you cannot
physically touch the machine.

| Cloud | Instance | TEE | GPU |
|---|---|---|---|
| Microsoft Azure | NCCads_H100_v5 | AMD SEV-SNP | 1 x H100 NVL |
| Google Cloud | a3-highgpu-1g (Confidential VM) | Intel TDX | 1 x H100 |

On these you are a guest, so the Kubernetes confidential-containers path (which
needs the host) does not apply. Use the dstack path where dstack supports the
platform (it lists Google Cloud TDX), or your own measured image.
