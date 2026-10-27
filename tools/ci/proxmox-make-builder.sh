#!/usr/bin/env bash
# =============================================================================
# proxmox-make-builder.sh : create the `strat9-builder` VM on Proxmox (option A).
#
# Run ONCE on the Proxmox host (or over SSH), as root:
#   ./tools/ci/proxmox-make-builder.sh \
#     --node pve --vmid 9000 --name strat9-builder \
#     --storage local-lvm --bridge0 vmbr0 --bridge1 vmbr1 \
#     --cores 4 --memory 8192 --disk 60 \
#     --debian-iso local:iso/debian-12-generic-amd64.iso
#
# What it does:
#   1. Creates a KVM VM (cpu=host for nested virtualization, qemu-guest-agent
#      enabled) with 2 NICs: vmbr0 (WAN/GitLab/crates.io) + vmbr1 (isolated,
#      for DHCP/e1000 loopback tests : never bridged to the LAN).
#   2. Attaches the Debian installer ISO. You complete the install manually
#      (or via cloud-init, see --cloud-init flag in future option B work).
#   3. Prints the follow-up: run tools/ci/builder-provision.sh INSIDE the VM.
#
# Proxmox used here: https://192.168.1.235:8006 (PVE 9.2).
# Requires: qm/pvesm on the host. Idempotent-ish: refuses to overwrite an
# existing VMID unless --force is given.
# =============================================================================
set -euo pipefail

NODE="pve"
VMID=9000
NAME="strat9-builder"
STORAGE="local-lvm"
BRIDGE0="vmbr0"
BRIDGE1="vmbr1"
CORES=4
MEMORY=8192
DISK_GB=60
DEBIAN_ISO="local:iso/debian-12-generic-amd64.iso"
FORCE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --node)       NODE="$2"; shift 2 ;;
        --vmid)       VMID="$2"; shift 2 ;;
        --name)       NAME="$2"; shift 2 ;;
        --storage)    STORAGE="$2"; shift 2 ;;
        --bridge0)    BRIDGE0="$2"; shift 2 ;;
        --bridge1)    BRIDGE1="$2"; shift 2 ;;
        --cores)      CORES="$2"; shift 2 ;;
        --memory)     MEMORY="$2"; shift 2 ;;
        --disk)       DISK_GB="$2"; shift 2 ;;
        --debian-iso) DEBIAN_ISO="$2"; shift 2 ;;
        --force)      FORCE=1; shift ;;
        -h|--help)    grep '^#' "$0" | head -40; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

if ! command -v qm >/dev/null 2>&1; then
    echo "ERROR: 'qm' not found : run this script ON the Proxmox host (root)." >&2
    exit 2
fi

if qm status "$VMID" >/dev/null 2>&1; then
    if [[ $FORCE -eq 0 ]]; then
        echo "ERROR: VMID $VMID already exists. Pass --force to destroy + recreate." >&2
        exit 1
    fi
    echo "==> Destroying existing VM $VMID (--force)"
    qm stop "$VMID" || true
    sleep 2
    qm destroy "$VMID" --purge 1
fi

echo "==> Creating VM $VMID ($NAME) on node $NODE"
qm create "$VMID" \
    --name "$NAME" \
    --ostype l26 \
    --cores "$CORES" --sockets 1 \
    --memory "$MEMORY" \
    --cpu host \
    --kvm 1 \
    --machine q35 \
    --bios seabios \
    --scsihw virtio-scsi-pci \
    --scsi0 "$STORAGE:$DISK_GB" \
    --ide2 "$DEBIAN_ISO,media=cdrom" \
    --boot order=ide2 \
    --net0 "virtio,bridge=$BRIDGE0" \
    --net1 "virtio,bridge=$BRIDGE1" \
    --agent enabled=1 \
    --serial0 socket \
    --vga std

echo ""
echo "==> VM $VMID created. Next steps:"
echo "    1. qm start $VMID"
echo "    2. Install Debian 12 (console: qm terminal $VMID, or SPICE via https://192.168.1.235:8006)"
echo "    3. Inside the VM, as root: bash tools/ci/builder-provision.sh --gitlab-token <TOKEN>"
echo "       (installs qemu-system-x86, OVMF, rust pinned toolchain, gitlab-runner"
echo "        registered with tags: qemu,kvm,proxmox)"
echo ""
