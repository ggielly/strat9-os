#!/usr/bin/env bash
# =============================================================================
# builder-provision.sh : provision the strat9-builder LXC (ArchLinux, option A).
#
# Run INSIDE the ArchLinux container, as root:
#   bash tools/ci/builder-provision.sh --gitlab-url https://<gitlab> \
#        --gitlab-token <RUNNER_TOKEN> [--concurrent 2]
#
# Installs (pacman):
#   - qemu-system-x86, edk2-ovmf, parted, mtools, dosfstools, libisoburn,
#     base-devel + build tools
#   - rust pinned toolchain from rust-toolchain.toml + cargo-make
#     (exposed via /usr/local/bin symlinks so CI shell jobs find them)
#   - gitlab-runner official binary as systemd service
#     (shell executor, tags: qemu,kvm,proxmox)
# Verifies: /dev/kvm present, OVMF firmware present, qemu + runner running.
# Idempotent: safe to re-run.
# =============================================================================
set -euo pipefail

GITLAB_URL=""
GITLAB_TOKEN=""
CONCURRENT=2

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gitlab-url)   GITLAB_URL="$2"; shift 2 ;;
        --gitlab-token) GITLAB_TOKEN="$2"; shift 2 ;;
        --concurrent)   CONCURRENT="$2"; shift 2 ;;
        -h|--help)      grep '^#' "$0" | head -30; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root inside the builder container." >&2
    exit 2
fi
if [[ -z "$GITLAB_URL" || -z "$GITLAB_TOKEN" ]]; then
    echo "ERROR: --gitlab-url and --gitlab-token are required." >&2
    exit 2
fi

echo "==> [1/4] pacman packages"
pacman -Syu --noconfirm --needed \
    qemu-system-x86 edk2-ovmf \
    parted mtools dosfstools libisoburn \
    base-devel pkgconf git curl ca-certificates \
    openssl socat file

echo "==> [2/4] KVM + OVMF sanity checks"
if [[ -e /dev/kvm ]]; then
    echo "    [OK] /dev/kvm present (nested virtualization)"
    chmod 666 /dev/kvm || true
else
    echo "    [WARN] /dev/kvm MISSING : QEMU will fall back to TCG (10x slower)."
    echo "           Fix ON THE PROXMOX HOST (container stopped, cannot be done from inside):"
    echo "             pct stop <ctid> && echo 'dev0: /dev/kvm' >> /etc/pve/lxc/<ctid>.conf && pct start <ctid>"
fi
# OVMF layout differs per distro and package version: probe known locations,
# then ask pacman which files edk2-ovmf actually installed, then search /usr/share.
locate_fd() {
    local pattern="$1"  # e.g. OVMF_CODE
    local c
    for c in "/usr/share/OVMF/${pattern}_4M.fd" \
             "/usr/share/edk2-ovmf/x64/${pattern}_4M.fd" \
             "/usr/share/edk2-ovmf/x64/${pattern}.fd" \
             "/usr/share/edk2/${pattern}.fd" \
             "/usr/share/qemu/${pattern}_4M.fd"; do
        if [[ -f "$c" ]]; then echo "$c"; return 0; fi
    done
    if command -v pacman >/dev/null 2>&1; then
        c="$(pacman -Ql edk2-ovmf 2>/dev/null | awk '{print $2}' \
             | grep -E "/${pattern}(_4M)?\\.fd$" | sort | head -1 || true)"
        if [[ -n "$c" && -f "$c" ]]; then echo "$c"; return 0; fi
    fi
    c="$(find /usr/share -name "${pattern}*.fd" 2>/dev/null | sort | head -1 || true)"
    if [[ -n "$c" ]]; then echo "$c"; return 0; fi
    return 1
}
OVMF_CODE="$(locate_fd OVMF_CODE || true)"
OVMF_VARS="$(locate_fd OVMF_VARS || true)"
if [[ -z "$OVMF_CODE" || -z "$OVMF_VARS" ]]; then
    echo "    [ERROR] no OVMF firmware found." >&2
    echo "            Installed edk2-ovmf files:" >&2
    pacman -Ql edk2-ovmf 2>/dev/null | grep -E '\\.fd$' >&2 || echo "            (edk2-ovmf not installed?)" >&2
    exit 1
fi
echo "    [OK] code=$OVMF_CODE"
echo "    [OK] vars=$OVMF_VARS"

echo "==> [3/4] Rust toolchain (pinned via rust-toolchain.toml) + cargo-make"
if ! id gitlab-runner >/dev/null 2>&1; then
    useradd -m -s /bin/bash gitlab-runner
fi
export CARGO_HOME="${CARGO_HOME:-/var/cache/cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/var/cache/rustup}"
mkdir -p "$CARGO_HOME" "$RUSTUP_HOME"
if [[ ! -x "$CARGO_HOME/bin/rustup" ]]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --profile minimal
fi
export PATH="$CARGO_HOME/bin:$PATH"
# The repo's rust-toolchain.toml pins nightly-2026-07-20; rustup syncs on first use.
rustup toolchain install nightly-2026-07-20 --component rust-src llvm-tools 2>/dev/null || true
rustup target add x86_64-unknown-none --toolchain nightly-2026-07-20 2>/dev/null || true
rustup target add x86_64-unknown-linux-gnu --toolchain nightly-2026-07-20 2>/dev/null || true
if ! command -v cargo-make >/dev/null 2>&1; then
    "$CARGO_HOME/bin/cargo" install cargo-make
fi
chown -R gitlab-runner:gitlab-runner "$CARGO_HOME" "$RUSTUP_HOME"
# CI shell jobs run with a minimal PATH: expose the toolchain system-wide.
for bin in rustup rustc cargo cargo-make; do
    ln -sf "$CARGO_HOME/bin/$bin" "/usr/local/bin/$bin"
done
echo "    [OK] $(cargo --version) | $(cargo make --version 2>/dev/null || echo no-cargo-make)"

echo "==> [4/4] GitLab Runner (shell executor, systemd)"
if ! command -v gitlab-runner >/dev/null 2>&1; then
    curl -L --fail -o /usr/local/bin/gitlab-runner \
        "https://gitlab-runner-downloads.s3.amazonaws.com/latest/binaries/gitlab-runner-linux-amd64"
    chmod +x /usr/local/bin/gitlab-runner
    gitlab-runner install --user=gitlab-runner --working-directory=/home/gitlab-runner
fi
if ! gitlab-runner list 2>/dev/null | grep -q "strat9-builder"; then
    gitlab-runner register --non-interactive \
        --url "$GITLAB_URL" \
        --registration-token "$GITLAB_TOKEN" \
        --executor shell \
        --shell bash \
        --tag-list "qemu,kvm,proxmox" \
        --description "strat9-builder (Arch LXC, ephemeral QEMU per job)" \
        --limit "$CONCURRENT"
fi
systemctl enable --now gitlab-runner
systemctl is-active --quiet gitlab-runner && echo "    [OK] gitlab-runner active"

echo ""
echo "==> Builder ready. Tags: qemu,kvm,proxmox | concurrent=$CONCURRENT"
echo "    QEMU: $(qemu-system-x86_64 --version | head -1)"
