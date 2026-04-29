#!/bin/bash
set -e

echo "=== Container bootstrap: installing packages and Rust ==="

# Non-interactive frontend
export DEBIAN_FRONTEND=noninteractive

apt update
apt install -y curl build-essential nasm qemu-system-x86 xorriso git ca-certificates pkg-config libssl-dev

# Install rustup if not present
if [ ! -f /root/.cargo/bin/rustc ]; then
    echo "Installing rustup (stable)..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source /root/.cargo/env
else
    source /root/.cargo/env
    echo "Rust already installed"
fi

# Install cargo-make
if [ ! -f /root/.cargo/bin/cargo-make ]; then
    echo "Installing cargo-make..."
    cargo install cargo-make --locked
else
    echo "cargo-make already installed"
fi

# Add the x86_64-unknown-none target
echo "Adding rust target x86_64-unknown-none (if available)"
rustup target add x86_64-unknown-none || true

# Ensure workspace ownership (if mounted from Windows, may be root-owned already)
if [ -d /workspace ]; then
    echo "Workspace mounted at /workspace"
fi

echo "Bootstrap complete."