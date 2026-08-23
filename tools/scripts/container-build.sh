#!/bin/bash
set -e

# Build helper to run inside the container
# Usage: container-build.sh [kernel|image|all]

cmd=${1:-all}

source /root/.cargo/env || true
cd /workspace

case "$cmd" in
  kernel)
    echo "Building kernel..."
    cargo make kernel
    ;;
  image)
    echo "Creating UEFI image..."
    cargo make uefi-image
    ;;
  all)
    echo "Full build: kernel + uefi-image"
    cargo make kernel
    cargo make uefi-image
    ;;
  *)
    echo "Unknown command: $cmd" >&2
    exit 2
    ;;
esac

echo "Build completed. Artifacts in /workspace/build and /workspace/target."