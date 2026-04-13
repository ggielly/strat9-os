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
    echo "Creating limine image..."
    cargo make limine-image
    ;;
  all)
    echo "Full build: kernel + limine-image"
    cargo make kernel
    cargo make limine-image
    ;;
  *)
    echo "Unknown command: $cmd" >&2
    exit 2
    ;;
esac

echo "Build completed. Artifacts in /workspace/build and /workspace/target."