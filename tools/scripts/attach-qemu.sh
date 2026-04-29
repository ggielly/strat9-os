#!/bin/bash
# Attach to QEMU serial log inside the 'strat9-os-dev' container
container="strat9-os-dev"

if ! podman ps --format '{{.Names}}' | grep -q "^${container}$"; then
    echo "Container $container is not running. Start it with: ./tools/scripts/launch-podman.ps1"
    exit 1
fi

exec podman exec -it "$container" bash -lc "tail -f /workspace/build/qemu.log"