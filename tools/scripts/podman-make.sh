#!/usr/bin/env bash
set -euo pipefail

CONTAINER="strat9-os-dev"
TASK=${1:-default}
shift || true
TASK_ARGS=("$@")

ensure_podman_machine() {
    if ! podman ps >/dev/null 2>&1; then
        echo "Podman machine not responding, trying to start it..." >&2
        podman machine start
    fi
}

ensure_container() {
    if ! podman ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
        echo "Container '$CONTAINER' not found. Creating it..." >&2
        # call the windows script semantics: use the launch script (works if host is WSL / Linux with PowerShell available)
        # Prefer a local launch script if exists
        if [ -x "$(pwd)/tools/scripts/launch-podman.sh" ]; then
            ./tools/scripts/launch-podman.sh
        else
            # try powershell script via pwsh if available
            if command -v pwsh >/dev/null 2>&1; then
                pwsh -File tools/scripts/launch-podman.ps1
            else
                echo "No helper to create container found. Run launch-podman.ps1 manually." >&2
                exit 1
            fi
        fi
    fi
    # start the container if stopped
    if ! podman ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
        echo "Starting container '$CONTAINER'..." >&2
        podman start "$CONTAINER"
    fi
}

exec_in_container() {
    local cmd="$1"
    local interactive=${2:-false}
    if [ "$interactive" = true ]; then
        podman exec -it "$CONTAINER" bash -lc "$cmd"
    else
        podman exec "$CONTAINER" bash -lc "$cmd"
    fi
}

ensure_podman_machine
ensure_container

case "$TASK" in
  attach)
    exec_in_container "tail -f /workspace/build/qemu.log" true
    ;;
  run)
    # optionally start qemu detached if asked via env var START_QEMU=1
    if [ "${START_QEMU:-0}" = "1" ]; then
        podman exec -d "$CONTAINER" bash -lc "/workspace/tools/scripts/run-qemu-nographic.sh"
    fi
    exec_in_container "cd /workspace && source /root/.cargo/env && cargo make run" true
    ;;
  run-nographic)
    if [ "${FOREGROUND:-0}" = "1" ]; then
        exec_in_container "/workspace/tools/scripts/run-qemu-nographic.sh --foreground" true
    else
        podman exec -d "$CONTAINER" bash -lc "/workspace/tools/scripts/run-qemu-nographic.sh"
        echo "QEMU started detached (see /workspace/build/qemu.log)"
    fi
    ;;
  run-gui)
    exec_in_container "cd /workspace && source /root/.cargo/env && cargo make run-gui" true
    ;;
  run-debug)
    exec_in_container "cd /workspace && source /root/.cargo/env && cargo make run-debug" true
    ;;
  *)
    # forward to cargo make
    args=""
    if [ ${#TASK_ARGS[@]} -gt 0 ]; then
        args=" ${TASK_ARGS[*]}"
    fi
    exec_in_container "cd /workspace && source /root/.cargo/env && cargo make $TASK$args" true
    ;;
esac
