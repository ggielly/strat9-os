#!/usr/bin/env bash
# builder.sh
# Main orchestration script for strat9-os
# Clones repositories and launches build in podman container

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOS_CONFIG="${SCRIPT_DIR}/repos.toml"
CONTAINER_NAME="strat9-builder"
CONTAINER_TAG="latest"
WORKSPACE_DIR="${SCRIPT_DIR}/workspace"
BUILD_DIR="${SCRIPT_DIR}/build"

# Colors for logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# Utility functions
# =============================================================================

log_info() {
    echo -e "${BLUE}[info]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[success]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[warning]${NC} $*"
}

log_error() {
    echo -e "${RED}[error]${NC} $*"
}

# Parse simple TOML file (requires grep/sed/awk)
parse_toml() {
    local file=$1
    local section=$2
    local key=$3

    # Extract value from [section] key = "value"
    awk -v section="$section" -v key="$key" '
        /^\[/ { in_section=0 }
        $0 ~ "^\\[" section "\\]" { in_section=1; next }
        in_section && $1 == key {
            match($0, /"([^"]*)"/, arr)
            print arr[1]
            exit
        }
    ' "$file"
}

# =============================================================================
# Podman container management
# =============================================================================

build_container() {
    log_info "building podman container: ${CONTAINER_NAME}:${CONTAINER_TAG}"

    if ! command -v podman &> /dev/null; then
        log_error "podman not found. Please install podman first."
        exit 1
    fi

    podman build -t "${CONTAINER_NAME}:${CONTAINER_TAG}" -f Containerfile .

    log_success "container built successfully"
}

start_container() {
    log_info "starting persistent container: ${CONTAINER_NAME}"

    # Stop existing container if present
    if podman ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
        log_warning "container ${CONTAINER_NAME} already exists, removing..."
        podman rm -f "${CONTAINER_NAME}" || true
    fi

    # Create and start container in persistent mode
    podman run -d \
        --name "${CONTAINER_NAME}" \
        -v "${SCRIPT_DIR}:/build:Z" \
        "${CONTAINER_NAME}:${CONTAINER_TAG}" \
        sleep infinity

    log_success "container started and mounted at /build"
}

stop_container() {
    log_info "stopping container: ${CONTAINER_NAME}"
    podman stop "${CONTAINER_NAME}" 2>/dev/null || true
    podman rm "${CONTAINER_NAME}" 2>/dev/null || true
    log_success "container stopped and removed"
}

exec_in_container() {
    podman exec -it "${CONTAINER_NAME}" "$@"
}

# =============================================================================
# Repository management
# =============================================================================

clone_repos() {
    log_info "cloning repositories from ${REPOS_CONFIG}"

    if [ ! -f "${REPOS_CONFIG}" ]; then
        log_error "repos.toml not found at ${REPOS_CONFIG}"
        exit 1
    fi

    mkdir -p "${WORKSPACE_DIR}"

    # Parse repos.toml and clone each repo
    local repos=($(grep '^\[repos\.' "${REPOS_CONFIG}" | sed 's/\[repos\.//;s/\]//'))

    for repo in "${repos[@]}"; do
        log_info "processing repository: ${repo}"

        local url=$(parse_toml "${REPOS_CONFIG}" "repos.${repo}" "url")
        local branch=$(parse_toml "${REPOS_CONFIG}" "repos.${repo}" "branch")
        local dest=$(parse_toml "${REPOS_CONFIG}" "repos.${repo}" "destination")
        local submodules=$(parse_toml "${REPOS_CONFIG}" "repos.${repo}" "submodules")

        if [ -z "$url" ]; then
            log_warning "no URL found for ${repo}, skipping"
            continue
        fi

        local full_dest="${SCRIPT_DIR}/${dest}"

        if [ -d "${full_dest}/.git" ]; then
            log_info "repository ${repo} already exists, pulling latest..."
            (cd "${full_dest}" && git pull origin "${branch:-master}")
        else
            log_info "cloning ${repo} from ${url}"
            mkdir -p "$(dirname "${full_dest}")"
            git clone "${url}" "${full_dest}" ${branch:+--branch "${branch}"}

            if [ "$submodules" = "true" ]; then
                log_info "initializing submodules for ${repo}"
                (cd "${full_dest}" && git submodule update --init --recursive)
            fi
        fi

        log_success "repository ${repo} ready at ${dest}"
    done

    log_success "all repositories cloned"
}

update_repos() {
    log_info "updating all repositories"

    find "${WORKSPACE_DIR}" -name ".git" -type d | while read -r git_dir; do
        repo_dir=$(dirname "${git_dir}")
        log_info "updating $(basename "${repo_dir}")"
        (cd "${repo_dir}" && git pull)
    done

    log_success "all repositories updated"
}

# =============================================================================
# Build orchestration
# =============================================================================

build_os() {
    local profile=${1:-release}

    log_info "building strat9-os (profile: ${profile})"

    # Check if container is running
    if ! podman ps --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
        log_error "container ${CONTAINER_NAME} is not running"
        log_info "run: $0 start"
        exit 1
    fi

    # Launch build inside container
    log_info "executing build inside container..."
    exec_in_container cargo make build-all

    log_success "build completed successfully"
    log_info "bootable image: build/strat9-os.iso"
}

run_qemu() {
    log_info "launching QEMU with strat9-os"

    if [ ! -f "${BUILD_DIR}/strat9-os.iso" ]; then
        log_error "ISO not found at ${BUILD_DIR}/strat9-os.iso"
        log_info "run: $0 build first"
        exit 1
    fi

    exec_in_container cargo make run
}

clean_build() {
    log_info "cleaning build artifacts"
    rm -rf "${BUILD_DIR}"/*
    rm -rf "${WORKSPACE_DIR}/target"
    log_success "build cleaned"
}

# =============================================================================
# Usage
# =============================================================================

usage() {
    cat <<EOF
builder.sh - strat9-os build orchestrator

USAGE:
    $0 <command> [options]

COMMANDS:
    setup           Clone all repositories and build container
    clone           Clone/update all repositories from repos.toml
    update          Update all cloned repositories (git pull)

    build-container Build the podman container
    start           Start persistent build container
    stop            Stop persistent build container
    shell           Open a shell inside the container

    build [profile] Build strat9-os (default: release)
    run             Build and run in QEMU
    clean           Clean build artifacts

    help            Show this help message

EXAMPLES:
    # First time setup
    $0 setup

    # Build and run
    $0 build
    $0 run

    # Development workflow
    $0 start           # Start container once
    $0 build debug     # Fast debug builds
    $0 shell           # Interactive debugging
    $0 stop            # When done

CONTAINER:
    Name: ${CONTAINER_NAME}
    Config: repos.toml
    Workspace: workspace/

EOF
}

# =============================================================================
# Main
# =============================================================================

main() {
    local command=${1:-help}

    case "$command" in
        setup)
            build_container
            start_container
            clone_repos
            log_success "setup complete! Run: $0 build"
            ;;

        clone)
            clone_repos
            ;;

        update)
            update_repos
            ;;

        build-container)
            build_container
            ;;

        start)
            start_container
            ;;

        stop)
            stop_container
            ;;

        shell)
            exec_in_container /bin/bash
            ;;

        build)
            build_os "${2:-release}"
            ;;

        run)
            run_qemu
            ;;

        clean)
            clean_build
            ;;

        help|--help|-h)
            usage
            ;;

        *)
            log_error "unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

main "$@"
