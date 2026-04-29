#!/usr/bin/env bash
# builder-native.sh
# Native host build orchestration for strat9-os (without containers)
# Runs all build operations directly on the host machine

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOS_CONFIG="${SCRIPT_DIR}/repos.toml"
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
# Dependency checking
# =============================================================================

check_dependencies() {
    log_info "checking host dependencies..."

    local missing=()

    # Build essentials
    command -v gcc >/dev/null 2>&1 || missing+=("gcc")
    command -v g++ >/dev/null 2>&1 || missing+=("g++")
    command -v make >/dev/null 2>&1 || missing+=("make")
    command -v cmake >/dev/null 2>&1 || missing+=("cmake")
    command -v git >/dev/null 2>&1 || missing+=("git")
    command -v curl >/dev/null 2>&1 || missing+=("curl")

    # Assemblers
    command -v nasm >/dev/null 2>&1 || missing+=("nasm")
    command -v yasm >/dev/null 2>&1 || missing+=("yasm")

    # QEMU
    command -v qemu-system-x86_64 >/dev/null 2>&1 || missing+=("qemu-system-x86")

    # ISO creation tools
    command -v xorriso >/dev/null 2>&1 || missing+=("xorriso")
    command -v mtools >/dev/null 2>&1 || missing+=("mtools")

    # Rust toolchain
    if ! command -v rustc >/dev/null 2>&1; then
        missing+=("rust")
    else
        # Check for nightly
        if ! rustc --version | grep -q "nightly"; then
            log_warning "rust nightly not detected as default"
        fi

        # Check for rust-src component
        if ! rustup component list --installed 2>/dev/null | grep -q "rust-src"; then
            log_warning "rust-src component not installed"
            log_info "run: rustup component add rust-src llvm-tools-preview"
        fi
    fi

    # Cargo tools
    command -v cargo-make >/dev/null 2>&1 || log_warning "cargo-make not installed (optional)"

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "missing required dependencies: ${missing[*]}"
        log_info ""
        log_info "to install on Debian/Ubuntu:"
        log_info "  sudo apt-get install gcc g++ make cmake git curl nasm yasm \\"
        log_info "    qemu-system-x86 xorriso mtools parted dosfstools gdb \\"
        log_info "    python3 python3-pip pkg-config ca-certificates"
        log_info ""
        log_info "to install Rust:"
        log_info "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        log_info "  rustup default nightly"
        log_info "  rustup component add rust-src llvm-tools-preview"
        log_info ""
        log_info "to install cargo tools:"
        log_info "  cargo install cargo-make cargo-binutils"
        exit 1
    fi

    log_success "all required dependencies found"
}

# =============================================================================
# Limine bootloader setup
# =============================================================================

setup_limine() {
    local limine_dir="${SCRIPT_DIR}/limine"

    if [ -d "${limine_dir}" ]; then
        log_info "limine bootloader already present at ${limine_dir}"
        return 0
    fi

    log_info "cloning and building limine bootloader..."

    git clone https://github.com/limine-bootloader/limine.git \
        --depth=1 --branch=v8.x-binary "${limine_dir}"

    (cd "${limine_dir}" && make)

    log_success "limine bootloader ready"
    log_info "add to PATH: export PATH=\"${limine_dir}:\$PATH\""
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

    find "${WORKSPACE_DIR}" -name ".git" -type d 2>/dev/null | while read -r git_dir; do
        repo_dir=$(dirname "${git_dir}")
        log_info "updating $(basename "${repo_dir}")"
        (cd "${repo_dir}" && git pull)
    done

    log_success "all repositories updated"
}

# =============================================================================
# Workspace setup
# =============================================================================

setup_workspace_links() {
    log_info "checking workspace structure..."

    # Check if workspace exists and has content
    if [ ! -d "${WORKSPACE_DIR}" ]; then
        log_error "workspace directory not found"
        log_info "run: $0 clone first to clone repositories"
        return 1
    fi

    # No symlinks needed - we use workspace/* paths directly
    log_success "workspace structure verified"
}

setup_build_scripts() {
    log_info "setting up build scripts..."

    # Create tools/scripts directory if needed
    mkdir -p "${SCRIPT_DIR}/tools/scripts"

    # Create setup-limine.sh script if it doesn't exist
    if [ ! -f "${SCRIPT_DIR}/tools/scripts/setup-limine.sh" ]; then
        log_info "creating setup-limine.sh script..."
        cat > "${SCRIPT_DIR}/tools/scripts/setup-limine.sh" <<'LIMINESCRIPT'
#!/usr/bin/env bash
# Setup Limine bootloader

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIMINE_DIR="${SCRIPT_DIR}/limine"

if [ -d "${LIMINE_DIR}" ]; then
    echo "Limine already present at ${LIMINE_DIR}"
    exit 0
fi

echo "Cloning Limine bootloader..."
git clone https://github.com/limine-bootloader/limine.git \
    --depth=1 --branch=v8.x-binary "${LIMINE_DIR}"

echo "Building Limine..."
cd "${LIMINE_DIR}" && make

echo "Limine ready!"
LIMINESCRIPT
        chmod +x "${SCRIPT_DIR}/tools/scripts/setup-limine.sh"
    fi

    log_success "build scripts ready"
}

# =============================================================================
# Build orchestration
# =============================================================================

build_os() {
    local profile=${1:-release}

    log_info "building strat9-os (profile: ${profile}) [NATIVE MODE]"

    # Ensure workspace is properly set up
    setup_workspace_links
    setup_build_scripts

    # Ensure Limine is in PATH
    export PATH="${SCRIPT_DIR}/limine:$PATH"

    # Check if workspace has content
    if [ ! -d "${WORKSPACE_DIR}/kernel" ]; then
        log_error "kernel directory not found in workspace"
        log_info "run: $0 clone first to clone repositories"
        exit 1
    fi

    # Check if Makefile.toml exists
    if [ ! -f "${SCRIPT_DIR}/Makefile.toml" ]; then
        log_error "Makefile.toml not found"
        log_info "ensure you have cloned all repositories first"
        exit 1
    fi

    # Launch build natively
    log_info "executing native build..."
    cd "${SCRIPT_DIR}"

    if command -v cargo-make >/dev/null 2>&1; then
        cargo make build-all
    else
        log_warning "cargo-make not found, using cargo build directly"
        cargo build --release --target x86_64-unknown-none
    fi

    log_success "build completed successfully"
    log_info "bootable image: build/strat9-os.iso"
}

run_qemu() {
    log_info "launching QEMU with strat9-os [NATIVE MODE]"

    if [ ! -f "${BUILD_DIR}/strat9-os.iso" ]; then
        log_error "ISO not found at ${BUILD_DIR}/strat9-os.iso"
        log_info "run: $0 build first"
        exit 1
    fi

    if command -v cargo-make >/dev/null 2>&1; then
        cargo make run
    else
        log_info "running QEMU directly..."
        qemu-system-x86_64 \
            -machine q35 \
            -m 256M \
            -cdrom "${BUILD_DIR}/strat9-os.iso" \
            -serial stdio \
            -display none \
            -no-reboot
    fi
}

clean_build() {
    log_info "cleaning build artifacts"
    rm -rf "${BUILD_DIR}"/*
    rm -rf "${WORKSPACE_DIR}/target"
    log_success "build cleaned"
}

# =============================================================================
# Environment setup
# =============================================================================

setup_environment() {
    log_info "setting up native build environment..."

    # Check dependencies first
    check_dependencies

    # Clone repositories
    clone_repos

    # Setup Limine
    setup_limine

    # Setup workspace links and scripts
    setup_workspace_links
    setup_build_scripts

    # Create directory structure
    mkdir -p "${WORKSPACE_DIR}" "${BUILD_DIR}" targets qemu-stuff

    log_success "native environment setup complete!"
    log_info ""
    log_info "next steps:"
    log_info "  1. Add limine to PATH: export PATH=\"${SCRIPT_DIR}/limine:\$PATH\""
    log_info "  2. Build the OS: $0 build"
    log_info "  3. Run in QEMU: $0 run"
}

show_info() {
    log_info "native build environment information"
    log_info ""
    log_info "mode: NATIVE (no container)"
    log_info "workspace: ${WORKSPACE_DIR}"
    log_info "build output: ${BUILD_DIR}"
    log_info ""
    log_info "rust toolchain:"
    rustc --version 2>/dev/null || echo "  not installed"
    cargo --version 2>/dev/null || echo "  not installed"
    log_info ""
    log_info "key tools:"
    for tool in gcc g++ nasm yasm qemu-system-x86_64 xorriso cargo-make; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf "  %-20s %s\n" "$tool" "$(command -v "$tool")"
        else
            printf "  %-20s %s\n" "$tool" "NOT FOUND"
        fi
    done
}

# =============================================================================
# Usage
# =============================================================================

usage() {
    cat <<EOF
builder-native.sh - strat9-os native build orchestrator (no containers)

USAGE:
    $0 <command> [options]

COMMANDS:
    setup           Setup native environment (check deps, clone repos, setup limine)
    check-deps      Check if all required dependencies are installed
    info            Show information about the native build environment

    clone           Clone/update all repositories from repos.toml
    update          Update all cloned repositories (git pull)
    setup-limine    Clone and build Limine bootloader locally
    setup-links     Create symlinks from root to workspace/* for Cargo

    build [profile] Build strat9-os natively (default: release)
    run             Build and run in QEMU
    clean           Clean build artifacts

    help            Show this help message

EXAMPLES:
    # First time setup
    $0 setup

    # Check what's installed
    $0 check-deps
    $0 info

    # Build and run
    $0 build
    $0 run

    # Development workflow
    $0 build debug     # Fast debug builds
    $0 clean           # Clean when needed

ADVANTAGES:
    - No container overhead
    - Direct access to host tools
    - Faster iteration cycles
    - Easier debugging with native tools

REQUIREMENTS:
    - All build tools installed on host (gcc, rust, nasm, qemu, etc.)
    - See 'check-deps' command for full list

COMPARISON:
    builder.sh        -> Uses Podman container (isolated, reproducible)
    builder-native.sh -> Uses host tools (faster, direct)

EOF
}

# =============================================================================
# Main
# =============================================================================

main() {
    local command=${1:-help}

    case "$command" in
        setup)
            setup_environment
            ;;

        check-deps)
            check_dependencies
            ;;

        info)
            show_info
            ;;

        clone)
            clone_repos
            ;;

        update)
            update_repos
            ;;

        setup-limine)
            setup_limine
            ;;

        setup-links)
            setup_workspace_links
            setup_build_scripts
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
