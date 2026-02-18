# Containerfile (Podman/Docker)
# Build container for strat9-os
# Usage: podman build -t strat9-builder -f Containerfile .
#        podman run -v $(pwd):/build -it strat9-builder

FROM debian:bookworm-slim

LABEL maintainer="strat9-os team"
LABEL description="Build environment for strat9-os microkernel"
LABEL version="1.0"

# =============================================================================
# System dependencies
# =============================================================================

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    # Build essentials
    gcc \
    g++ \
    make \
    cmake \
    git \
    curl \
    wget \
    ca-certificates \
    pkg-config \
    # Assemblers
    nasm \
    yasm \
    # QEMU for testing
    qemu-system-x86 \
    # Additional tools
    xorriso \
    mtools \
    parted \
    dosfstools \
    # Debugging
    gdb \
    # Utils
    python3 \
    python3-pip \
    jq \
    tree \
    vim \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# =============================================================================
# Rust toolchain (nightly for build-std)
# =============================================================================

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain nightly \
    --profile minimal \
    --component rust-src,llvm-tools-preview,rustfmt,clippy

# =============================================================================
# Cargo tools
# =============================================================================

RUN cargo install cargo-make --version 0.37.9 && \
    cargo install cargo-binutils && \
    rustup component add rust-src llvm-tools-preview

# =============================================================================
# Limine bootloader (latest release)
# =============================================================================

WORKDIR /opt
RUN git clone https://github.com/limine-bootloader/limine.git --depth=1 --branch=v8.x-binary && \
    cd limine && \
    make

ENV PATH=/opt/limine:$PATH

# =============================================================================
# Working directory setup
# =============================================================================

WORKDIR /build

# Create expected directory structure
RUN mkdir -p workspace build targets qemu-stuff

# =============================================================================
# Entry point
# =============================================================================

# Default command: show help
CMD ["/bin/bash", "-c", "echo 'strat9-os builder container ready!' && echo 'Run: ./builder.sh --help' && /bin/bash"]
