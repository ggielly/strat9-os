#!/usr/bin/env bash
set -euo pipefail

# Build a publishable docs website that combines:
# - mdBook guide pages
# - rustdoc API reference for ABI/syscall crates

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SITE_DIR="${ROOT_DIR}/build/docs-site"
RUSTDOC_DIR="${ROOT_DIR}/target/doc"

echo "==> Building rustdoc (strat9-abi + strat9-syscall)"
cargo +nightly doc \
  --manifest-path "${ROOT_DIR}/Cargo.toml" \
  -p strat9-abi \
  -p strat9-syscall \
  --no-deps

echo "==> Building mdBook pages"
mdbook build "${ROOT_DIR}/docs-site"

echo "==> Assembling website"
rm -rf "${SITE_DIR}"
mkdir -p "${SITE_DIR}/api"
cp -r "${ROOT_DIR}/docs-site/book/." "${SITE_DIR}/"
cp -r "${RUSTDOC_DIR}/." "${SITE_DIR}/api/"

echo ""
echo "Done. Website generated at:"
echo "  ${SITE_DIR}"
echo ""
echo "Open locally with:"
echo "  python3 -m http.server --directory ${SITE_DIR} 8000"
