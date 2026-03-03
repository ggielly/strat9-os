#!/usr/bin/env bash
set -euo pipefail

# Build a publishable docs website that combines:
# - mdBook guide pages
# - rustdoc API reference for ABI/syscall crates

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SITE_DIR="${ROOT_DIR}/build/docs-site"
RUSTDOC_DIR="${ROOT_DIR}/target/doc"
ABI_LIB_RS="${ROOT_DIR}/workspace/abi/src/lib.rs"
ABI_CHANGELOG_MD="${ROOT_DIR}/docs-site/src/abi-changelog.md"

echo "==> Refreshing ABI changelog page"
ABI_MAJOR="$(awk -F'= ' '/^pub const ABI_VERSION_MAJOR/ {gsub(/;| /, "", $2); print $2; exit}' "${ABI_LIB_RS}")"
ABI_MINOR="$(awk -F'= ' '/^pub const ABI_VERSION_MINOR/ {gsub(/;| /, "", $2); print $2; exit}' "${ABI_LIB_RS}")"
ABI_VERSION="${ABI_MAJOR}.${ABI_MINOR}"

ABI_COMMITS="$(
  git log \
    --date=short \
    --pretty='- %ad `%h` %s' \
    -- \
    workspace/abi \
    workspace/components/syscall \
    workspace/kernel/src/syscall \
    | sed -n '1,30p'
)"

if [[ -z "${ABI_COMMITS}" ]]; then
  ABI_COMMITS="- No ABI-related commit found yet."
fi

ABI_AUTO_BLOCK="$(cat <<EOF
## Current version

- \`ABI_VERSION_MAJOR = ${ABI_MAJOR}\`
- \`ABI_VERSION_MINOR = ${ABI_MINOR}\`
- Packed: \`${ABI_VERSION}\`

See:

- [crate root constants](./api/strat9_abi/index.html)
- [syscall numbers](./api/strat9_abi/syscall/index.html)
- [ABI data structs](./api/strat9_abi/data/index.html)

## Recent ABI updates (auto-generated)

${ABI_COMMITS}

EOF
)"

printf "%s" "${ABI_AUTO_BLOCK}" > /tmp/abi-auto-block.txt
python3 - "${ABI_CHANGELOG_MD}" "/tmp/abi-auto-block.txt" <<'PY'
import re
import sys
from pathlib import Path

md_path = Path(sys.argv[1])
auto_path = Path(sys.argv[2])
text = md_path.read_text(encoding="utf-8")
auto = auto_path.read_text(encoding="utf-8").rstrip()
start = "<!-- AUTO-ABI-CHANGELOG:START -->"
end = "<!-- AUTO-ABI-CHANGELOG:END -->"
pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.S)
replacement = f"{start}\n\n{auto}\n\n{end}"
new_text, n = pattern.subn(replacement, text, count=1)
if n != 1:
    raise SystemExit(f"Could not replace auto block in {md_path}")
md_path.write_text(new_text, encoding="utf-8")
PY
rm -f /tmp/abi-auto-block.txt

echo "==> Building rustdoc (workspace, resilient mode)"
METADATA_JSON="$(mktemp)"
cargo metadata \
  --manifest-path "${ROOT_DIR}/Cargo.toml" \
  --format-version 1 \
  --no-deps > "${METADATA_JSON}"

mapfile -t WORKSPACE_PACKAGES < <(
  python3 - "${METADATA_JSON}" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
id_to_name = {p["id"]: p["name"] for p in data["packages"]}
for pkg_id in data["workspace_members"]:
    print(id_to_name[pkg_id])
PY
)
rm -f "${METADATA_JSON}"

FAILED_PACKAGES=()
for pkg in "${WORKSPACE_PACKAGES[@]}"; do
  if [[ "${pkg}" == "strat9-bootloader" ]]; then
    echo "   - skipping ${pkg} (custom asm build script is not rustdoc-friendly yet)"
    continue
  fi
  echo "   - doc ${pkg}"
  if ! cargo +nightly doc \
      --manifest-path "${ROOT_DIR}/Cargo.toml" \
      -p "${pkg}" \
      --no-deps; then
    echo "     warning: rustdoc failed for ${pkg}, continuing"
    FAILED_PACKAGES+=("${pkg}")
  fi
done

if [[ "${#FAILED_PACKAGES[@]}" -gt 0 ]]; then
  echo "==> rustdoc skipped/failed packages:"
  for pkg in "${FAILED_PACKAGES[@]}"; do
    echo "   - ${pkg}"
  done
fi

echo "==> Building mdBook pages"
mdbook build "${ROOT_DIR}/docs-site"

echo "==> Assembling website"
rm -rf "${SITE_DIR}"
mkdir -p "${SITE_DIR}/api"
cp -r "${ROOT_DIR}/docs-site/book/." "${SITE_DIR}/"
cp -r "${RUSTDOC_DIR}/." "${SITE_DIR}/api/"
touch "${SITE_DIR}/.nojekyll"

echo ""
echo "Done. Website generated at:"
echo "  ${SITE_DIR}"
echo ""
echo "Open locally with:"
echo "  python3 -m http.server --directory ${SITE_DIR} 8000"
