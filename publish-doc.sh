#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

NO_COMMIT=0
NO_PUSH=0
NO_DISPATCH=0
STAGE_ALL=0
COMMIT_MSG="docs: update published documentation"
REMOTE_NAME="${REMOTE_NAME:-origin}"
PAGES_REPO="${PAGES_REPO:-ggielly/ggielly.github.io}"
PAGES_BRANCH="${PAGES_BRANCH:-main}"
PAGES_SUBDIR="${PAGES_SUBDIR:-strat9-os-docs}"
NO_PAGES_UPLOAD=0
NO_VHOST_UPLOAD=0
VHOST_SSH_ALIAS="${VHOST_SSH_ALIAS:-strat9web}"
VHOST_REMOTE_PATH="${VHOST_REMOTE_PATH:-/usr/local/www/strat9/api.strat9-os.org/public}"

usage() {
  cat <<'EOF'
Usage: ./publish-doc.sh [options]

Options:
  --no-commit         Build docs, but do not create a git commit
  --no-push           Build/commit, but do not push to remote
  --no-dispatch       Do not trigger the GitHub Actions workflow manually
  --no-pages-upload   Do not upload docs to github.io repository
  --no-vhost-upload   Do not upload docs to remote vhost via SSH
  --all-changes       Stage all changes (git add -A) before commit
  -m, --message MSG   Commit message (default: docs: update published documentation)
  -h, --help          Show this help

Environment:
  REMOTE_NAME         Git remote to push (default: origin)
  PAGES_REPO          Target pages repository (default: ggielly/ggielly.github.io)
  PAGES_BRANCH        Target pages branch (default: main)
  PAGES_SUBDIR        Target docs directory in pages repo (default: strat9-os-docs)
  VHOST_SSH_ALIAS     SSH alias for the remote vhost (default: strat9web)
  VHOST_REMOTE_PATH   Remote path on the vhost (default: /usr/local/www/strat9/api.strat9-os.org/public)

Examples:
  ./publish-doc.sh
  ./publish-doc.sh -m "docs: refresh ABI reference"
  ./publish-doc.sh --all-changes
  ./publish-doc.sh --no-pages-upload
  ./publish-doc.sh --no-dispatch
  ./publish-doc.sh --no-vhost-upload
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-commit)
      NO_COMMIT=1
      shift
      ;;
    --no-push)
      NO_PUSH=1
      shift
      ;;
    --no-dispatch)
      NO_DISPATCH=1
      shift
      ;;
    --all-changes)
      STAGE_ALL=1
      shift
      ;;
    --no-pages-upload)
      NO_PAGES_UPLOAD=1
      shift
      ;;
    --no-vhost-upload)
      NO_VHOST_UPLOAD=1
      shift
      ;;
    -m|--message)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for $1" >&2
        exit 1
      fi
      COMMIT_MSG="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required but not found in PATH." >&2
  exit 1
fi

echo "==> Building docs website"
cargo make docs-site

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
REPO_FULL_NAME="$(gh repo view --json nameWithOwner -q .nameWithOwner)"

if [[ "${NO_COMMIT}" -eq 0 ]]; then
  echo "==> Staging changes"
  if [[ "${STAGE_ALL}" -eq 1 ]]; then
    git add -A
  else
    git add \
      docs-site \
      tools/scripts/build-docs-site.sh \
      .github/workflows/publish-docs.yml \
      publish-doc.sh \
      Makefile.toml
  fi

  if ! git diff --cached --quiet; then
    echo "==> Creating commit"
    git commit -m "${COMMIT_MSG}"
  else
    echo "==> No staged changes to commit"
  fi
else
  echo "==> Skipping commit (--no-commit)"
fi

if [[ "${NO_PUSH}" -eq 0 ]]; then
  echo "==> Pushing branch ${BRANCH} to ${REMOTE_NAME}"
  git push "${REMOTE_NAME}" "${BRANCH}"
else
  echo "==> Skipping push (--no-push)"
fi

if [[ "${NO_DISPATCH}" -eq 0 ]]; then
  echo "==> Triggering workflow: Publish Docs"
  gh workflow run "Publish Docs" --ref "${BRANCH}" || {
    echo "Warning: workflow dispatch failed (check workflow name/permissions)." >&2
  }
else
  echo "==> Skipping workflow dispatch (--no-dispatch)"
fi

if [[ "${NO_PAGES_UPLOAD}" -eq 0 ]]; then
  echo "==> Uploading docs to ${PAGES_REPO}/${PAGES_SUBDIR} (${PAGES_BRANCH})"
  TMP_DIR="$(mktemp -d)"
  cleanup() { rm -rf "${TMP_DIR}"; }
  trap cleanup EXIT

  git clone --depth 1 "https://github.com/${PAGES_REPO}.git" "${TMP_DIR}/pages"
  pushd "${TMP_DIR}/pages" >/dev/null
  git checkout "${PAGES_BRANCH}" >/dev/null 2>&1 || git checkout -b "${PAGES_BRANCH}"
  popd >/dev/null
  mkdir -p "${TMP_DIR}/pages/${PAGES_SUBDIR}"
  rsync -a --delete "build/docs-site/" "${TMP_DIR}/pages/${PAGES_SUBDIR}/"

  pushd "${TMP_DIR}/pages" >/dev/null
  README_FILE="README.md"
  DOCS_URL="https://ggielly.github.io/${PAGES_SUBDIR}/"
  README_MARK_START="<!-- AUTO-STRAT9-DOCS:START -->"
  README_MARK_END="<!-- AUTO-STRAT9-DOCS:END -->"

  if [[ ! -f "${README_FILE}" ]]; then
    cat > "${README_FILE}" <<EOF
# ggielly.github.io

${README_MARK_START}
## Documentation Strat9 OS

- ${DOCS_URL}
${README_MARK_END}
EOF
  elif ! grep -q "${README_MARK_START}" "${README_FILE}"; then
    cat >> "${README_FILE}" <<EOF

${README_MARK_START}
## Documentation Strat9 OS

- ${DOCS_URL}
${README_MARK_END}
EOF
  else
    python3 - "${README_FILE}" "${DOCS_URL}" <<'PY'
import re
import sys
from pathlib import Path

readme = Path(sys.argv[1])
docs_url = sys.argv[2]
text = readme.read_text(encoding="utf-8")
start = "<!-- AUTO-STRAT9-DOCS:START -->"
end = "<!-- AUTO-STRAT9-DOCS:END -->"
pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.S)
replacement = f"{start}\n## Documentation Strat9 OS\n\n- {docs_url}\n{end}"
new_text, n = pattern.subn(replacement, text, count=1)
if n != 1:
    raise SystemExit("failed to update AUTO-STRAT9-DOCS block in README.md")
readme.write_text(new_text, encoding="utf-8")
PY
  fi

  git add "${PAGES_SUBDIR}" "${README_FILE}"
  if ! git diff --cached --quiet; then
    git commit -m "docs: publish ${PAGES_SUBDIR} from ${REPO_FULL_NAME}@${BRANCH}"
    git push origin "${PAGES_BRANCH}"
    echo "==> Uploaded to https://github.com/${PAGES_REPO}/tree/${PAGES_BRANCH}/${PAGES_SUBDIR}"
  else
    echo "==> No changes to upload in ${PAGES_SUBDIR}"
  fi
  popd >/dev/null
else
  echo "==> Skipping github.io upload (--no-pages-upload)"
fi

if [[ "${NO_VHOST_UPLOAD}" -eq 0 ]]; then
  echo "==> Déploiement vers ${VHOST_SSH_ALIAS}:${VHOST_REMOTE_PATH}"
  if ! ssh -q -o BatchMode=yes -o ConnectTimeout=5 "${VHOST_SSH_ALIAS}" exit 2>/dev/null; then
    echo "Warning: impossible de joindre '${VHOST_SSH_ALIAS}' — déploiement vhost ignoré." >&2
  else
    ssh "${VHOST_SSH_ALIAS}" "mkdir -p '${VHOST_REMOTE_PATH}'"
    rsync -az --delete --checksum \
      -e ssh \
      "build/docs-site/" \
      "${VHOST_SSH_ALIAS}:${VHOST_REMOTE_PATH}/"
    echo "==> Documentation déployée sur ${VHOST_SSH_ALIAS}:${VHOST_REMOTE_PATH}"
  fi
else
  echo "==> Déploiement vhost ignoré (--no-vhost-upload)"
fi

PAGES_URL="$(gh api "repos/${REPO_FULL_NAME}/pages" -q .html_url 2>/dev/null || true)"
if [[ -n "${PAGES_URL}" ]]; then
  echo "==> GitHub Pages URL: ${PAGES_URL}"
else
  echo "==> GitHub Pages URL unavailable (Pages may not be enabled yet)."
fi

echo "==> Direct docs URL: https://ggielly.github.io/${PAGES_SUBDIR}/"

echo "Done."
