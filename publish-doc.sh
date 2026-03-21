#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

NO_COMMIT=0
NO_PUSH=0
STAGE_ALL=0
COMMIT_MSG="docs: update published documentation"
REMOTE_NAME="${REMOTE_NAME:-origin}"
NO_VHOST_UPLOAD=0
VHOST_SSH_ALIAS="${VHOST_SSH_ALIAS:-strat9web}"
VHOST_REMOTE_PATH="${VHOST_REMOTE_PATH:-/usr/local/www/strat9/api.strat9-os.org/public}"

usage() {
  cat <<'EOF'
Usage: ./publish-doc.sh [options]

Options:
  --no-commit         Build docs, but do not create a git commit
  --no-push           Build/commit, but do not push to remote
  --no-vhost-upload   Do not upload docs to remote vhost via SSH
  --all-changes       Stage all changes (git add -A) before commit
  -m, --message MSG   Commit message (default: docs: update published documentation)
  -h, --help          Show this help

Environment:
  REMOTE_NAME         Git remote to push (default: origin)
  VHOST_SSH_ALIAS     SSH alias for the remote vhost (default: strat9web)
  VHOST_REMOTE_PATH   Remote path on the vhost (default: /usr/local/www/strat9/api.strat9-os.org/public)

Examples:
  ./publish-doc.sh
  ./publish-doc.sh -m "docs: refresh ABI reference"
  ./publish-doc.sh --all-changes
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
    --all-changes)
      STAGE_ALL=1
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

echo "==> Building docs website"
cargo make docs-site

BRANCH="$(git rev-parse --abbrev-ref HEAD)"

if [[ "${NO_COMMIT}" -eq 0 ]]; then
  echo "==> Staging changes"
  if [[ "${STAGE_ALL}" -eq 1 ]]; then
    git add -A
  else
    git add \
      docs-site \
      tools/scripts/build-docs-site.sh \
      .gitlab-ci.yml \
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

echo "Done."
