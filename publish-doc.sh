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
# NAT Proxmox : 22 = hote Proxmox lui-meme, 2222 = VM GitLab,
# 80/443 -> CT edge-nginx (10.10.10.10). L'ancien 32222 est ferme.
# On expose donc le CT via 2223 -> 10.10.10.10:22 (voir nftables sur Proxmox).
# VHOST_SSH_PORT surcharge le Port du ~/.ssh/config.
VHOST_SSH_PORT="${VHOST_SSH_PORT:-2223}"
VHOST_REMOTE_PATH="${VHOST_REMOTE_PATH:-/var/www/ram_strat9/api.strat9-os.org/public}"

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
  VHOST_SSH_PORT      SSH port, overrides ssh_config (default: 2223 -> CT edge-nginx:22; old 32222 is closed)
  VHOST_REMOTE_PATH   Remote path on the vhost (default: /var/www/ram_strat9/api.strat9-os.org/public)

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
  echo "==> Deploying to ${VHOST_SSH_ALIAS}:${VHOST_REMOTE_PATH} (ssh port ${VHOST_SSH_PORT})"
  if [[ ! -d "build/docs-site" ]]; then
    echo "Error: build/docs-site/ missing (cargo make docs-site failed?)" >&2
    exit 1
  fi
  # -p overrides a stale Port in ~/.ssh/config (ex: 32222 ferme depuis la migration)
  SSH_BASE=(ssh -p "${VHOST_SSH_PORT}" -o BatchMode=yes -o ConnectTimeout=10)
  RSYNC_SSH="ssh -p ${VHOST_SSH_PORT} -o BatchMode=yes -o ConnectTimeout=10"
  SSH_ERR="$(mktemp)"
  if ! "${SSH_BASE[@]}" "${VHOST_SSH_ALIAS}" exit 2>"${SSH_ERR}"; then
    echo "Error: unable to join '${VHOST_SSH_ALIAS}' (port ${VHOST_SSH_PORT}) : vhost deployment FAILED." >&2
    echo "--- ssh diagnostic ---" >&2
    cat "${SSH_ERR}" >&2
    # Diagnostic best-effort : DNS vs TCP vs auth
    VHOST_HOSTNAME="$(ssh -G "${VHOST_SSH_ALIAS}" 2>/dev/null | awk '/^hostname /{print $2; exit}')"
    if [[ -n "${VHOST_HOSTNAME:-}" ]]; then
      echo "ssh_config hostname: ${VHOST_HOSTNAME}" >&2
      if ! getent hosts "${VHOST_HOSTNAME}" >/dev/null 2>&1; then
        echo "-> DNS ne resout pas ${VHOST_HOSTNAME} (piste migration DNS)." >&2
      else
        echo "-> DNS OK: $(getent hosts "${VHOST_HOSTNAME}" | head -n 1)" >&2
      fi
      if ! timeout 5 bash -c "</dev/tcp/${VHOST_HOSTNAME}/${VHOST_SSH_PORT}" 2>/dev/null; then
        echo "-> TCP ${VHOST_HOSTNAME}:${VHOST_SSH_PORT} refuse/ferme (firewall ou NAT post-migration ? port 32222 historique ferme, 22 ouvert)." >&2
      else
        echo "-> TCP OK, donc echec d'authentification : verifiez" >&2
        echo "   1) ~/.ssh/config : Port ${VHOST_SSH_PORT} (plus 32222), HostName a jour" >&2
        echo "   2) cle publique re-deployeee sur le nouveau vhost (authorized_keys vide apres migration ?)" >&2
        echo "      cles locales : $(ssh-add -l 2>/dev/null | cut -d' ' -f3- | tr '\n' ' ')" >&2
        echo "   3) VHOST_SSH_PORT / VHOST_SSH_ALIAS si le vhost a change" >&2
      fi
    fi
    rm -f "${SSH_ERR}"
    echo "Deploiement annule. Relancez avec --no-vhost-upload pour ignorer, ou corrigez le SSH." >&2
    exit 1
  fi
  rm -f "${SSH_ERR}"
  "${SSH_BASE[@]}" "${VHOST_SSH_ALIAS}" "mkdir -p '${VHOST_REMOTE_PATH}'"
  rsync -az --delete --checksum \
    -e "${RSYNC_SSH}" \
    "build/docs-site/" \
    "${VHOST_SSH_ALIAS}:${VHOST_REMOTE_PATH}/"
  echo "==> Documentation deployed to ${VHOST_SSH_ALIAS}:${VHOST_REMOTE_PATH}"
else
  echo "==> Vhost deployment skipped (--no-vhost-upload)"
fi

echo "Done."
