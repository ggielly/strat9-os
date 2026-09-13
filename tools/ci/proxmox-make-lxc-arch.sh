#!/usr/bin/env bash
# =============================================================================
# proxmox-make-lxc-arch.sh : déploie un LXC ArchLinux minimal sur Proxmox.
# À lancer UNE FOIS sur le host Proxmox (root) : https://192.168.1.235:8006
#
#   ./tools/ci/proxmox-make-lxc-arch.sh --vmid 100 --ssh-key ~/.ssh/id_rsa.pub
#
# Tu finis l'install du template dedans (pct enter / ssh), le script s'arrête
# après le déploiement + démarrage.
#
# Options (toutes optionnelles sauf --ssh-key) :
#   --vmid 100 --hostname arch-ci --storage local-lvm --bridge vmbr0
#   --cores 2 --memory 2048 --disk 20 --ssh-key ~/.ssh/id_rsa.pub
# =============================================================================
set -euo pipefail

VMID=100
HOSTNAME="arch-ci"
STORAGE="local"
BRIDGE="vmbr0"
CORES=2
MEMORY=2048
DISK=20
SSH_KEY="$HOME/.ssh/id_rsa.pub"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --vmid) VMID="$2"; shift 2 ;;
        --hostname) HOSTNAME="$2"; shift 2 ;;
        --storage) STORAGE="$2"; shift 2 ;;
        --bridge) BRIDGE="$2"; shift 2 ;;
        --cores) CORES="$2"; shift 2 ;;
        --memory) MEMORY="$2"; shift 2 ;;
        --disk) DISK="$2"; shift 2 ;;
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        -h|--help) grep '^#' "$0"; exit 0 ;;
        *) echo "option inconnue: $1" >&2; exit 2 ;;
    esac
done

command -v pct >/dev/null || { echo "ERREUR: lance ce script sur le host Proxmox (root)." >&2; exit 2; }
[[ -f "$SSH_KEY" ]] || { echo "ERREUR: clé introuvable: $SSH_KEY (passe --ssh-key)." >&2; exit 2; }
pct status "$VMID" >/dev/null 2>&1 && { echo "ERREUR: CT $VMID existe déjà." >&2; exit 1; }

# Template ArchLinux le plus récent (téléchargé si absent).
# pveam download veut : pveam download <storage> <fichier>
# pct create veut : <storage>:vztmpl/<fichier>
pveam update >/dev/null
FILE="$(pveam available --section system 2>/dev/null | awk '$1 == "system" && /archlinux-base.*amd64/ {print $2}' | sort -V | tail -1)"
[[ -n "$FILE" ]] || { echo "ERREUR: template archlinux introuvable via pveam." >&2; exit 1; }
pveam list "$STORAGE" 2>/dev/null | grep -q "$FILE" || pveam download "$STORAGE" "$FILE"
TEMPLATE="$STORAGE:vztmpl/$FILE"

echo "==> Création CT $VMID ($HOSTNAME) depuis $TEMPLATE"
pct create "$VMID" "$TEMPLATE" \
    --hostname "$HOSTNAME" \
    --storage "$STORAGE" --rootfs "$STORAGE:$DISK" \
    --cores "$CORES" --memory "$MEMORY" --swap 512 \
    --net0 "name=eth0,bridge=$BRIDGE,ip=dhcp" \
    --unprivileged 1 --features "nesting=1,keyctl=1" \
    --ssh-public-keys "$SSH_KEY" \
    --onboot 0 --start 0

pct start "$VMID"
echo "==> Démarré. IP :"
sleep 3
pct exec "$VMID" -- ip -brief addr || true
echo ""
echo "==> Suite : pct enter $VMID  (ou ssh root@<ip>) puis finis ton template."
