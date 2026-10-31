#!/usr/bin/env bash
# Diagnostique la chaîne Bluetooth à partir d'un log série / debugcon.
#
#   ./diagnose.sh build/qemu-debugcon.log
#   dmesg | ./diagnose.sh -
#
# Le script ne teste pas la radio : il dit où la chaîne s'arrête dans l'OS.
set -u

log=${1:-}
if [ -z "$log" ]; then
    echo "usage: $0 <log-file|->" >&2
    exit 2
fi

tmp=
if [ "$log" = "-" ]; then
    tmp=$(mktemp)
    cat >"$tmp"
    log=$tmp
    trap 'rm -f "$tmp"' EXIT
fi
if [ ! -r "$log" ]; then
    echo "log illisible: $log" >&2
    exit 2
fi

has() { grep -aqE "$1" "$log"; }

echo "== lignes USB / Bluetooth =="
grep -aE '\[USB\]|\[xHCI\]|\[USB-BT\]|\[USB-HID\]|/dev/bt|strate-bt' "$log" \
    | tail -n 60 || true
echo
echo "== verdict =="

if ! has 'Initializing USB subsystem'; then
    echo "USB : le sous-système USB n'a pas démarré."
    echo "      → la tâche QEMU utilisée n'attache probablement aucun contrôleur"
    echo "        USB (ex. run-gui-smp-release), ou l'image bootée est ancienne."
    exit 1
fi

if ! has '\[xHCI\] Found [1-9]'; then
    echo "xHCI : aucun contrôleur initialisé."
    echo "      → ajouter -device qemu-xhci (tâches run-gui-smp-dev-opt /"
    echo "        run-uefi-gui), ou vérifier le port PCI sur matériel réel."
    exit 1
fi
echo "xHCI : contrôleur présent."

if has '\[USB-BT\] Attached'; then
    echo "HCI : dongle Bluetooth attaché, endpoints configurés."
elif has '\[USB-HID\] Non-HID device.*class=e0'; then
    echo "HCI : dongle vu sur EHCI/UHCI."
    echo "      → le transport Bluetooth est xHCI uniquement : brancher sur un"
    echo "        port racine xHCI (pas de hub, pas de EHCI/UHCI)."
    exit 1
elif has '\[USB-BT\] Probing'; then
    echo "HCI : device sondé mais pas d'interface E0/01/01 exploitable."
    echo "      → regarder les warnings [USB-BT] juste au-dessus (descripteur"
    echo "        tronqué, endpoints manquants, setup_endpoint en échec)."
    exit 1
else
    echo "HCI : aucun dongle Bluetooth énuméré."
    if has '\[USB\] dev .*class=00/00/00'; then
        echo "      → des devices class 0x00 existent mais pas d'interface HCI."
    fi
    echo "      → sous QEMU c'est normal : aucun dongle BT n'est émulé."
    echo "        Passer un dongle USB réel en usb-host, ou tester sur matériel."
    exit 1
fi

if ! has '\[VFS\] Mounted /dev/bt|Registered bt scheme'; then
    echo "/dev/bt : schéma non monté (mount trop tôt ?). Voir [VFS]."
    exit 1
fi
echo "/dev/bt : monté."

if ! has '\[strate-bt\] starting'; then
    echo "strate-bt : non démarrée."
    echo "      → vérifier silo.toml, tools/uefi-modules.manifest et que"
    echo "        cargo make uefi-image a bien reconstruit strate-bt-release."
    exit 1
fi

if ! has '\[strate-bt\] device opened'; then
    echo "strate-bt : démarrée, en attente de /dev/bt/hci0."
    echo "      → le transport n'est pas prêt (voir verdict HCI ci-dessus)."
    exit 1
fi

echo "strate-bt : transport ouvert."
if has 'Realtek RTL8761BU firmware ready'; then
    echo "firmware : patch RTL8761BU chargé."
elif has 'Realtek: /initfs/rtl8761bu_fw.bin missing'; then
    echo "firmware : blob absent de l'initfs."
    echo "      → copier rtl8761bu_fw.bin / rtl8761bu_config.bin dans"
    echo "        workspace/assets/firmware/ puis reconstruire l'image."
    exit 1
elif has 'no Realtek firmware loaded'; then
    echo "firmware : pas de patch Realtek (contrôleur non-Realtek ou échec)."
fi
if has 'LE advertising enable failed'; then
    echo "advertising : LE Set Advertising Enable a échoué."
    echo "      → firmware absent/incompatible, ou radio désactivée par le BIOS/EC."
    exit 1
fi

echo "strate-bt : advertising lancé."
echo
echo "Côté Windows, si rien n'apparaît :"
echo "  - service Bluetooth actif (bthserv) et adaptateur présent ;"
echo "  - client Python sur le PC Windows, pas dans une VM sans passthrough ;"
echo "  - firmware du dongle : la plupart des Intel/Realtek/Broadcom en exigent un."
echo "Verdict global : chaîne OS complète jusqu'à l'advertising."
