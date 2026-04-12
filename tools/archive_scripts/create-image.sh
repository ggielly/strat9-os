#!/bin/bash

# =====================================================================
# Create strat9 Bootable Disk Image
# =====================================================================

set -e

echo ""
echo "=== Création de l'image disque ==="
echo ""

# Chemins
build_dir="build"
disk_img="$build_dir/strat9-os.img"
boot_bin="$build_dir/boot.bin"
kernel_elf="target/x86_64-unknown-none/release/kernel"

# Vérifier que les fichiers existent
if [ ! -f "$boot_bin" ]; then
    echo "Bootloader not found: $boot_bin"
    echo "Run 'cargo make assemble-bootloader' first."
    exit 1
fi

if [ ! -f "$kernel_elf" ]; then
    echo "Kernel not found: $kernel_elf"
    echo "Run 'cargo make kernel' first."
    exit 1
fi

# Copier le kernel dans build/
cp "$kernel_elf" "$build_dir/kernel.elf"

# Tailles
boot_size=$(stat -c%s "$boot_bin")
kernel_size=$(stat -c%s "$kernel_elf")
boot_sectors=$(( (boot_size + 511) / 512 ))

echo "  Composants :"
echo "    Bootloader : $boot_size bytes ($boot_sectors secteurs)"
echo "    Kernel     : $kernel_size bytes"
echo ""

# Créer une image disque de 64 MB
disk_size=$((64 * 1024 * 1024))
dd if=/dev/zero of="$disk_img" bs=1M count=64 >/dev/null 2>&1

# Écrire le bootloader au début
dd if="$boot_bin" of="$disk_img" bs=512 conv=notrunc >/dev/null 2>&1

# Écrire le kernel au secteur 17 (offset 8704)
kernel_offset=$((17 * 512))
dd if="$kernel_elf" of="$disk_img" bs=1 seek="$kernel_offset" conv=notrunc >/dev/null 2>&1

echo "============================================"
echo "  Image disque bootable créée !"
echo "============================================"
echo ""
echo "  Fichier : build/strat-os.img (64 MB)"
echo ""
echo "  Layout :"
echo "    - Secteur  0     : Bootloader stage1 (MBR)"
echo "    - Secteurs 1-16  : Bootloader stage2 (8KB)"
echo "    - Secteur  17+   : Kernel ELF ($kernel_size bytes)"
echo ""
echo "--------------------------------------------"
echo "  Lancer avec : cargo make run-gui"
echo "============================================"
echo ""

exit 0
