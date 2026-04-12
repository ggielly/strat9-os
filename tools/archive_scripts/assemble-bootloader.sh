#!/bin/bash

# =====================================================================
# Assemble strat9-os bootloader (NASM)
# =====================================================================

set -e

echo ""
echo "=== Assemblage du bootloader ==="
echo ""

# Créer le dossier build
mkdir -p "build"

# Assembler stage1.asm (qui inclut stage2.asm)
asm_dir="bootloader/asm/x86_64"
output="build/boot.bin"

echo "  Assemblage de $asm_dir/stage1.asm..."

nasm -f bin -I"$asm_dir/" -o "$output" "$asm_dir/stage1.asm"

if [ $? -ne 0 ]; then
    echo "NASM failed to assemble bootloader"
    exit 1
fi

size=$(stat -c%s "$output")
sectors=$(( (size + 511) / 512 ))

echo "  [OK] Bootloader assemblé : boot.bin"
echo "       Taille : $size bytes ($sectors secteurs)"
echo ""

exit 0
