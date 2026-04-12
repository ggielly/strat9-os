#!/bin/bash

# Script to download and setup Limine bootloader
# Uses git clone of the binary branch for prebuilt binaries

set -e

LIMINE_BRANCH="v8.x-binary"
BUILD_DIR="build"
LIMINE_DIR="$BUILD_DIR/limine"

echo "=== Setting up Limine Bootloader ==="

# Create build directory
mkdir -p "$BUILD_DIR"

# Clone Limine binary branch if not already present
if [ ! -d "$LIMINE_DIR" ]; then
    echo "Cloning Limine $LIMINE_BRANCH binary distribution..."
    
    if git clone https://github.com/limine-bootloader/limine.git --branch="$LIMINE_BRANCH" --depth=1 "$LIMINE_DIR"; then
        echo "  Cloned successfully"
    else
        echo "  ERROR: Failed to clone Limine"
        echo "  Try manually: git clone https://github.com/limine-bootloader/limine.git --branch=$LIMINE_BRANCH --depth=1 $LIMINE_DIR"
        exit 1
    fi
else
    echo "Limine directory already exists, skipping clone."
fi

# Check for required files
required_files=(
    "limine-bios.sys"
    "limine-bios-cd.bin"
    "limine-uefi-cd.bin"
)

all_found=true
for file in "${required_files[@]}"; do
    if [ -f "$LIMINE_DIR/$file" ]; then
        echo "  [OK] $file"
    else
        echo "  [MISSING] $file"
        all_found=false
    fi
done

# Build limine host utility (limine.exe) if make is available
if [ ! -f "$LIMINE_DIR/limine.exe" ] && [ ! -f "$LIMINE_DIR/limine" ]; then
    echo "Building limine host utility..."
    
    # Try with make
    if command -v make >/dev/null 2>&1; then
        (cd "$LIMINE_DIR" && make) >/dev/null 2>&1
        if [ -f "$LIMINE_DIR/limine.exe" ]; then
            echo "  [OK] limine.exe built"
        elif [ -f "$LIMINE_DIR/limine" ]; then
            echo "  [OK] limine utility built"
        fi
    elif command -v gcc >/dev/null 2>&1; then
        gcc -g -O2 -pipe -Wall -Wextra -std=c99 "$LIMINE_DIR/limine.c" -o "$LIMINE_DIR/limine.exe" >/dev/null 2>&1
        if [ -f "$LIMINE_DIR/limine.exe" ]; then
            echo "  [OK] limine.exe compiled"
        fi
    else
        echo "  [WARN] Cannot build limine utility (no make/gcc found)"
        echo "  BIOS boot may not work without limine bios-install"
    fi
fi

if [ "$all_found" = true ]; then
    echo ""
    echo "Limine setup complete!"
    echo "  Location: $LIMINE_DIR"
else
    echo ""
    echo "WARNING: Some Limine files are missing."
    echo "  Try re-cloning: rm -rf $LIMINE_DIR; then run this script again"
fi