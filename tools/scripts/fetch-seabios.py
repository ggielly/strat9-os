#!/usr/bin/env python3
"""Fetches the official SeaBIOS 1.17.0 assets embedded by s9vm.

* the main BIOS is downloaded from <https://www.seabios.org/downloads/> and
  checked against the SHA-256 of both the gzip archive and the decoded binary;
* the official source archive is downloaded and checked (the VGA ROM is built
  from it, because seabios.org publishes no prebuilt VGA ROM);
* the committed SeaVGABIOS image is verified against its build hash.

Usage:
    python tools/scripts/fetch-seabios.py [--force]

The script is idempotent: a file with the expected hash is left untouched.
Building the VGA ROM is intentionally out of scope (it needs an i386-elf cross
toolchain); the build recipe is in workspace/assets/firmware/README.md.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import sys
import urllib.request

VERSION = "1.17.0"
BASE_URL = "https://www.seabios.org/downloads"

BIOS_GZ = f"bios.bin-{VERSION}.gz"
BIOS_GZ_SHA256 = "188dc9693c5e0d150bbf4403ab96755538f8518e52250db86e6f749194f44069"
BIOS_SHA256 = "fdf5d27097f3126c8708102482859f9b538e187126e79bb0da99e0b02a45cd15"
SOURCE_TAR = f"seabios-{VERSION}.tar.gz"
SOURCE_TAR_SHA256 = "5159a35fac5c1579dd5d702001033c826ce45d30d3bd657ec1b2695455997712"

VGA_NAME = f"seabios-vgabios-stdvga-{VERSION}.bin"
VGA_SHA256 = "373675d9cbb08973cf4921a6e83ac191134d2836348c29d27a738189ff73ab48"

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DESTINATION = os.path.join(ROOT, "workspace", "assets", "firmware")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download(url: str) -> bytes:
    print(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def write_if_needed(path: str, data: bytes) -> None:
    with open(path, "wb") as stream:
        stream.write(data)
    print(f"wrote: {os.path.basename(path)} ({len(data)} bytes, sha256 {sha256(data)})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force",
        action="store_true",
        help="re-download and rewrite the images even when they already match",
    )
    args = parser.parse_args()

    os.makedirs(DESTINATION, exist_ok=True)
    bios_path = os.path.join(DESTINATION, f"seabios-{VERSION}.bin")
    vga_path = os.path.join(DESTINATION, VGA_NAME)

    bios_current = False
    if not args.force and os.path.exists(bios_path):
        with open(bios_path, "rb") as stream:
            bios_current = sha256(stream.read()) == BIOS_SHA256
    if not bios_current:
        archive = download(f"{BASE_URL}/{BIOS_GZ}")
        if sha256(archive) != BIOS_GZ_SHA256:
            print(
                f"error: {BIOS_GZ} checksum mismatch "
                f"(expected {BIOS_GZ_SHA256}, got {sha256(archive)})",
                file=sys.stderr,
            )
            return 1
        binary = gzip.decompress(archive)
        if sha256(binary) != BIOS_SHA256:
            print(
                f"error: decoded bios.bin checksum mismatch "
                f"(expected {BIOS_SHA256}, got {sha256(binary)})",
                file=sys.stderr,
            )
            return 1
        write_if_needed(bios_path, binary)
    else:
        print(f"up to date: {os.path.basename(bios_path)}")

    # Keep the source archive identity documented and checked even though s9vm
    # embeds only the built ROM: a later rebuild must start from these bytes.
    source_archive = download(f"{BASE_URL}/{SOURCE_TAR}")
    if sha256(source_archive) != SOURCE_TAR_SHA256:
        print(
            f"error: {SOURCE_TAR} checksum mismatch "
            f"(expected {SOURCE_TAR_SHA256}, got {sha256(source_archive)})",
            file=sys.stderr,
        )
        return 1
    print(f"source archive verified: {SOURCE_TAR}")

    if not os.path.exists(vga_path):
        print(
            f"error: {VGA_NAME} is missing; build it from the verified source "
            f"archive with the recipe in workspace/assets/firmware/README.md",
            file=sys.stderr,
        )
        return 1
    with open(vga_path, "rb") as stream:
        vga = stream.read()
    if sha256(vga) != VGA_SHA256:
        print(
            f"error: {VGA_NAME} checksum mismatch "
            f"(expected {VGA_SHA256}, got {sha256(vga)})",
            file=sys.stderr,
        )
        return 1
    print(f"verified: {VGA_NAME}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
