#!/usr/bin/env python3
"""Build the FreeDOS 1.4 s9vm selftest floppy from the official boot image.

The official `144m/x86BOOT.img` boots through a multilingual menu driven by
`FDCONFIG.SYS`. The s9vm selftest image replaces three root-directory files so
the boot is deterministic, signal is raised for the kernel selftest, and no
keyboard is needed:

1. `FDCONFIG.SYS`  - the boot menu is replaced by plain directives and a direct
   `SHELL=` line. No leading `@echo off`: that is a batch directive, and the
   FreeDOS kernel reports `CONFIG.SYS error in line 0` and echoes the line when
   it sees it (this is what the first patched image got wrong).
2. `FDAUTO.BAT`    - the installer launcher is replaced by two `ECHO` lines and
   `S9VMK.COM`.
3. `SETUP.BAT`     - renamed to `S9VMK.COM` (its long-name entry is dropped) and
   filled with a 8-byte program that writes `'K'` to the s9vm debug port
   `0x00E9` and terminates with `INT 20h`.

Every edit rewrites the payload inside the file's existing clusters and shrinks
the directory-entry size: no cluster is allocated, the FAT is untouched, and no
other file changes. The result is deterministic: the official image always
produces the same output hash.

The script is also idempotent: applied to an image that already carries the
patch, it reports it and changes nothing (it still removes the stray
`@echo off` line from the previous patched revision).

Usage: python scripts/patch-freedos-boot-image.py <image>
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

#: SHA-256 of the official `144m/x86BOOT.img`.
PRISTINE_SHA256 = "552f7cbb0625960c050a3e682a4d2121cc2ffdfa9dc9d592ccd49edf179333dc"

#: Content of FDCONFIG.SYS: plain directives, no menu, no invalid batch line.
FDCONFIG_SYS = (
    b"!COUNTRY=001,858:\\FREEDOS\\BIN\\COUNTRY.SYS\r\n"
    b"!LASTDRIVE=Z\r\n"
    b"!BUFFERS=20\r\n"
    b"!FILES=40\r\n"
    b"SHELL=\\FREEDOS\\BIN\\COMMAND.COM \\FREEDOS\\BIN /E:2048 /P=\\FDAUTO.BAT\r\n"
)

#: Content of FDAUTO.BAT: announce the boot, then raise the selftest marker.
FDAUTO_BAT = (
    b"@ECHO OFF\r\n"
    b"ECHO s9vm: FreeDOS 1.4 booting\r\n"
    b"ECHO FreeDOS 1.4 booted under s9vm\r\n"
    b"S9VMK.COM\r\n"
)

#: Content of S9VMK.COM: mov al,'K' / mov dx,0x00E9 / out dx,al / int 20h.
S9VMK_COM = b"\xb0\x4b\xba\xe9\x00\xee\xcd\x20"

#: The stray batch line that must not be the first CONFIG.SYS directive.
DROPPED_LINE = b"@echo off\r\n"

BASE_SECTORS = "bytes_per_sector"
SECTORS_PER_CLUSTER = "sectors_per_cluster"
RESERVED = "reserved"
FATS = "fats"
FAT_SIZE = "fat_size"
ROOT_ENTRIES = "root_entries"
ROOT_DIR_OFFSET = "root_dir_offset"
DATA_OFFSET = "data_offset"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bpb(image: bytes) -> dict[str, int]:
    """Decodes the FAT12 BIOS parameter block of a 1.44 MiB floppy."""
    (bytes_per_sector,) = struct.unpack_from("<H", image, 0x0B)
    (reserved,) = struct.unpack_from("<H", image, 0x0E)
    (root_entries,) = struct.unpack_from("<H", image, 0x11)
    (fat_size,) = struct.unpack_from("<H", image, 0x16)
    sectors_per_cluster = image[0x0D]
    fats = image[0x10]
    root_dir_sectors = (root_entries * 32 + bytes_per_sector - 1) // bytes_per_sector
    root_dir_offset = (reserved + fats * fat_size) * bytes_per_sector
    data_offset = (reserved + fats * fat_size + root_dir_sectors) * bytes_per_sector
    return {
        BASE_SECTORS: bytes_per_sector,
        SECTORS_PER_CLUSTER: sectors_per_cluster,
        RESERVED: reserved,
        FATS: fats,
        FAT_SIZE: fat_size,
        ROOT_ENTRIES: root_entries,
        ROOT_DIR_OFFSET: root_dir_offset,
        DATA_OFFSET: data_offset,
    }


def short_name(name: str) -> tuple[bytes, bytes]:
    """Splits `NAME.EXT` into the padded 8.3 fields of a directory entry."""
    base, _, ext = name.partition(".")
    return base.upper().ljust(8).encode("ascii"), ext.upper().ljust(3).encode("ascii")


def find_entry(image: bytes, bpb: dict[str, int], name: bytes, ext: bytes) -> int:
    """Returns the byte offset of one 8.3 root-directory entry."""
    for index in range(bpb[ROOT_ENTRIES]):
        offset = bpb[ROOT_DIR_OFFSET] + index * 32
        entry = image[offset : offset + 32]
        if entry[0] == 0x00:
            break
        if entry[0] == 0xE5:
            continue
        if bytes(entry[0:8]) == name and bytes(entry[8:11]) == ext:
            return offset
    raise SystemExit(f"{name.decode()}.{ext.decode()} not found in the root directory")


def cluster_offset(cluster: int, bpb: dict[str, int]) -> int:
    return (
        bpb[DATA_OFFSET]
        + (cluster - 2) * bpb[SECTORS_PER_CLUSTER] * bpb[BASE_SECTORS]
    )


def fat12_next(image: bytes, cluster: int, bpb: dict[str, int]) -> int:
    """Reads one FAT12 entry (12 bits, little endian, odd entries shifted)."""
    entry = bpb[RESERVED] * bpb[BASE_SECTORS] + cluster + cluster // 2
    (word,) = struct.unpack_from("<H", image, entry)
    return (word >> 4) if cluster & 1 else (word & 0x0FFF)


def cluster_chain(image: bytes, start: int, bpb: dict[str, int]) -> list[int]:
    chain = []
    cluster = start
    while 2 <= cluster < 0xFF8:
        chain.append(cluster)
        cluster = fat12_next(image, cluster, bpb)
        if len(chain) > 4096:
            raise SystemExit("FAT chain loop")
    return chain


def read_file(image: bytes, entry_offset: int, bpb: dict[str, int]) -> bytes:
    (start,) = struct.unpack_from("<H", image, entry_offset + 0x1A)
    (size,) = struct.unpack_from("<I", image, entry_offset + 0x1C)
    cluster_length = bpb[SECTORS_PER_CLUSTER] * bpb[BASE_SECTORS]
    data = bytearray()
    for cluster in cluster_chain(image, start, bpb):
        offset = cluster_offset(cluster, bpb)
        data += image[offset : offset + cluster_length]
        if len(data) >= size:
            break
    return bytes(data[:size])


def write_file(image: bytearray, entry_offset: int, payload: bytes, bpb: dict[str, int]) -> None:
    """Rewrites a file payload inside its existing clusters."""
    (start,) = struct.unpack_from("<H", image, entry_offset + 0x1A)
    chain = cluster_chain(image, start, bpb)
    cluster_length = bpb[SECTORS_PER_CLUSTER] * bpb[BASE_SECTORS]
    capacity = len(chain) * cluster_length
    if len(payload) > capacity:
        raise SystemExit(f"payload of {len(payload)} bytes does not fit in {capacity}")
    written = 0
    for cluster in chain:
        if written >= len(payload):
            break
        offset = cluster_offset(cluster, bpb)
        chunk = payload[written : written + cluster_length]
        image[offset : offset + len(chunk)] = chunk
        written += len(chunk)
    struct.pack_into("<I", image, entry_offset + 0x1C, len(payload))


def clear_preceding_long_name(image: bytearray, entry_offset: int) -> None:
    """Drops the long-name entries attached to a short entry being renamed."""
    offset = entry_offset
    while offset >= 32:
        offset -= 32
        entry = image[offset : offset + 32]
        if entry[0] == 0x00 or entry[0] == 0xE5 or entry[0x0B] != 0x0F:
            break
        image[offset] = 0xE5


def rename_entry(image: bytearray, entry_offset: int, name: bytes, ext: bytes) -> None:
    image[entry_offset : entry_offset + 8] = name
    image[entry_offset + 8 : entry_offset + 11] = ext
    for index in range(0x0C, 0x1A):
        image[entry_offset + index] = 0


def patch_fdconfig(image: bytearray, bpb: dict[str, int]) -> bool:
    """Removes the stray batch line left by the first patched revision."""
    entry_offset = find_entry(image, bpb, *short_name("FDCONFIG.SYS"))
    content = read_file(image, entry_offset, bpb)
    if not content.startswith(DROPPED_LINE):
        return False
    write_file(image, entry_offset, content[len(DROPPED_LINE) :], bpb)
    return True


def apply_patch(image: bytearray, bpb: dict[str, int]) -> None:
    """Rewrites FDCONFIG.SYS, FDAUTO.BAT and SETUP.BAT -> S9VMK.COM."""
    write_file(image, find_entry(image, bpb, *short_name("FDCONFIG.SYS")), FDCONFIG_SYS, bpb)
    write_file(image, find_entry(image, bpb, *short_name("FDAUTO.BAT")), FDAUTO_BAT, bpb)
    setup = find_entry(image, bpb, *short_name("SETUP.BAT"))
    clear_preceding_long_name(image, setup)
    rename_entry(image, setup, *short_name("S9VMK.COM"))
    write_file(image, setup, S9VMK_COM, bpb)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    path = Path(sys.argv[1])
    image = bytearray(path.read_bytes())
    original = sha256(image)
    bpb = read_bpb(image)

    if original == PRISTINE_SHA256:
        apply_patch(image, bpb)
        action = "patched from the official image"
    elif patch_fdconfig(image, bpb):
        action = "removed the stray @echo off line"
    else:
        print(f"already patched ({original}); nothing to do")
        return 0

    path.write_bytes(bytes(image))
    patched = sha256(image)
    print(f"original: {original}")
    print(f"patched:  {patched}")
    print(action)
    for name in ("FDCONFIG.SYS", "FDAUTO.BAT", "S9VMK.COM"):
        entry_offset = find_entry(image, bpb, *short_name(name))
        content = read_file(image, entry_offset, bpb)
        print(f"{name}: {len(content)} bytes")
    fdconfig = read_file(image, find_entry(image, bpb, *short_name("FDCONFIG.SYS")), bpb)
    print(f"FDCONFIG.SYS first line: {fdconfig.splitlines()[0].decode('ascii')!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
