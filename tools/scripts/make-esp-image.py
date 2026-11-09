#!/usr/bin/env python3
"""Creates a UEFI disk image (MBR + FAT32 ESP) from a directory.

Goal: produce a bootable artifact for a host hypervisor that exposes
VT-x, without depending on formatting tools absent from the development
host (no WSL, no administrator privileges, no mtools/mkfs).

    python tools/scripts/make-esp-image.py --source build/qemu-esp \\
        --output build/s9vm-esp.img [--size-mb 280]

The image contains an MBR partition table (one FAT32 partition of type
0x0C, boot LBA 2048) and a complete FAT32 tree, long names (LFN)
included. The kernel bootloader reads the 8.3 entries and LFN.

No external dependency: standard Python 3 only.
"""

import argparse
import os
import struct
import sys

SECTOR = 512
PART_START_LBA = 2048
RESERVED_SECTORS = 32
NUM_FATS = 2
SECTORS_PER_CLUSTER = 8  # 4 KiB
CLUSTER_SIZE = SECTOR * SECTORS_PER_CLUSTER
EOC = 0x0FFFFFFF
FAT_ENTRIES_PER_SECTOR = SECTOR // 4
FAT_DATE = ((2026 - 1980) << 9) | (1 << 5) | 1
FAT_TIME = 0
SHORT_OK = set("$%'-_@~`!(){}^#&")


class Entry:
    def __init__(self, name, attr, cluster, size):
        self.name = name
        self.attr = attr
        self.cluster = cluster
        self.size = size


def split_name(name):
    base, dot, ext = name.rpartition(".")
    if not dot:
        return name, ""
    return base, ext


def is_plain_83(name):
    base, ext = split_name(name)
    if not (1 <= len(base) <= 8 and len(ext) <= 3):
        return False
    if name != name.upper():
        return False
    return all(char.isalnum() or char in SHORT_OK for char in base + ext)


def natural_short(name):
    base, ext = split_name(name)
    return base.upper().ljust(8)[:8] + ext.upper().ljust(3)[:3]


def make_short(name, used):
    if is_plain_83(name):
        short = natural_short(name)
        used.add(short)
        return short
    base, ext = split_name(name)
    cleaned = "".join(char.upper() if char.isalnum() else "_" for char in base)
    cleaned = cleaned[:6] or "FILE"
    ext_clean = "".join(char.upper() if char.isalnum() else "_" for char in ext)[:3]
    for index in range(1, 10000):
        candidate = f"{cleaned}~{index}"[:8].ljust(8) + ext_clean.ljust(3)
        if candidate not in used:
            used.add(candidate)
            return candidate
    raise RuntimeError(f"impossible de générer un nom court pour {name}")


def lfn_checksum(short_name):
    total = 0
    for byte in short_name.encode("ascii"):
        total = (((total & 1) << 7) + (total >> 1) + byte) & 0xFF
    return total


def lfn_entries(name, short_name):
    """Builds the LFN entries (disk order: last part first)."""
    checksum = lfn_checksum(short_name)
    encoded = name.encode("utf-16-le")
    units = [encoded[i : i + 2] for i in range(0, len(encoded), 2)]
    units.append(b"\x00\x00")
    while len(units) % 13 != 0:
        units.append(b"\xff\xff")
    chunks = [units[i : i + 13] for i in range(0, len(units), 13)]
    entries = []
    for index, chunk in enumerate(chunks):
        order = index + 1
        if index == len(chunks) - 1:
            order |= 0x40
        data = b"".join(chunk)
        entry = bytearray(32)
        entry[0] = order
        entry[1:11] = data[0:10]
        entry[11] = 0x0F
        entry[12] = 0
        entry[13] = checksum
        entry[14:26] = data[10:22]
        entry[26:28] = b"\x00\x00"
        entry[28:32] = data[22:26]
        entries.append(bytes(entry))
    entries.reverse()
    return entries


def short_entry(name, short_name, attr, cluster, size):
    entry = bytearray(32)
    entry[0:11] = short_name.encode("ascii")[:11]
    entry[11] = attr
    entry[12] = 0  # NT reserved
    entry[13] = 0  # creation tenths of a second
    struct.pack_into("<H", entry, 14, FAT_TIME)  # creation time
    struct.pack_into("<H", entry, 16, FAT_DATE)  # creation date
    struct.pack_into("<H", entry, 18, FAT_DATE)  # last access date
    struct.pack_into("<H", entry, 20, (cluster >> 16) & 0xFFFF)  # clusterHigh
    struct.pack_into("<H", entry, 22, FAT_TIME)  # modification time
    struct.pack_into("<H", entry, 24, FAT_DATE)  # modification date
    struct.pack_into("<H", entry, 26, cluster & 0xFFFF)  # clusterLow
    struct.pack_into("<I", entry, 28, size)
    return bytes(entry)


def dir_entries_for(name, cluster, size, used):
    short = make_short(name, used)
    entries = []
    if not is_plain_83(name):
        entries.extend(lfn_entries(name, short))
    entries.append(short_entry(name, short, 0x20 if size is not None else 0x10, cluster, size or 0))
    return entries


class Fat32Image:
    def __init__(self, total_bytes):
        self.part_sectors = (total_bytes // SECTOR) - PART_START_LBA
        self.fat_sectors, self.clusters = self._layout()
        self.data_start_sector = RESERVED_SECTORS + NUM_FATS * self.fat_sectors
        self.image = bytearray((PART_START_LBA + self.part_sectors) * SECTOR)
        self.fat = [0] * (self.clusters + 2)
        self.next_cluster = 3
        self.root_cluster = 2
        self.fat[self.root_cluster] = EOC
        self._format_mbr()

    def _layout(self):
        fat_sectors = 1
        while True:
            data_sectors = self.part_sectors - RESERVED_SECTORS - NUM_FATS * fat_sectors
            clusters = data_sectors // SECTORS_PER_CLUSTER
            needed = (clusters + 2 + FAT_ENTRIES_PER_SECTOR - 1) // FAT_ENTRIES_PER_SECTOR
            if needed <= fat_sectors:
                return fat_sectors, clusters
            fat_sectors = needed

    def _format_mbr(self):
        entry = bytearray(16)
        entry[0] = 0x80
        entry[1:4] = b"\xfe\xff\xff"
        entry[4] = 0x0C
        entry[5:8] = b"\xfe\xff\xff"
        struct.pack_into("<I", entry, 8, PART_START_LBA)
        struct.pack_into("<I", entry, 12, self.part_sectors)
        self.image[446:462] = entry
        self.image[510:512] = b"\x55\xaa"

    def cluster_offset(self, cluster):
        sector = PART_START_LBA + self.data_start_sector + (cluster - 2) * SECTORS_PER_CLUSTER
        return sector * SECTOR

    def alloc_cluster(self):
        cluster = self.next_cluster
        if cluster >= self.clusters + 2:
            raise RuntimeError("image pleine")
        self.next_cluster += 1
        return cluster

    def allocate_file(self, entries, name, data):
        first = 0
        if data:
            first_allocated = None
            previous = None
            offset = 0
            while offset < len(data):
                cluster = self.alloc_cluster()
                if first_allocated is None:
                    first_allocated = cluster
                if previous is not None:
                    self.fat[previous] = cluster
                chunk = data[offset : offset + CLUSTER_SIZE]
                start = self.cluster_offset(cluster)
                self.image[start : start + len(chunk)] = chunk
                previous = cluster
                offset += len(chunk)
            self.fat[previous] = EOC
            first = first_allocated
        entries.append(Entry(name, 0x20, first, len(data)))

    def build(self, source):
        root_entries = []
        self._populate(source, root_entries)
        self._write_directory(self.root_cluster, root_entries)
        self._write_fat()
        self._write_boot_sector()
        return bytes(self.image)

    def _populate(self, source, entries):
        for name in sorted(os.listdir(source)):
            path = os.path.join(source, name)
            if os.path.isdir(path):
                cluster = self.alloc_cluster()
                self.fat[cluster] = EOC
                child_entries = []
                self._populate(path, child_entries)
                self._write_directory(cluster, child_entries)
                entries.append(Entry(name, 0x10, cluster, 0))
            else:
                with open(path, "rb") as handle:
                    data = handle.read()
                self.allocate_file(entries, name, data)

    def _write_directory(self, cluster, entries):
        used = set()
        raw = bytearray()
        for entry in entries:
            raw.extend(b"".join(dir_entries_for(entry.name, entry.cluster, entry.size if entry.attr == 0x20 else None, used)))
        if len(raw) > CLUSTER_SIZE:
            raise RuntimeError("trop d'entrées dans un répertoire (une grappe max)")
        offset = self.cluster_offset(cluster)
        self.image[offset : offset + len(raw)] = raw

    def _write_fat(self):
        primary_len = self.fat_sectors * SECTOR
        primary = bytearray(primary_len)
        for index, value in enumerate(self.fat):
            struct.pack_into("<I", primary, index * 4, value & 0x0FFFFFFF)
        start = (PART_START_LBA + RESERVED_SECTORS) * SECTOR
        self.image[start : start + primary_len] = primary
        self.image[start + primary_len : start + 2 * primary_len] = primary

    def _write_boot_sector(self):
        boot = bytearray(SECTOR)
        boot[0:3] = b"\xeb\x58\x90"
        boot[3:11] = b"S9VMESP "
        struct.pack_into("<H", boot, 11, SECTOR)
        boot[13] = SECTORS_PER_CLUSTER
        struct.pack_into("<H", boot, 14, RESERVED_SECTORS)
        boot[16] = NUM_FATS
        struct.pack_into("<H", boot, 17, 0)
        struct.pack_into("<H", boot, 19, 0)
        boot[21] = 0xF8
        struct.pack_into("<H", boot, 22, 0)
        struct.pack_into("<H", boot, 24, 63)
        struct.pack_into("<H", boot, 26, 255)
        struct.pack_into("<I", boot, 28, PART_START_LBA)
        struct.pack_into("<I", boot, 32, self.part_sectors)
        struct.pack_into("<I", boot, 36, self.fat_sectors)
        struct.pack_into("<H", boot, 40, 0)
        struct.pack_into("<H", boot, 42, 0)
        struct.pack_into("<I", boot, 44, self.root_cluster)
        struct.pack_into("<H", boot, 48, 1)
        struct.pack_into("<H", boot, 50, 6)
        boot[52:64] = b"\x00" * 12
        boot[64] = 0x80
        boot[66] = 0x29
        struct.pack_into("<I", boot, 67, 0x53394D56)
        boot[71:82] = b"S9VMESP    "
        boot[82:90] = b"FAT32   "
        boot[510:512] = b"\x55\xaa"
        start = PART_START_LBA * SECTOR
        self.image[start : start + SECTOR] = boot
        self.image[start + 6 * SECTOR : start + 7 * SECTOR] = boot
        fsinfo = bytearray(SECTOR)
        struct.pack_into("<I", fsinfo, 0, 0x41615252)
        struct.pack_into("<I", fsinfo, 484, 0x61417272)
        struct.pack_into("<I", fsinfo, 488, max(0, self.clusters - (self.next_cluster - 3)))
        struct.pack_into("<I", fsinfo, 492, self.next_cluster)
        struct.pack_into("<I", fsinfo, 508, 0xAA550000)
        self.image[start + SECTOR : start + 2 * SECTOR] = fsinfo
        self.image[start + 7 * SECTOR : start + 8 * SECTOR] = fsinfo


def main():
    parser = argparse.ArgumentParser(description="Crée une image disque UEFI FAT32 (MBR).")
    parser.add_argument("--source", required=True, help="répertoire à copier (racine de l'ESP)")
    parser.add_argument("--output", required=True, help="fichier image à écrire")
    parser.add_argument("--size-mb", type=int, default=280, help="taille de l'image en Mio")
    args = parser.parse_args()

    if not os.path.isdir(args.source):
        print(f"source introuvable : {args.source}", file=sys.stderr)
        return 1
    image = Fat32Image(args.size_mb * 1024 * 1024)
    data = image.build(args.source)
    os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".", exist_ok=True)
    with open(args.output, "wb") as handle:
        handle.write(data)
    print(f"image écrite : {args.output} ({len(data)} octets, {image.clusters} grappes FAT32)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
