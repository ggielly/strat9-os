#!/usr/bin/env python3
"""Read-only checks for Strat9's 512-byte-sector GPT and FAT32 images."""
import argparse
from pathlib import Path
import struct
import sys
import uuid
import zlib

SECTOR = 512
ESP_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b").bytes_le


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_at(source, offset, size):
    source.seek(offset)
    data = source.read(size)
    require(len(data) == size, "truncated image")
    return data


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def fat32(source, offset, sectors, hidden):
    boot = read_at(source, offset, SECTOR)
    require(boot[510:512] == b"\x55\xaa", "missing FAT boot-sector signature")
    require(u16(boot, 11) == SECTOR, "FAT sector size must be 512 bytes")
    cluster = boot[13]
    reserved, fats = u16(boot, 14), boot[16]
    total, fat_sectors = u32(boot, 32), u32(boot, 36)
    require(cluster in (1, 2, 4, 8, 16, 32, 64, 128), "invalid FAT cluster size")
    require(reserved > 0 and fats == 2 and fat_sectors > 0, "invalid FAT32 geometry")
    require(u16(boot, 17) == 0 and u16(boot, 19) == 0 and u16(boot, 22) == 0,
            "expected FAT32, not FAT12/16")
    require(total == sectors, "FAT BPB size differs from its containing partition/image")
    require(u32(boot, 28) == hidden, "FAT hidden-sector count differs from partition start")
    require(u16(boot, 42) == 0, "unsupported FAT32 version")
    data_sectors = total - reserved - fats * fat_sectors
    clusters = data_sectors // cluster
    require(data_sectors > 0 and 65525 <= clusters < 0x0FFFFFF5,
            "cluster count does not describe FAT32")
    require((clusters + 2) * 4 <= fat_sectors * SECTOR, "FAT cannot describe all data clusters")
    require(2 <= u32(boot, 44) < clusters + 2, "invalid FAT32 root cluster")
    info, backup = u16(boot, 48), u16(boot, 50)
    require(0 < info < reserved and 0 < backup < reserved, "invalid FAT32 reserved-sector layout")
    require(read_at(source, offset + backup * SECTOR, SECTOR) == boot,
            "FAT backup boot sector differs from primary")
    fsinfo = read_at(source, offset + info * SECTOR, SECTOR)
    require(fsinfo[:4] == b"RRaA" and fsinfo[484:488] == b"rrAa"
            and fsinfo[508:512] == b"\x00\x00\x55\xaa", "invalid FAT32 FSInfo signatures")


def gpt_header(source, lba, total_sectors):
    header = read_at(source, lba * SECTOR, SECTOR)
    require(header[:8] == b"EFI PART", "missing GPT header")
    size = u32(header, 12)
    require(u32(header, 8) == 0x10000 and 92 <= size <= SECTOR, "unsupported GPT header")
    require(u32(header, 20) == 0, "nonzero GPT reserved field")
    crc_bytes = bytearray(header[:size])
    crc_bytes[16:20] = bytes(4)
    require(zlib.crc32(crc_bytes) == u32(header, 16), "invalid GPT header CRC")
    current, alternate, first, last = struct.unpack_from("<QQQQ", header, 24)
    entries_lba = struct.unpack_from("<Q", header, 72)[0]
    count, entry_size, entries_crc = struct.unpack_from("<III", header, 80)
    require(current == lba and alternate == (total_sectors - 1 if lba == 1 else 1),
            "incorrect GPT primary/backup locations")
    require(34 <= first <= last < total_sectors - 1, "invalid GPT usable range")
    require(128 <= count <= 4096 and entry_size == 128, "unsupported GPT entry-array geometry")
    array_sectors = (count * entry_size + SECTOR - 1) // SECTOR
    if lba == 1:
        require(2 <= entries_lba and entries_lba + array_sectors <= first,
                "primary GPT array overlaps usable space")
    else:
        require(last < entries_lba and entries_lba + array_sectors <= lba,
                "backup GPT array overlaps usable space")
    entries = read_at(source, entries_lba * SECTOR, count * entry_size)
    require(zlib.crc32(entries) == entries_crc, "invalid GPT partition-array CRC")
    return first, last, header[56:72], entries


def validate(path, kind, esp_start=2048, esp_sectors=524288):
    size = Path(path).stat().st_size
    require(size > 0 and size % SECTOR == 0, "image size must be a nonzero sector multiple")
    sectors = size // SECTOR
    with open(path, "rb") as source:
        if kind == "fat":
            fat32(source, 0, sectors, 0)
            return
        mbr = read_at(source, 0, SECTOR)
        require(mbr[510:512] == b"\x55\xaa", "missing protective MBR")
        records = [mbr[446 + i * 16:462 + i * 16] for i in range(4)]
        active = [record for record in records if any(record)]
        require(len(active) == 1 and active[0][4] == 0xEE,
                "expected a GPT protective MBR with one record")
        require(u32(active[0], 8) == 1 and u32(active[0], 12) == min(sectors - 1, 0xFFFFFFFF),
                "protective MBR does not cover disk")
        primary = gpt_header(source, 1, sectors)
        backup = gpt_header(source, sectors - 1, sectors)
        require(primary == backup, "GPT primary and backup disagree")
        first, last, guid, entries = primary
        require(any(guid), "zero GPT disk GUID")
        used = [entries[i:i + 128] for i in range(0, len(entries), 128) if any(entries[i:i + 16])]
        require(len(used) == 1 and used[0][:16] == ESP_TYPE, "expected exactly one EFI System Partition")
        require(any(used[0][16:32]), "zero ESP partition GUID")
        start, end = struct.unpack_from("<QQ", used[0], 32)
        require(first <= start <= end <= last, "ESP lies outside GPT usable range")
        require(start == esp_start and end - start + 1 == esp_sectors,
                "ESP bounds differ from requested sector layout")
        fat32(source, start * SECTOR, end - start + 1, start)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("disk", "fat"))
    parser.add_argument("image", type=Path)
    parser.add_argument("--esp-start", type=int, default=2048)
    parser.add_argument("--esp-sectors", type=int, default=524288)
    args = parser.parse_args()
    try:
        validate(args.image, args.kind, args.esp_start, args.esp_sectors)
    except (OSError, ValueError, struct.error) as error:
        print(f"ERROR: {args.image}: {error}", file=sys.stderr)
        return 1
    print(f"[OK] {args.kind} geometry validated: {args.image}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
