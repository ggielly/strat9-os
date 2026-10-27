#!/usr/bin/env python3
"""Validate xorriso's El Torito report for the generated EFI boot image."""
import re
from pathlib import Path
import sys


def validate_report(report):
    # xorriso columns: index, platform, bootable, emulation, load segment,
    # hard-disk type, load size, LBA. Require exactly one matching EFI entry.
    entries = re.findall(r"^El Torito boot img\s*:\s*(\d+)\s+UEFI\s+y\s+none\s+"
                         r"0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+\d+\s+\d+\s*$",
                         report, re.MULTILINE)
    if len(entries) != 1:
        raise ValueError("expected one bootable UEFI no-emulation El Torito entry")
    paths = re.findall(r"^El Torito img path\s*:\s*" + re.escape(entries[0])
                       + r"\s+(/\S+)\s*$", report, re.MULTILINE)
    if paths != ["/efiboot.img"]:
        raise ValueError("El Torito entry does not reference /efiboot.img")


if __name__ == "__main__":
    try:
        validate_report(Path(sys.argv[1]).read_text())
    except (OSError, ValueError, IndexError) as error:
        print(f"ERROR: ISO boot catalog: {error}", file=sys.stderr)
        sys.exit(1)
