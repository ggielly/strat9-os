#!/usr/bin/env python3
"""
Add PVH (Para-Virtualization Hardware) ELF notes to a kernel binary.

PVH boot allows QEMU to load a bare-metal ELF kernel directly via -kernel.
QEMU reads Xen PVH notes to set up initial page tables and jump to the entry point.

Usage:
    python3 tools/scripts/add_pvh_notes.py <kernel_elf>
"""

import struct
import sys


def make_note(n_type, desc):
    """Create a Xen ELF note with proper alignment."""
    name = b'Xen\x00'
    namesz = 4
    descsz = len(desc)
    note = struct.pack('<III', namesz, descsz, n_type)
    note += name
    note += desc
    pad = (4 - (len(desc) % 4)) % 4
    note += b'\x00' * pad
    return note


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <kernel_elf>")
        sys.exit(1)

    elf_path = sys.argv[1]

    with open(elf_path, 'rb') as f:
        data = bytearray(f.read())

    assert data[:4] == b'\x7fELF', "Not an ELF file"
    assert data[4] == 2, "Not ELF64"

    e_entry = struct.unpack_from('<Q', data, 0x18)[0]
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]

    print(f"Entry: {hex(e_entry)}, PHDRs: {e_phnum}")

    # Find first PT_LOAD paddr
    first_paddr = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        p_paddr = struct.unpack_from('<Q', data, off + 24)[0]
        if p_type == 1 and first_paddr is None:
            first_paddr = p_paddr

    print(f"First paddr: {hex(first_paddr)}")

    # Build Xen PVH notes
    XEN_LOADER = 0x00
    XEN_ENTRY = 0x01
    XEN_PADDR_NOTE = 0x02
    XEN_GUEST_OS = 0x03
    XEN_XEN_VERSION = 0x04

    notes = bytearray()
    notes += make_note(XEN_LOADER, b'generic\x00')
    notes += make_note(XEN_ENTRY, struct.pack('<Q', e_entry))
    notes += make_note(XEN_PADDR_NOTE, struct.pack('<Q', first_paddr + 0x1000000))
    notes += make_note(XEN_GUEST_OS, b'strat9-os\x00')
    notes += make_note(XEN_XEN_VERSION, b'Xen version 3.0\x00')

    # Pad to page boundary
    while len(notes) % 4096 != 0:
        notes += b'\x00'

    # Place at 16MB offset from first load
    note_paddr = first_paddr + 0x1000000
    # Account for the new PHDR (56 bytes) we're about to insert
    phdr_size = 56  # ELF64 Phdr
    note_offset = len(data) + phdr_size

    # Create PT_NOTE program header
    phdr = struct.pack('<IIQQQQQQ',
        4,               # PT_NOTE
        0,               # p_flags
        note_offset,     # p_offset
        note_paddr,      # p_vaddr
        note_paddr,      # p_paddr
        len(notes),      # p_filesz
        len(notes),      # p_memsz
        4,               # p_align
    )

    # Update e_phnum
    new_phnum = e_phnum + 1
    data[0x38] = new_phnum & 0xFF
    data[0x39] = (new_phnum >> 8) & 0xFF

    # Build result
    result = bytearray()
    result += data[:e_phoff + e_phnum * e_phentsize]
    result += phdr
    result += data[e_phoff + e_phnum * e_phentsize:]
    while len(result) < note_offset:
        result += b'\x00'
    result += notes

    with open(elf_path, 'wb') as f:
        f.write(result)

    print(f"Done! {len(data)} -> {len(result)} bytes")


if __name__ == '__main__':
    main()
