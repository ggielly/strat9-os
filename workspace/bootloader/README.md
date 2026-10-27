# strat9-os bootloader

UEFI bootloader for strat9-os, with BIOS support (archived).

## Architecture

The bootloader follows a BOOTBOOT-inspired design with fixed virtual addresses:

```text
Virtual Memory Layout:
  0xFFFF_DEAD_0000_0000  → Framebuffer (DEAD)
  0xFFFF_BEEF_0000_0000  → Environment string (BEEF)
  0xFFFFFFFF_8000_0000  → Kernel code/data
  0x0000_0000_0000_0000  → Identity map (first 4GB)
```

## Boot Flow (UEFI)

```text
UEFI Firmware → bootx64.efi (FAT ESP)
  │
  ├── 1. Open SimpleFileSystem → /boot/kernel.elf
  ├── 2. Parse ELF64, load segments to physical memory
  ├── 3. Load modules from /boot/initfs/*
  ├── 4. GOP → framebuffer
  ├── 5. GetMemoryMap → memory regions
  ├── 6. ACPI RSDP → config table
  ├── 7. Build environment string (key=value)
  ├── 8. ExitBootServices() → bare metal
  ├── 9. Create page tables (identity + higher-half + framebuffer)
  ├── 10. Build KernelArgs (ABI v2, 132 bytes)
  └── 11. Context switch → kernel_main(KernelArgs)
```

## ABI v6 (156 bytes, `#[repr(C, packed)]`)

Offsets are pinned by `workspace/abi/tests/boot_handoff.rs`.

| Offset | Field | Type | Description |
|---:|---|---|---|
| 0 | `magic` | u32 | 0x53543942 ("ST9B") |
| 4 | `abi_version` | u32 | 6 |
| 8 | `kernel_base` | u64 | Physical address of kernel ELF |
| 16 | `kernel_size` | u64 | Size of kernel in bytes |
| 24 | `acpi_rsdp_base` | u64 | Physical address of RSDP |
| 32 | `memory_map_base` | u64 | Physical address of MemoryRegion array |
| 40 | `memory_map_size` | u64 | Size of memory map in bytes |
| 48 | `framebuffer_addr` | u64 | Physical address of the GOP aperture |
| 56 | `hhdm_offset` | u64 | Higher Half Direct Map offset |
| 64 | `cmdline_ptr` | u64 | Physical address of environment string |
| 72 | `cmdline_len` | u64 | Length of environment string |
| 80 | `modules_base` | u64 | Physical address of ModuleTable |
| 88 | `modules_size` | u64 | Size of ModuleTable |
| 96 | `framebuffer_width` | u32 | Width in pixels |
| 100 | `framebuffer_height` | u32 | Height in pixels |
| 104 | `framebuffer_stride` | u32 | Bytes per row |
| 108 | `framebuffer_bpp` | u16 | Bits per pixel |
| 110 | `framebuffer_*_mask_*` | u8×6 | RGB channel masks |
| 116 | `bss_virt_base` | u64 | Start of the kernel's zeroed BSS |
| 124 | `bss_virt_size` | u64 | Size of the zeroed BSS |
| 132 | `boot_log_base` | u64 | Physical address of the boot log ring |
| 140 | `boot_log_size` | u64 | Ring capacity (power of two) |
| 148 | `boot_log_written` | u64 | Bytes ever appended (monotonic), see below |

`abi_version` is checked for exact equality by the kernel: a mismatched pair
refuses to boot instead of reading fields at the wrong offsets.

## Memory map labels (v6)

`MemoryRegion.kind` is 8 bytes: the low 32 bits are the kind (`Null`, `Free`,
`Reclaim`, `Reserved`) and bits 32..40 optionally hold a `MemoryLabel` naming
*why* the loader kept a range -- `kernel image`, `boot modules`, `page tables`,
`boot log`, `environment`, `KernelArgs`, `memory map`, `boot stack`,
`framebuffer`. No new field, no new ABI version.

Only reserved ranges are labelled, and the builder rejects a label anywhere
else: the kernel compares free and reclaimable regions with
`kind == MemoryKind::Free`, so a label there would hide RAM from the allocator.
Classification code uses `kind.base()`. The kernel prints one line per labelled
range at boot:

```text
[init]   reserved 0x000000400000+0x40000 : kernel image
[init]   reserved 0x000000500000+0x4000 : boot log
```

## Boot log ring (v6)

The loader reserves 16 KiB (`boot_log.rs`) and appends every `[boot]` line to
it, including the ones printed after `ExitBootServices`, when the UEFI console
is already gone. It is a plain byte buffer with no header: the writer always
appends at `boot_log_written % boot_log_size`, so the kernel derives the valid
window with `KernelArgs::boot_log_spans()` -- oldest byte first, split in two
spans when the ring wrapped -- and replays it once through the HHDM before the
first allocation. Nothing is allocated, no firmware is called, and a ring
never written costs nothing (`boot_log_written == 0`).

## Environment String

The bootloader builds a `key=value\n` environment string (max 4096 bytes):

```text
loader=strat9-bootloader-uefi
loader.version=0.1.0
fb.phys=0x7F800000
fb.virt=0xFFFF_DEAD_0000_0000
fb.width=1024
fb.height=768
fb.stride=1024
fb.bpp=32
acpi.rsdp=0x7FE23000
console=ttyS0
console.baud=115200
kernel.entry=0xFFFFFFFF80001234
```

## Module Table

```rust
#[repr(C)]
pub struct ModuleTable {
    pub count: u32,
    pub entries: [ModuleEntry; 64],
}

#[repr(C)]
pub struct ModuleEntry {
    pub name: [u8; 64],   // null-terminated filename
    pub base: u64,        // physical address
    pub size: u64,        // size in bytes
}
```

## Build

```bash
# Build UEFI bootloader
cargo make bootloader-uefi

# Create bootable image
cargo make uefi-image

# Run with OVMF
cargo make run-uefi
```

## Page tables

`page_tables.rs` builds a bounded four-level tree in one arena computed by
`MappingPlan::table_pages()`. The identity map (low physical memory) and the
HHDM share the same policy, per 1 GiB window:

| Leaves | When |
|---|---|
| 4 KiB | low memory (`0..2 MiB`: fixed MTRRs, AP trampoline), the kernel image, and any window whose cache policy changes inside it |
| 2 MiB | a 1 GiB window that needs finer granularity because of the kernel, the EFI transition image, or a WB/UC boundary |
| 1 GiB | the whole window is one WB or one UC range with no kernel or EFI image (CPUID `8000_0001h` EDX[26] only) |

`MappingPlan::gib_pages` is fed from `CpuFeatures::supports_1gib_pages()`, so
CPUs without 1 GiB leaves keep the 2 MiB topology. Splitting is decided during
planning (`map_gib_leaf` / `map_huge_leaf`), never by rewriting a leaf that has
already been stored, so `Tables::child` can reject collisions.

## Tests

```bash
# Host tests for the pure modules (no firmware, no privileged instructions)
cargo make test-bootloader
# or
cargo test --manifest-path workspace/bootloader-tests/Cargo.toml
```

## Dependencies

- `uefi` 0.39 (UEFI protocols)
- `x86_64` 0.15 (page tables)
- `strat9-abi` (shared ABI definitions)

## Archived

The old BIOS bootloader (NASM stage1/stage2) is archived in `archive/asm/`.

## References

- [uefi-rs](https://github.com/rust-osdev/uefi-rs)
- [Phil Opp bootloader](https://github.com/rust-osdev/bootloader)
- [BOOTBOOT Protocol](https://gitlab.com/bztsrc/bootboot)
- [OSDev Wiki - Bootloader](https://wiki.osdev.org/Bootloader)

## License

GPLv3
