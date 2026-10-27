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
  ├── 4. GOP → framebuffer (best console mode)
  ├── 5. GetMemoryMap → memory regions
  ├── 6. ACPI RSDP → config table
  ├── 7. Build environment string (key=value)
  ├── 8. Allocate every handoff object (transition stack, module
  │      table, environment, KernelArgs, memory map)
  ├── 9. Create page tables (identity + HHDM + kernel + framebuffer
  │      + environment) and preflight the final memory map
  ├── 10. ExitBootServices() → bare metal
  ├── 11. Fill KernelArgs in its reserved page
  └── 12. Context switch → kernel_main(KernelArgs)
```

Steps 9 and 10 are ordered this way on purpose: the page-table arena is
written through the firmware identity map, so the tables must exist before
`ExitBootServices`. Only the `CR3` load happens afterwards, inside
`paging::context_switch`, where no firmware call or allocation is possible.

## ABI v5 (132 bytes, `#[repr(C, packed)]`)

Version 5 adds nothing to the layout: it widens `MemoryKind` with `Bad` (4)
and `AcpiNvs` (5). The struct is still exactly 132 bytes, checked by a
`const` assertion in `abi/src/boot.rs`.

| Field | Type | Description |
|---|---|---|
| `magic` | u32 | 0x53543942 ("ST9B") |
| `abi_version` | u32 | 5 |
| `kernel_base` | u64 | Physical address of kernel ELF |
| `kernel_size` | u64 | Size of kernel in bytes |
| `acpi_rsdp_base` | u64 | Physical address of RSDP |
| `memory_map_base` | u64 | Physical address of MemoryRegion array |
| `memory_map_size` | u64 | Size of memory map in bytes |
| `framebuffer_addr` | u64 | **Physical** address of pixel 0 |
| `hhdm_offset` | u64 | Higher Half Direct Map offset |
| `cmdline_ptr` | u64 | Physical address of environment string |
| `cmdline_len` | u64 | Length of environment string |
| `modules_base` | u64 | Physical address of ModuleTable |
| `modules_size` | u64 | Size of ModuleTable |
| `framebuffer_width` | u32 | Width in pixels |
| `framebuffer_height` | u32 | Height in pixels |
| `framebuffer_stride` | u32 | Bytes per row |
| `framebuffer_bpp` | u16 | Bits per pixel |
| `framebuffer_*_mask_*` | u8×6 | RGB channel masks |
| `bss_virt_base` | u64 | Virtual start of the kernel zero-fill tail |
| `bss_virt_size` | u64 | Size of that tail (0 if none) |

The transition stack is not part of the ABI: the loader switches to a
64 KiB stack it owns, but only `RSP` is affected, and the kernel installs
its own stack during early init.

### Memory kinds (`MemoryRegion.kind`)

| Value | Name | Meaning |
|---|---|---|
| 1 | `Free` | usable RAM |
| 2 | `Reclaim` | boot-services/loader memory, reusable after init |
| 3 | `Reserved` | firmware/devices/bootloader, never allocate |
| 4 | `Bad` | firmware-reported unusable memory, never touch |
| 5 | `AcpiNvs` | ACPI NVS tables, preserved for system lifetime |

`Null` (0) is a placeholder and is never emitted. `AcpiNvs` and `Bad` are
new in ABI v5; a v4 kernel refuses a v5 loader (version mismatch) instead
of silently treating them as `Reserved`.

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
