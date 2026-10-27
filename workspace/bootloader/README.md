# strat9-os bootloader

UEFI bootloader for strat9-os. A legacy NASM BIOS bootloader also lives in this crate but is **not** on the active boot path — see [Legacy BIOS bootloader](#legacy-bios-bootloader).

## Architecture

The bootloader follows a BOOTBOOT-inspired design with fixed virtual addresses:

```text
Virtual Memory Layout:
  0xFFFF_DEAD_0000_0000  → Framebuffer (DEAD)
  0xFFFF_BEEF_0000_0000  → Environment string (BEEF)
  0xFFFF_FF00_0000_0000  → Higher-Half Direct Map offset (HHDM)
  0xFFFF_FFFF_8000_0000  → Kernel code/data  (KERNEL_VIRT_BASE, PML4[511])
  0x0000_0000_0000_0000  → Identity map
```

Direct-map window: `INITIAL_ALLOCATION_LIMIT = 8 GiB`, `MAX_DIRECT_MAP = 512 GiB`
(`boot_plan.rs`). The kernel extends the HHDM itself as RAM is discovered, so the
8 GiB figure is only what the loader maps eagerly.

> Note the HHDM is at `0xFFFF_FF00_0000_0000` (PML4[510]), **not** the more
> common `0xFFFF_8000_0000_0000`.

## Boot flow (UEFI)

```text
UEFI Firmware → BOOTX64.EFI (FAT ESP)
  │
  ├── 1. BootMemory::new() + serial banner
  ├── 2. cpu::detect() — CPUID feature detection
  ├── 3. LoadedImage protocol; verify context_switch is inside the image
  ├── 4. SimpleFileSystem → open the ESP volume
  ├── 5. Read /boot/kernel.elf
  ├── 6. Parse ELF64, load segments to physical memory (KERNEL_PHYS_BASE = 1 MiB)
  ├── 7. Load modules from /boot/initfs/* — a file named "init" or
  │       "strate-init" MUST exist or boot aborts
  ├── 8. GOP → select_framebuffer (Bitmask and BltOnly pixel formats rejected)
  ├── 9. ACPI RSDP from the configuration table (ACPI2_GUID, else ACPI_GUID)
  ├── 10. Build the environment string (key=value, max 4096 bytes)
  ├── 11. Allocate: 64 KiB transition stack, module table, env block,
  │        KernelArgs page, memory-map array, page-table arena
  ├── 12. Build page tables → pml4_phys
  ├── 13. Memory-map pre-flight conversion
  ├── 14. exit_boot_services() → cli / cld
  ├── 15. Re-init COM1 (firmware may have left it in an unknown state)
  ├── 16. Fill KernelArgs and write it into a reserved page
  └── 17. context_switch(pml4_phys, stack_top, entry, args_ptr)
```

`context_switch` (`paging.rs`, inline asm) fixes CR0, disables caching and runs
`wbinvd`, clears CR4 `PCIDE|PGE`, sets `OSFXSR|OSXMMEXCPT`, sets `IA32_EFER.NXE`,
sets `rsp`, loads CR3, `wbinvd`, re-enables caching and jumps to the kernel.

## Boot handoff ABI — v4 (132 bytes, `#[repr(C, packed)]`)

`STRAT9_BOOT_MAGIC = 0x5354_3942` (`"ST9B"`), `STRAT9_BOOT_ABI_VERSION = 4`.
The size is asserted at compile time in two places in `workspace/abi/src/boot.rs`.

| Offset | Field | Type | Description |
|---|---|---|---|
| 0 | `magic` | u32 | 0x53543942 (`"ST9B"`) |
| 4 | `abi_version` | u32 | 4 |
| 8 | `kernel_base` | u64 | Physical address of the kernel ELF |
| 16 | `kernel_size` | u64 | Size of the kernel in bytes |
| 24 | `acpi_rsdp_base` | u64 | **Physical** address of the RSDP |
| 32 | `memory_map_base` | u64 | Physical address of the `MemoryRegion` array |
| 40 | `memory_map_size` | u64 | Size of the memory map in bytes |
| 48 | `framebuffer_addr` | u64 | **Physical** address of the framebuffer |
| 56 | `hhdm_offset` | u64 | Higher-Half Direct Map offset |
| 64 | `cmdline_ptr` | u64 | Physical address of the environment string |
| 72 | `cmdline_len` | u64 | Length of the environment string |
| 80 | `modules_base` | u64 | Physical address of the `ModuleTable` |
| 88 | `modules_size` | u64 | Size of the `ModuleTable` |
| 96 | `framebuffer_width` | u32 | Width in pixels |
| 100 | `framebuffer_height` | u32 | Height in pixels |
| 104 | `framebuffer_stride` | u32 | Bytes per row |
| 108 | `framebuffer_bpp` | u16 | Bits per pixel |
| 110–115 | `framebuffer_*_mask_*` | u8 ×6 | RGB size/shift pairs |
| 116 | `bss_virt_base` | u64 | **Added in v4** |
| 124 | `bss_virt_size` | u64 | **Added in v4** |

### Changes across boot ABI versions

| Version | Change |
|---------|--------|
| 2 | Initial layout: included `stack_base` and `stack_size` |
| 3 | Added the HHDM offset and the 64-entry module table |
| **4** | **Removed `stack_base` / `stack_size`** (the stack is passed to `context_switch` in registers); **added `bss_virt_base` / `bss_virt_size`** |

### Notes

- **There is no PML4 address in `KernelArgs`.** The loader keeps `pml4_phys` for
  its own `context_switch` and prints it over serial; the kernel recovers CR3
  itself.
- **`framebuffer_addr` is a physical address.** The virtual FB address
  (`0xFFFF_DEAD_0000_0000`) appears only in the `fb.virt=` environment key. The
  kernel defensively accepts either form.
- The memory map is the **UEFI** map, not E820. `CONVENTIONAL` → `MemoryKind::Free`,
  `BOOT_SERVICES_*` / `LOADER_*` → `Reclaim`, everything else → `Reserved`.

## Environment string

The bootloader builds a `key=value\n` string, max 4096 bytes:

```text
loader=strat9-bootloader-uefi
loader.version=0.1.0
loader.paging=wx-uc-v1
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

`loader.paging=wx-uc-v1` tells the kernel to call `retire_uefi_identity_code()`
and drop the UEFI identity mapping to read-only.

## Module table

```rust
#[repr(C)]
pub struct ModuleTable {
    pub count: u32,
    pub entries: [ModuleEntry; 64],   // MAX_BOOT_MODULES = 64
}

#[repr(C)]
pub struct ModuleEntry {
    pub name: [u8; 64],   // null-terminated filename
    pub base: u64,        // physical address
    pub size: u64,        // size in bytes
}
```

`ModuleTable` is 5128 bytes; `ModuleEntry` is 80 bytes. The kernel exposes them
in the VFS under `/initfs/<name>`.

## Build

```bash
cargo make bootloader-uefi          # debug
cargo make bootloader-uefi-release  # release
cargo make uefi-image               # bootable image
cargo make run-uefi                 # boot under OVMF
```

The image builder is `tools/scripts/create-uefi-image.sh`. The ESP spans
sectors 2048..526335 (256 MiB) of a GPT disk.

## Dependencies

- `uefi` 0.39 (UEFI protocols)
- `x86_64` 0.15 (page tables)
- `strat9-abi` (shared ABI definitions)

## Legacy BIOS bootloader

The NASM stage1/stage2 flow lives in **`asm/x86_64/`**, not `archive/asm/`. It is
legacy and the tree says so itself:

- `asm/Makefile` states that the standalone flow "is legacy and currently broken".
- Only the `assemble-bootloader` cargo-make task reaches it, and that task's own
  description begins with `LEGACY`.
- Only `stage1.asm` is actually assembled; the flow targets a BIOS/ISO path that
  is no longer produced.

Do not use it to describe how the system actually boots. See
[Boot Sequence](../../docs-site/src/boot-sequence.md).

## References

- [uefi-rs](https://github.com/rust-osdev/uefi-rs)
- [Phil Opp bootloader](https://github.com/rust-osdev/bootloader)
- [BOOTBOOT Protocol](https://gitlab.com/bztsrc/bootboot)
- [OSDev Wiki - Bootloader](https://wiki.osdev.org/Bootloader)

## License

GPLv3
