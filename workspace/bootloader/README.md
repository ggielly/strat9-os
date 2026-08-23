# strat9-os bootloader

UEFI bootloader for strat9-os, with BIOS support (archived).

## Architecture

The bootloader follows a BOOTBOOT-inspired design with fixed virtual addresses:

```text
Virtual Memory Layout:
  0xFFFF_DEAD_0000_0000  → Framebuffer (DEAD)
  0xFFFF_BEEF_0000_0000  → Environment string (BEEF)
  0xFFFFFFFF_8000_0000  → Kernel code/data
  0x0000_0000_0000_0000  → Identity map (first 8GB)
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
  ├── 3. Load modules from /boot/initfs/ (known filenames)
  ├── 4. GOP → framebuffer
  ├── 5. GetMemoryMap → memory regions
  ├── 6. ACPI RSDP → config table
  ├── 7. Build environment string (key=value)
  ├── 8. ExitBootServices() → bare metal
  ├── 9. Create page tables (identity + higher-half + framebuffer)
  └── 10. Context switch → _start (boot64.S) with KernelArgs in RDI
```

## KernelArgs (ABI v4, 132 bytes, `#[repr(C, packed)]`)

The authoritative definition lives in `workspace/abi/src/boot.rs`. The kernel
entry symbol is `_start` (`workspace/kernel/src/boot/boot64.S`), which calls
`kmain(args_ptr)`; a null RDI means "no arguments" (PVH boot). The PML4 is not
part of the struct: the bootloader loads it into CR3 before the jump.

| Field | Type | Description |
|---|---|---|
| `magic` | u32 | 0x53543942 ("ST9B") |
| `abi_version` | u32 | `STRAT9_BOOT_ABI_VERSION` (currently 4) |
| `kernel_base` | u64 | Physical address of first loaded segment |
| `kernel_size` | u64 | Physical span covered by the kernel image (incl. BSS margin) |
| `acpi_rsdp_base` | u64 | Physical address of RSDP |
| `memory_map_base` | u64 | Physical address of MemoryRegion array |
| `memory_map_size` | u64 | Size of memory map in bytes |
| `framebuffer_addr` | u64 | **Virtual** address (0xFFFF_DEAD_...) |
| `hhdm_offset` | u64 | Currently always 0 (the 8 GB identity map serves as direct map) |
| `cmdline_ptr` | u64 | Physical address of environment string |
| `cmdline_len` | u64 | Length of environment string (with NUL) |
| `modules_base` | u64 | Physical address of ModuleTable |
| `modules_size` | u64 | Size of ModuleTable |
| `framebuffer_width` | u32 | Width in pixels |
| `framebuffer_height` | u32 | Height in pixels |
| `framebuffer_stride` | u32 | Bytes per row |
| `framebuffer_bpp` | u16 | Bits per pixel |
| `framebuffer_*_mask_*` | u8×6 | RGB channel masks |
| `bss_virt_base` | u64 | Virtual start of the zero-init region |
| `bss_virt_size` | u64 | Size of the mapped-but-not-file-backed region |

There is no boot-stack field: the kernel allocates its own stack after the
buddy allocator is up (boot64.S only provides a 64 KiB bootstrap stack).

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

Modules are looked up by a **hardcoded list of known filenames** under
`/boot/initfs/` (see `src/modules.rs`); missing files are silently skipped,
and the table is capped at 64 entries.

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

Note: this struct is duplicated between `src/modules.rs` (bootloader side)
and `workspace/abi/src/boot.rs` (kernel side) and must stay in sync.

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

- `uefi` 0.39 (UEFI protocols, allocator, logger, panic handler)
- `strat9-abi` (shared ABI definitions)

## Security model & hardening

### Trust model (alpha)

The boot volume (ESP) is currently treated as **trusted input**: nothing is
signature-verified yet, which is an explicit alpha-mode trade-off for
simplicity. Anyone able to write `\boot\kernel.elf` or `/boot/initfs/*`
controls what the loader executes and hands to the kernel. The hardening
below therefore focuses on *memory-safety of the loader itself* and on not
amplifying a corrupted input into loader-level memory corruption.

### Implemented hardening

| Area | Guarantee |
|---|---|
| ELF parsing (`src/elf.rs`) | All header/program-header accesses bounds-checked with checked arithmetic; higher-half `p_paddr` rebasing restricted to `[KERNEL_VIRT_BASE, KERNEL_VIRT_BASE + 16 MiB)` — no integer wrap can produce an out-of-window physical write; segments outside the supported window are fatal errors instead of silently skipped |
| Kernel mapping | Per-segment W^X built from ELF `p_flags`: writable data/stack get `W`, only code stays executable, everything else read-only; identity map is RW+NX and `EFER.NXE` is enabled before CR3 is loaded so NX is actually enforced |
| Page tables | Table frames allocated above the kernel image are validated against the final memory map before use; the whole window must lie inside usable RAM |
| Framebuffer | Mapped with exact-span 4 KiB pages (no 2 MiB rounding over neighbouring MMIO) in **Write-Combining** via a dedicated IA32_PAT entry (entry 4 programmed at context switch, PTE PAT bit on the fb mapping only) |
| File reads | Full-read loops for `kernel.elf` and initfs modules; truncated images are rejected/skipped, never partially executed |
| Allocation limits | `kernel.elf` and each module capped at 64 MiB; oversized inputs are rejected instead of OOM-ing the loader |
| Memory map | Every bootloader allocation (map itself, boot stack with guard page, module table, env string, `KernelArgs`) is carved out of Free regions; the handed-over map never lists them as available |
| `KernelArgs` placement | Built on a carved page, not on the firmware stack (which is Reclaim-classified after EBS) |
| Post-EBS failures | All fatal paths after `ExitBootServices` use a raw COM1 + `cli;hlt` path (`paging::fatal`), never UEFI services or panics |
| ACPI | RSDP checksum-validated (config table first, then bounded physical scan); XSDT/RSDT checksum covers the full declared length; degenerate lengths (<36 B) rejected |
| Kernel side | `kernel_main` reserves the kernel image, every boot page-table frame (CR3 walk) and all module data ranges from the working map *before* the boot/buddy allocators initialize |

### Signing roadmap (not implemented, by design for alpha)

Planned minimal scheme, kept deliberately simple:

1. A detached digest manifest (`\boot\kernel.sha256`, optionally
   `/boot/initfs.sha256` with one line per module) is written next to the
   artifacts at image-build time.
2. The bootloader hashes the bytes it just read and compares against the
   manifest **before** parsing/executing anything. Mismatch ⇒ refuse to boot
   (raw serial message). No manifest ⇒ proceed, and export
   `digest.ok=0/1` through the environment string so the kernel can decide.
   A `require_digest=1` env entry will make absence fatal.
3. Hash implementation: small self-contained SHA-256 in the bootloader (no
   external crates — see the ed25519-dalek/LLVM issues in this repo's
   history). Asymmetric signatures (Ed25519 over the manifest) are a later
   step once the toolchain issue is settled.

If/when kernel-side verification is wanted (defense in depth), the two
insertion points are:

- kernel image digest: `boot::dtb_boot::kmain`, right after the
  `STRAT9_BOOT_MAGIC` check, hashing `[kernel_base, kernel_base+kernel_size)`
  against a `kernel.digest=` environment entry written by the loader;
- module digests: `register_boot_modules()` in `workspace/kernel/src/lib.rs`,
  before modules are registered into the VFS.

Both depend on the bootloader exporting the expected values through the
environment string, which is why the two sides must evolve together.

## Archived

The old BIOS bootloader (NASM stage1/stage2) is still present in `asm/` but is
legacy: nothing in the default build flow assembles it, and its standalone
Makefile (`asm/Makefile`) is broken (stage1 embeds stage2 via `%include`, so
the "512 bytes" and "standalone stage2" assumptions no longer hold).

## References

- [uefi-rs](https://github.com/rust-osdev/uefi-rs)
- [Phil Opp bootloader](https://github.com/rust-osdev/bootloader)
- [BOOTBOOT Protocol](https://gitlab.com/bztsrc/bootboot)
- [OSDev Wiki - Bootloader](https://wiki.osdev.org/Bootloader)

## License

GPLv3
