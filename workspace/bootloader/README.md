# strat9-os bootloader

Boot path for Strat9-OS. The **active** bootloader is [Limine](https://github.com/limine-bootloader/limine); this workspace also contains a custom, legacy multi-stage BIOS bootloader that is kept for reference.

## Active boot path: Limine

- Configuration: [`limine.conf`](../../limine.conf) at the repository root (Limine v8 format, `protocol: limine`, kernel at `boot():/boot/kernel.elf`).
- Image creation: `tools/scripts/create-limine-image.sh` (invoked by `cargo make limine-image`). Userspace modules are provided to the kernel as Limine internal modules from `/initfs/`.
- Kernel entry: Limine Boot Protocol handled in `workspace/kernel/src/boot/limine.rs`. The kernel builds its own `KernelArgs` (see below) from the Limine responses.
- Note: a legacy `limine.cfg` (v1-style format) still exists at the repository root but nothing references it; `limine.conf` is the file actually used.

## Legacy custom bootloader (this workspace)

A hand-written BIOS bootloader inspired by the Redox OS bootloader:

- `asm/x86_64/stage1.asm`: MBR boot sector (loaded by BIOS at `0x7C00`), reads stage 2 from disk via INT 13h extensions and jumps to it. Stage 2 is `%include`d at the end of stage 1 and assembled as a single flat binary (`build/boot.bin`, 17 sectors: 512-byte MBR + 8 KiB of stage 2).
- `asm/x86_64/stage2.asm`: real mode → protected mode → long mode transition, loads the kernel ELF from sector 17 into a buffer at `0x10000`, copies `PT_LOAD` segments, installs a minimal `KernelArgs` block at `0x60000` with a hardcoded memory-map entry, then jumps to the kernel entry point in long mode.
- Assembly is driven by `build.rs` (NASM) and/or `tools/scripts/assemble-bootloader.sh`; the resulting image layout matches `tools/scripts/create-image.sh` (boot.bin written at LBA 0, kernel at LBA 17).
- This path is legacy: `cargo make assemble-bootloader` / `cargo make boot-disk` are marked LEGACY in `Makefile.toml`, and no default run target uses it.

### Rust sources status

The Rust logic under `src/` (`main.rs`, `os/`, `arch/`, `disk.rs`, `ext4.rs`) is **not compiled today**: the cargo target list contains only `src/lib.rs` (an rlib re-exporting the boot ABI types), because `autobins = false` and no module tree is declared in `lib.rs`. These sources are an in-progress adaptation of the Redox OS bootloader (BIOS backend with VBE/VGA/INT 13h thunks, UEFI backend placeholder, EXT4 wrapper) and do not compile as-is yet; they are kept as reference for a future native bootloader.

## Kernel handoff ABI

The bootloader-to-kernel contract lives in the `strat9-abi` crate (`workspace/abi/src/boot.rs`):

- Magic `0x5354_3942` (`"ST9B"`), ABI version 1.
- `KernelArgs` is a 160-byte `#[repr(C)]` structure (kernel/stack/env base+size, ACPI RSDP, memory map, initfs, framebuffer description, HHDM offset, cmdline pointer).
- The memory map is an array of 24-byte `MemoryRegion { base, size, kind }` entries (`MemoryKind`: Null/Free/Reclaim/Reserved).

Both the legacy assembly stage 2 and the kernel's Limine entry produce/consume this exact structure.

## References

### Source code inspired by

- **Redox OS Bootloader**: <https://gitlab.redox-os.org/redox-os/bootloader>
  - Multi-stage BIOS/UEFI architecture
  - `KernelArgs` protocol
  - GDT and mode transitions

- **MaestroOS**: <https://github.com/llenotre/maestro>
  - Memory management (buddy allocator)
  - VGA console with ANSI escape codes
  - Linux compatibility approach

### Technical documentation

- [OSDev Wiki - Bootloader](https://wiki.osdev.org/Bootloader)
- [OSDev Wiki - Protected Mode](https://wiki.osdev.org/Protected_Mode)
- [OSDev Wiki - Long Mode](https://wiki.osdev.org/Long_Mode)
- [Intel Software Developer Manual](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html)
- [AMD64 Architecture Programmer's Manual](https://www.amd.com/en/support/tech-docs)
- [Limine Boot Protocol](https://github.com/limine-bootloader/limine/blob/trunk/PROTOCOL.md)

## License

Licensed under the GPLv3.
