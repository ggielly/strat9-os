# strat9-os Bootloader

Multi-stage bootloader for strat9.

## Architecture

The strat9 bootloader follows a 3-stage architecture:

```
┌─────────────────────────────────────────────┐
│  Stage 1 (MBR - 512 bytes)                  │
│  • Loaded by BIOS at 0x7C00                 │
│  • 16-bit Real Mode                         │
│  • Loads Stage 2 from disk                  │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  Stage 2 (4KB max)                          │
│  • Loaded at 0x7E00                         │
│  • Enables A20 line                         │
│  • Checks CPU features (CPUID)              │
│  • Configures page tables                   │
│  • Real Mode → Protected Mode → Long Mode   │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  Stage 3 (Rust bootloader)                  │
│  • 64-bit Long Mode                         │
│  • Mounts filesystem                        │
│  • Loads kernel                             │
│  • Passes control to kernel                 │
└─────────────────────────────────────────────┘
```

## File Structure

```
bootloader/
├── asm/                      # Assembly code
│   └── x86_64/
│       ├── stage1.asm        # MBR (512 bytes)
│       ├── stage2.asm        # Main Stage 2
│       ├── gdt.asm           # Global Descriptor Table
│       ├── print.asm         # Display utilities
│       ├── cpuid.asm         # CPU feature detection
│       ├── protected_mode.asm # Transition to protected mode
│       └── long_mode.asm     # Transition to long mode
├── src/
│   ├── main.rs               # Rust entry point (Stage 3)
│   ├── lib.rs                # Bootloader library
│   └── os/
│       ├── bios.rs           # BIOS implementation
│       └── uefi.rs           # UEFI implementation
├── build.rs                  # Build script (assembles with NASM)
└── Cargo.toml
```

## Stage 1 : MBR (0x7C00)
:
**File**: `asm/x86_64/stage1.asm`

The Master Boot Record (MBR) is the first code executed by the BIOS:

- **Size**: exactly 512 bytes (signature 0x55AA at the end)
- **Loading**: bIOS loads it at address 0x7C00
- **Function**: loads the next 8 sectors (4KB) to address 0x7E00
- **Error handling**: displays BIOS error code in hexadecimal

### Features :

- Initialization of segment registers (DS, ES, SS)
- Saving of boot disk number (DL)
- Screen clearing (80x25 text mode)
- Disk reading via INT 13h (function 02h)
- Progress message display
- Control transfer to Stage 2

## Stage 2 : mode transitions (0x7E00)

**File**: `asm/x86_64/stage2.asm`

Stage 2 performs all necessary mode transitions to reach 64-bit long mode:

### 1. A20 line activation

- **Method 1**: BIOS INT 15h, AX=2401h
- **Method 2**: Keyboard controller (ports 0x60/0x64)
- **Effect**: Allows access to more than 1MB of memory

### 2. CPU verification (CPUID)

- Testing CPUID support (bit 21 of EFLAGS)
- Checking required features:
  - **FPU** (bit 0): Floating Point Unit
  - **PSE** (bit 3): Page Size Extension
  - **PGE** (bit 13): Page Global Enable
  - **FXSR** (bit 24): FXSAVE/FXRSTOR
  - **Long Mode** (extended function 0x80000001, bit 29)
- Displaying detailed error messages if a feature is missing

### 3. Page table configuration

- **PML4** (Page Map Level 4): 0x70000
- **PDPT** (Page Directory Pointer Table): 0x71000
- **PD** (Page Directory): 0x72000
- **Mapping**: Identity mapping of first 2GB with 2MB pages

### 4. Real mode → protected mode transition
**File**: `protected_mode.asm`

```asm
1. CLI (disable interrupts)
2. LGDT (load GDT)
3. CR0 |= PE (Protection Enable)
4. Far JMP (reload CS)
5. Load 32-bit data segments
```

### 5. Protected mode → long mode transition
**File**: `long_mode.asm`

```asm
1. CLI (disable interrupts)
2. CR0 &= ~PG (temporarily disable paging)
3. CR4 |= PAE | PSE | PGE | OSFXSR
4. CR3 = page_table_base
5. EFER MSR |= LME | NXE (Long Mode Enable, No-Execute)
6. CR0 |= PG | WP | PE (enable paging)
7. LGDT (load 64-bit GDT)
8. Far JMP to 64-bit code segment
9. Load 64-bit data segments
```

## GDT (Global Descriptor Table)

**File**: `asm/x86_64/gdt.asm`

The GDT defines memory segments for each mode:

| Offset | Segment | Description |
|--------|---------|-------------|
| 0x00 | Null | Null descriptor (mandatory) |
| 0x08 | Code 64-bit | Long Mode code segment |
| 0x10 | Data 64-bit | Long Mode data segment |
| 0x18 | Code 32-bit | Protected Mode code segment |
| 0x20 | Data 32-bit | Protected Mode data segment |
| 0x28 | Code 16-bit | BIOS thunking code segment |
| 0x30 | Data 16-bit | BIOS thunking data segment |

## Stage 3 : Rust bootloader

**File**: `src/main.rs`

Stage 3 runs in 64-bit long mode:

### Responsibilities:

1. Initialize the heap allocator
2. Configure serial console (debug)
3. Detect available memory
4. Mount the EXT4 filesystem
5. Load the ELF kernel from `/boot/kernel`
6. Parse ELF headers and load segments
7. Configure kernel arguments (`KernelArgs`)
8. Transfer control to the kernel

### KernelArgs structure

```rust
#[repr(C, packed(8))]
pub struct KernelArgs {
    kernel_base: u64,
    kernel_size: u64,
    stack_base: u64,
    stack_size: u64,
    env_base: u64,
    env_size: u64,
    acpi_rsdp_base: u64,
    acpi_rsdp_size: u64,
    areas_base: u64,          // Memory map
    areas_size: u64,
    bootstrap_base: u64,       // Initramfs
    bootstrap_size: u64,
}
```

## Compilation

### Prerequisites

- **NASM** (Netwide Assembler): To assemble stages 1 and 2
  - Installation: `apt install nasm` (Linux) or download from https://www.nasm.us/
- **Rust nightly**: With components `rust-src` and `llvm-tools`
  ```bash
  rustup component add rust-src llvm-tools
  ```

### Build

```bash
# From Strat9-OS root directory
cargo build --release

# Or from bootloader directory
cd bootloader
cargo build --release
```

The `build.rs` script:
1. Verifies NASM is installed
2. Assembles `stage1.asm` → `stage1.bin` (512 bytes)
3. Assembles `stage2.asm` → `stage2.bin` (max 4KB)
4. Verifies sizes
5. Binaries are available in `$OUT_DIR/`

### Makefile (alternative)

A Makefile is also available in `asm/`:

```bash
cd bootloader/asm
make            # Compile stage1 and stage2
make test       # Launch QEMU with the bootloader
make clean      # Clean artifacts
```

## Test

### QEMU

```bash
# Create a bootable disk image
dd if=/dev/zero of=boot.img bs=512 count=2880  # 1.44MB floppy
dd if=stage1.bin of=boot.img conv=notrunc       # Write MBR
dd if=stage2.bin of=boot.img bs=512 seek=1 conv=notrunc

# Launch QEMU
qemu-system-x86_64 \
    -drive format=raw,file=boot.img \
    -serial stdio \
    -no-reboot \
    -no-shutdown
```

### Expected output

```
Strat9-OS Stage 1 Bootloader
Stage 2 loaded successfully
Jumping to Stage 2...

Strat9-OS Stage 2 Bootloader
Enabling A20 line... [OK]
Checking CPU features... [OK]
Setting up page tables... [OK]
Entering protected mode...
```

## Debugging

### QEMU with GDB

```bash
# Terminal 1: Launch QEMU with GDB stub
qemu-system-x86_64 \
    -drive format=raw,file=boot.img \
    -s -S

# Terminal 2: Connect GDB
gdb
(gdb) target remote :1234
(gdb) set architecture i8086    # For 16-bit code
(gdb) break *0x7C00             # Breakpoint at MBR
(gdb) continue
```

### QEMU logs

```bash
qemu-system-x86_64 \
    -drive format=raw,file=boot.img \
    -d int,cpu_reset \
    -D qemu.log
```

The `qemu.log` file will contain interrupts and CPU resets.

## References

### Source code inspired by:
- **Redox OS Bootloader**: https://gitlab.redox-os.org/redox-os/bootloader
  - Multi-stage BIOS/UEFI architecture
  - `KernelArgs` protocol
  - GDT and mode transitions

- **MaestroOS**: https://github.com/llenotre/maestro
  - Memory management (buddy allocator)
  - VGA console with ANSI escape codes
  - Linux compatibility approach

### Technical documentation:
- [OSDev Wiki - Bootloader](https://wiki.osdev.org/Bootloader)
- [OSDev Wiki - Protected Mode](https://wiki.osdev.org/Protected_Mode)
- [OSDev Wiki - Long Mode](https://wiki.osdev.org/Long_Mode)
- [Intel Software Developer Manual](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html)
- [AMD64 Architecture Programmer's Manual](https://www.amd.com/en/support/tech-docs)

## License

Licensed under the GPLv3.

