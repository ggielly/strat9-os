# Strat9-OS bootloader : implementation

## Assembly (asm/x86_64/)

1. **gdt.asm** - Complete Global Descriptor Table
   - Segments for Real Mode, Protected Mode (32-bit), and Long Mode (64-bit)
   - Support for BIOS thunking (BIOS calls from protected mode)
   - GDTR for 32-bit and 64-bit

2. **print.asm** - Real mode display utilities
   - `print_line`: Displays CR+LF
   - `print`: Displays null-terminated string
   - `print_char`: Displays a character via INT 10h
   - `print_hex`: Displays a 16-bit number in hexadecimal

3. **cpuid.asm** - CPU feature detection and validation
   - Tests CPUID support (bit 21 of EFLAGS)
   - Checks required features: FPU, PSE, PGE, FXSR
   - Checks Long Mode (64-bit) support
   - Detailed error messages if features are missing

4. **protected_mode.asm** - Real mode → protected mode transition
   - Loads the GDT
   - Sets the PE bit (Protection Enable) in CR0
   - Far jump to reload CS
   - Loads all 32-bit data segments

5. **long_mode.asm** - Protected mode → long mode transition
   - Configuration of CR4 (PAE, PSE, PGE, OSFXSR)
   - Configuration of EFER MSR (LME, NXE)
   - Loading of CR3 with page table
   - Paging activation (CR0)
   - Far jump to 64-bit code

### Stage 1

- **stage1.asm** (512 bytes, MBR)
  - Loading of Stage 2 from disk (8 sectors)
  - Error handling with BIOS error codes
  - Progress display
  - Control transfer to 0x7E00

### Stage 2 

- **stage2.asm** (4KB max)
  - Enables A20 line (BIOS and keyboard controller methods)
  - Checks CPU features
  - Configures page tables (PML4, PDPT, PD)
  - Identity mapping of first 2GB with 2MB pages
  - Complete transitions: Real Mode → Protected Mode → Long Mode
  - Progress messages at each step

## Build system

1. **build.rs** - Cargo build script
   - Checks for NASM presence
   - Assembles stage1.asm and stage2.asm
   - Validates sizes (stage1: 512 bytes, stage2: max 4KB)
   - Exports binary paths

2. **asm/Makefile** - Alternative build
   - Targets: `all`, `clean`, `test`
   - Creates stage1.bin and stage2.bin binaries
   - Combines into bootloader.bin
   - Target `test` launches QEMU

## Technical architecture

### Memory layout

```bash
0x00000 - 0x004FF: BIOS Data Area (BDA)
0x00500 - 0x07BFF: Usable (28KB)
0x07C00 - 0x07DFF: Stage 1 (MBR, 512 bytes)
0x07E00 - 0x0BFFF: Stage 2 (4KB)
0x70000 - 0x73FFF: Page Tables (16KB)
  0x70000: PML4 (4KB)
  0x71000: PDPT (4KB)
  0x72000: PD (4KB)
0x90000: Stack (grows downward)
```

### Page Table Configuration

- **PML4[0]** → PDPT @ 0x71000
- **PDPT[0]** → PD @ 0x72000
- **PD[0-511]** → 2MB Pages (identity map 0-1GB)

Flags used: Present (bit 0), R/W (bit 1), User (bit 2), Page Size/PS (bit 7 for 2MB pages)

### GDT layout

| Selector | Segment | Base | Limit | Flags |
|----------|---------|------|-------|-------|
| 0x00 | Null | - | - | - |
| 0x08 | Code 64 | 0 | - | Long Mode |
| 0x10 | Data 64 | 0 | - | Long Mode |
| 0x18 | Code 32 | 0 | 4GB | Granular, 32-bit |
| 0x20 | Data 32 | 0 | 4GB | Granular, 32-bit |
| 0x28 | Code 16 | 0 | 64KB | 16-bit |
| 0x30 | Data 16 | 0 | 64KB | 16-bit |

## Current status and next steps

### Completed

- [x] Stage 1 complete (functional MBR)
- [x] Stage 2 complete (mode transitions)
- [x] GDT configuration
- [x] CPUID checking
- [x] A20 line enable
- [x] Page tables setup
- [x] Protected mode transition
- [x] Long mode transition
- [x] Build system (build.rs + Makefile)
- [x] Complete documentation

### In progress...

- [x] Stage 3 Rust bootloader (main.rs) : basic implementation complete
- [x] Integration with EXT4 filesystem
- [ ] ELF kernel loading
- [ ] KernelArgs population

### TODO

- [ ] Hardware testing
- [ ] UEFI support (uefi.rs)
- [ ] BIOS thunking for disk/video calls from protected mode
- [ ] Framebuffer setup
- [ ] ACPI RSDP detection
- [ ] Initramfs loading
- [ ] Memory map construction

## Recommended tests

### Test 1 : assembly

```bash
cd bootloader/asm
make clean && make
# Verify: stage1.bin = 512 bytes, stage2.bin <= 4096 bytes
```

### Test 2 : QEMU boot

```bash
cd bootloader/asm
make test
# Should display stage1 and stage2 messages
```

### Test 3 : cargo build

```bash
cd bootloader
cargo build --release
# Should assemble stages via build.rs
```

## Debugging notes

### Useful QEMU flags

```bash
-d int              # Log interrupts
-d cpu_reset        # Log CPU resets
-D qemu.log         # Output file
-no-reboot          # Stop instead of reboot
-no-shutdown        # Freeze instead of shutdown
-serial stdio       # Serial console on stdout
```

### GDB with 16-bit code

```gdb
set architecture i8086       # 16-bit real mode
break *0x7C00               # Breakpoint at MBR
break *0x7E00               # Breakpoint at stage2
x/10i $pc                   # Disassemble 10 instructions
info registers              # Display registers
```

### Common errors

1. **Stage 1 != 512 bytes**
   - Check padding `times 510-($-$$)`
   - Check signature 0xAA55

2. **Stage 2 too large (> 4KB)**
   - Optimize code
   - Move code to stage3 (Rust)

3. **A20 line not enabled**
   - Test with: `mov ax, 0xFFFF; mov ds, ax; mov word [0x10], 0x1234; cmp word [0x100000], 0x1234`
   - If equal, A20 is off

4. **Long mode activation fails**
   - Check CPUID long mode bit
   - Check page tables (present, R/W)
   - Check EFER MSR (LME bit)

## Source code references

### Files inspired by Redox OS

- GDT structure and layout
- Mode transitions (instruction sequence)
- CPUID checking pattern
- Stage1/Stage2 architecture
