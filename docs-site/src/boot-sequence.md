# Boot Sequence

Strat9 OS boots on x86_64 via the UEFI bootloader. The boot flow transitions from 16-bit real mode through protected mode to 64-bit long mode before jumping into Rust.

---

## Boot flow

```mermaid
flowchart TD
    A[BIOS/UEFI] --> B[MBR / Stage 1]
    B --> C[Stage 2]
    C --> D[UEFI Bootloader]
    D --> E[kstart - Assembly]
    E --> F[start - Rust init]
    F --> G[main.rs - Kernel main]

    style A fill:#333,color:#fff
    style D fill:#1a6b3a,color:#fff
    style G fill:#1a6b3a,color:#fff
```

---

## Stage 1 : MBR bootloader (`bootloader/asm/`)

The bootloader is written in NASM assembly. Stage 1 fits in exactly 512 bytes (MBR).

**Responsibilities:**

1. Load Stage 2 from disk (LBA reads via BIOS INT 13h)
2. Enable A20 line
3. Enter protected mode (32-bit)
4. Jump to Stage 2

---

## Stage 2 : Protected → Long mode

**Responsibilities:**

1. Detect available memory (INT 15h, E820)
2. Load the kernel binary from disk
3. Set up initial page tables (identity mapping + higher-half)
4. Enable PAE, PGE, long mode
5. Jump to 64-bit code

---

## UEFI bootloader handoff

The kernel is loaded by the UEFI bootloader. The bootloader provides:

- Memory map (E820 equivalent)
- HHDM (Higher Half Direct Map) base address
- PML4 physical address
- RSDP (ACPI tables)
- Framebuffer info

The `KernelArgs` struct captures all handoff data:

```text
KernelArgs {
    hhdm_offset: u64,       // Higher-half direct map base
    pml4_physical: u64,     // Boot page table
    acpi_rsdp: Option<NonNull<u8>>,  // ACPI RSDP
    memory_regions: &[MemoryRegion],  // E820 memory map
    framebuffer: FramebufferInfo,     // VGA/framebuffer
}
```

---

## Kernel entry : `kstart` (assembly)

Located in `boot/boot64.S`:

1. Verify BSS is zero, data is non-zero (sanity check)
2. Set up kernel stack (128 KiB, from `STACK` static)
3. Jump to `start()` (Rust)

---

## Kernel init : `start()` (Rust)

Located in `boot/boot.rs` → `main.rs`:

```mermaid
flowchart TD
    A[serial::init] --> B[gdt::init_bsp]
    B --> C[idt::init_bsp]
    C --> D[memory::init]
    D --> E[paging::init]
    E --> F[interrupt::syscall::init]
    F --> G[allocator::init - buddy + slab]
    G --> H[acpi::init - parse MADT/IOAPIC]
    H --> I[apic::init - Local APIC]
    I --> J[smp::init - boot APs]
    J --> K[timer::init - APIC timer]
    K --> L[process::init - scheduler]
    L --> M[shell::init - init process]
    M --> N[scheduler::run - never returns]
```

**Key init steps:**

| Step | Module | What happens |
|------|--------|-------------|
| Serial | `serial.rs` | Initialize COM1 (0x3F8) at 115200 baud |
| GDT | `gdt.rs` | Set up kernel/user code/data segments |
| IDT | `idt.rs` | Install interrupt handlers (timer, syscall, page fault) |
| Memory | `memory/` | Parse E820, initialize buddy allocator |
| Paging | `paging.rs` | Set up kernel page tables (HHDM + higher-half) |
| Syscall | `syscall.rs` | Install `syscall`/`sysret` MSRs |
| Heap | `heap.rs` | Initialize slab allocator on top of buddy |
| ACPI | `acpi/` | Parse MADT (APICs), IOAPIC, interrupt overrides |
| APIC | `apic.rs` | Initialize Local APIC (xAPIC or x2APIC) |
| SMP | `smp.rs` | INIT+SIPI sequence to boot Application Processors |
| Timer | `timer.rs` | Calibrate and start APIC timer (periodic) |
| Scheduler | `scheduler/` | Create per-CPU run queues, spawn idle tasks |
| Init | `shell/` | Spawn the first userspace process (init) |

---

## SMP boot : Application Processors

```mermaid
sequenceDiagram
    participant BSP
    participant TRAMP as Trampoline (0x8000)
    participant AP

    BSP->>TRAMP: Copy trampoline to 0x8000
    BSP->>TRAMP: Write CR3 + RSP to data area
    BSP->>AP: INIT IPI (0x4500)
    Note right of AP: 16-bit real mode
    BSP->>AP: SIPI (vector=0x8 → 0x8000)
    TRAMP->>AP: Enable protected mode
    TRAMP->>AP: Enable long mode + paging
    TRAMP->>AP: Load kernel stack
    TRAMP->>AP: Jump to smp_main (Rust)
    AP->>BSP: BOOTED_CORES++
    BSP->>BSP: Wait for all APs
    BSP->>AP: Open scheduler gate
    AP->>AP: Start per-CPU scheduler
```
