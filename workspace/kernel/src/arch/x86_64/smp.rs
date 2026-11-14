/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! SMP (Symmetric Multi-Processing) boot for x86_64.
//!
//! Boots Application Processors (APs) using the legacy INIT+SIPI sequence.
//! Inspired by Redox-OS's approach: a minimal trampoline does the 16=>64 bit
//! mode switch, then jumps directly to `smp_main` in Rust.
//!
//! Data layout after the trampoline code (written by BSP, read by AP):
//!   offset +0:  PML4 physical address (CR3)
//!   offset +8:  legacy kernel stack top virtual address (first AP only)
//!   offset +16: virtual address of `AP_STACK_TOPS` (per-APIC stack table)
//!
//! Synchronization: AP increments `BOOTED_CORES` after finishing per-CPU init.
//! BSP spins until all expected APs are online.

use core::{
    arch::global_asm,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

use alloc::vec::Vec;
use x86_64::{
    structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};

use crate::{
    acpi::madt,
    arch::x86_64::{apic, idt, io::io_wait, percpu, timer},
    memory,
};

/// Physical address where the SMP trampoline is copied.
pub const TRAMPOLINE_PHYS_ADDR: u64 = 0x8000;

/// Maximum APIC ID (0..=4095) addressable by the per-AP stack table.
/// x2APIC IDs can exceed 255, so the table spans 16 KiB of `AtomicU64`
/// entries (32 KiB .bss); IDs above this are simply skipped.
const MAX_APIC_IDS: usize = 4096;

/// Per-APIC-ID kernel stack top, read by the 64-bit trampoline stub.
///
/// Each AP indexes this table with its own APIC ID, so a late AP can never
/// pick up another AP's stack from a single shared slot. A zero entry means
/// "no stack assigned": the stub halts rather than using address 0.
static AP_STACK_TOPS: [AtomicU64; MAX_APIC_IDS] = [const { AtomicU64::new(0) }; MAX_APIC_IDS];

/// Number of booted cores (starts at 1 for BSP).
static BOOTED_CORES: AtomicUsize = AtomicUsize::new(1);
/// Counter for synchronization barriers.
static SYNC_BARRIER: AtomicUsize = AtomicUsize::new(0);
/// Target count for the rendezvous barrier (set by BSP before barrier).
static BARRIER_TARGET: AtomicUsize = AtomicUsize::new(0);
/// Gate used by BSP to release APs into scheduler/timer start.
static AP_SCHED_GATE_OPEN: AtomicBool = AtomicBool::new(false);
/// AP ACK: set to apic_id by each AP at start of smp_main(), BSP waits for it.
/// Sentinel usize::MAX means "no ACK yet" (avoids collision with APIC ID 0).
static AP_REACHED_RUST: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Set by the BSP once the AP boot window is closed. An AP that publishes its
/// online bit after this becomes `true` revokes it and halts instead of joining
/// the scheduler too late (after `init_scheduler` has already run on the BSP).
static BOOT_WINDOW_CLOSED: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Trampoline: 16-bit => 32-bit => 64-bit mode switch.
//
// The AP starts in real mode at the SIPI vector (0x8000).  This stub:
//   1. Loads a GDT embedded at known physical offsets.
//   2. Enables protected mode, then PAE + long mode + paging.
//   3. Loads the kernel PML4 (CR3) and kernel stack (RSP) from the data area.
//   4. Jumps to smp_main (64-bit Rust code).
//
// LAYOUT (physical addresses, copied to 0x8000):
//   0x8000:  cli ; cld ; ljmp 0, 0x8040         (16-bit)
//   0x8010:  _gdt_table  (32 bytes: null, code64, data, code32)
//   0x8030:  _gdt        (GDTR: limit=31, base=0x8010)
//   0x8040:  real-mode setup (xor ax,ax; lgdt; enter PM)
//   SMP_PM_ADDR:   32-bit code (PAT programming, PAE + NXE + LME + paging)
//   SMP_LONG_ADDR: 64-bit code (load stack, jump to smp_main)
//
// CRITICAL: The GDT table and descriptor MUST occupy these exact offsets.
// The `lgdt [0x8030]` instruction reads physical 0x8030 which contains the
// GDTR. Without this embedded GDT data, the AP loads garbage and triple-faults.
//
// Data area (at smp_trampoline_end, written by BSP via HHDM):
//   +0  u64: CR3 (PML4 physical address)
//   +8  u64: legacy RSP (kernel stack top virtual address)
//   +16 u64: virtual address of AP_STACK_TOPS (indexed by APIC ID)
// ---------------------------------------------------------------------------
#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
.pushsection .text, "ax", @progbits
.code16

.global smp_trampoline
.global smp_trampoline_end
# Exported only so the Rust side can assert the hard-coded physical layout.
.global smp_gdt_table
.global smp_gdt_descr
.global smp_pm_setup

.set SMP_VAR_ADDR, 0x8000 + (smp_trampoline_end - smp_trampoline)
.set SMP_PM_ADDR, 0x8000 + (smp_trampoline_32 - smp_trampoline)
.set SMP_LONG_ADDR, 0x8000 + (smp_trampoline_64 - smp_trampoline)

# The GDT/GDTR/real-mode prologue use hard-coded physical offsets (0x8010,
# 0x8030, 0x8040) because they are reached before any relocation logic
# exists. Those offsets are only valid if the stub itself lands on a 16-byte
# boundary: `.align` is relative to the SECTION, not to the label, so an
# unaligned `smp_trampoline` would silently shift everything and the AP
# would triple-fault on `lgdt [0x8030]`. Pin it and assert the layout below.
.balign 16
smp_trampoline:
    cli
    cld
    # Jump over the GDT data : code continues at 0x8040.
    ljmp 0, 0x8040

# -------------------------------------------------------------------
# GDT : must be at physical offset 0x10 so that:
#   _gdt_table starts at 0x8010, _gdt (GDTR) is at 0x8030.
# -------------------------------------------------------------------
.align 16
smp_gdt_table:
_gdt_table:
    .long 0, 0                       # null  (selector 0)
    .long 0x0000ffff, 0x00af9b00     # code64, accessed (identity page is RX)
    .long 0x0000ffff, 0x00cf9300     # data, accessed
    .long 0x0000ffff, 0x00cf9b00     # code32, accessed
smp_gdt_descr:
_gdt:
    .word _gdt - _gdt_table - 1      # limit = 31 (4 entries × 8 - 1)
    .long 0x8010                     # base  = 0x8010
    .long 0, 0                       # padding
.align 64

# -------------------------------------------------------------------
# Real-mode setup continues at 0x8040.
# -------------------------------------------------------------------
smp_pm_setup:
    xor ax, ax
    mov ds, ax
    lgdt [0x8030]                    # loads GDTR from 0x8030

    # Enter protected mode
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    # Far JMP ptr16:16 (EA iw iw). LLVM's Intel-syntax `ljmp` rejects
    # this forward expression; data directives resolve it after layout.
    # The trampoline lives entirely in 0x8000..0x8fff, so IP fits in u16.
    .byte 0xea
    .word SMP_PM_ADDR
    .word 24                        # => code32 segment

.align 32
.code32
smp_trampoline_32:
    mov ax, 16
    mov ds, ax
    mov ss, ax

    # INIT does not reset PAT, and firmware may leave no WC slot. Program the
    # kernel layout before enabling paging so this AP indexes the same memory
    # types as the BSP: PA0=WB, PA1=WC, PA2=WT, PA3=UC.
    #
    # Selectors are BYTE-spaced in IA32_PAT (PA0 bits 2:0, PA1 bits 10:8,
    # PA2 bits 18:16, PA3 bits 26:24) => 6 | (1<<8) | (4<<16) = 0x40106.
    # Packing them as 3-bit fields sets reserved bits and #GPs on real CPUs.
    #
    # NOTE: this constant duplicates arch/x86_64/pat::PAT_WC_VALUE; the 32-bit
    # real-mode/protected-mode trampoline cannot call into Rust.
    #
    # Gate on CPUID.01H:EDX[16] (PAT): WRMSR to an unsupported MSR is a #GP,
    # and there is no IDT yet on this AP => triple fault.
    mov eax, 1
    xor ecx, ecx
    cpuid
    test edx, 0x10000
    jz 4f

    mov ecx, 0x277
    mov eax, 0x40106
    xor edx, edx
    wrmsr

    # Verify the four low selectors (PA0..PA3) survived the write; stop this
    # AP explicitly if the CPU refuses the WC layout.
    mov ecx, 0x277
    rdmsr
    and eax, 0x07070707
    cmp eax, 0x40106
    je 4f
    mov al, 0x50                     # E9: P (PAT mismatch)
    out 0xe9, al
2:  hlt
    jmp 2b
4:
    mov eax, cr0
    or eax, 0x40000000              # CD = 1
    and eax, 0xdfffffff             # NW = 0
    mov cr0, eax
    wbinvd

    # Enable PAE + PSE + OSFXSR + OSXMMEXCPT
    # NOTE: do NOT force SMEP/SMAP (CR4 bits 20/21) here. qemu64 (and many
    # older hosts) lack them: `mov cr4` then raises #GP and the AP dies
    # silently (no IDT yet -> triple fault -> "waiting for APs" hang).
    # Feature-gated bits (OSXSAVE, SMEP, SMAP) are enabled conditionally
    # in Rust once CPUID detection has run.
    mov eax, cr4
    or eax, 0x630
    mov cr4, eax

    # Enable Long Mode (EFER.LME)
    #
    # NXE (bit 11) is only writable if CPUID.80000001H:EDX[20] is set; without
    # the check, `wrmsr` takes a #GP and, with no IDT yet on this AP, a triple
    # fault. Mirror the PAT guard above.
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb 5f
    mov eax, 0x80000001
    xor ecx, ecx
    cpuid
    test edx, 0x100000               # EDX[20] = NX
    jz 5f

    mov ecx, 0xc0000080
    rdmsr                            # (rdmsr already overwrites EDX)
    or eax, 0x901                    # NXE + LME + SCE
    wrmsr
    jmp 6f
5:
    mov ecx, 0xc0000080
    rdmsr
    or eax, 0x101                    # LME + SCE, no NXE
    wrmsr
6:

    # Load kernel PML4 from data area.
    # NOTE: only the low 32 bits are loaded (we are still in 32-bit mode), so
    # the PML4 must live below 4 GiB. copy_trampoline() asserts this.
    mov eax, [SMP_VAR_ADDR]
    mov cr3, eax

    # Enable paging (activates long mode)
    mov eax, cr0
    and eax, 0x9FFFFFF3              # Clear CD/NW/EM/TS
    or eax, 0x80010002               # PG + WP + MP
    mov cr0, eax

    # Far JMP ptr16:32 (EA id iw), decoded while CS is still 32-bit.
    # Keep the destination symbolic when the preceding stub changes size.
    .byte 0xea
    .long SMP_LONG_ADDR
    .word 8                         # => code64 segment

.align 32
.code64
smp_trampoline_64:
    # Resolve this AP's kernel stack from the per-APIC stack table *before*
    # using the stack. RSP is not yet valid here (the AP is in a reset-like
    # state), so RBX is preserved across CPUID in R8 rather than by push/pop.
    #
    # APIC ID may be up to 32 bits on x2APIC systems: prefer the x2APIC ID
    # from leaf 0x1F/0xB (EDX) and fall back to leaf 1 EBX[31:24] otherwise.
    mov r8, rbx                     # preserve RBX across CPUID
    xor eax, eax
    cpuid                           # EAX = max basic CPUID leaf
    cmp eax, 0x1f
    jae .Lapic_leaf_1f
    cmp eax, 0x0b
    jae .Lapic_leaf_0b
    jmp .Lapic_leaf_1
.Lapic_leaf_1f:
    mov eax, 0x1f
    xor ecx, ecx
    cpuid                           # EDX = x2APIC ID
    test edx, edx
    jnz .Lapic_have_id
    jmp .Lapic_leaf_1
.Lapic_leaf_0b:
    mov eax, 0x0b
    xor ecx, ecx
    cpuid                           # EDX = x2APIC ID
    test edx, edx
    jnz .Lapic_have_id
    jmp .Lapic_leaf_1
.Lapic_leaf_1:
    mov eax, 1
    xor ecx, ecx
    cpuid
    mov edx, ebx                    # EBX[31:24] = initial APIC ID
    shr edx, 24
.Lapic_have_id:
    mov rbx, r8                     # restore RBX
    mov ecx, edx                    # ECX = APIC ID
    and ecx, 0xfff                  # mask to table index range
    mov rsp, [SMP_VAR_ADDR + 16]    # table base (virtual address)
    mov rsp, [rsp + rcx*8]          # AP_STACK_TOPS[apic_id]
    test rsp, rsp
    jnz 7f
8:  cli
    hlt                             # no stack assigned: stop this AP
    jmp 8b
7:
    # We arrive via `jmp`, not `call`, so no return address was pushed. The
    # SysV ABI requires RSP % 16 == 8 *at function entry* (it is 16-aligned at
    # the call site, minus the 8-byte return address). Stack tops are page
    # aligned, so bias RSP by 8 to keep the invariant; otherwise any
    # movaps/movdqa spill emitted by smp_main's prologue raises #GP.
    sub rsp, 8

    # Clear RFLAGS.IF only, preserve architectural default state.
    # pushfq reads RFLAGS; AND clears IF (bit 9); popfq restores.
    pushfq
    pop rax
    btr rax, 9             # IF = 0
    push rax
    popfq

    # Jump to smp_main (Rust)
    # NOTE: must use movabs (64-bit absolute), NOT RIP-relative lea.
    # The trampoline is copied to 0x8000, so RIP-relative would compute
    # an offset based on the wrong base address (the linker's original
    # placement in the kernel .text section, not 0x8000).
    movabs rax, offset smp_main
    jmp rax

.align 8
smp_trampoline_end:

# -------------------------------------------------------------------
# Layout invariants are verified at runtime by copy_trampoline() (the LLVM
# integrated assembler cannot evaluate label differences in `.if`): the
# 16-bit prologue jumps to *hard-coded* physical addresses, so any drift
# becomes a silent triple fault on AP boot. Checked here instead.
# -------------------------------------------------------------------
.popsection
"#
);

unsafe extern "C" {
    fn smp_trampoline();
    fn smp_trampoline_end();
    fn smp_gdt_table();
    fn smp_gdt_descr();
    fn smp_pm_setup();
}

/// Busy-wait for the given number of microseconds.
///
/// Uses the TSC when its frequency is known (it is seeded to a conservative
/// default before calibration). Falls back to the old `io_wait` loop only if
/// no frequency is available at all.
fn udelay(us: u32) {
    let khz = crate::arch::x86_64::boot_timestamp::tsc_khz();
    if khz == 0 {
        for _ in 0..us {
            io_wait();
        }
        return;
    }
    let ticks = (us as u64).saturating_mul(khz) / 1_000;
    let start = crate::arch::x86_64::rdtsc();
    while crate::arch::x86_64::rdtsc().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}

/// Convert a duration in milliseconds to TSC ticks, or 0 when unknown.
fn tsc_ticks_for_ms(ms: u64) -> u64 {
    let khz = crate::arch::x86_64::boot_timestamp::tsc_khz();
    if khz == 0 {
        return 0;
    }
    khz.saturating_mul(ms)
}

/// Halt this CPU forever (interrupts disabled). Used to retire an AP that
/// arrived outside the boot window or was not registered.
fn halt_forever() -> ! {
    loop {
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Identity-map the trampoline physical pages so the AP can execute the
/// trampoline code in real mode / protected mode before paging is enabled.
fn ensure_identity_mapping(phys_start: u64, length: usize) -> Result<(), &'static str> {
    let start = phys_start & !0xFFFu64;
    let end = (phys_start + length as u64 + 0xFFF) & !0xFFFu64;
    let flags = PageTableFlags::PRESENT;

    let mut addr = start;
    while addr < end {
        let virt = VirtAddr::new(addr);
        if let Some(mapped) = crate::memory::paging::translate(virt) {
            if mapped.as_u64() != addr {
                return Err("SMP: trampoline identity map collision");
            }
            crate::memory::paging::set_trampoline_execution(addr, true)?;
        } else {
            let page = Page::<Size4KiB>::containing_address(virt);
            let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(addr));
            crate::memory::paging::map_page(page, frame, flags)?;
        }
        addr += 0x1000;
    }
    Ok(())
}

/// Copy the trampoline to physical address 0x8000 and write the data area.
///
/// Data area layout (at smp_trampoline_end):
///   +0:  CR3 (PML4 physical address)
///   +8:  legacy RSP (kernel stack top of the first AP)
///   +16: virtual address of the per-APIC stack table (`AP_STACK_TOPS`)
///
/// After writing, performs WBINVD to flush the cache hierarchy to RAM.
/// This is essential on real hardware: the BSP writes the trampoline via
/// HHDM (WB cacheable), but the AP boots in real mode where the effective
/// memory type is determined by MTRRs. If MTRRs mark the region as UC, or
/// if platform firmware does not guarantee cache coherency, the AP would
/// read stale data from RAM without this flush.
fn copy_trampoline(cr3_phys: u64, stack_top_virt: u64) -> Result<(), &'static str> {
    let tramp_len = (smp_trampoline_end as *const u8 as usize)
        .saturating_sub(smp_trampoline as *const u8 as usize);

    if tramp_len + 24 > 4096 {
        return Err("SMP: trampoline exceeds its reserved page");
    }
    // The 16-bit prologue jumps to hard-coded physical addresses (0x8040) and
    // `lgdt [0x8030]` reads an embedded GDTR. Verify the assembled layout once:
    // any drift would otherwise be a silent triple fault on AP boot.
    let base = smp_trampoline as *const u8 as usize;
    let gdt_off = smp_gdt_table as *const u8 as usize - base;
    let descr_off = smp_gdt_descr as *const u8 as usize - base;
    let pm_off = smp_pm_setup as *const u8 as usize - base;
    if gdt_off != 0x10 || descr_off != 0x30 || pm_off != 0x40 {
        crate::serial_force_println!(
            "[smp] FATAL: trampoline layout drifted (gdt={:#x} expected 0x10, \
             gdtr={:#x} expected 0x30, pm={:#x} expected 0x40)",
            gdt_off,
            descr_off,
            pm_off
        );
        return Err("SMP: trampoline layout does not match hard-coded offsets");
    }
    // The 32-bit stage loads CR3 with `mov eax, [..]` / `mov cr3, eax`: only
    // the low 32 bits survive. A PML4 above 4 GiB would boot the AP on a
    // truncated address space.
    if cr3_phys >= 1 << 32 {
        return Err("SMP: PML4 above 4 GiB, unreachable from the 32-bit trampoline");
    }
    // RSP must satisfy the SysV ABI at smp_main entry once the stub biases it
    // by 8 (see smp_trampoline_64): the stack top itself must be 16-aligned.
    if stack_top_virt & 0xF != 0 {
        return Err("SMP: AP kernel stack top is not 16-byte aligned");
    }
    ensure_identity_mapping(TRAMPOLINE_PHYS_ADDR, tramp_len + 24)?;

    let tramp_virt = memory::phys_to_virt(TRAMPOLINE_PHYS_ADDR) as *mut u8;

    // SAFETY: trampoline destination is mapped and writable in HHDM.
    unsafe {
        core::ptr::copy_nonoverlapping(smp_trampoline as *const u8, tramp_virt, tramp_len);
        let data = tramp_virt.add(tramp_len) as *mut u64;
        // +0: CR3
        core::ptr::write_volatile(data, cr3_phys);
        // +8: legacy RSP (stack top virtual address)
        core::ptr::write_volatile(data.add(1), stack_top_virt);
        // +16: per-APIC stack table base (virtual address)
        core::ptr::write_volatile(data.add(2), AP_STACK_TOPS.as_ptr() as u64);

        // SFENCE + WBINVD: ensure all stores reach RAM before the AP starts.
        core::arch::asm!("sfence");
        core::arch::asm!("wbinvd");
    }
    Ok(())
}

/// Wait for ICR delivery to complete.
///
/// In x2APIC mode, the ICR MSR write is synchronous : the CPU blocks until
/// the IPI is dispatched, so there is nothing to wait for.  In xAPIC mode,
/// we poll the delivery-pending bit (ICR_LOW bit 12) until it clears.
fn wait_delivery() {
    // x2APIC: MSR write is synchronous, no pending bit to poll.
    if apic::is_x2apic_enabled() {
        return;
    }

    const DELIVERY_PENDING: u32 = 1 << 12;
    for i in 0..1_000_000 {
        let val = unsafe { apic::read_reg(apic::REG_ICR_LOW) };
        if val & DELIVERY_PENDING == 0 {
            return;
        }
        if i > 0 && i % 200_000 == 0 {
            crate::serial_println!(
                "[smp] wait_delivery: still pending (iter={}, icr={:#x})",
                i,
                val,
            );
        }
        core::hint::spin_loop();
    }
    let final_val = unsafe { apic::read_reg(apic::REG_ICR_LOW) };
    crate::serial_println!("[smp] wait_delivery: TIMEOUT, final icr={:#x}", final_val,);
    log::warn!("SMP: IPI delivery timeout");
}

/// Send an IPI and wait for delivery.
fn send_ipi(apic_id: u32, value: u32) {
    apic::send_ipi_raw(apic_id, value);
    wait_delivery();
}

/// Send INIT + SIPI×2 to an AP per Intel SDM Volume 3, Section 10.6.7.1.
///
/// The Intel SDM recommends sending SIPI twice (200 µs apart) so that if
/// the first SIPI is missed, the second one still catches the AP. Some
/// platforms (Redox-OS) succeed with a single SIPI, but sending two is
/// more robust and matches Linux/FreeBSD behaviour.
///
///   Step 1: INIT level-assert (0xC500) : wait ≥10 ms
///   Step 2: INIT level-de-assert (0x8500) : wait ≥200 µs
///   Step 3: SIPI (0x4608, vector=0x08 => trampoline at 0x8000) : 200 µs
///   Step 4: SIPI again : 200 µs
///
/// ICR values (xAPIC format, delivery-mode bit-fields):
///   INIT:  delivery=INIT(101), level=1(assert), trigger=1(level)
///   Deassert: delivery=INIT(101), level=0(de-assert), trigger=1(level)
///   SIPI:  delivery=STARTUP(110), level=1, vector=0x8
fn send_init_sipi(apic_id: u32) {
    crate::serial_println!("[smp] send_init_sipi: apic_id={}", apic_id);

    // Step 1: INIT level-assert
    crate::serial_println!("[smp]   INIT assert -> {}", apic_id);
    send_ipi(apic_id, 0xC500);
    udelay(10_000);

    // Step 2: INIT level-de-assert
    crate::serial_println!("[smp]   INIT de-assert -> {}", apic_id);
    send_ipi(apic_id, 0x8500);
    udelay(200);

    // Step 3: SIPI #1
    crate::serial_println!("[smp]   SIPI (1/2) -> {} (vector=0x8)", apic_id);
    send_ipi(apic_id, 0x0608);
    udelay(200);

    // Step 4: SIPI #2  (SDM recommends two SIPIs)
    crate::serial_println!("[smp]   SIPI (2/2) -> {} (vector=0x8)", apic_id);
    send_ipi(apic_id, 0x0608);
    udelay(200);

    crate::serial_println!("[smp]   INIT+SIPI complete for {}", apic_id);
}

/// Broadcast a halt command to all other CPUs.
///
/// Used during panic to stop the system and prevent log corruption.
pub fn broadcast_panic_halt() {
    if !apic::is_initialized() {
        return;
    }
    // NMI delivery mode (0b100 << 8), all-excluding-self shorthand (0b11 << 18).
    // Level bit = 0 (reserved for NMI mode per Intel SDM Vol. 3A Table 10-1).
    let icr_low = (0b11 << 18) | (0b100 << 8);
    apic::send_ipi_raw(0, icr_low);
    // xAPIC: poll the delivery-pending bit so the NMI is actually dispatched.
    // x2APIC: the MSR write is synchronous and wait_delivery() is a no-op.
    wait_delivery();
}

/// Wait at a synchronization barrier until all expected CPUs arrive.
fn rendezvous_barrier() {
    let expected = BARRIER_TARGET.load(Ordering::Acquire);
    SYNC_BARRIER.fetch_add(1, Ordering::AcqRel);
    while SYNC_BARRIER.load(Ordering::Acquire) < expected {
        core::hint::spin_loop();
    }
    // BSP may have revoked the trampoline before publishing BARRIER_TARGET.
    // Each AP drops its formerly executable translation before normal work.
    unsafe {
        core::arch::asm!(
            "invlpg [{}]", in(reg) TRAMPOLINE_PHYS_ADDR,
            options(nostack, preserves_flags),
        );
    }
}

/// Boot Application Processors.
///
/// AP kernel stacks are allocated from the vmalloc arena during this function
/// and intentionally leaked (never freed): the guard page's backing frame is
/// released by `unmap_page`, while the remaining pages stay mapped forever.
/// The allocation happens once at boot while only the BSP is online, so there
/// is no lock contention and no risk of heap exhaustion under concurrent
/// pressure.
///
/// If CPU hotplug is added in the future, stack allocation must be moved to
/// a sleepable context (e.g. `Mutex`-protected) to avoid heap allocation
/// under any spinlock that could be held during hot-add.
pub fn init() -> Result<usize, &'static str> {
    crate::serial_println!("[smp] init: entering SMP initialization");
    if !apic::is_initialized() {
        crate::serial_println!("[smp] init: ERROR - APIC not initialized");
        return Err("APIC not initialized");
    }

    BOOTED_CORES.store(1, Ordering::Release);
    SYNC_BARRIER.store(0, Ordering::Release);
    BARRIER_TARGET.store(0, Ordering::Release);
    BOOT_WINDOW_CLOSED.store(false, Ordering::SeqCst);

    let madt_info = madt::parse_madt().ok_or("MADT not available")?;
    let bsp_apic_id = apic::lapic_id();

    crate::serial_println!(
        "[smp] init: MADT parsed, {} local APICs, BSP apic_id={}",
        madt_info.local_apic_count,
        bsp_apic_id,
    );

    if madt_info.local_apic_count <= 1 {
        crate::serial_println!("[smp] init: single CPU system, returning");
        log::info!("SMP: single CPU system");
        return Ok(1);
    }

    let mut max_apic_id: usize = 0;
    for i in 0..madt_info.local_apic_count {
        if let Some(ref entry) = madt_info.local_apics[i] {
            let apic_id = entry.apic_id as usize;
            if apic_id >= MAX_APIC_IDS {
                log::warn!(
                    "SMP: APIC id {} exceeds MAX_APIC_IDS ({}), skipping",
                    apic_id,
                    MAX_APIC_IDS
                );
                continue;
            }
            crate::serial_println!(
                "[smp]   APIC[{}]: id={} proc={} flags={:#x} {}",
                i,
                entry.apic_id,
                entry.processor,
                entry.flags,
                if entry.flags & 1 == 0 {
                    "(DISABLED)"
                } else {
                    ""
                },
            );
            max_apic_id = max_apic_id.max(apic_id);
        }
    }
    crate::serial_println!("[smp] init: max APIC id seen = {}", max_apic_id);

    let mut stack_tops = [0u64; MAX_APIC_IDS];
    let cr3_phys = crate::memory::paging::kernel_l4_phys().as_u64();
    let mut targets: Vec<u32> = Vec::new();
    let mut expected: usize = 1;

    for i in 0..madt_info.local_apic_count {
        let Some(ref entry) = madt_info.local_apics[i] else {
            continue;
        };

        let apic_id = entry.apic_id as u32;
        if apic_id == bsp_apic_id {
            continue;
        }

        // Skip IDs the per-AP stack table cannot address: no stack slot, no
        // SIPI. Only allocate after this check to avoid leaking a stack for an
        // AP we can never boot.
        if apic_id as usize >= MAX_APIC_IDS {
            log::warn!(
                "SMP: APIC id {} exceeds MAX_APIC_IDS ({}), skipping AP",
                apic_id,
                MAX_APIC_IDS
            );
            continue;
        }

        // Allocate the AP kernel stack from the vmalloc arena. vmalloc gives a
        // virtually contiguous, page-by-page mapping, which is what lets us
        // leave a non-present guard page below the usable stack: an overflow
        // then faults instead of silently corrupting the physically adjacent
        // frames that a buddy/HHDM stack would touch. Physical contiguity is
        // unnecessary because the stack is only ever reached through its
        // virtual mapping, and the range lives in the shared kernel L4 subtree
        // (mapped NX, which is fine for a data stack).
        let stack_size = crate::process::task::Task::DEFAULT_STACK_SIZE;
        let total = stack_size + 4096;
        let raw = crate::sync::with_irqs_disabled(|token| {
            crate::memory::allocate_kernel_virtual(total, token)
        })
        .map_err(|_| "SMP: failed to allocate AP stack from vmalloc")?;

        // The first page is the guard: unmap it so an overflow past the bottom
        // of the stack raises a page fault rather than touching live memory.
        // `unmap_page` releases the guard page's backing frame; the rest of the
        // range stays mapped forever (the stack is intentionally leaked).
        let guard_page = Page::<Size4KiB>::containing_address(VirtAddr::new(raw as u64));
        crate::memory::paging::unmap_page(guard_page)
            .map_err(|_| "SMP: failed to unmap AP stack guard page")?;

        // The usable stack sits directly above the guard page and grows
        // downward toward it.
        let stack_base = raw as u64 + 4096;
        let stack_top = stack_base + stack_size as u64;

        // Zero only the usable range; the guard page is already unmapped.
        unsafe { core::ptr::write_bytes(stack_base as *mut u8, 0, stack_size) };

        stack_tops[apic_id as usize] = stack_top;
        // Publish this AP's stack into the per-APIC table read by the 64-bit
        // stub, so a late AP can never observe another AP's stack.
        AP_STACK_TOPS[apic_id as usize].store(stack_top, Ordering::Release);

        // Exceeding MAX_CPUS must not abort the whole bring-up: skip this AP
        // (no SIPI) and keep booting the remaining ones. The stack allocated
        // above is intentionally leaked, like every other AP stack.
        let cpu_index = match percpu::register_cpu(apic_id) {
            Some(index) => index,
            None => {
                log::error!(
                    "SMP: APIC id {} exceeds MAX_CPUS (per-CPU registration full), skipping AP",
                    apic_id
                );
                crate::serial_println!(
                    "[smp] init: APIC id {} exceeds MAX_CPUS, skipping AP",
                    apic_id
                );
                AP_STACK_TOPS[apic_id as usize].store(0, Ordering::Release);
                continue;
            }
        };
        percpu::set_kernel_stack_top(cpu_index, stack_top);

        targets.push(apic_id);
        expected += 1;
    }

    // Copy trampoline and write the shared data area. All APs share the same
    // CR3; each AP resolves its own stack from AP_STACK_TOPS using its APIC ID.
    // The legacy +8 slot is kept for the first target only (diagnostic/back-compat).
    let first_stack_top = targets
        .first()
        .and_then(|id| stack_tops.get(*id as usize))
        .copied()
        .unwrap_or(0);
    copy_trampoline(cr3_phys, first_stack_top)?;
    crate::serial_println!(
        "[smp] init: trampoline at {:#x}, cr3={:#x}, stack={:#x}",
        TRAMPOLINE_PHYS_ADDR,
        cr3_phys,
        first_stack_top,
    );

    // Send INIT + SIPI to each AP, one at a time. Each AP resolves its own
    // stack from AP_STACK_TOPS, so the shared data area is never rewritten
    // between targets. We still wait for AP_REACHED_RUST before booting the
    // next AP to keep the console/APIC sequencing deterministic.
    crate::serial_println!(
        "[smp] init: sending INIT+SIPI to {} APs (sequential)",
        targets.len(),
    );
    for apic_id in &targets {
        AP_REACHED_RUST.store(usize::MAX, Ordering::Release);

        send_init_sipi(*apic_id);

        // Wait for this AP to reach Rust (100 ms TSC deadline).
        let start = crate::arch::x86_64::rdtsc();
        let budget = tsc_ticks_for_ms(100);
        let mut acked = false;
        let mut spin: u64 = 0;
        const ACK_SPIN_FALLBACK: u64 = 500_000_000;
        loop {
            if AP_REACHED_RUST.load(Ordering::Acquire) == *apic_id as usize {
                acked = true;
                break;
            }
            if budget != 0 {
                if crate::arch::x86_64::rdtsc().wrapping_sub(start) >= budget {
                    break;
                }
            } else if spin >= ACK_SPIN_FALLBACK {
                break;
            } else {
                spin = spin.saturating_add(1);
            }
            core::hint::spin_loop();
        }
        if !acked {
            crate::serial_println!(
                "[smp] init: WARNING AP {} did not ACK within timeout",
                apic_id
            );
            // Revoke this AP's stack slot and stop it with an INIT assert so it
            // cannot join later on a stale/shared stack.
            AP_STACK_TOPS[*apic_id as usize].store(0, Ordering::Release);
            send_ipi(*apic_id, 0xC500);
        } else {
            crate::serial_println!("[smp] init: AP {} ACKed (rust reached)", apic_id);
        }
    }

    // Wait for APs to publish themselves online. `online_count()` counts only
    // CPU indices that actually reached phase 3, unlike BOOTED_CORES (kept as
    // a diagnostic counter only).
    let start = crate::arch::x86_64::rdtsc();
    let budget = tsc_ticks_for_ms(2000);
    let mut last_log = 0u64;
    let mut spins: u64 = 0;
    crate::serial_println!("[smp] init: waiting for APs (expected={})...", expected,);
    loop {
        if percpu::online_count() >= expected {
            break;
        }
        if budget != 0 {
            let elapsed = crate::arch::x86_64::rdtsc().wrapping_sub(start);
            if elapsed >= budget {
                break;
            }
            // Periodic diagnostics, bounded to one line every 500 ms.
            if elapsed.wrapping_sub(last_log) >= tsc_ticks_for_ms(500) {
                last_log = elapsed;
                crate::serial_println!(
                    "[smp] init: waiting... online={} expected={} elapsed_ms={}",
                    percpu::online_count(),
                    expected,
                    elapsed / crate::arch::x86_64::boot_timestamp::tsc_khz().max(1),
                );
            }
        } else {
            // No TSC frequency: bounded spin fallback.
            const MAX_SPINS: u64 = 200_000_000;
            if spins >= MAX_SPINS {
                break;
            }
            spins = spins.saturating_add(1);
        }
        core::hint::spin_loop();
    }

    // Close the boot window. Any AP that publishes its online bit after this
    // point revokes it and halts (see smp_main), so the count below is
    // authoritative: it cannot grow once we read it back.
    BOOT_WINDOW_CLOSED.store(true, Ordering::SeqCst);
    let online = percpu::online_count();
    crate::serial_println!(
        "[smp] init: AP wait done: online={} expected={} booted_cores={}",
        online,
        expected,
        BOOTED_CORES.load(Ordering::Acquire),
    );
    if online < expected {
        crate::serial_println!(
            "[smp] init: WARNING only {}/{} APs online",
            online,
            expected,
        );
        log::warn!(
            "SMP: timeout waiting APs (online={} expected={}), continuing",
            online,
            expected
        );
    }

    log::info!("SMP: {} cores online (expected {})", online, expected);

    // Publish barrier target so APs can proceed. `online` is only an upper
    // bound for the barrier: an AP that lost the boot-window race still
    // arrives here before halting, so the target is always met.
    BARRIER_TARGET.store(online, Ordering::Release);
    rendezvous_barrier();

    // Retire the trampoline unconditionally once every AP has left it. A
    // legacy boot path can provide a huge identity leaf; never revoke
    // execution of unrelated addresses when that happens (log and tolerate).
    if let Err(error) = crate::memory::paging::set_trampoline_execution(TRAMPOLINE_PHYS_ADDR, false)
    {
        log::warn!("SMP: cannot retire trampoline execution: {}", error);
    }

    // Every AP has now completed its publication/revocation decision, so this
    // snapshot is final and cannot disagree with the scheduler's online view.
    let online = percpu::online_count();
    Ok(online)
}

/// Read this CPU's APIC ID via CPUID, mirroring the trampoline stub.
///
/// Prefer the 32-bit x2APIC ID from leaf 0x1F (if supported) or 0xB (EDX,
/// subleaf 0), falling back to leaf 1 EBX[31:24]. Must not use
/// `apic::lapic_id()` before `apic::init_ap()`: x2APIC MSRs may still be
/// disabled on the AP at this point.
fn read_apic_id_cpuid() -> u32 {
    use core::arch::x86_64::{__cpuid, __cpuid_count};

    let max_leaf = unsafe { __cpuid(0) }.eax;
    if max_leaf >= 0x1F {
        let id = unsafe { __cpuid_count(0x1F, 0) }.edx;
        if id != 0 {
            return id;
        }
    } else if max_leaf >= 0xB {
        let id = unsafe { __cpuid_count(0xB, 0) }.edx;
        if id != 0 {
            return id;
        }
    }
    unsafe { __cpuid(1) }.ebx >> 24
}

/// First Rust function executed on APs after the trampoline.
///
/// The trampoline enables paging with the kernel's PML4, sets up the stack,
/// and jumps here. All virtual addresses are valid at this point.
#[unsafe(no_mangle)]
pub extern "C" fn smp_main() -> ! {
    // Read APIC ID first : needed to find our per-CPU state.
    // Diagnostics use the raw E9 port path (no UART lock, no reprogramming).
    let apic_id: u32;
    {
        crate::serial_force_println!("[smp][ap] entered smp_main");
        apic_id = read_apic_id_cpuid();
        crate::serial_force_println!("[smp][ap] cpuid apic_id={}", apic_id);
    }

    // Signal BSP that this AP has reached Rust and consumed its stack.
    // Must happen immediately : before any per-CPU init that might fail.
    AP_REACHED_RUST.store(apic_id as usize, Ordering::Release);

    // The BSP closes the boot window once it stops accepting new APs. An AP
    // arriving after that must not touch per-CPU/scheduler state.
    if BOOT_WINDOW_CLOSED.load(Ordering::SeqCst) {
        halt_forever();
    }

    let cpu_index = match percpu::cpu_index_by_apic(apic_id) {
        Some(idx) => idx,
        None => {
            crate::serial_force_println!(
                "[smp][ap] ERROR: apic_id={} not registered, halting",
                apic_id
            );
            halt_forever();
        }
    };

    // ── Phase 1: per-CPU invariants (before any interrupt can fire) ──
    // Order matters: GS base must be set before any percpu access,
    // GDT before IDT (CS selector must be valid), TSS before any
    // ring-0 → ring-3 transition.

    crate::arch::x86_64::percpu::init_gs_base(cpu_index);

    crate::arch::x86_64::tss::init_cpu(cpu_index);
    crate::arch::x86_64::gdt::init_cpu(cpu_index);

    crate::arch::x86_64::syscall::init();
    crate::arch::x86_64::init_cpu_extensions();

    // Verify XCR0 was programmed correctly on this AP.
    if crate::arch::x86_64::cpuid::host_uses_xsave() {
        let expected = crate::arch::x86_64::cpuid::host_default_xcr0_fast();
        let actual = crate::arch::x86_64::xgetbv(0);
        if actual != expected {
            crate::serial_force_println!(
                "[smp][ap] WARNING: XCR0 mismatch! expected={:#x} actual={:#x}",
                expected,
                actual
            );
        }
    }

    if let Some(stack_top) = percpu::kernel_stack_top(cpu_index) {
        crate::arch::x86_64::tss::set_kernel_stack_for(cpu_index, x86_64::VirtAddr::new(stack_top));
    }

    // ── Phase 2: interrupt infrastructure ──
    // IDT is loaded LAST after all per-CPU state is established.
    // This prevents any exception/IPI from firing with incomplete state.
    idt::load();

    // Re-initialize Local APIC for this core.
    apic::init_ap();

    // ── Phase 3: signal online ──
    // Boot-window handshake. Check before publishing: if the BSP already
    // closed the window, do not publish at all. Publishing then clearing would
    // let the BSP count a CPU that immediately disappears, which could make the
    // rendezvous barrier wait forever.
    if BOOT_WINDOW_CLOSED.load(Ordering::SeqCst) {
        halt_forever();
    }
    // Publish with a SeqCst OR (inside mark_online_by_apic) so it is ordered
    // against the BSP's SeqCst close + online_count() read.
    let _ = percpu::mark_online_by_apic(apic_id);
    // If the window closed concurrently, the BSP may or may not have counted
    // us. Either way, participate in the rendezvous (an extra arrival is
    // harmless) and halt *after* it without joining the scheduler too late.
    let late = BOOT_WINDOW_CLOSED.load(Ordering::SeqCst);
    BOOTED_CORES.fetch_add(1, Ordering::Release);

    crate::serial_force_println!(
        "[smp][ap] cpu_index={} online, waiting for barrier",
        cpu_index
    );

    // AP spins until BSP publishes the barrier target.
    while BARRIER_TARGET.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    rendezvous_barrier();

    // The BSP may have revoked our online bit while closing the window, or we
    // may have lost the publication race. Retire this AP now that the barrier
    // is satisfied: clearing online after the rendezvous is safe and keeps the
    // scheduler's online view accurate.
    if late || !percpu::is_online(cpu_index) {
        percpu::clear_online(cpu_index);
        halt_forever();
    }

    crate::serial_println!("[trace][ap] cpu_index={} entering scheduler", cpu_index);

    // Wait until BSP has finished scheduler initialization.
    while !AP_SCHED_GATE_OPEN.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    // Start APIC timer on this CPU.
    timer::start_apic_timer_cached();

    // Start per-CPU scheduler (never returns).
    crate::process::scheduler::schedule_on_cpu(cpu_index)
}

/// Return the number of online CPUs.
pub fn cpu_count() -> usize {
    BOOTED_CORES.load(Ordering::Acquire)
}

/// Allow APs to start their local timer and enter the scheduler.
pub fn open_ap_scheduler_gate() {
    AP_SCHED_GATE_OPEN.store(true, Ordering::Release);
}
