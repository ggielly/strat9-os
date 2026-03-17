//! Pre-IRETQ diagnostics for transitioning from Ring 0 to Ring 3
//!
//! [`validate_ring3_state`] should be invoked **immediately before** the IRETQ
//! trampoline. It checks the four prerequisites required for a safe switch to
//! Ring 3:
//!
//! 1. **GDT** – CS/SS descriptors have DPL=3, P=1 and the code segment has L=1
//!    (64‑bit).
//! 2. **Paging** – every level (PML4 → PDPT → PD → PT) for `target_rip` and
//!    `target_rsp` has the `USER_ACCESSIBLE` flag.
//! 3. **Alignment** – `target_rsp` is 16‑byte aligned (System V ABI requirement).
//! 4. **TSS** – a TSS is loaded (`TR ≠ 0`) and `rsp0` points into kernel space
//!    (≥ 0xffff_8000_0000_0000), ensuring the CPU can switch back on exception.
//!
//! If any check fails the function `panic!`s with a detailed description.

use x86_64::{
    instructions::tables::sgdt,
    registers::control::Cr3,
    structures::paging::PageTableFlags,
};

//  GDT descriptor decoding constants 

/// Bit 47 : Present.
const DESC_PRESENT_BIT: u64 = 1 << 47;
/// Bits [46:45] : DPL.
const DESC_DPL_SHIFT: u32 = 45;
const DESC_DPL_MASK: u64 = 0x3 << DESC_DPL_SHIFT;
/// Bit 53 : L  Long Mode code segment (64-bit).
const DESC_L_BIT: u64 = 1 << 53;
/// Bit 44 : S  1 = segment code/data, 0 = system descriptor.
const DESC_S_BIT: u64 = 1 << 44;
/// Bit 43 : Executable (type bit for code segments).
const DESC_EXEC_BIT: u64 = 1 << 43;

//  Raw GDT descriptor access 

/// Reads an 8-byte GDT descriptor at the given `index` (base 0).
///
/// # Safety
/// `gdt_base` must be the address returned by `sgdt` and `index` must remain
/// within the `limit` of the GDTR.
#[inline]
unsafe fn read_gdt_raw(gdt_base: *const u64, index: usize) -> u64 {
    // SAFETY: bounds check performed by the caller
    unsafe { *gdt_base.add(index) }
}

//  Descriptor field accessors 

#[inline]
fn desc_present(raw: u64) -> bool {
    raw & DESC_PRESENT_BIT != 0
}

#[inline]
fn desc_dpl(raw: u64) -> u8 {
    ((raw & DESC_DPL_MASK) >> DESC_DPL_SHIFT) as u8
}

#[inline]
fn desc_is_code(raw: u64) -> bool {
    // S=1 (code/data) ET E=1 (executable)
    raw & DESC_S_BIT != 0 && raw & DESC_EXEC_BIT != 0
}

#[inline]
fn desc_long_mode(raw: u64) -> bool {
    raw & DESC_L_BIT != 0
}

// ===  Recursive page-table walk helpers =======================================

/// Physical address mask inside a page-table entry (bits [51:12]).
const PHYS_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Checks that `vaddr` is mapped and USER_ACCESSIBLE at every level of the
/// page hierarchy (PML4 → PDPT → PD → PT).
///
/// Returns `Ok(())` if all levels have `PRESENT | USER_ACCESSIBLE` set.
/// Otherwise returns `Err(&str)` naming the problematic level.
///
/// Handles 1 GiB (PDPT) and 2 MiB (PD) huge pages: stop descending once a
/// huge-page entry is found with USER_ACCESSIBLE.
fn check_user_mapping(vaddr: u64) -> Result<(), &'static str> {
    let hhdm = crate::memory::hhdm_offset();

    // == PML4 ==================================================================
    let (pml4_frame, _) = Cr3::read();
    let pml4_phys = pml4_frame.start_address().as_u64();
    let pml4_ptr = (pml4_phys + hhdm) as *const u64;
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;

    // SAFETY: pml4_ptr is an HHDM address pointing to the active PML4 (CR3)
    let pml4_e = unsafe { *pml4_ptr.add(pml4_idx) };
    let f4 = PageTableFlags::from_bits_truncate(pml4_e);

    if !f4.contains(PageTableFlags::PRESENT) {
        return Err("PML4: entry not present (PRESENT=0)");
    }
    if !f4.contains(PageTableFlags::USER_ACCESSIBLE) {
        return Err("PML4: bit USER_ACCESSIBLE missing");
    }

    // == PDPT ==================================================================
    let pdpt_ptr = ((pml4_e & PHYS_ADDR_MASK) + hhdm) as *const u64;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;

    // SAFETY: physical address extracted from a valid PML4 entry + HHDM offset
    let pdpt_e = unsafe { *pdpt_ptr.add(pdpt_idx) };
    let fp = PageTableFlags::from_bits_truncate(pdpt_e);

    if !fp.contains(PageTableFlags::PRESENT) {
        return Err("PDPT: entrée non présente (PRESENT=0)");
    }
    if !fp.contains(PageTableFlags::USER_ACCESSIBLE) {
        return Err("PDPT: bit USER_ACCESSIBLE manquant");
    }
    // Huge page 1 Go pas besoin de descendre plus loin
    if fp.contains(PageTableFlags::HUGE_PAGE) {
        return Ok(());
    }

    // == PD ==================================================================
    let pd_ptr = ((pdpt_e & PHYS_ADDR_MASK) + hhdm) as *const u64;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;

    // SAFETY: physical address extracted from a valid PDPT entry + HHDM offset
    let pd_e = unsafe { *pd_ptr.add(pd_idx) };
    let fd = PageTableFlags::from_bits_truncate(pd_e);

    if !fd.contains(PageTableFlags::PRESENT) {
        return Err("PD: entry not preset (PRESENT=0)");
    }
    if !fd.contains(PageTableFlags::USER_ACCESSIBLE) {
        return Err("PD: bit USER_ACCESSIBLE manquant");
    }
    // Huge page 2 Mo pas besoin de descendre plus loin
    if fd.contains(PageTableFlags::HUGE_PAGE) {
        return Ok(());
    }

    // == PT ==================================================================
    let pt_ptr = ((pd_e & PHYS_ADDR_MASK) + hhdm) as *const u64;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    // SAFETY: physical address extracted from a valid PD entry + HHDM offset
    let pt_e = unsafe { *pt_ptr.add(pt_idx) };
    let ft = PageTableFlags::from_bits_truncate(pt_e);

    if !ft.contains(PageTableFlags::PRESENT) {
        return Err("PT (page 4 KiB): entry not here (PRESENT=0)");
    }
    if !ft.contains(PageTableFlags::USER_ACCESSIBLE) {
        return Err("PT (page 4 KiB): bit USER_ACCESSIBLE missing");
    }

    Ok(())
}

//  Main validation routine ===============================================================

/// Validates all CPU preconditions for a safe Ring 3 transition via `iretq`.
///
/// # When to call
/// Immediately **before** the `iretq` trampoline. If this function returns,
/// all prerequisites are satisfied. If a check fails it `panic!`s with a
/// detailed diagnosis (bad GDT/paging/TSS, raw descriptor values, addresses
/// involved).
///
/// # Arguments
/// * `target_rip` – Ring 3 instruction pointer (ELF entry point)
/// * `target_rsp` – User-stack top (must be 16‑byte aligned)
/// * `cs`         – Code-segment selector in the IRETQ frame (e.g. `0x2B`)
/// * `ss`         – Stack-segment selector in the IRETQ frame (e.g. `0x23`)
///
/// # Panics
/// Panics with an explicit message if any of the following is false:
/// - CS/SS present in GDT with DPL=3, P=1; CS has L=1
/// - `target_rip` and `target_rsp` are USER_ACCESSIBLE at every page level
/// - `target_rsp` is 16‑byte aligned
/// - TSS is loaded and `rsp0` resides in kernel space
pub fn validate_ring3_state(target_rip: u64, target_rsp: u64, cs: u16, ss: u16) {
    crate::serial_force_println!(
        "[validate_ring3] === Begin validation Ring 3 === \
         RIP={:#x} RSP={:#x} CS={:#x} SS={:#x}",
        target_rip,
        target_rsp,
        cs,
        ss,
    );

    // ==================================================================
    // 1. Verification GDT
    // ==================================================================

    // SAFETY: `sgdt` only reads the GDTR register — no side effects.
    let gdtr = unsafe { sgdt() };
    let gdt_base = gdtr.base.as_u64() as *const u64;
    let gdt_limit = gdtr.limit as usize; // in bytes, inclusive

    crate::serial_force_println!(
        "[validate_ring3] GDTR base={:#x} limit={:#x}",
        gdtr.base.as_u64(),
        gdt_limit,
    );

    // Conversion selector → index in the qword table (RPL = bits [1:0],
    // TI = bit 2 ; the byte index is in bits [15:3]).
    let cs_byte_offset = (cs & !0x7) as usize; // align to 8 bytes by masking RPL+TI
    let ss_byte_offset = (ss & !0x7) as usize;
    let cs_index = cs_byte_offset / 8;
    let ss_index = ss_byte_offset / 8;

    // Verify that the offsets are within the GDT limits
    if cs_byte_offset + 7 > gdt_limit {
        panic!(
            "[validate_ring3] GDT: CS selector {:#x} (byte offset {}) \
             exceeds GDTR limit ({:#x}). GDT too small or invalid selector.",
            cs, cs_byte_offset, gdt_limit,
        );
    }
    if ss_byte_offset + 7 > gdt_limit {
        panic!(
            "[validate_ring3] GDT: sélecteur SS {:#x} (offset octet {}) \
             dépasse la limite GDTR ({:#x}). GDT trop petite ou sélecteur invalide.",
            ss, ss_byte_offset, gdt_limit,
        );
    }

    // SAFETY: bounds checked just above; gdtr.base points to the active GDT.
    let cs_raw = unsafe { read_gdt_raw(gdt_base, cs_index) };
    let ss_raw = unsafe { read_gdt_raw(gdt_base, ss_index) };

    crate::serial_force_println!(
        "[validate_ring3] GDT[{}] CS raw={:#018x}  GDT[{}] SS raw={:#018x}",
        cs_index, cs_raw, ss_index, ss_raw,
    );

    //  CS : Present ======================================
    if !desc_present(cs_raw) {
        panic!(
            "[validate_ring3] GDT CS {:#x} (index {}): bit P (Present) = 0 ! \
             The descriptor is marked as absent. raw={:#018x}",
            cs, cs_index, cs_raw,
        );
    }

    //  CS : DPL = 3 =====================================
    let cs_dpl = desc_dpl(cs_raw);
    if cs_dpl != 3 {
        panic!(
            "[validate_ring3] GDT CS {:#x} (index {}): DPL={} (3 expected). \
             The descriptor will not allow execution in Ring 3. raw={:#018x}",
            cs, cs_index, cs_dpl, cs_raw,
        );
    }

    //  CS : segment de code ==============================
    if !desc_is_code(cs_raw) {
        panic!(
            "[validate_ring3] GDT CS {:#x} (index {}): this is not a code segment \
             (S={} E={}). IRETQ with a data selector in CS will cause a #GP. \
             raw={:#018x}",
            cs,
            cs_index,
            (cs_raw >> 44) & 1,
            (cs_raw >> 43) & 1,
            cs_raw,
        );
    }

    // CS : Long Mode (L=1 requis in 64-bit) ==================================
    if !desc_long_mode(cs_raw) {
        panic!(
            "[validate_ring3] GDT CS {:#x} (index {}): bit L (Long Mode 64-bit) = 0 ! \
             In 64-bit mode, all Ring 3 code segments must have L=1. \
             Without L=1, the CPU switches to 32-bit compatibility mode → TRIPLE FAULT guaranteed. \
             raw={:#018x}",
            cs, cs_index, cs_raw,
        );
    }

    //  SS : Present ==========================================
    if !desc_present(ss_raw) {
        panic!(
            "[validate_ring3] GDT SS {:#x} (index {}): bit P (Present) = 0 ! \
             raw={:#018x}",
            ss, ss_index, ss_raw,
        );
    }

    //  SS : DPL = 3 ==========================
    let ss_dpl = desc_dpl(ss_raw);
    if ss_dpl != 3 {
        panic!(
            "[validate_ring3] GDT SS {:#x} (index {}): DPL={} (3 attendu). \
             IRETQ requiert DPL(SS) == RPL(CS) == 3. raw={:#018x}",
            ss, ss_index, ss_dpl, ss_raw,
        );
    }

    crate::serial_force_println!(
        "[validate_ring3] [1/4] GDT OK — \
         CS={:#x} P=1 DPL={} L=1 | SS={:#x} P=1 DPL={}",
        cs, cs_dpl, ss, ss_dpl,
    );

    // ====================================================
    // 2. RSP ALIGNMENT CHECK (System V ABI §3.2.2)
    // ====================================================
    //
    // Before a CALL, RSP must be 16‑byte aligned. CALL itself pushes an 8-byte
    // return address, so the ABI requires RSP ≡ 0 (mod 16) *before* the CALL,
    // i.e. at the entry point of the callee. In our case we use `iretq` with
    // no preceding CALL, hence `target_rsp` must already satisfy the alignment
    // for the libc/crt0 startup code to work.
    if target_rsp & 0xF != 0 {
        panic!(
            "[validate_ring3] RSP={:#x} not 16-byte aligned \
             (RSP & 0xF = {:#x}). The System V ABI requires RSP ≡ 0 (mod 16) \
             before calling _start. Align the stack by subtracting {}.",
            target_rsp,
            target_rsp & 0xF,
            target_rsp & 0xF,
        );
    }

    crate::serial_force_println!(
        "[validate_ring3] [2/4] Alignement RSP OK — RSP={:#x} ≡ 0 (mod 16)",
        target_rsp,
    );

    // ====================================================
    // 3. PAGE TABLES VERIFICATION
    // ====================================================
    //
    // We check that RIP and RSP (as well as the page just below RSP,
    // which will be the first used during a push) are accessible from
    // Ring 3 at all levels of the paged hierarchy.

    // -- RIP ------------------------------------------------------------------
    match check_user_mapping(target_rip) {
        Ok(()) => {
            crate::serial_force_println!(
                "[validate_ring3] Pagination RIP OK — {:#x} USER_ACCESSIBLE \
                 on 4 levels (PML4 -> PDPT -> PD -> PT)",
                target_rip,
            );
        }
        Err(reason) => {
            panic!(
                "[validate_ring3] Pagination RIP {:#x} INVALID : {}. \
                 The CPU will trigger a #PF immediately after iretq, \
                 then a TRIPLE FAULT (as rsp0 might also be invalid).",
                target_rip, reason,
            );
        }
    }

    // -- RSP : current page + previous page (first push crosses the boundary) -
    //
    // target_rsp points to the top of the stack; the first instruction
    // from the user will likely perform a PUSH that subtracts 8 from RSP.
    // If RSP is exactly at the start of a page (RSP & 0xFFF == 0), this first
    // PUSH will access the previous page (RSP - 8). We check both.
    for &probe in &[target_rsp, target_rsp.wrapping_sub(8)] {
        match check_user_mapping(probe) {
            Ok(()) => {
                crate::serial_force_println!(
                    "[validate_ring3] Pagination RSP OK — page de {:#x} USER_ACCESSIBLE",
                    probe,
                );
            }
            Err(reason) => {
                panic!(
                    "[validate_ring3] Pagination RSP probe {:#x} INVALID : {}. \
                     The user stack is not accessible from Ring 3.",
                    probe, reason,
                );
            }
        }
    }

    crate::serial_force_println!(
        "[validate_ring3] [3/4] Pagination OK — RIP={:#x} RSP={:#x} USER_ACCESSIBLE",
        target_rip,
        target_rsp,
    );

    // ====================================================
    // 4. VeRIFICATION TSS
    // ====================================================
    //
    // The CPU automatically loads rsp0 from the TSS when an exception occurs
    // from Ring 3. If the TSS is not loaded (TR=0) or if rsp0 is invalid,
    // the CPU will generate a Triple Fault on the first exception.

    // Read the Task Register (TR) via the STR instruction, which gives us the selector of the currently loaded TSS. If TR=0, no TSS is loaded.
    let tr_sel: u16;
    // SAFETY: STR is a system register read instruction,
    // with no side effects and always available in Ring 0.
    unsafe {
        core::arch::asm!(
            "str {0:x}",
            out(reg) tr_sel,
            options(nostack, nomem),
        );
    }

    if tr_sel == 0 {
        panic!(
            "[validate_ring3] TR=0 : no TSS loaded (instruction `ltr` never executed). \
             Without a TSS, the CPU cannot recover the kernel stack during an exception \
             from Ring 3 → immediate Triple Fault. Call gdt::init() before this trampoline.",
        );
    }

    // Verify rsp0 via our TSS abstraction (TSS::privilege_stack_table[0]) since the CPU would load rsp0 from there on exception.
    let cpu_index = crate::arch::x86_64::percpu::current_cpu_index();
    let tss = crate::arch::x86_64::tss::tss_for(cpu_index);
    let rsp0 = tss.privilege_stack_table[0].as_u64();
    let loaded_tss = crate::arch::x86_64::tss::loaded_tss_info();

    if rsp0 == 0 {
        panic!(
            "[validate_ring3] TSS.rsp0=0 : kernel stack (Ring 0) not configured. \
             Call tss::set_kernel_stack() with the current thread's stack \
             before entering Ring 3.",
        );
    }

    // The kernel space starts at 0xffff_8000_0000_0000 on x86_64 with the
    // "high half" canonical address scheme. Any address below this is in
    // user space and unacceptable as a kernel stack.
    const KERNEL_VADDR_START: u64 = 0xffff_8000_0000_0000;

    if rsp0 < KERNEL_VADDR_START {
        panic!(
            "[validate_ring3] TSS.rsp0={:#x} is a user address (< {:#x}). \
             The CPU would load a user stack in Ring 0 during an exception, \
             which allows trivial privilege escalation. \
             Call tss::set_kernel_stack() with a valid kernel address.",
            rsp0, KERNEL_VADDR_START,
        );
    }

    crate::serial_force_println!(
        "[validate_ring3] [4/4] TSS OK — TR={:#x} rsp0={:#x} (kernel space, CPU {})",
        tr_sel,
        rsp0,
        cpu_index,
    );
    crate::e9_println!(
        "[validate_ring3] [4/4] TSS OK TR={:#x} rsp0={:#x} cpu={}",
        tr_sel,
        rsp0,
        cpu_index,
    );
    if let Some(info) = loaded_tss {
        crate::serial_force_println!(
            "[validate_ring3] TSS live — TR={:#x} base={:#x} rsp0={:#x}",
            info.tr_selector,
            info.tss_base,
            info.rsp0,
        );
        crate::e9_println!(
            "[validate_ring3] TSS live TR={:#x} base={:#x} rsp0={:#x}",
            info.tr_selector,
            info.tss_base,
            info.rsp0,
        );
        if info.rsp0 != rsp0 {
            crate::serial_force_println!(
                "[validate_ring3] TSS MISMATCH — software_rsp0={:#x} live_rsp0={:#x} cpu={}",
                rsp0,
                info.rsp0,
                cpu_index,
            );
            crate::e9_println!(
                "[validate_ring3] TSS MISMATCH sw={:#x} live={:#x} cpu={}",
                rsp0,
                info.rsp0,
                cpu_index,
            );
        }
    }

    for vector in [crate::arch::x86_64::apic::LVT_TIMER_VECTOR, crate::arch::x86_64::apic::IPI_RESCHED_VECTOR] {
        if let Some(gate) = crate::arch::x86_64::idt::live_gate_info(vector) {
            crate::serial_force_println!(
                "[validate_ring3] IDT live vec={:#x} sel={:#x} opts={:#x} off={:#x}",
                gate.vector,
                gate.selector,
                gate.options,
                gate.offset,
            );
            crate::e9_println!(
                "[validate_ring3] IDT live vec={:#x} sel={:#x} opts={:#x} off={:#x}",
                gate.vector,
                gate.selector,
                gate.options,
                gate.offset,
            );
        }
    }

    // ====================================================
    // SYNTHÈSE
    // ====================================================
    crate::serial_force_println!(
        "[validate_ring3] ALL RING 3 PREREQUISiTES VALIDATED !@#% \
         RIP={:#x} RSP={:#x} CS={:#x} SS={:#x} → iretq",
        target_rip,
        target_rsp,
        cs,
        ss,
    );
}
