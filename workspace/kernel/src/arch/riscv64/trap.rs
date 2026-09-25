use core::arch::asm;

#[repr(C)]
pub(crate) struct TrapFrame {
    ra: usize,
    sp: usize,
    gp: usize,
    tp: usize,
    t0: usize,
    t1: usize,
    t2: usize,
    s0: usize,
    s1: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    s2: usize,
    s3: usize,
    s4: usize,
    s5: usize,
    s6: usize,
    s7: usize,
    s8: usize,
    s9: usize,
    s10: usize,
    s11: usize,
    t3: usize,
    t4: usize,
    t5: usize,
    t6: usize,
    sstatus: usize,
    sepc: usize,
    scause: usize,
    stval: usize,
    padding: usize,
}

extern "C" {
    fn riscv_trap_entry();
}

pub fn init() {
    unsafe {
        asm!(
            "csrw stvec, {0}",
            in(reg) riscv_trap_entry as *const () as usize,
            options(nostack)
        );
    }
}

#[no_mangle]
pub(crate) extern "C" fn riscv_trap_handler(frame: *mut TrapFrame) {
    let frame = unsafe { &*frame };
    let is_interrupt = frame.scause & (1usize << 63) != 0;
    let code = frame.scause & 0x7f;
    if is_interrupt && code == 5 {
        super::timer::handle_interrupt();
        return;
    }

    super::serial::_print(format_args!(
        "[strat9] trap scause={:#x} sepc={:#x} stval={:#x} sstatus={:#x}\r\n",
        frame.scause, frame.sepc, frame.stval, frame.sstatus
    ));
    super::cli();
    loop {
        unsafe {
            asm!("wfi", options(nomem, nostack));
        }
    }
}
