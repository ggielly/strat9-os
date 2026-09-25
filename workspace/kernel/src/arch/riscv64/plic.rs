use core::sync::atomic::{AtomicU64, Ordering};

const PLIC_PRIORITY_BASE: u64 = 0x0010_0000;
const PLIC_ENABLE_BASE: u64 = 0x0c00_1000;
const PLIC_CLAIM_BASE: u64 = 0x0c00_2000;
const PLIC_CONTEXT_STRIDE: u64 = 0x1000;
const SIE_SEIE: usize = 1 << 9;

static BASE: AtomicU64 = AtomicU64::new(0);
static CONTEXT: AtomicU64 = AtomicU64::new(u64::MAX);

pub fn init(base: u64, hart_id: usize) -> Result<(), &'static str> {
    if base == 0 {
        return Err("PLIC base is null");
    }
    BASE.store(base, Ordering::Release);
    CONTEXT.store(hart_id as u64 + 1, Ordering::Release);
    unsafe {
        core::arch::asm!("csrs sie, {0}", in(reg) SIE_SEIE, options(nostack));
    }
    Ok(())
}

pub fn enable_source(irq: u32, priority: u32) {
    let Some(base) = base() else {
        return;
    };
    let priority_address = base + PLIC_PRIORITY_BASE + irq as u64 * 4;
    unsafe {
        core::ptr::write_volatile(priority_address as *mut u32, priority);
    }
    let enable_address =
        base + PLIC_ENABLE_BASE + CONTEXT.load(Ordering::Acquire) * PLIC_CONTEXT_STRIDE;
    let value = 1u32 << (irq % 32);
    unsafe {
        core::ptr::write_volatile(enable_address as *mut u32, value);
    }
}

pub fn handle_interrupt() {
    let Some(irq) = claim() else {
        return;
    };
    complete(irq);
}

fn claim() -> Option<u32> {
    let base = base()?;
    let address = base + PLIC_CLAIM_BASE + CONTEXT.load(Ordering::Acquire) * PLIC_CONTEXT_STRIDE;
    let irq = unsafe { core::ptr::read_volatile(address as *const u32) };
    (irq != 0).then_some(irq)
}

fn complete(irq: u32) {
    let Some(base) = base() else {
        return;
    };
    let address = base + PLIC_CLAIM_BASE + CONTEXT.load(Ordering::Acquire) * PLIC_CONTEXT_STRIDE;
    unsafe {
        core::ptr::write_volatile(address as *mut u32, irq);
    }
}

fn base() -> Option<u64> {
    let value = BASE.load(Ordering::Acquire);
    (value != 0).then_some(value)
}
