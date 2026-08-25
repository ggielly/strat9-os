//! RISC-V facade re-exports (mirrors the x86_64 `facade` surface).
//!
//! Everything the neutral kernel code reaches via `crate::arch::*`.
//! Items marked "transitional stub" exist only so the riscv64 build
//! progresses; each is replaced by real code in a later jalon.

pub use super::riscv64::{
    boot_timestamp, cli, cpuid, hlt, idt, interrupts_enabled, restore_flags,
    rdtsc, save_flags_and_cli, serial, speaker, sti, timer, vga, vgabuf,
};

/// Neutral MAX_CPUS constant for riscv64 (matches x86_64 value).
pub const MAX_CPUS: usize = 32;

// ---------------------------------------------------------------------------
// Transitional per-cpu stub. Real implementation via sscratch: jalon R2.5.
// ---------------------------------------------------------------------------
pub mod percpu {
    pub use super::MAX_CPUS;

    pub fn current_cpu_index() -> usize {
        0
    }
    pub fn current_cpu_index_fast() -> usize {
        0
    }
    pub fn cpu_count() -> usize {
        1
    }
    pub fn get_cpu_count() -> usize {
        1
    }
    pub fn init_boot_cpu(_hartid: u64) -> usize {
        0
    }
    pub fn init_gs_base(_idx: usize) {}
    pub fn set_kernel_rsp_current(_rsp: u64) {}
    pub fn mark_tlb_ready_current() {}
    pub fn tlb_ready(_index: usize) -> bool {
        true
    }
    pub fn set_signal_pending_current() {}
    pub fn test_and_clear_signal_pending_current() -> bool {
        false
    }
    pub fn apic_id_by_cpu_index(index: usize) -> Option<u32> {
        if index == 0 { Some(0) } else { None }
    }
    pub fn cpu_index_by_apic(apic_id: u32) -> Option<usize> {
        if apic_id == 0 { Some(0) } else { None }
    }
    pub fn preempt_disable() {}
    pub fn preempt_enable() {}
}

// ---------------------------------------------------------------------------
// Transitional stubs for x86-only subsystems still referenced by shared code.
// Each disappears when its call-site is gated per-arch (jalons R4-R6).
// ---------------------------------------------------------------------------

pub mod tlb {
    pub fn init() {}
    pub fn local_page(_vaddr: u64) {}
    pub fn local_range(_start: u64, _end: u64) {}
    pub fn shootdown_range(_start: u64, _end: u64) {}
    pub fn shootdown_all() {}
}

pub mod apic {
    pub fn lapic_phys() -> u64 {
        0
    }
    pub fn lapic_id() -> u32 {
        0
    }
    pub fn is_initialized() -> bool {
        false
    }
    pub fn send_resched_ipi(_target: u32) {}
    pub const REG_LVT_TIMER: u32 = 0x320;
    pub const REG_TIMER_INIT: u32 = 0x380;
    pub const REG_TIMER_CURRENT: u32 = 0x390;
    pub fn read_reg(_reg: u32) -> u32 {
        0
    }
}

pub mod smp {
    pub fn cpu_count() -> usize {
        1
    }
    pub fn init() -> Result<usize, &'static str> {
        Ok(1)
    }
    pub fn open_ap_scheduler_gate() {}
    pub fn broadcast_panic_halt() {}
}

pub use pci_full::*;

pub mod gdt {
    // No segment selectors on RISC-V; iret-frame fields become arch-neutral.
    pub fn kernel_code_selector() -> u16 {
        0
    }
    pub fn kernel_data_selector() -> u16 {
        0
    }
    pub fn user_code_selector() -> u16 {
        0
    }
    pub fn user_data_selector() -> u16 {
        0
    }
}

pub mod tss {
    pub fn init() {}
    pub fn set_kernel_stack(_top: u64) {}
}

pub mod io {
    // Port I/O does not exist on RISC-V (all MMIO). These trap loudly if
    // ever called rather than silently succeeding.
    #[inline]
    pub fn inb(_port: u16) -> u8 {
        panic!("port I/O unavailable on riscv64")
    }
    #[inline]
    pub fn outb(_port: u16, _val: u8) {
        panic!("port I/O unavailable on riscv64")
    }
}

pub mod keyboard {
    pub const KEY_LEFT: &str = "\x1b[D";
    pub const KEY_RIGHT: &str = "\x1b[C";
    pub const KEY_UP: &str = "\x1b[A";
    pub const KEY_DOWN: &str = "\x1b[B";
    pub const KEY_HOME: &str = "\u{1b}[H";
    pub const KEY_END: &str = "\u{1b}[F";
    pub fn init() {}
    pub fn read_char() -> Option<char> {
        crate::arch::serial::getc().map(|b| b as char)
    }
    pub fn add_to_buffer(_c: char) {}
}

pub mod mouse {
    pub fn init() -> bool { false }
    pub fn handle_irq() {}
    pub fn read_event() -> Option<(i32, i32, u8)> { None }
    pub fn mouse_pos() -> (usize, usize) { (0, 0) }
    pub fn update_mouse_cursor(_x: usize, _y: usize) {}
}

pub mod pic {
    pub fn init(_o1: u8, _o2: u8) {}
    pub fn disable() {}
    pub fn enable_irq(_irq: u8) {}
}

pub mod syscall {
    pub fn init() {}
    pub fn set_kernel_rsp(_rsp: u64) {}
}

pub mod keyboard_layout {
    pub fn set_french_layout() {}
}

// VGA console macros: no-op on riscv64 (serial-only console).
#[macro_export]
macro_rules! vga_print {
    ($($arg:tt)*) => {{
        $crate::serial_print!($($arg)*)
    }};
}

#[macro_export]
macro_rules! vga_println {
    () => {
        $crate::vga_print!("\n")
    };
    ($($arg:tt)*) => {
        $crate::vga_print!("{}\n", format_args!($($arg)*))
    };
}

// Extended PCI surface used by hardware/pci_client.rs. Real ECAM driver: R5.
pub mod pci_full {
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct PciAddress {
        pub bus: u8,
        pub device: u8,
        pub function: u8,
    }
    impl PciAddress {
        pub const fn new(bus: u8, device: u8, function: u8) -> Self {
            Self { bus, device, function }
        }
    }
    pub struct PciDevice;
    pub fn all_devices() -> alloc::vec::Vec<PciAddress> {
        alloc::vec::Vec::new()
    }
    pub fn invalidate_cache() {}
    pub mod vendor { pub const UNKNOWN: u16 = 0; }
    pub mod device { pub const UNKNOWN: u16 = 0; }
    pub mod class { pub const UNCLASSIFIED: u8 = 0; }
    pub mod config {}
    pub mod msi_cap {}
    pub mod msix_cap {}
    pub mod msix_ctrl {}
    pub mod msi_ctrl {}
    pub mod intel_eth {}
    pub mod net_subclass {}
    pub mod storage_subclass {}
    pub mod sata_progif {}
    pub const MSI_ADDR_BASE: u32 = 0xFEE0_0000;
}
