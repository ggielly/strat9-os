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
    pub fn is_preemptible() -> bool {
        true
    }
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

pub mod pci {
    pub use super::pci_full::*;
}

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
    pub fn set_kernel_stack_for(_cpu: usize, _top: u64) {}
    pub fn kernel_stack_for(_cpu: usize) -> Option<crate::ostd::mm::VirtAddr> {
        None
    }
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
    #[inline]
    pub fn inw(_port: u16) -> u16 {
        panic!("port I/O unavailable on riscv64")
    }
    #[inline]
    pub fn outw(_port: u16, _val: u16) {
        panic!("port I/O unavailable on riscv64")
    }
    #[inline]
    pub fn inl(_port: u16) -> u32 {
        panic!("port I/O unavailable on riscv64")
    }
    #[inline]
    pub fn outl(_port: u16, _val: u32) {
        panic!("port I/O unavailable on riscv64")
    }
}

pub mod mouse_ready_marker {}

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
    pub static MOUSE_READY: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
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
    pub fn probe_all(_crit: ProbeCriteria) -> alloc::vec::Vec<PciAddress> {
        alloc::vec::Vec::new()
    }
    pub fn probe_first(_crit: ProbeCriteria) -> Option<(PciAddress, PciDevice)> {
        None
    }
    pub mod vendor {
        pub const UNKNOWN: u16 = 0xFFFF;
        pub const VIRTIO: u16 = 0x1AF4;
    }
    pub mod device {
        pub const UNKNOWN: u16 = 0;
        pub const VIRTIO_NET: u16 = 0x1000;
        pub const VIRTIO_BLOCK: u16 = 0x1001;
    }
    pub mod class {
        pub const UNCLASSIFIED: u8 = 0x00;
        pub const NETWORK: u8 = 0x02;
        pub const MASS_STORAGE: u8 = 0x01;
    }
    pub mod config {
        pub const BAR0: u8 = 0x10;
        pub const COMMAND: u8 = 0x04;
        pub const INTERRUPT_LINE: u8 = 0x3C;
        pub const INTERRUPT_PIN: u8 = 0x3D;
        pub fn read_u32(_addr: PciAddress, _off: u8) -> u32 {
            0xFFFF_FFFF
        }
    }
    pub mod cap_id {
        pub const MSI: u8 = 0x05;
        pub const MSIX: u8 = 0x11;
    }
    pub mod command {
        pub const MEMORY_SPACE: u16 = 0x2;
        pub const BUS_MASTER: u16 = 0x4;
        pub const INTERRUPT_DISABLE: u16 = 0x400;
    }
    pub struct Bar;
    impl Bar {
        pub fn phys_addr(&self) -> u64 {
            0
        }
        pub fn size(&self) -> u64 {
            0
        }
    }
    #[derive(Clone, Copy)]
    pub struct ProbeCriteria;
    impl ProbeCriteria {
        pub fn new() -> Self {
            ProbeCriteria
        }
    }
    pub mod msi_cap {}
    pub mod msix_cap {}
    pub mod msix_ctrl {}
    pub mod msi_ctrl {}
    pub mod intel_eth {
        pub const E1000_82540EM: u16 = 0x100E;
        pub const E1000_82545EM: u16 = 0x100F;
    }
    pub mod net_subclass {
        pub const ETHERNET: u8 = 0x00;
    }
    pub mod storage_subclass {
        pub const SCSI: u8 = 0x00;
    }
    pub mod sata_progif {}
    pub const MSI_ADDR_BASE: u32 = 0xFEE0_0000;
    pub const MSI_ADDR_DEST_SHIFT: u32 = 12;
}

// stac/clac: SMAP does not exist on RISC-V — no-ops.
pub fn stac() {}
pub fn clac() {}

// xsave/xcr0 helpers referenced by task.rs/framebuffer — always false on RISC-V.
pub mod cpuid_x86 {
    pub use crate::arch::riscv64::cpuid_x86_shim::CpuFeatures;
    pub fn host_uses_xsave() -> bool {
        false
    }
    pub fn host_default_xcr0() -> u64 {
        0
    }
    pub fn host_default_xcr0_fast() -> u64 {
        0
    }
    pub fn xsave_size_for_xcr0(_xcr0: u64) -> usize {
        512
    }
}

// pci_full re-exported as `pci` already; add missing submodules used by gfx/shell.
pub mod msi {
    pub fn enable(_dev: (), _vec: u8) {}
}
pub mod ioapic {
    pub fn init(_addr: u64, _gsi: u32) {}
    pub fn mask_legacy_irq(_irq: u8) {}
    pub fn route_nic_irq(_irq: u8, _vector: u8) {}
    pub fn route_irq(_gsi: u32, _vector: u8) {}
}
pub mod vga_text {
    pub enum TextAlign {
        Left,
        Center,
        Right,
    }
    pub struct TextOptions;
    impl TextOptions {
        pub fn new() -> Self {
            TextOptions
        }
        pub fn align(self, _a: TextAlign) -> Self {
            self
        }
    }
    pub struct UiTheme;
    impl UiTheme {
        pub const DEFAULT: UiTheme = UiTheme;
    }
}

// io: MMIO-only on RISC-V; port accessors panic (see io stubs above).
pub mod io2 {
    pub use super::io::{inb, outb, inw, outw, inl, outl};
}

pub mod ring3_diag {
    pub fn validate_ring3_state(_rip: u64, _rsp: u64, _cs: u64) {}
}

pub mod tss_extra {
    pub fn kernel_stack_for(_cpu: usize) -> Option<u64> {
        None
    }
}
