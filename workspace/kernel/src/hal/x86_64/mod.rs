//! x86_64 Hardware Abstraction Layer implementation.

use super::Hal;

/// x86_64 HAL implementation
pub struct X86_64Hal;

impl Hal for X86_64Hal {
    fn init() {
        crate::serial_println!("[hal] x86_64 HAL initialized");
    }

    fn setup_paging() {
        // x86_64 paging is handled by the memory subsystem
        crate::serial_println!("[hal] x86_64 paging setup delegated to memory subsystem");
    }

    fn init_interrupt_controller() {
        // x86_64 uses APIC/IOAPIC
        crate::serial_println!("[hal] x86_64 interrupt controller (APIC) init delegated");
    }

    fn enable_interrupts() {
        unsafe {
            core::arch::asm!("sti");
        }
    }

    fn disable_interrupts() {
        unsafe {
            core::arch::asm!("cli");
        }
    }

    fn halt() {
        unsafe {
            core::arch::asm!("hlt");
        }
    }

    fn current_cpu_id() -> u32 {
        // For now, return 0 (BSP)
        // TODO: Use CPUID or APIC ID for SMP
        0
    }

    fn kernel_text_start() -> u64 {
        // This would be filled by the linker script symbol
        0xFFFFFFFF80000000
    }

    fn kernel_text_end() -> u64 {
        // This would be filled by the linker script symbol
        0xFFFFFFFF80000000
    }
}
