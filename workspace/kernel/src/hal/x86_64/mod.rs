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
