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

//! Platform power control (`SYS_REBOOT`).
//!
//! Arch-neutral entry point. Rebooting tries the ACPI FADT reset register,
//! then the x86 reset-control port, then the keyboard controller. Powering off
//! tries the ACPI PM1a control block, then the QEMU poweroff port. Successful
//! paths never return: they spin on `hlt`.

use crate::{silo::require_silo_admin, syscall::error::SyscallError};

const REBOOT_CMD_REBOOT: u32 = 0;
const REBOOT_CMD_POWEROFF: u32 = 1;

/// ACPI FADT flag: reset register is present and valid.
const FADT_FLAG_RESET_REG: u32 = 1 << 10;
/// ACPI address space id: system I/O.
const ACPI_ADDRESS_SPACE_IO: u8 = 1;
/// ACPI `SLP_EN` bit in the PM1 control register.
const SLP_EN: u16 = 1 << 13;
/// ACPI `SLP_TYP` value for the S5 (soft off) state.
const SLP_TYP_S5: u16 = 5 << 10;

/// `SYS_REBOOT` handler.
pub fn sys_reboot(how: u64) -> Result<u64, SyscallError> {
    require_silo_admin()?;
    match how as u32 {
        REBOOT_CMD_REBOOT => reboot(),
        REBOOT_CMD_POWEROFF => poweroff(),
        _ => Err(SyscallError::InvalidArgument),
    }
}

#[cfg(target_arch = "x86_64")]
fn halt_forever() -> ! {
    loop {
        // SAFETY: halting with interrupts disabled parks the CPU until the
        // reset/poweroff takes effect (or an NMI arrives).
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
}

#[cfg(target_arch = "x86_64")]
fn reboot() -> Result<u64, SyscallError> {
    use crate::arch::x86_64::io::{io_wait, outb};

    if let Some(fadt) = crate::acpi::get_fadt() {
        // Packed struct: copy fields out before taking any reference.
        let flags = fadt.flags;
        let reset_reg = fadt.reset_reg;
        let reset_value = fadt.reset_value;
        if flags & FADT_FLAG_RESET_REG != 0 && reset_reg.address_space == ACPI_ADDRESS_SPACE_IO {
            // SAFETY: the FADT declared this as a system-I/O reset register.
            unsafe {
                outb(reset_reg.phys_addr as u16, reset_value);
            }
            halt_forever();
        }
    }

    // SAFETY: legacy x86 reset control port, then keyboard controller pulse.
    unsafe {
        outb(0xCF9, 0x02);
        io_wait();
        outb(0xCF9, 0x06);
        outb(0x64, 0xFE);
    }
    halt_forever()
}

#[cfg(target_arch = "x86_64")]
fn poweroff() -> Result<u64, SyscallError> {
    use crate::arch::x86_64::io::{io_wait, outw};

    if let Some(fadt) = crate::acpi::get_fadt() {
        let pm1a = fadt.pm1a_control_block;
        let pm1b = fadt.pm1b_control_block;
        if pm1a != 0 {
            // SAFETY: PM1 control blocks are fixed ACPI system-I/O registers.
            unsafe {
                outw(pm1a as u16, SLP_TYP_S5 | SLP_EN);
                io_wait();
                if pm1b != 0 {
                    outw(pm1b as u16, SLP_TYP_S5 | SLP_EN);
                }
            }
        }
    }

    // SAFETY: QEMU/Bochs ACPI shutdown port fallback.
    unsafe {
        outw(0x604, 0x2000);
    }
    halt_forever()
}

#[cfg(not(target_arch = "x86_64"))]
fn reboot() -> Result<u64, SyscallError> {
    Err(SyscallError::NotImplemented)
}

#[cfg(not(target_arch = "x86_64"))]
fn poweroff() -> Result<u64, SyscallError> {
    Err(SyscallError::NotImplemented)
}
