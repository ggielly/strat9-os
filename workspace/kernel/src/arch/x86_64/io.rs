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

//! Port I/O functions for x86_64 (inspired by Maestro OS)
//!
//! These functions allow communication with hardware via I/O ports.

use core::arch::asm;

/// Read a byte from the specified port.
///
/// # Safety
/// Reading from an invalid port has undefined behavior.
#[inline(always)]
pub unsafe fn inb(port: u16) -> u8 {
    let ret: u8;
    unsafe {
        asm!("in al, dx", out("al") ret, in("dx") port, options(nostack, nomem));
    }
    ret
}

/// Read a word from the specified port.
///
/// # Safety
/// Reading from an invalid port has undefined behavior.
#[inline(always)]
pub unsafe fn inw(port: u16) -> u16 {
    let ret: u16;
    unsafe {
        asm!("in ax, dx", out("ax") ret, in("dx") port, options(nostack, nomem));
    }
    ret
}

/// Read a dword from the specified port.
///
/// # Safety
/// Reading from an invalid port has undefined behavior.
#[inline(always)]
pub unsafe fn inl(port: u16) -> u32 {
    let ret: u32;
    unsafe {
        asm!("in eax, dx", out("eax") ret, in("dx") port, options(nostack, nomem));
    }
    ret
}

/// Write a byte to the specified port.
///
/// # Safety
/// Writing to an invalid port has undefined behavior.
#[inline(always)]
pub unsafe fn outb(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("al") value, in("dx") port, options(nostack, nomem));
    }
}

/// Write a word to the specified port.
///
/// # Safety
/// Writing to an invalid port has undefined behavior.
#[inline(always)]
pub unsafe fn outw(port: u16, value: u16) {
    unsafe {
        asm!("out dx, ax", in("ax") value, in("dx") port, options(nostack, nomem));
    }
}

/// Write a dword to the specified port.
///
/// # Safety
/// Writing to an invalid port has undefined behavior.
#[inline(always)]
pub unsafe fn outl(port: u16, value: u32) {
    unsafe {
        asm!("out dx, eax", in("eax") value, in("dx") port, options(nostack, nomem));
    }
}

/// Short delay for I/O operations (port 0x80 trick)
#[inline(always)]
pub fn io_wait() {
    unsafe {
        outb(0x80, 0);
    }
}
