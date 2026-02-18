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
