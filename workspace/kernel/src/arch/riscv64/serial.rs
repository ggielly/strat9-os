//! NS16550A UART driver (MMIO) for riscv64 QEMU virt.
//!
//! QEMU virt maps the first UART at physical 0x10000000, IRQ 10, with a
//! 8-byte register stride. The same uart_16550 crate used by the x86_64
//! backend works here in MMIO mode, but early boot needs a minimal
//! dependency-free path so this module implements the few required
//! operations directly.

use core::ptr::{read_volatile, write_volatile};

/// QEMU virt UART0 physical base address.
pub const UART0_BASE: u64 = 0x1000_0000;
/// Register stride in bytes.
const REG_SHIFT: u64 = 0;
/// Offset of the THR (transmit holding register) / RBR (receive buffer).
const REG_THR_RBR: u64 = 0x0;
/// Offset of the LSR (line status register).
const REG_LSR: u64 = 0x5;
/// LSR bit: transmit holding register empty.
const LSR_THRE: u8 = 1 << 5;
/// LSR bit: data ready (received byte available).
const LSR_DR: u8 = 1 << 0;

static mut UART0_MMIO: Option<u64> = None;

#[inline]
unsafe fn reg(offset: u64) -> *mut u8 {
    let base = core::ptr::addr_of!(UART0_MMIO).read().unwrap_or(UART0_BASE);
    (base.wrapping_add(offset << REG_SHIFT)) as *mut u8
}

/// Initialise the UART. Nothing to configure on QEMU virt (firmware leaves
/// it in a working state), we just record the base for potential remap.
pub fn init() {
    unsafe {
        core::ptr::addr_of_mut!(UART0_MMIO).write(Some(UART0_BASE));
    }
}

/// Write one byte to the serial line (blocking).
pub fn putc(byte: u8) {
    unsafe {
        while read_volatile(reg(REG_LSR)) & LSR_THRE == 0 {
            core::hint::spin_loop();
        }
        write_volatile(reg(REG_THR_RBR), byte);
    }
}

/// Read one byte if available, otherwise return `None` (non-blocking).
pub fn getc() -> Option<u8> {
    unsafe {
        if read_volatile(reg(REG_LSR)) & LSR_DR != 0 {
            Some(read_volatile(reg(REG_THR_RBR)))
        } else {
            None
        }
    }
}

/// Write a complete string to the serial line.
pub fn write_str(s: &str) {
    for b in s.bytes() {
        putc(b);
    }
}

/// `core::fmt::Write` bridge used by the early logger / panic path.
impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write_str(s);
        Ok(())
    }
}

/// Marker type implementing [`core::fmt::Write`] on the serial port.
pub struct SerialWriter;

/// Format-args entry point mirroring `arch::x86_64::serial::_print`.
pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    let _ = SerialWriter.write_fmt(args);
}

/// Compatibility no-op: x86-specific boot-log prefix toggling.
pub fn set_boot_log_prefix_enabled(_enabled: bool) {}

/// No cmdline source on the SBI path yet; returns an empty string until
/// the DTB `/chosen/bootargs` parser lands (jalon R1.4).
pub fn get_cmdline() -> &'static str {
    ""
}

/// Emergency mode is x86 COM1-specific; nothing to do on RISC-V.
pub fn enter_emergency_mode() {}

/// Print to serial port
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::arch::serial::_print(format_args!($($arg)*))
    };
}

/// Print to serial port with newline
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
}

/// Print to serial port with newline, bypassing the shared mutex.
#[macro_export]
macro_rules! serial_force_println {
    () => ($crate::arch::serial::_print(format_args!("\n")));
    ($($arg:tt)*) => ($crate::arch::serial::_print(format_args!("{}\n", format_args!($($arg)*))));
}

/// Store a boot cmdline for later retrieval (set by the SBI boot path).
static mut CMDLINE: Option<&'static str> = None;

/// Parse and retain the kernel cmdline from the boot protocol.
pub fn parse_cmdline(_ptr: *const u8, _len: usize) {}
