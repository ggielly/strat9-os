use core::fmt;
use crate::x86_crate_shim::instructions::port::Port;

/// Raw e9 debugcon marker: writes a single byte to port 0xe9 using inline asm.
/// This works even when the Port type from x86_64 crate doesn't.
#[macro_export]
macro_rules! e9_mark {
    ($byte:expr) => {
        unsafe { core::arch::asm!("out 0xe9, al", in("al") $byte, options(nomem, nostack)); }
    };
}

pub struct QemuDebug;

impl fmt::Write for QemuDebug {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut port = Port::new(0xe9);
        for &byte in s.as_bytes() {
            unsafe {
                port.write(byte);
            }
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! e9_print {
    ($($arg:tt)*) => {
        {
            use core::fmt::Write;
            let _ = write!($crate::debug::QemuDebug, $($arg)*);
        }
    };
}

#[macro_export]
macro_rules! e9_println {
    () => {
        if !$crate::debug_cfg::is_quiet() {
            $crate::e9_print!("\n");
        }
    };
    ($($arg:tt)*) => {
        if !$crate::debug_cfg::is_quiet() {
            $crate::e9_print!("{}\n", format_args!($($arg)*));
        }
    };
}

/// Log a boot milestone with elapsed time since kernel entry.
///
/// Output format: `[boot +     12ms] Paging initialized`
#[macro_export]
macro_rules! boot_milestone {
    ($($arg:tt)*) => {
        if !$crate::debug_cfg::is_quiet() {
            $crate::serial_println!(
                "[boot +{:>6}ms] {}",
                $crate::arch::boot_timestamp::elapsed_ms(),
                format_args!($($arg)*)
            );
            if $crate::arch::vga::is_available() {
                let mut vbuf = [0u8; $crate::arch::vgabuf::VGABUF_LINE_LEN];
                let mut vpos = 0usize;
                use core::fmt::Write;
                struct VgaBufWriter<'a> {
                    buf: &'a mut [u8],
                    pos: &'a mut usize,
                }
                impl Write for VgaBufWriter<'_> {
                    fn write_str(&mut self, s: &str) -> core::fmt::Result {
                        let bytes = s.as_bytes();
                        let remaining = self.buf.len().saturating_sub(*self.pos);
                        let n = bytes.len().min(remaining);
                        self.buf[*self.pos..*self.pos + n].copy_from_slice(&bytes[..n]);
                        *self.pos += n;
                        Ok(())
                    }
                }
                let _ = write!(
                    VgaBufWriter { buf: &mut vbuf, pos: &mut vpos },
                    "[boot +{:>6}ms] {}\n",
                    $crate::arch::boot_timestamp::elapsed_ms(),
                    format_args!($($arg)*)
                );
                if vpos > 0 {
                    $crate::arch::vgabuf::vgabuf_write(&vbuf[..vpos]);
                }
            }
        }
    };
}
