use core::fmt;
use x86_64::instructions::port::Port;

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
    () => ($crate::e9_print!("\n"));
    ($($arg:tt)*) => ($crate::e9_print!("{}\n", format_args!($($arg)*)));
}
