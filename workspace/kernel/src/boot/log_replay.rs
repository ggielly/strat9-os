//! Replay of the bootloader log ring handed over in `KernelArgs` (ABI v6).
//!
//! The loader records every `[boot]` line in reserved RAM, including the ones
//! written after `ExitBootServices`, when its UEFI console is already gone.
//! Those lines exist nowhere else, so they are replayed once here -- early,
//! before a late failure can make them unreachable, and before any allocator
//! could reuse the pages.
//!
//! The ring geometry is validated by [`KernelArgs::boot_log_spans`]; this
//! module only maps the spans through the HHDM and prints them.

use strat9_abi::boot::KernelArgs;

/// Print the loader log, oldest line first. Does nothing when the loader did
/// not provide a ring (ABI < 6, or a failed allocation).
pub fn replay(args: &KernelArgs) {
    let spans = match args.boot_log_spans() {
        Ok(spans) => spans,
        Err(reason) => {
            // A bad handoff must not panic before the memory map is consumed.
            crate::serial_println!("[boot-log] unusable ring: {}", reason);
            return;
        }
    };
    if spans.is_empty() {
        return;
    }
    let physical = args.boot_log_base;
    let base = crate::memory::phys_to_virt(physical) as *const u8;
    // SAFETY: the loader reserved `boot_log_size` bytes at `boot_log_base`,
    // still covered by the HHDM at this point (it lives below the direct map
    // window), and `boot_log_spans` keeps both spans inside that buffer.
    let (head, tail) = unsafe {
        (
            core::slice::from_raw_parts(base.add(spans.start), spans.first),
            core::slice::from_raw_parts(base, spans.second),
        )
    };
    crate::serial_println!(
        "[boot-log] loader log at {:#x}, {} bytes",
        physical,
        spans.len()
    );
    write_text(head);
    write_text(tail);
    crate::serial_println!("[boot-log] end of loader log");
}

/// Emit raw bytes without formatting, so the replayed text is byte-identical.
fn write_text(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    if let Ok(text) = core::str::from_utf8(bytes) {
        crate::serial_print!("{}", text);
        return;
    }
    // A ring wrap can start mid-sequence. Escape instead of dropping the tail.
    for &byte in bytes {
        match byte {
            b'\n' | b'\r' | b'\t' => crate::serial_print!("{}", byte as char),
            0x20..=0x7e => crate::serial_print!("{}", byte as char),
            _ => crate::serial_print!("\\x{:02x}", byte),
        }
    }
}
