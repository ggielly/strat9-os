use super::*;

/// Attach to a silo's debug output stream.
///
/// Usage: `silo attach <id|label>`
///
/// Displays output from `sys_debug_log` calls made by tasks in the silo.
/// Press Ctrl+C or 'q' to detach.
pub(super) fn cmd_silo_attach(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: silo attach <id|label>");
        return Err(ShellError::InvalidArguments);
    }
    let selector = args[1].as_str();

    let sid = match silo::silo_detail_snapshot(selector) {
        Ok(detail) => {
            shell_println!(
                "Attached to silo {} ({}). Press Ctrl+C or 'q' to detach.",
                detail.base.id,
                detail.base.name
            );
            detail.base.id
        }
        Err(e) => {
            shell_println!("silo attach: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };

    loop {
        if let Some(ch) = crate::arch::x86_64::keyboard::read_char() {
            if ch == b'q' || ch == 0x03 || ch == 0x1B {
                break;
            }
        }

        match silo::silo_output_drain(&alloc::format!("{}", sid)) {
            Ok(data) if !data.is_empty() => {
                if let Ok(s) = core::str::from_utf8(&data) {
                    crate::shell_print!("{}", s);
                }
            }
            _ => {}
        }

        crate::process::yield_task();
    }

    shell_println!("\nDetached from silo {}", sid);
    Ok(())
}
