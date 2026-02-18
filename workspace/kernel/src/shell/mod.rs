//! Chevron shell - Minimal interactive kernel shell
//!
//! Provides a simple interactive command-line interface for kernel management.
//! Prompt: >>>

pub mod builtins;
pub mod commands;
pub mod output;
pub mod parser;

use commands::CommandRegistry;
use output::{print_char, print_prompt};
use parser::parse;

// Import the shell output macros
use crate::shell_println;

/// Shell error types
#[derive(Debug)]
pub enum ShellError {
    /// Unknown command
    UnknownCommand,
    /// Invalid arguments
    InvalidArguments,
    /// Command execution failed
    ExecutionFailed,
}

/// Main shell loop
///
/// This function never returns. It continuously reads keyboard input,
/// parses commands, and executes them.
pub extern "C" fn shell_main() -> ! {
    let registry = CommandRegistry::new();
    let mut input_buf = [0u8; 256];
    let mut input_len = 0;

    // Display welcome message
    shell_println!("");
    shell_println!("+--------------------------------------------------------------+");
    shell_println!("|         Strat9-OS chevron shell v0.1.0 (Bedrock)             |");
    shell_println!("|         Type 'help' for available commands                   |");
    shell_println!("+--------------------------------------------------------------+");
    shell_println!("");

    print_prompt();

    loop {
        // Read from keyboard buffer
        if let Some(ch) = crate::arch::x86_64::keyboard::read_char() {
            match ch {
                b'\r' | b'\n' => {
                    // Echo newline
                    shell_println!();

                    // Execute command
                    if input_len > 0 {
                        let line = core::str::from_utf8(&input_buf[..input_len]).unwrap_or("");

                        if let Some(cmd) = parse(line) {
                            match registry.execute(&cmd) {
                                Ok(()) => {
                                    // Command executed successfully
                                }
                                Err(ShellError::UnknownCommand) => {
                                    shell_println!("Error: Unknown command '{}'", cmd.name);
                                    shell_println!("Type 'help' for available commands.");
                                }
                                Err(ShellError::InvalidArguments) => {
                                    shell_println!("Error: invalid arguments");
                                }
                                Err(ShellError::ExecutionFailed) => {
                                    shell_println!("Error: command execution failed");
                                }
                            }
                        }
                        input_len = 0;
                    }

                    print_prompt();
                }
                b'\x08' | b'\x7f' => {
                    // Backspace
                    if input_len > 0 {
                        input_len -= 1;
                        print_char('\x08');
                        print_char(' ');
                        print_char('\x08');
                    }
                }
                _ if ch >= 0x20 && ch < 0x7f => {
                    // Printable character
                    if input_len < input_buf.len() {
                        input_buf[input_len] = ch;
                        input_len += 1;
                        print_char(ch as char);
                    }
                }
                _ => {}
            }
        } else {
            // No keyboard input - yield CPU to other tasks
            // This prevents deadlock when commands need locks held by other tasks
            crate::process::yield_task();
        }
    }
}
