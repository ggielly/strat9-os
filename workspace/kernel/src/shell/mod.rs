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

use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use crate::arch::x86_64::keyboard::{KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT, KEY_HOME, KEY_END};

/// Redraw the current shell input line after the prompt
fn redraw_line(input: &[u8], cursor_pos: usize) {
    // Print current buffer from current position
    for &b in input {
        print_char(b as char);
    }
    
    // Print a trailing space to clear any leftover char from a longer previous line
    print_char(' ');
    print_char('\x08');
    
    // Move visual cursor back to its logical position
    let back_moves = input.len() - cursor_pos;
    for _ in 0..back_moves {
        print_char('\x08');
    }
}

/// Main shell loop
///
/// This function never returns. It continuously reads keyboard input,
/// parses commands, and executes them.
pub extern "C" fn shell_main() -> ! {
    let registry = CommandRegistry::new();
    let mut input_buf = [0u8; 256];
    let mut input_len = 0;
    let mut cursor_pos = 0;

    // Command history
    let mut history = VecDeque::new();
    let mut history_idx: isize = -1; 
    let mut current_input_saved = String::new();

    // Display welcome message
    shell_println!("");
    shell_println!("+--------------------------------------------------------------+");
    shell_println!("|         Strat9-OS chevron shell v0.1.0 (Bedrock)             |");
    shell_println!("|         Type 'help' for available commands                   |");
    shell_println!("+--------------------------------------------------------------+");
    shell_println!("");

    print_prompt();

    let mut last_blink_tick = 0;
    let mut cursor_visible = false;

    loop {
        // Handle cursor blinking (graphics only)
        let ticks = crate::process::scheduler::ticks();
        if ticks / 50 != last_blink_tick {
            last_blink_tick = ticks / 50;
            cursor_visible = !cursor_visible;
            
            if crate::arch::x86_64::vga::is_available() {
                let color = if cursor_visible {
                    crate::arch::x86_64::vga::RgbColor::new(0x4F, 0xB3, 0xB3) // Cyan
                } else {
                    crate::arch::x86_64::vga::RgbColor::new(0x12, 0x16, 0x1E) // Background
                };
                crate::arch::x86_64::vga::draw_text_cursor(color);
            }
        }

        // Read from keyboard buffer
        if let Some(ch) = crate::arch::x86_64::keyboard::read_char() {
            // Hide cursor before any action
            if crate::arch::x86_64::vga::is_available() {
                crate::arch::x86_64::vga::draw_text_cursor(crate::arch::x86_64::vga::RgbColor::new(0x12, 0x16, 0x1E));
            }

            match ch {
                b'\r' | b'\n' => {
                    shell_println!();

                    if input_len > 0 {
                        let line = core::str::from_utf8(&input_buf[..input_len]).unwrap_or("");
                        
                        if !line.is_empty() {
                            if history.is_empty() || history.back().map(|s: &String| s.as_str()) != Some(line) {
                                history.push_back(line.to_string());
                                if history.len() > 50 {
                                    history.pop_front();
                                }
                            }
                        }

                        if let Some(cmd) = parse(line) {
                            match registry.execute(&cmd) {
                                Ok(()) => {}
                                Err(ShellError::UnknownCommand) => {
                                    shell_println!("Error: unknown command '{}'", cmd.name);
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
                        cursor_pos = 0;
                        history_idx = -1;
                    }

                    print_prompt();
                }
                b'\x08' | b'\x7f' => {
                    if cursor_pos > 0 {
                        print_char('\x08');
                        for i in (cursor_pos - 1)..(input_len - 1) {
                            input_buf[i] = input_buf[i+1];
                        }
                        input_len -= 1;
                        cursor_pos -= 1;
                        redraw_line(&input_buf[cursor_pos..input_len], 0);
                    }
                }
                KEY_LEFT => {
                    if cursor_pos > 0 {
                        cursor_pos -= 1;
                        print_char('\x08');
                    }
                }
                KEY_RIGHT => {
                    if cursor_pos < input_len {
                        let ch = input_buf[cursor_pos] as char;
                        print_char(ch);
                        cursor_pos += 1;
                    }
                }
                KEY_HOME => {
                    while cursor_pos > 0 {
                        cursor_pos -= 1;
                        print_char('\x08');
                    }
                }
                KEY_END => {
                    while cursor_pos < input_len {
                        let ch = input_buf[cursor_pos] as char;
                        print_char(ch);
                        cursor_pos += 1;
                    }
                }
                KEY_UP => {
                    if !history.is_empty() && history_idx < (history.len() as isize - 1) {
                        if history_idx == -1 {
                            current_input_saved = core::str::from_utf8(&input_buf[..input_len]).unwrap_or("").to_string();
                        }
                        
                        while cursor_pos < input_len {
                            print_char(input_buf[cursor_pos] as char);
                            cursor_pos += 1;
                        }
                        for _ in 0..input_len {
                            print_char('\x08');
                            print_char(' ');
                            print_char('\x08');
                        }
                        
                        history_idx += 1;
                        let hist_str = &history[history.len() - 1 - history_idx as usize];
                        let bytes = hist_str.as_bytes();
                        let copy_len = bytes.len().min(input_buf.len());
                        input_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
                        input_len = copy_len;
                        cursor_pos = input_len;
                        
                        for &b in &input_buf[..input_len] {
                            print_char(b as char);
                        }
                    }
                }
                KEY_DOWN => {
                    if history_idx >= 0 {
                        while cursor_pos < input_len {
                            print_char(input_buf[cursor_pos] as char);
                            cursor_pos += 1;
                        }
                        for _ in 0..input_len {
                            print_char('\x08');
                            print_char(' ');
                            print_char('\x08');
                        }
                        
                        history_idx -= 1;
                        if history_idx == -1 {
                            let bytes = current_input_saved.as_bytes();
                            let copy_len = bytes.len().min(input_buf.len());
                            input_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
                            input_len = copy_len;
                        } else {
                            let hist_str = &history[history.len() - 1 - history_idx as usize];
                            let bytes = hist_str.as_bytes();
                            let copy_len = bytes.len().min(input_buf.len());
                            input_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
                            input_len = copy_len;
                        }
                        cursor_pos = input_len;
                        
                        for &b in &input_buf[..input_len] {
                            print_char(b as char);
                        }
                    }
                }
                _ if ch >= 0x20 && ch < 0x7f => {
                    if input_len < input_buf.len() {
                        if cursor_pos < input_len {
                            for i in (cursor_pos + 1..=input_len).rev() {
                                input_buf[i] = input_buf[i-1];
                            }
                        }
                        input_buf[cursor_pos] = ch;
                        input_len += 1;
                        redraw_line(&input_buf[cursor_pos..input_len], 1);
                        cursor_pos += 1;
                        history_idx = -1;
                    }
                }
                _ => {}
            }
            // Reset blink state on input
            last_blink_tick = ticks / 50;
            cursor_visible = true;
        } else {
            crate::process::yield_task();
        }
    }
}
