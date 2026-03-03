//! Chevron shell - Minimal interactive kernel shell
//!
//! Provides a simple interactive command-line interface for kernel management.
//! Prompt: >>>

// TODO UTF8
//- clavier/layout renvoie des codepoints Unicode (pas seulement u8), puis conversion UTF‑8 pour l’édition.
//- plus tard seulement, gestion graphemes/combinaisons complexes.

pub mod commands;
pub mod output;
pub mod parser;
pub mod scripting;

use commands::CommandRegistry;
use output::{print_char, print_prompt};
use parser::{parse_pipeline, Redirect};

use crate::{shell_print, shell_println, vfs};
use strat9_abi::flag::OpenFlags;

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

use crate::arch::x86_64::keyboard::{KEY_DOWN, KEY_END, KEY_HOME, KEY_LEFT, KEY_RIGHT, KEY_UP};
use alloc::{
    collections::VecDeque,
    string::{String, ToString},
};
use core::sync::atomic::{AtomicBool, Ordering};

/// Global flag set by Ctrl+C. Long-running commands should poll this
/// via [`is_interrupted`] and abort early when it returns `true`.
pub static SHELL_INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Returns `true` if Ctrl+C was pressed, and clears the flag.
///
/// Commands that loop (e.g. `top`, `watch`) should call this each
/// iteration to support cancellation.
pub fn is_interrupted() -> bool {
    SHELL_INTERRUPTED.swap(false, Ordering::Relaxed)
}

/// Returns whether continuation byte.
#[inline]
fn is_continuation_byte(b: u8) -> bool {
    (b & 0b1100_0000) == 0b1000_0000
}

/// Performs the prev char boundary operation.
fn prev_char_boundary(input: &[u8], mut idx: usize) -> usize {
    if idx == 0 {
        return 0;
    }
    idx -= 1;
    while idx > 0 && is_continuation_byte(input[idx]) {
        idx -= 1;
    }
    idx
}

/// Performs the next char boundary operation.
fn next_char_boundary(input: &[u8], mut idx: usize) -> usize {
    if idx >= input.len() {
        return input.len();
    }
    idx += 1;
    while idx < input.len() && is_continuation_byte(input[idx]) {
        idx += 1;
    }
    idx
}

/// Performs the char count operation.
fn char_count(input: &[u8]) -> usize {
    core::str::from_utf8(input)
        .map(|s| s.chars().count())
        .unwrap_or(input.len())
}

/// Performs the print bytes operation.
fn print_bytes(input: &[u8]) {
    if let Ok(s) = core::str::from_utf8(input) {
        for ch in s.chars() {
            print_char(ch);
        }
    } else {
        for &b in input {
            print_char(if b.is_ascii() { b as char } else { '?' });
        }
    }
}

/// Performs the move cursor left chars operation.
fn move_cursor_left_chars(n: usize) {
    for _ in 0..n {
        print_char('\x08');
    }
}

/// Performs the clear visible line operation.
fn clear_visible_line(line: &[u8]) {
    let n = char_count(line);
    move_cursor_left_chars(n);
    for _ in 0..n {
        print_char(' ');
    }
    move_cursor_left_chars(n);
}

/// Redraw the current shell input line after the prompt
fn redraw_line(input: &[u8], cursor_pos: usize) {
    print_bytes(input);

    // Print a trailing space to clear any leftover char from a longer previous line
    print_char(' ');
    print_char('\x08');

    // Move visual cursor back to its logical position
    let back_moves = if cursor_pos <= input.len() {
        if let (Ok(full), Ok(prefix)) = (
            core::str::from_utf8(input),
            core::str::from_utf8(&input[..cursor_pos]),
        ) {
            full.chars().count().saturating_sub(prefix.chars().count())
        } else {
            input.len().saturating_sub(cursor_pos)
        }
    } else {
        0
    };
    for _ in 0..back_moves {
        print_char('\x08');
    }
}

/// Performs the redraw full line operation.
fn redraw_full_line(input: &[u8], cursor_pos: usize) {
    clear_visible_line(input);
    print_bytes(input);
    if cursor_pos <= input.len() {
        if let Ok(sfx) = core::str::from_utf8(&input[cursor_pos..]) {
            move_cursor_left_chars(sfx.chars().count());
        } else {
            move_cursor_left_chars(input.len().saturating_sub(cursor_pos));
        }
    }
}

/// Performs the insert bytes at cursor operation.
fn insert_bytes_at_cursor(
    input_buf: &mut [u8],
    input_len: &mut usize,
    cursor_pos: &mut usize,
    bytes: &[u8],
) -> bool {
    if bytes.is_empty() {
        return true;
    }
    if *input_len + bytes.len() > input_buf.len() {
        return false;
    }
    let old_cursor = *cursor_pos;
    if old_cursor < *input_len {
        for i in (old_cursor..*input_len).rev() {
            input_buf[i + bytes.len()] = input_buf[i];
        }
    }
    input_buf[old_cursor..old_cursor + bytes.len()].copy_from_slice(bytes);
    *input_len += bytes.len();
    *cursor_pos += bytes.len();
    redraw_line(&input_buf[old_cursor..*input_len], bytes.len());
    true
}

/// Performs the delete prev char at cursor operation.
fn delete_prev_char_at_cursor(
    input_buf: &mut [u8],
    input_len: &mut usize,
    cursor_pos: &mut usize,
) -> bool {
    if *cursor_pos == 0 {
        return false;
    }

    let prev = prev_char_boundary(&input_buf[..*input_len], *cursor_pos);
    let removed = *cursor_pos - prev;
    for i in *cursor_pos..*input_len {
        input_buf[i - removed] = input_buf[i];
    }
    *input_len -= removed;
    *cursor_pos = prev;

    // Backspace behavior: visual cursor moves left by one character first.
    move_cursor_left_chars(1);
    redraw_line(&input_buf[*cursor_pos..*input_len], 0);
    true
}

/// Performs the delete next char at cursor operation.
fn delete_next_char_at_cursor(
    input_buf: &mut [u8],
    input_len: &mut usize,
    cursor_pos: &mut usize,
) -> bool {
    if *cursor_pos >= *input_len {
        return false;
    }

    let next = next_char_boundary(&input_buf[..*input_len], *cursor_pos);
    let removed = next - *cursor_pos;
    for i in next..*input_len {
        input_buf[i - removed] = input_buf[i];
    }
    *input_len -= removed;

    // Delete behavior: cursor stays at the same logical position.
    redraw_line(&input_buf[*cursor_pos..*input_len], 0);
    true
}

/// Main shell loop
///
/// This function never returns. It continuously reads keyboard input,
/// parses commands, and executes them.
pub extern "C" fn shell_main() -> ! {
    let registry = CommandRegistry::new();
    commands::util::init_shell_env();
    let mut input_buf = [0u8; 256];
    let mut input_len = 0;
    let mut cursor_pos = 0;

    // Command history
    let mut history = VecDeque::new();
    let mut history_idx: isize = -1;
    let mut current_input_saved = String::new();
    let mut utf8_pending = [0u8; 4];
    let mut utf8_pending_len = 0usize;
    let mut in_escape_seq = false;

    // Mouse state
    let mut prev_left = false;
    let mut selecting = false;
    let mut scrollbar_dragging = false;
    let mut last_scrollbar_drag_tick = 0u64;
    let mut pending_scrollbar_drag_y: Option<usize> = None;
    let mut mouse_x: i32 = 0;
    let mut mouse_y: i32 = 0;

    // Display welcome message using ASCII for robust terminal rendering.
    shell_println!("");
    shell_println!("+--------------------------------------------------------------+");
    shell_println!("|         Strat9-OS chevron shell v0.1.0 (Bedrock)            |");
    shell_println!("|         Type 'help' for available commands                  |");
    shell_println!("+--------------------------------------------------------------+");
    shell_println!("");

    print_prompt();

    let mut last_blink_tick = 0;
    let mut cursor_visible = false;
    const MAX_MOUSE_EVENTS_PER_TURN: usize = 64;
    const SCROLLBAR_DRAG_MIN_TICKS: u64 = 1;

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
            // Any keypress returns the view to live output.
            if crate::arch::x86_64::vga::is_available() {
                crate::arch::x86_64::vga::scroll_to_live();
            }

            // Hide cursor before any action
            if crate::arch::x86_64::vga::is_available() {
                crate::arch::x86_64::vga::draw_text_cursor(
                    crate::arch::x86_64::vga::RgbColor::new(0x12, 0x16, 0x1E),
                );
            }

            match ch {
                b'\r' | b'\n' => {
                    in_escape_seq = false;
                    utf8_pending_len = 0;
                    shell_println!();

                    if input_len > 0 {
                        let line = core::str::from_utf8(&input_buf[..input_len]).unwrap_or("");

                        if !line.is_empty() {
                            if history.is_empty()
                                || history.back().map(|s: &String| s.as_str()) != Some(line)
                            {
                                history.push_back(line.to_string());
                                if history.len() > 50 {
                                    history.pop_front();
                                }
                            }
                        }

                        execute_line(line, &registry);
                        input_len = 0;
                        cursor_pos = 0;
                        history_idx = -1;
                    }

                    print_prompt();
                }
                b'\x08' | b'\x7f' => {
                    in_escape_seq = false;
                    utf8_pending_len = 0;
                    let _ = delete_prev_char_at_cursor(
                        &mut input_buf,
                        &mut input_len,
                        &mut cursor_pos,
                    );
                }
                b'\x03' => {
                    in_escape_seq = false;
                    utf8_pending_len = 0;
                    shell_println!("^C");
                    input_len = 0;
                    cursor_pos = 0;
                    history_idx = -1;
                    SHELL_INTERRUPTED.store(false, Ordering::Relaxed);
                    print_prompt();
                }
                b'\t' => {
                    in_escape_seq = false;
                    utf8_pending_len = 0;
                    tab_complete(
                        &mut input_buf,
                        &mut input_len,
                        &mut cursor_pos,
                        &registry,
                    );
                }
                b'\x04' => {
                    in_escape_seq = false;
                    utf8_pending_len = 0;
                    let _ = delete_next_char_at_cursor(
                        &mut input_buf,
                        &mut input_len,
                        &mut cursor_pos,
                    );
                }
                KEY_LEFT => {
                    in_escape_seq = false;
                    utf8_pending_len = 0;
                    if cursor_pos > 0 {
                        cursor_pos = prev_char_boundary(&input_buf[..input_len], cursor_pos);
                        print_char('\x08');
                    }
                }
                KEY_RIGHT => {
                    in_escape_seq = false;
                    utf8_pending_len = 0;
                    if cursor_pos < input_len {
                        let next = next_char_boundary(&input_buf[..input_len], cursor_pos);
                        print_bytes(&input_buf[cursor_pos..next]);
                        cursor_pos = next;
                    }
                }
                KEY_HOME => {
                    in_escape_seq = false;
                    utf8_pending_len = 0;
                    while cursor_pos > 0 {
                        cursor_pos = prev_char_boundary(&input_buf[..input_len], cursor_pos);
                        print_char('\x08');
                    }
                }
                KEY_END => {
                    in_escape_seq = false;
                    utf8_pending_len = 0;
                    while cursor_pos < input_len {
                        let next = next_char_boundary(&input_buf[..input_len], cursor_pos);
                        print_bytes(&input_buf[cursor_pos..next]);
                        cursor_pos = next;
                    }
                }
                KEY_UP => {
                    in_escape_seq = false;
                    utf8_pending_len = 0;
                    if !history.is_empty() && history_idx < (history.len() as isize - 1) {
                        if history_idx == -1 {
                            current_input_saved = core::str::from_utf8(&input_buf[..input_len])
                                .unwrap_or("")
                                .to_string();
                        }

                        while cursor_pos < input_len {
                            let next = next_char_boundary(&input_buf[..input_len], cursor_pos);
                            print_bytes(&input_buf[cursor_pos..next]);
                            cursor_pos = next;
                        }
                        clear_visible_line(&input_buf[..input_len]);

                        history_idx += 1;
                        let hist_str = &history[history.len() - 1 - history_idx as usize];
                        let bytes = hist_str.as_bytes();
                        let copy_len = bytes.len().min(input_buf.len());
                        input_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
                        input_len = copy_len;
                        cursor_pos = input_len;

                        redraw_full_line(&input_buf[..input_len], cursor_pos);
                    }
                }
                KEY_DOWN => {
                    in_escape_seq = false;
                    utf8_pending_len = 0;
                    if history_idx >= 0 {
                        while cursor_pos < input_len {
                            let next = next_char_boundary(&input_buf[..input_len], cursor_pos);
                            print_bytes(&input_buf[cursor_pos..next]);
                            cursor_pos = next;
                        }
                        clear_visible_line(&input_buf[..input_len]);

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

                        redraw_full_line(&input_buf[..input_len], cursor_pos);
                    }
                }
                b'\x1b' => {
                    utf8_pending_len = 0;
                    in_escape_seq = true;
                }
                _ if in_escape_seq => {
                    if (0x40..=0x7E).contains(&ch) {
                        in_escape_seq = false;
                    } else if ch == b'[' || ch == b';' || ch == b'?' || ch.is_ascii_digit() {
                        // stay in escape sequence
                    } else {
                        in_escape_seq = false;
                    }
                }
                _ if ch >= 0x20 => {
                    in_escape_seq = false;
                    if ch < 0x80 {
                        utf8_pending_len = 0;
                        if insert_bytes_at_cursor(
                            &mut input_buf,
                            &mut input_len,
                            &mut cursor_pos,
                            core::slice::from_ref(&ch),
                        ) {
                            history_idx = -1;
                        }
                    } else {
                        if utf8_pending_len >= utf8_pending.len() {
                            utf8_pending_len = 0;
                        }
                        utf8_pending[utf8_pending_len] = ch;
                        utf8_pending_len += 1;
                        match core::str::from_utf8(&utf8_pending[..utf8_pending_len]) {
                            Ok(s) => {
                                if insert_bytes_at_cursor(
                                    &mut input_buf,
                                    &mut input_len,
                                    &mut cursor_pos,
                                    s.as_bytes(),
                                ) {
                                    history_idx = -1;
                                }
                                utf8_pending_len = 0;
                            }
                            Err(err) => {
                                if err.error_len().is_some() {
                                    utf8_pending_len = 0;
                                }
                            }
                        }
                    }
                }
                _ => {
                    in_escape_seq = false;
                    utf8_pending_len = 0;
                }
            }
            // Reset blink state on input
            last_blink_tick = ticks / 50;
            cursor_visible = true;
        } else {
            if crate::arch::x86_64::mouse::MOUSE_READY.load(core::sync::atomic::Ordering::Relaxed) {
                let mut scroll_delta: i32 = 0;
                let mut left_pressed = false;
                let mut left_released = false;
                let mut left_held = false;
                let mut had_events = false;

                let mut mouse_events_seen = 0usize;
                while let Some(ev) = crate::arch::x86_64::mouse::read_event() {
                    had_events = true;
                    scroll_delta += ev.dz as i32;
                    if ev.left && !prev_left {
                        left_pressed = true;
                    }
                    if !ev.left && prev_left {
                        left_released = true;
                    }
                    if ev.left && prev_left {
                        left_held = true;
                    }
                    prev_left = ev.left;
                    mouse_events_seen += 1;
                    if mouse_events_seen >= MAX_MOUSE_EVENTS_PER_TURN {
                        // Prevent monopolizing the CPU under heavy mouse input
                        // (e.g. rapid drag on scrollbar). Remaining events are
                        // processed on next loop iteration after yield_task().
                        break;
                    }
                }

                if had_events || left_held {
                    let (new_mx, new_my) = crate::arch::x86_64::mouse::mouse_pos();
                    let moved = new_mx != mouse_x || new_my != mouse_y;
                    mouse_x = new_mx;
                    mouse_y = new_my;

                    if crate::arch::x86_64::vga::is_available() {
                        // Inverted wheel: wheel up (dz>0) → scroll down (history forward)
                        if scroll_delta > 0 {
                            crate::arch::x86_64::vga::scroll_view_down((scroll_delta as usize) * 3);
                        } else if scroll_delta < 0 {
                            crate::arch::x86_64::vga::scroll_view_up((-scroll_delta as usize) * 3);
                        }

                        if left_pressed {
                            let (mx, my) = (new_mx as usize, new_my as usize);
                            if crate::arch::x86_64::vga::scrollbar_hit_test(mx, my) {
                                crate::arch::x86_64::vga::scrollbar_click(mx, my);
                                crate::arch::x86_64::vga::clear_selection();
                                selecting = false;
                                scrollbar_dragging = true;
                            } else {
                                crate::arch::x86_64::vga::start_selection(mx, my);
                                selecting = true;
                                scrollbar_dragging = false;
                            }
                        } else if left_held && scrollbar_dragging && moved {
                            pending_scrollbar_drag_y = Some(new_my as usize);
                            if ticks.saturating_sub(last_scrollbar_drag_tick)
                                >= SCROLLBAR_DRAG_MIN_TICKS
                            {
                                if let Some(py) = pending_scrollbar_drag_y.take() {
                                    crate::arch::x86_64::vga::scrollbar_drag_to(py);
                                    last_scrollbar_drag_tick = ticks;
                                }
                            }
                        } else if left_held && selecting && moved {
                            crate::arch::x86_64::vga::update_selection(
                                new_mx as usize,
                                new_my as usize,
                            );
                        } else if left_released {
                            if selecting {
                                crate::arch::x86_64::vga::end_selection();
                                selecting = false;
                            }
                            if scrollbar_dragging {
                                if let Some(py) = pending_scrollbar_drag_y.take() {
                                    crate::arch::x86_64::vga::scrollbar_drag_to(py);
                                }
                            }
                            scrollbar_dragging = false;
                        }

                        if moved {
                            crate::arch::x86_64::vga::update_mouse_cursor(new_mx, new_my);
                        }
                    }
                }
            }
            crate::process::yield_task();
        }
    }
}

/// Execute a command line, handling scripting, pipes and redirections.
fn execute_line(line: &str, registry: &CommandRegistry) {
    let expanded = scripting::expand_vars(line);

    match scripting::parse_script(&expanded) {
        scripting::ScriptConstruct::SetVar { key, val } => {
            let expanded_val = scripting::expand_vars(&val);
            scripting::set_var(&key, &expanded_val);
            scripting::set_last_exit(0);
            return;
        }
        scripting::ScriptConstruct::UnsetVar(key) => {
            scripting::unset_var(&key);
            scripting::set_last_exit(0);
            return;
        }
        scripting::ScriptConstruct::ForLoop { var, items, body } => {
            for item in &items {
                scripting::set_var(&var, item);
                for cmd in &body {
                    let exp = scripting::expand_vars(cmd);
                    execute_pipeline(&exp, registry);
                }
            }
            return;
        }
        scripting::ScriptConstruct::WhileLoop { cond, body } => {
            let mut iters = 0u32;
            loop {
                if iters > 10000 || SHELL_INTERRUPTED.load(Ordering::Relaxed) {
                    break;
                }
                execute_pipeline(&cond, registry);
                if scripting::last_exit() != 0 {
                    break;
                }
                for cmd in &body {
                    let exp = scripting::expand_vars(cmd);
                    execute_pipeline(&exp, registry);
                }
                iters += 1;
            }
            return;
        }
        scripting::ScriptConstruct::IfElse { cond, then_body, else_body } => {
            execute_pipeline(&cond, registry);
            let branch = if scripting::last_exit() == 0 {
                &then_body
            } else {
                &else_body
            };
            for cmd in branch {
                let exp = scripting::expand_vars(cmd);
                execute_pipeline(&exp, registry);
            }
            return;
        }
        scripting::ScriptConstruct::Simple(s) => {
            execute_pipeline(&s, registry);
        }
    }
}

/// Execute a single pipeline (no scripting).
fn execute_pipeline(line: &str, registry: &CommandRegistry) {
    let pipeline = match parse_pipeline(line) {
        Some(p) => p,
        None => return,
    };

    let stage_count = pipeline.stages.len();
    let mut pipe_data: Option<alloc::vec::Vec<u8>> = None;

    for (i, stage) in pipeline.stages.iter().enumerate() {
        let is_last = i == stage_count - 1;
        let needs_capture = !is_last || stage.stdout_redirect.is_some();

        if let Some(ref stdin_path) = stage.stdin_redirect {
            match vfs::open(stdin_path, vfs::OpenFlags::READ) {
                Ok(fd) => {
                    let data = vfs::read_all(fd).unwrap_or_default();
                    let _ = vfs::close(fd);
                    output::set_pipe_input(data);
                }
                Err(e) => {
                    shell_println!("shell: cannot open '{}': {:?}", stdin_path, e);
                    return;
                }
            }
        } else if let Some(data) = pipe_data.take() {
            output::set_pipe_input(data);
        }

        if needs_capture {
            output::start_capture();
        }

        let result = registry.execute(&stage.command);

        let captured = if needs_capture {
            output::take_capture()
        } else {
            alloc::vec::Vec::new()
        };

        match result {
            Ok(()) => {
                scripting::set_last_exit(0);
            }
            Err(ShellError::UnknownCommand) => {
                scripting::set_last_exit(127);
                shell_println!("Error: unknown command '{}'", stage.command.name);
                return;
            }
            Err(ShellError::InvalidArguments) => {
                scripting::set_last_exit(2);
                shell_println!("Error: invalid arguments for '{}'", stage.command.name);
                return;
            }
            Err(ShellError::ExecutionFailed) => {
                scripting::set_last_exit(1);
                shell_println!("Error: '{}' execution failed", stage.command.name);
                return;
            }
        }

        if let Some(ref redirect) = stage.stdout_redirect {
            apply_redirect(redirect, &captured);
        }

        if !is_last {
            pipe_data = Some(captured);
        }
    }
}

/// Tab completion for command names and VFS paths.
///
/// If the cursor is on the first token, completes against registered commands.
/// Otherwise completes against VFS directory entries.
fn tab_complete(
    input_buf: &mut [u8],
    input_len: &mut usize,
    cursor_pos: &mut usize,
    registry: &CommandRegistry,
) {
    let text = match core::str::from_utf8(&input_buf[..*input_len]) {
        Ok(s) => s,
        Err(_) => return,
    };

    let before_cursor = &text[..*cursor_pos];
    let has_space = before_cursor.contains(' ');

    if !has_space {
        let prefix = before_cursor;
        let names = registry.command_names();
        let matches: alloc::vec::Vec<&str> =
            names.iter().copied().filter(|n| n.starts_with(prefix)).collect();

        if matches.len() == 1 {
            complete_replace_word(input_buf, input_len, cursor_pos, 0, matches[0], true);
        } else if matches.len() > 1 {
            let common = longest_common_prefix(&matches);
            if common.len() > prefix.len() {
                complete_replace_word(input_buf, input_len, cursor_pos, 0, &common, false);
            } else {
                shell_println!();
                for m in &matches {
                    shell_print!("{}  ", m);
                }
                shell_println!();
                output::print_prompt();
                print_bytes(&input_buf[..*input_len]);
                let back = char_count(&input_buf[*cursor_pos..*input_len]);
                move_cursor_left_chars(back);
            }
        }
    } else {
        let last_space = before_cursor.rfind(' ').unwrap_or(0);
        let partial = &before_cursor[last_space + 1..];
        let (dir, file_prefix) = if let Some(slash_pos) = partial.rfind('/') {
            (&partial[..=slash_pos], &partial[slash_pos + 1..])
        } else {
            ("/", partial)
        };

        if let Ok(fd) = vfs::open(dir, OpenFlags::READ | OpenFlags::DIRECTORY) {
            let entries = vfs::getdents(fd).unwrap_or_default();
            let _ = vfs::close(fd);

            let matches: alloc::vec::Vec<alloc::string::String> = entries
                .iter()
                .filter(|e| e.name != "." && e.name != ".." && e.name.starts_with(file_prefix))
                .map(|e| {
                    let mut s = alloc::string::String::from(dir);
                    s.push_str(&e.name);
                    if e.file_type == strat9_abi::data::DT_DIR {
                        s.push('/');
                    }
                    s
                })
                .collect();

            if matches.len() == 1 {
                let add_space = !matches[0].ends_with('/');
                complete_replace_word(
                    input_buf,
                    input_len,
                    cursor_pos,
                    last_space + 1,
                    &matches[0],
                    add_space,
                );
            } else if matches.len() > 1 {
                let refs: alloc::vec::Vec<&str> = matches.iter().map(|s| s.as_str()).collect();
                let common = longest_common_prefix(&refs);
                if common.len() > partial.len() {
                    complete_replace_word(
                        input_buf,
                        input_len,
                        cursor_pos,
                        last_space + 1,
                        &common,
                        false,
                    );
                } else {
                    shell_println!();
                    for m in &matches {
                        let name = m.rsplit('/').next().unwrap_or(m);
                        shell_print!("{}  ", name);
                    }
                    shell_println!();
                    output::print_prompt();
                    print_bytes(&input_buf[..*input_len]);
                    let back = char_count(&input_buf[*cursor_pos..*input_len]);
                    move_cursor_left_chars(back);
                }
            }
        }
    }
}

/// Replace the word starting at `word_start` (byte offset) with `replacement`.
fn complete_replace_word(
    buf: &mut [u8],
    len: &mut usize,
    cursor: &mut usize,
    word_start: usize,
    replacement: &str,
    add_trailing_space: bool,
) {
    let mut new_line = alloc::string::String::new();
    if let Ok(prefix) = core::str::from_utf8(&buf[..word_start]) {
        new_line.push_str(prefix);
    }
    new_line.push_str(replacement);
    if add_trailing_space {
        new_line.push(' ');
    }
    let new_cursor = new_line.len();
    if let Ok(suffix) = core::str::from_utf8(&buf[*cursor..*len]) {
        new_line.push_str(suffix);
    }

    let bytes = new_line.as_bytes();
    if bytes.len() > buf.len() {
        return;
    }

    let old_visible = char_count(&buf[..*len]);
    move_cursor_left_chars(char_count(&buf[..*cursor]));

    buf[..bytes.len()].copy_from_slice(bytes);
    *len = bytes.len();
    *cursor = new_cursor;

    for _ in 0..old_visible {
        print_char(' ');
    }
    move_cursor_left_chars(old_visible);
    print_bytes(&buf[..*len]);
    let back = char_count(&buf[*cursor..*len]);
    move_cursor_left_chars(back);
}

/// Find the longest common prefix of a set of strings.
fn longest_common_prefix(strings: &[&str]) -> alloc::string::String {
    if strings.is_empty() {
        return alloc::string::String::new();
    }
    let first = strings[0];
    let mut end = first.len();
    for s in &strings[1..] {
        end = end.min(s.len());
        for (i, (a, b)) in first.bytes().zip(s.bytes()).enumerate() {
            if a != b {
                end = end.min(i);
                break;
            }
        }
    }
    alloc::string::String::from(&first[..end])
}

/// Write captured output to a file (truncate or append).
fn apply_redirect(redirect: &Redirect, data: &[u8]) {
    match redirect {
        Redirect::Truncate(path) => {
            let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE;
            match vfs::open(path, flags) {
                Ok(fd) => {
                    let _ = vfs::write(fd, data);
                    let _ = vfs::close(fd);
                }
                Err(e) => shell_println!("shell: cannot write '{}': {:?}", path, e),
            }
        }
        Redirect::Append(path) => {
            let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::APPEND;
            match vfs::open(path, flags) {
                Ok(fd) => {
                    let _ = vfs::write(fd, data);
                    let _ = vfs::close(fd);
                }
                Err(e) => shell_println!("shell: cannot append '{}': {:?}", path, e),
            }
        }
    }
}
