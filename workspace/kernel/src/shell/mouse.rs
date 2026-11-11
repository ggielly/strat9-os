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

//! Mouse input and rendering are independent of shell command execution.
//! The mouse task never touches the VGA writer: it publishes commands through
//! [`crate::shell::vga_input`] and the console-render task applies them.
pub extern "C" fn mouse_task_main() -> ! {
    use crate::shell::vga_input::{self, InputCommand};

    // Local button/position state only; visual state lives in the renderer.
    let mut prev_left = false;
    let mut mouse_x: i32 = 0;
    let mut mouse_y: i32 = 0;

    // Cap per-loop mouse work to avoid starving timer ticks when dragging.
    const MAX_MOUSE_EVENTS_PER_TURN: usize = 16;
    // Wheel, Press/Held, Release, Cursor plus the EndTurn marker.
    const MAX_COMMANDS_PER_TURN: usize = vga_input::MAX_TURN_COMMANDS;

    loop {
        if crate::hardware::usb::hid::is_available() {
            crate::hardware::usb::hid::poll_all();
        }
        // Backpressure: if the ring cannot hold this turn's commands, leave the
        // events queued and retry next tick instead of dropping input.
        if crate::arch::mouse::MOUSE_READY.load(core::sync::atomic::Ordering::Relaxed)
            && vga_input::has_space(MAX_COMMANDS_PER_TURN)
        {
            let mut scroll_delta: i32 = 0;
            let mut left_pressed = false;
            let mut left_released = false;
            let mut left_held = false;
            let mut had_events = false;

            let mut mouse_events_seen = 0usize;
            while let Some(ev) = crate::arch::mouse::read_event() {
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
                    // processed on next loop iteration.
                    break;
                }
            }

            if had_events {
                let (new_mx, new_my) = crate::arch::mouse::mouse_pos();
                let moved = new_mx != mouse_x || new_my != mouse_y;
                mouse_x = new_mx;
                mouse_y = new_my;

                let mut cmds = [InputCommand::Empty; vga_input::MAX_TURN_COMMANDS];
                let mut n = 0;
                if scroll_delta != 0 {
                    cmds[n] = InputCommand::Wheel(scroll_delta);
                    n += 1;
                }
                if left_pressed {
                    cmds[n] = InputCommand::Press(new_mx, new_my);
                    n += 1;
                } else if left_held && moved {
                    cmds[n] = InputCommand::Held(new_mx, new_my);
                    n += 1;
                }
                // A press and release may both occur in this bounded batch;
                // keep the press-before-release order the writer expects.
                if left_released {
                    cmds[n] = InputCommand::Release;
                    n += 1;
                }
                if moved {
                    cmds[n] = InputCommand::Cursor(new_mx, new_my);
                    n += 1;
                }
                cmds[n] = InputCommand::EndTurn;
                n += 1;
                // Space was checked above, so this cannot drop a command.
                if vga_input::push_turn(&cmds[..n]) {
                    vga_input::wake();
                }
            }
        }
        // USB HID and mouse input are polled at the 100 Hz scheduler cadence.
        // Block between polls instead of remaining continuously runnable.
        crate::process::sleep_current_task_ticks(1);
    }
}
