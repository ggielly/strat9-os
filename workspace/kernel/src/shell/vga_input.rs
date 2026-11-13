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

//! Lock-free mouse -> console command hand-off.
//!
//! The mouse task must never hold `VGA_WRITER`: it publishes the input work
//! here and the console-render task (which already owns the writer) applies it.
//! Single-producer/single-consumer ring: the mouse task pushes, the console
//! task pops. No allocation, no locks.
//!
//! Press/release ordering is preserved: the mouse task's local button state
//! machine emits `Press` before `Release` for a turn that observes both, and
//! each turn is published as one unit (a single `tail` store) so the renderer
//! never observes a half-written turn.

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

/// Ring slot count. One slot is reserved to distinguish full from empty, so
/// the usable capacity is `INPUT_RING_CAPACITY - 1` (63) commands.
pub const INPUT_RING_CAPACITY: usize = 64;
const RING_MASK: usize = INPUT_RING_CAPACITY - 1;

/// Maximum commands the mouse task can emit for one turn, including the
/// trailing [`InputCommand::EndTurn`] marker.
pub const MAX_TURN_COMMANDS: usize = 8;

/// Minimum ticks between scrollbar-drag applies (was in `mouse.rs`).
const SCROLLBAR_DRAG_MIN_TICKS: u64 = 1;
/// Minimum ticks between mouse visual renders (was in `mouse.rs`).
const MOUSE_RENDER_MIN_TICKS: u64 = 1;
/// Text lines moved per mouse-wheel notch. The wheel is eased: the console
/// tick applies one line per frame, so a notch settles over three frames.
const LINES_PER_NOTCH: isize = 3;

/// A deferred input action, applied by the console-render task.
#[derive(Clone, Copy)]
pub enum InputCommand {
    /// Unused slot initializer (never enqueued by the producer).
    Empty,
    /// Inverted wheel: raw `dz` sign convention as before; the render step
    /// multiplies by 3 lines exactly as the old mouse task did.
    Wheel(i32),
    /// Left button pressed at pixel `(x, y)`; the render step decides between
    /// scrollbar click and text-selection start.
    Press(i32, i32),
    /// Pointer moved while the left button stayed held.
    Held(i32, i32),
    /// Left button released.
    Release,
    /// Pointer moved without a button transition.
    Cursor(i32, i32),
    /// End of one mouse turn; never applied.
    EndTurn,
}

struct Ring {
    slots: UnsafeCell<[InputCommand; INPUT_RING_CAPACITY]>,
    head: AtomicUsize,
    tail: AtomicUsize,
}

// SAFETY: single producer (mouse task) writes slots and `tail`, single
// consumer (console task) writes `head`; atomics order the publication and no
// slot is written and read at the same time.
unsafe impl Sync for Ring {}

impl Ring {
    const fn new() -> Self {
        Self {
            slots: UnsafeCell::new([InputCommand::Empty; INPUT_RING_CAPACITY]),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    fn free_slots(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Relaxed);
        let used = tail.wrapping_add(INPUT_RING_CAPACITY).wrapping_sub(head) & RING_MASK;
        RING_MASK - used
    }

    /// Publish one whole turn atomically. Returns `false` when it does not fit.
    fn push_turn(&self, cmds: &[InputCommand]) -> bool {
        if cmds.len() > self.free_slots() {
            return false;
        }
        let mut tail = self.tail.load(Ordering::Relaxed);
        for &cmd in cmds {
            // SAFETY: `tail` is producer-owned until the single `tail` store
            // below publishes the whole turn.
            unsafe {
                (*self.slots.get())[tail] = cmd;
            }
            tail = (tail + 1) & RING_MASK;
        }
        self.tail.store(tail, Ordering::Release);
        true
    }

    fn pop(&self) -> Option<InputCommand> {
        let head = self.head.load(Ordering::Relaxed);
        if head == self.tail.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: the producer has published this slot via `tail`; it cannot
        // touch it again until `head` advances below.
        let cmd = unsafe { (*self.slots.get())[head] };
        self.head.store((head + 1) & RING_MASK, Ordering::Release);
        Some(cmd)
    }
}

static RING: Ring = Ring::new();
static INPUT_PENDING: AtomicBool = AtomicBool::new(false);

/// Publish one turn (the slice must end with [`InputCommand::EndTurn`]).
/// Returns `false` when the ring cannot hold the whole turn.
pub fn push_turn(cmds: &[InputCommand]) -> bool {
    RING.push_turn(cmds)
}

/// Whether a full turn can be enqueued without dropping any command.
pub fn has_space(n: usize) -> bool {
    RING.free_slots() >= n
}

/// Publish that input work is ready; consumed by [`take_pending`].
pub fn wake() {
    INPUT_PENDING.store(true, Ordering::Release);
}

/// Take and clear the pending flag.
pub fn take_pending() -> bool {
    INPUT_PENDING.swap(false, Ordering::AcqRel)
}

/// Drop every queued command (used when the console is unavailable).
pub fn discard() {
    while RING.pop().is_some() {}
    INPUT_PENDING.store(false, Ordering::Release);
}

/// Renderer-owned state carried across ticks; identical to the state the mouse
/// task used to keep locally.
pub struct InputState {
    selecting: bool,
    scrollbar_dragging: bool,
    last_scrollbar_drag_tick: u64,
    last_mouse_render_tick: u64,
    pending_scrollbar_drag_y: Option<usize>,
    pending_selection_pos: Option<(usize, usize)>,
    pending_mouse_cursor: Option<(i32, i32)>,
    pending_scroll_delta: i32,
}

impl InputState {
    pub const fn new() -> Self {
        Self {
            selecting: false,
            scrollbar_dragging: false,
            last_scrollbar_drag_tick: 0,
            last_mouse_render_tick: 0,
            pending_scrollbar_drag_y: None,
            pending_selection_pos: None,
            pending_mouse_cursor: None,
            pending_scroll_delta: 0,
        }
    }
}

/// Drain complete turns and apply each to `writer` with the exact call
/// sequence/order of the old in-lock mouse loop. Returns whether anything was
/// applied (commands consumed or a pending visual rendered).
pub fn apply_input(
    writer: &mut crate::arch::x86_64::vga::VgaWriter,
    state: &mut InputState,
) -> bool {
    let ticks = crate::process::scheduler::ticks();
    let mut applied = false;

    loop {
        let mut cmds = [InputCommand::Empty; MAX_TURN_COMMANDS];
        let mut n = 0;
        let mut complete = false;
        while n < MAX_TURN_COMMANDS {
            let Some(cmd) = RING.pop() else {
                break;
            };
            if let InputCommand::EndTurn = cmd {
                complete = true;
                break;
            }
            cmds[n] = cmd;
            n += 1;
        }
        if n == 0 && !complete {
            break;
        }
        applied |= apply_turn(&cmds[..n], writer, state, ticks);
        if !complete {
            break;
        }
    }

    // A visual update deferred by the tick gate (e.g. a drag throttled from the
    // previous turn) must still land on this tick even without new events.
    applied |= render_pending(writer, state, ticks, false, false);

    applied
}

/// Apply the commands of one mouse turn, preserving the original batching.
fn apply_turn(
    cmds: &[InputCommand],
    writer: &mut crate::arch::x86_64::vga::VgaWriter,
    state: &mut InputState,
    ticks: u64,
) -> bool {
    let mut wheel_delta: i32 = 0;
    let mut press: Option<(i32, i32)> = None;
    let mut held: Option<(i32, i32)> = None;
    let mut released = false;
    let mut cursor: Option<(i32, i32)> = None;

    for &cmd in cmds {
        match cmd {
            InputCommand::Wheel(dz) => wheel_delta += dz,
            InputCommand::Press(x, y) => press = Some((x, y)),
            InputCommand::Held(x, y) => held = Some((x, y)),
            InputCommand::Release => released = true,
            InputCommand::Cursor(x, y) => cursor = Some((x, y)),
            InputCommand::Empty | InputCommand::EndTurn => {}
        }
    }

    state.pending_scroll_delta += wheel_delta;

    if let Some((x, y)) = press {
        let (mx, my) = (x as usize, y as usize);
        if writer.scrollbar_hit_test(mx, my) {
            writer.scrollbar_click(mx, my);
            writer.clear_selection();
            state.selecting = false;
            state.scrollbar_dragging = true;
            state.pending_scrollbar_drag_y = None;
        } else {
            writer.start_selection(mx, my);
            state.selecting = true;
            state.scrollbar_dragging = false;
            state.pending_selection_pos = None;
        }
        state.last_mouse_render_tick = ticks;
    } else if let Some((x, y)) = held {
        if state.scrollbar_dragging {
            state.pending_scrollbar_drag_y = Some(y as usize);
        } else if state.selecting {
            state.pending_selection_pos = Some((x as usize, y as usize));
        }
    }
    // A press and release may both occur in this bounded batch: complete the
    // release even if a press was also observed.
    if released {
        if state.selecting {
            writer.end_selection();
            state.selecting = false;
            state.pending_selection_pos = None;
        }
        if state.scrollbar_dragging {
            if let Some(py) = state.pending_scrollbar_drag_y.take() {
                writer.scrollbar_drag_to(py);
            }
        }
        state.scrollbar_dragging = false;
        state.last_mouse_render_tick = ticks;
    }

    if let Some((cx, cy)) = cursor {
        state.pending_mouse_cursor = Some((cx, cy));
    }

    let rendered = render_pending(writer, state, ticks, press.is_some(), released);
    !cmds.is_empty() || rendered
}

fn has_pending_visual(state: &InputState) -> bool {
    state.pending_scroll_delta != 0
        || state.pending_scrollbar_drag_y.is_some()
        || state.pending_selection_pos.is_some()
        || state.pending_mouse_cursor.is_some()
}

/// Apply the pending visual updates under the original tick gates.
fn render_pending(
    writer: &mut crate::arch::x86_64::vga::VgaWriter,
    state: &mut InputState,
    ticks: u64,
    pressed: bool,
    released: bool,
) -> bool {
    if !has_pending_visual(state) {
        return false;
    }
    let render_due = ticks.saturating_sub(state.last_mouse_render_tick) >= MOUSE_RENDER_MIN_TICKS;
    let drag_due = ticks.saturating_sub(state.last_scrollbar_drag_tick) >= SCROLLBAR_DRAG_MIN_TICKS;
    if !(render_due || pressed || released) {
        return false;
    }

    let mut rendered = false;

    // Inverted wheel: wheel up (dz>0) -> scroll down (history forward).
    // `request_scroll_delta` takes positive as history-back (offset grows), so
    // the raw wheel sign is negated here.
    if state.pending_scroll_delta != 0 {
        let lines = (state.pending_scroll_delta as isize).saturating_mul(LINES_PER_NOTCH);
        writer.request_scroll_delta(lines.saturating_neg());
        state.pending_scroll_delta = 0;
        rendered = true;
    }

    if drag_due {
        if state.selecting {
            if let Some((sx, sy)) = state.pending_selection_pos.take() {
                writer.update_selection(sx, sy);
                rendered = true;
            }
        }
        if state.scrollbar_dragging {
            if let Some(py) = state.pending_scrollbar_drag_y.take() {
                writer.scrollbar_drag_to(py);
                state.last_scrollbar_drag_tick = ticks;
                rendered = true;
            }
        }
    }

    if let Some((cx, cy)) = state.pending_mouse_cursor.take() {
        writer.update_mouse_cursor(cx, cy);
        rendered = true;
    }

    if rendered {
        state.last_mouse_render_tick = ticks;
    }
    rendered
}
