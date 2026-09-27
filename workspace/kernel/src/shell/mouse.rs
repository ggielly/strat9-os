//! Mouse input and rendering are independent of shell command execution.
//! Dequeue only after acquiring the writer, so contention never loses an update.
pub extern "C" fn mouse_task_main() -> ! {
    // Mouse state
    let mut prev_left = false;
    let mut selecting = false;
    let mut scrollbar_dragging = false;
    let mut last_scrollbar_drag_tick = 0u64;
    let mut pending_scrollbar_drag_y: Option<usize> = None;
    let mut pending_selection_pos: Option<(usize, usize)> = None;
    let mut pending_mouse_cursor: Option<(i32, i32)> = None;
    let mut pending_scroll_delta: i32 = 0;
    let mut mouse_x: i32 = 0;
    let mut mouse_y: i32 = 0;

    // Cap per-loop mouse work to avoid starving timer ticks when dragging.
    const MAX_MOUSE_EVENTS_PER_TURN: usize = 16;
    const SCROLLBAR_DRAG_MIN_TICKS: u64 = 1;
    const MOUSE_RENDER_MIN_TICKS: u64 = 1;
    let mut last_mouse_render_tick = 0u64;

    loop {
        let ticks = crate::process::scheduler::ticks();
        if crate::hardware::usb::hid::is_available() {
            crate::hardware::usb::hid::poll_all();
        }
        crate::arch::vga::try_with_writer(|writer| {
            if crate::arch::mouse::MOUSE_READY.load(core::sync::atomic::Ordering::Relaxed) {
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
                        // processed on next loop iteration after yield_task().
                        break;
                    }
                }

                let has_pending_visual = pending_scroll_delta != 0
                    || pending_scrollbar_drag_y.is_some()
                    || pending_selection_pos.is_some()
                    || pending_mouse_cursor.is_some();

                if had_events || left_held || has_pending_visual {
                    let (new_mx, new_my) = crate::arch::mouse::mouse_pos();
                    let moved = new_mx != mouse_x || new_my != mouse_y;
                    mouse_x = new_mx;
                    mouse_y = new_my;
                    if had_events {
                        pending_scroll_delta += scroll_delta;
                    }

                    if left_pressed {
                        let (mx, my) = (new_mx as usize, new_my as usize);
                        if writer.scrollbar_hit_test(mx, my) {
                            writer.scrollbar_click(mx, my);
                            writer.clear_selection();
                            selecting = false;
                            scrollbar_dragging = true;
                            pending_scrollbar_drag_y = None;
                        } else {
                            writer.start_selection(mx, my);
                            selecting = true;
                            scrollbar_dragging = false;
                            pending_selection_pos = None;
                        }
                        last_mouse_render_tick = ticks;
                    } else if left_held && scrollbar_dragging && moved {
                        pending_scrollbar_drag_y = Some(new_my as usize);
                    } else if left_held && selecting && moved {
                        pending_selection_pos = Some((new_mx as usize, new_my as usize));
                    }
                    // A press and release may both occur in this bounded batch.
                    // Complete the release even if a press was also observed.
                    if left_released && !prev_left {
                        if selecting {
                            writer.end_selection();
                            selecting = false;
                            pending_selection_pos = None;
                        }
                        if scrollbar_dragging {
                            if let Some(py) = pending_scrollbar_drag_y.take() {
                                writer.scrollbar_drag_to(py);
                            }
                        }
                        scrollbar_dragging = false;
                        last_mouse_render_tick = ticks;
                    }

                    if moved {
                        pending_mouse_cursor = Some((new_mx, new_my));
                    }

                    let render_due =
                        ticks.saturating_sub(last_mouse_render_tick) >= MOUSE_RENDER_MIN_TICKS;
                    let drag_due =
                        ticks.saturating_sub(last_scrollbar_drag_tick) >= SCROLLBAR_DRAG_MIN_TICKS;
                    let has_pending_visual = pending_scroll_delta != 0
                        || pending_scrollbar_drag_y.is_some()
                        || pending_selection_pos.is_some()
                        || pending_mouse_cursor.is_some();
                    if has_pending_visual && (render_due || left_pressed || left_released) {
                        let mut rendered = false;

                        // Inverted wheel: wheel up (dz>0) -> scroll down (history forward)
                        if pending_scroll_delta > 0 {
                            writer.scroll_view_down((pending_scroll_delta as usize) * 3);
                            pending_scroll_delta = 0;
                            rendered = true;
                        } else if pending_scroll_delta < 0 {
                            writer.scroll_view_up(((-pending_scroll_delta) as usize) * 3);
                            pending_scroll_delta = 0;
                            rendered = true;
                        }

                        if drag_due {
                            if selecting {
                                if let Some((sx, sy)) = pending_selection_pos.take() {
                                    writer.update_selection(sx, sy);
                                    rendered = true;
                                }
                            }
                            if scrollbar_dragging {
                                if let Some(py) = pending_scrollbar_drag_y.take() {
                                    writer.scrollbar_drag_to(py);
                                    last_scrollbar_drag_tick = ticks;
                                    rendered = true;
                                }
                            }
                        }

                        if let Some((cx, cy)) = pending_mouse_cursor.take() {
                            writer.update_mouse_cursor(cx, cy);
                            rendered = true;
                        }

                        if rendered {
                            last_mouse_render_tick = ticks;
                        }
                    }
                }
            }
        });
        crate::process::yield_task();
    }
}
