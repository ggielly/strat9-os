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

//! Keyboard input handler for the console.
//!
//! Subscribes to `inputd` through `input-client` and consumes only
//! `INPUT_EVENT_TEXT` records: `inputd` already decoded scancodes into UTF-8,
//! so the console no longer touches `/dev/input/*` or the shared keymap.
//! `KEY` and pointer records are ignored.

use input_client::{Client, Poll};
use input_protocol::{INPUT_EVENT_TEXT, INPUT_TEXT_LEN};

/// Maximum number of text bytes one batch can carry (`MAX_INPUT_RECORDS *
/// INPUT_TEXT_LEN`). Buffered here so a burst larger than the caller's buffer
/// is never dropped.
const PENDING_MAX: usize = 16 * INPUT_TEXT_LEN;

pub struct InputHandler {
    client: Client,
    pending: [u8; PENDING_MAX],
    pending_len: usize,
    pending_pos: usize,
}

impl InputHandler {
    pub fn open() -> Option<Self> {
        let client = Client::open(1)?;
        // This component is the on-screen console: take input focus once so it
        // receives keystrokes instead of the rescue console.
        let _ = client.request_focus();
        Some(InputHandler {
            client,
            pending: [0u8; PENDING_MAX],
            pending_len: 0,
            pending_pos: 0,
        })
    }

    /// Copy pending UTF-8 text bytes into `out`, polling new batches while
    /// room remains.
    ///
    /// Non-blocking: returns 0 when nothing is pending. Bytes that do not fit
    /// in `out` are kept for the next call.
    pub fn read_text(&mut self, out: &mut [u8]) -> usize {
        let mut n = 0usize;

        // Drain bytes buffered by a previous, too-small call first.
        while n < out.len() && self.pending_pos < self.pending_len {
            out[n] = self.pending[self.pending_pos];
            n += 1;
            self.pending_pos += 1;
        }
        if n == out.len() {
            return n;
        }
        self.pending_len = 0;
        self.pending_pos = 0;

        loop {
            match self.client.poll() {
                Poll::Batch(batch) => {
                    for record in batch.records() {
                        if record.event.event_type != INPUT_EVENT_TEXT {
                            continue;
                        }
                        let len = (record.event.value.max(0) as usize).min(INPUT_TEXT_LEN);
                        for &byte in &record.text[..len] {
                            if n < out.len() {
                                out[n] = byte;
                                n += 1;
                            } else if self.pending_len < PENDING_MAX {
                                self.pending[self.pending_len] = byte;
                                self.pending_len += 1;
                            }
                        }
                    }
                }
                // A Reset only tells us to resynchronise; keep draining.
                Poll::Reset { .. } => continue,
                Poll::Empty | Poll::Error => break,
            }
        }
        n
    }
}
