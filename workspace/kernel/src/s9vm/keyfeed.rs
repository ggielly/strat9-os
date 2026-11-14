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

//! Host keystrokes waiting to be typed into a DOS guest.
//!
//! A key has two encodings, and a PC guest consumes exactly one of them:
//!
//! - the 8042 data port yields PS/2 set-1 scancodes (make/break, with a shift
//!   bracket for shifted characters and the `0xE0` prefix for arrows), which the
//!   guest's own `INT 9` handler reads;
//! - the firmware keyboard buffer holds `(scan code, ASCII)` pairs, which a guest
//!   that kept `INT 16h` at the firmware reads.
//!
//! The queue therefore stores whole keys, not bytes: the cursor is one key
//! index shared by both views. That matters because the two consumers are never
//! both fed — the runner types into the 8042 only once the guest owns `INT 9`,
//! and into the buffer before that. Advancing only one view used to leave a
//! phantom remainder in the other (a hardware run reported "4 keys not typed"
//! for keys that had all reached the 8042) and would have re-typed the same keys
//! after a restart.
//!
//! The module is pure — it only touches the keyboard and BIOS models — which is
//! what lets the host tests drive it without VT-x.

use alloc::vec::Vec;

use super::{bios, keyboard};

/// One queued key, in the encodings the two PC consumers expect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    /// Scancode bytes the 8042 must receive (2 or 4 bytes).
    pub(crate) bytes: [u8; 4],
    /// Number of valid bytes in [`Self::bytes`].
    pub(crate) len: u8,
    /// Scan code the firmware keyboard buffer stores.
    pub(crate) scan: u8,
    /// ASCII byte the firmware keyboard buffer stores (0 for extended keys).
    pub(crate) ascii: u8,
}

impl Key {
    /// Translates one host byte into its two encodings.
    ///
    /// `None` means the byte cannot be typed on a PC keyboard (a control byte
    /// other than the named ones), so it is skipped instead of typed as garbage.
    fn build(byte: u8) -> Option<Self> {
        let mut scratch = Vec::new();
        let (scan, ascii) = keyboard::keystroke_for(byte, &mut scratch)?;
        if scratch.len() > 4 {
            return None;
        }
        let mut bytes = [0u8; 4];
        bytes[..scratch.len()].copy_from_slice(&scratch);
        Some(Self {
            bytes,
            len: scratch.len() as u8,
            scan,
            ascii,
        })
    }

    /// Number of scancode bytes this key occupies on the 8042 path.
    pub const fn scancode_len(&self) -> usize {
        self.len as usize
    }
}

/// Host text waiting to be typed into a DOS guest.
pub struct KeyboardFeed {
    /// Keys still to deliver, in order; the front has not been consumed yet.
    keys: Vec<Key>,
    /// Index of the next key to deliver (shared by both consumer views).
    next: usize,
}

impl KeyboardFeed {
    /// Builds a feed from host text.
    pub fn new(text: &[u8]) -> Self {
        let mut feed = Self::empty();
        feed.extend(text);
        feed
    }

    /// A feed with nothing queued.
    pub const fn empty() -> Self {
        Self {
            keys: Vec::new(),
            next: 0,
        }
    }

    /// Continues a previous slice from exactly where it stopped.
    ///
    /// Whole keys are stored, so a slice hand-over cannot split a make/break
    /// pair or replay a key the guest already received.
    pub fn from_pending(keys: Vec<Key>) -> Self {
        Self { keys, next: 0 }
    }

    /// Appends more host text to the queue.
    pub fn extend(&mut self, text: &[u8]) {
        for &byte in text {
            if let Some(key) = Key::build(byte) {
                self.keys.push(key);
            }
        }
    }

    /// Keys not handed to the guest yet.
    pub fn remaining(&self) -> usize {
        self.keys.len().saturating_sub(self.next)
    }

    /// Copies the keys a slice hand-over must carry to the next slice.
    pub fn remaining_keys(&self) -> Vec<Key> {
        self.keys[self.next..].to_vec()
    }

    /// Queues whole keys on the 8042 path; returns how many scancode bytes were
    /// accepted.
    ///
    /// A key is only started when the controller has room for all of its bytes,
    /// so the guest never sees half of a make/break pair, and `limit` (a byte
    /// budget) can never split a key either.
    pub fn fill(&mut self, controller: &mut keyboard::KeyboardController, limit: usize) -> usize {
        let mut sent = 0usize;
        while self.next < self.keys.len() {
            let key = self.keys[self.next];
            let need = key.scancode_len();
            if sent + need > limit {
                break;
            }
            if usize::from(controller.pending_scancodes()) + need > keyboard::INPUT_CAPACITY {
                break;
            }
            for byte in &key.bytes[..need] {
                if !controller.push_scancode(*byte) {
                    return sent;
                }
            }
            sent += need;
            self.next += 1;
        }
        sent
    }

    /// Pushes whole keys into the firmware keyboard buffer.
    ///
    /// This is the path of a guest that did not install its own `INT 9`: its
    /// `INT 16h` calls still reach the firmware model, so the keys have to
    /// appear where that service reads them.
    pub fn fill_bios(&mut self, bios: &mut bios::BiosState, limit: usize) -> usize {
        let mut sent = 0;
        while sent < limit && self.next < self.keys.len() {
            let key = self.keys[self.next];
            bios.push_scan_key(key.scan, key.ascii);
            self.next += 1;
            sent += 1;
        }
        sent
    }
}
