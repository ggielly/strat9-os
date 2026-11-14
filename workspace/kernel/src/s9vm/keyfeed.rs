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
//! The text is translated to PS/2 set-1 scancodes once, then handed to the 8042
//! model only after the guest owns `INT 9` and has unmasked `IRQ1`: before that
//! the guest is still probing the controller and could mistake a scancode for a
//! command reply. Each typed byte also yields the `(scan, ASCII)` pair the
//! firmware keyboard buffer has to hold, which is the path of a guest that kept
//! `INT 16h` at the firmware.
//!
//! The two consumers advance at different rates (the 8042 sees make *and* break
//! codes, the buffer sees one entry per key), so the feed is also the unit that
//! carries a slice hand-over: [`KeyboardFeed::from_pending`] resumes from the
//! exact remainders of the previous slice instead of re-typing text the guest
//! already received.
//!
//! The module is pure — it only touches the keyboard and BIOS models — which is
//! what lets the host tests drive it without VT-x.

use alloc::vec::Vec;

use super::{bios, keyboard};

/// Host text waiting to be typed into a DOS guest, in both consumer views.
pub struct KeyboardFeed {
    /// Scancodes for the 8042 data port, in order, with make/break pairs.
    pub(crate) scancodes: Vec<u8>,
    /// Next scancode [`Self::fill`] hands to the controller.
    pub(crate) next: usize,
    /// `(scan code, ASCII)` of the same keys, for the firmware buffer.
    pub(crate) keys: Vec<(u8, u8)>,
    /// Next entry [`Self::fill_bios`] pushes into the firmware buffer.
    pub(crate) next_key: usize,
}

impl KeyboardFeed {
    /// Builds a feed from host text.
    pub fn new(text: &[u8]) -> Self {
        let mut feed = Self::empty();
        feed.extend(text);
        feed
    }

    /// A feed with nothing queued.
    pub fn empty() -> Self {
        Self {
            scancodes: Vec::new(),
            next: 0,
            keys: Vec::new(),
            next_key: 0,
        }
    }

    /// Continues a previous slice from exactly where it stopped.
    ///
    /// The 8042 and the firmware buffer consume at different rates, so both
    /// remainders are carried: rebuilding from the original text would re-type
    /// keys the guest already received.
    pub fn from_pending(scancodes: Vec<u8>, keys: Vec<(u8, u8)>) -> Self {
        Self {
            scancodes,
            next: 0,
            keys,
            next_key: 0,
        }
    }

    /// Appends more host text to the queue.
    pub fn extend(&mut self, text: &[u8]) {
        for &byte in text {
            if let Some(pair) = keyboard::keystroke_for(byte, &mut self.scancodes) {
                self.keys.push(pair);
            }
        }
    }

    /// Keys not handed to the guest yet, whichever path serves it.
    ///
    /// This counts scancode bytes, so it is an upper bound on the number of
    /// keys still waiting; it is only used to decide whether anything is left.
    pub fn remaining(&self) -> usize {
        self.scancodes
            .len()
            .saturating_sub(self.next)
            .max(self.keys.len().saturating_sub(self.next_key))
    }

    /// Queues up to `limit` scancodes; returns how many were accepted.
    pub fn fill(&mut self, controller: &mut keyboard::KeyboardController, limit: usize) -> usize {
        let mut sent = 0;
        while sent < limit && self.next < self.scancodes.len() {
            if !controller.push_scancode(self.scancodes[self.next]) {
                break;
            }
            self.next += 1;
            sent += 1;
        }
        sent
    }

    /// Pushes up to `limit` keys into the firmware keyboard buffer.
    ///
    /// This is the path of a guest that did not install its own `INT 9`: its
    /// `INT 16h` calls still reach the firmware model, so the keys have to
    /// appear where that service reads them.
    pub fn fill_bios(&mut self, bios: &mut bios::BiosState, limit: usize) -> usize {
        let mut sent = 0;
        while sent < limit && self.next_key < self.keys.len() {
            let (scan, ascii) = self.keys[self.next_key];
            bios.push_scan_key(scan, ascii);
            self.next_key += 1;
            sent += 1;
        }
        sent
    }
}
