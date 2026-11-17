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

//! Host-testable normalization half of the strat9-os input server.
//!
//! Raw PS/2 set-1 scancodes and 7-byte mouse packets become A.5
//! [`NormalizedEvent`]s / [`InputRecord`]s. No syscalls, no allocation.

#![no_std]

#[cfg(test)]
extern crate std;

use input_protocol::{
    InputRecord, NormalizedEvent, INPUT_EVENT_KEY, INPUT_EVENT_POINTER_AXIS,
    INPUT_EVENT_POINTER_BUTTON, INPUT_EVENT_POINTER_MOTION, INPUT_EVENT_TEXT, INPUT_TEXT_LEN,
    MAX_INPUT_RECORDS,
};
use strat9_keymap::{Decoder, Layout};

/// Keyboard device id in normalized events.
pub const KBD_DEVICE_ID: u32 = 1;
/// Mouse device id in normalized events.
pub const MOUSE_DEVICE_ID: u32 = 2;

/// Fixed-capacity record accumulator. No allocation.
#[derive(Clone, Copy)]
pub struct EventBuffer {
    /// Records in wire order.
    pub records: [InputRecord; MAX_INPUT_RECORDS],
    len: usize,
    timestamp_ns: u64,
}

/// Name used by the normalizers for the record accumulator.
pub type EventSink = EventBuffer;

impl EventBuffer {
    /// Empty buffer.
    pub const fn new() -> Self {
        Self {
            records: [InputRecord {
                event: NormalizedEvent {
                    timestamp_ns: 0,
                    sequence: 0,
                    device_id: 0,
                    event_type: 0,
                    code: 0,
                    value: 0,
                    flags: 0,
                },
                text: [0; INPUT_TEXT_LEN],
            }; MAX_INPUT_RECORDS],
            len: 0,
            timestamp_ns: 0,
        }
    }

    /// Drop all records and stamp the batch with `timestamp_ns`.
    pub fn clear(&mut self, timestamp_ns: u64) {
        self.len = 0;
        self.timestamp_ns = timestamp_ns;
    }

    /// Number of accumulated records.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when no record is accumulated.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The accumulated records, in wire order.
    pub fn as_slice(&self) -> &[InputRecord] {
        &self.records[..self.len]
    }

    /// Append one event, stamping it with the batch timestamp. Returns `false`
    /// when the buffer is full (the event is dropped).
    pub fn push(&mut self, mut event: NormalizedEvent) -> bool {
        if self.len == MAX_INPUT_RECORDS {
            return false;
        }
        event.timestamp_ns = self.timestamp_ns;
        self.records[self.len] = InputRecord {
            event,
            text: [0; INPUT_TEXT_LEN],
        };
        self.len += 1;
        true
    }

    /// Append `bytes` as one or more `TEXT` records of at most 16 bytes,
    /// never splitting a UTF-8 sequence. Invalid UTF-8 (the in-band `KEY_*`
    /// bytes) produces no `TEXT` record: the `KEY` event already carries it.
    ///
    /// Returns `false` if the buffer filled up.
    pub fn push_text(&mut self, bytes: &[u8], seq: &mut u64) -> bool {
        if bytes.is_empty() || core::str::from_utf8(bytes).is_err() {
            return true;
        }
        let mut offset = 0usize;
        while offset < bytes.len() {
            let chunk = utf8_chunk_len(&bytes[offset..], INPUT_TEXT_LEN);
            if chunk == 0 {
                return true;
            }
            *seq += 1;
            let mut text = [0u8; INPUT_TEXT_LEN];
            text[..chunk].copy_from_slice(&bytes[offset..offset + chunk]);
            let record = InputRecord {
                event: NormalizedEvent {
                    timestamp_ns: self.timestamp_ns,
                    sequence: *seq,
                    device_id: KBD_DEVICE_ID,
                    event_type: INPUT_EVENT_TEXT,
                    code: 0,
                    value: chunk as i32,
                    flags: 0,
                },
                text,
            };
            if self.len == MAX_INPUT_RECORDS {
                return false;
            }
            self.records[self.len] = record;
            self.len += 1;
            offset += chunk;
        }
        true
    }
}

impl Default for EventBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Longest prefix of `bytes`, at most `max` bytes, that ends on a UTF-8
/// boundary.
fn utf8_chunk_len(bytes: &[u8], max: usize) -> usize {
    let end = core::cmp::min(bytes.len(), max);
    match core::str::from_utf8(&bytes[..end]) {
        Ok(_) => end,
        Err(err) => err.valid_up_to(),
    }
}

/// PS/2 set-1 keyboard normalizer: physical keys plus composed text.
pub struct KbdNormalizer {
    decoder: Decoder,
    extended: bool,
}

impl KbdNormalizer {
    /// AZERTY-by-default normalizer.
    pub const fn new() -> Self {
        Self {
            decoder: Decoder::new(Layout::Azerty),
            extended: false,
        }
    }

    /// Normalizer for an explicit layout.
    pub const fn with_layout(layout: Layout) -> Self {
        Self {
            decoder: Decoder::new(layout),
            extended: false,
        }
    }

    /// Feed one raw scancode byte. Emits a `KEY` event for every scancode
    /// except the bare `0xE0` prefix, then the `TEXT` the decoder produced.
    pub fn feed(&mut self, raw: u8, seq: &mut u64, out: &mut EventSink) {
        if raw == 0xE0 {
            self.extended = true;
            let _ = self.decoder.feed(raw);
            return;
        }

        let extended = self.extended;
        self.extended = false;
        let pressed = raw & 0x80 == 0;
        let code = (raw & 0x7F) as u16;
        let code = if extended { 0x100 | code } else { code };

        *seq += 1;
        out.push(NormalizedEvent {
            timestamp_ns: 0,
            sequence: *seq,
            device_id: KBD_DEVICE_ID,
            event_type: INPUT_EVENT_KEY,
            code,
            value: i32::from(pressed),
            flags: 0,
        });

        let keys = self.decoder.feed(raw);
        if !keys.is_empty() {
            let _ = out.push_text(keys.as_bytes(), seq);
        }
    }
}

impl Default for KbdNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalize one 7-byte mouse packet: `dx i16 LE`, `dy i16 LE`, padding,
/// buttons, wheel delta.
///
/// Emits `POINTER_MOTION` (`value` = dx, `code` = dy), one `POINTER_BUTTON`
/// per changed bit among `0..=2`, and `POINTER_AXIS` (code 0) when the wheel
/// moved.
pub fn mouse_packet(
    packet: &[u8; 7],
    prev_buttons: &mut u8,
    seq: &mut u64,
    out: &mut EventSink,
) {
    let dx = i16::from_le_bytes([packet[0], packet[1]]);
    let dy = i16::from_le_bytes([packet[2], packet[3]]);
    let buttons = packet[5];
    let dz = packet[6] as i8;

    *seq += 1;
    out.push(NormalizedEvent {
        timestamp_ns: 0,
        sequence: *seq,
        device_id: MOUSE_DEVICE_ID,
        event_type: INPUT_EVENT_POINTER_MOTION,
        code: dy as u16,
        value: i32::from(dx),
        flags: 0,
    });

    let changed = buttons ^ *prev_buttons;
    for bit in 0..3u8 {
        if changed & (1 << bit) != 0 {
            *seq += 1;
            out.push(NormalizedEvent {
                timestamp_ns: 0,
                sequence: *seq,
                device_id: MOUSE_DEVICE_ID,
                event_type: INPUT_EVENT_POINTER_BUTTON,
                code: u16::from(bit),
                value: i32::from((buttons >> bit) & 1),
                flags: 0,
            });
        }
    }
    *prev_buttons = buttons;

    if dz != 0 {
        *seq += 1;
        out.push(NormalizedEvent {
            timestamp_ns: 0,
            sequence: *seq,
            device_id: MOUSE_DEVICE_ID,
            event_type: INPUT_EVENT_POINTER_AXIS,
            code: 0,
            value: i32::from(dz),
            flags: 0,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(out: &EventBuffer, event_type: u16) -> usize {
        out.as_slice()
            .iter()
            .filter(|record| record.event.event_type == event_type)
            .count()
    }

    fn text_of(record: &InputRecord) -> &str {
        core::str::from_utf8(&record.text[..record.event.value as usize]).unwrap()
    }

    fn last_text(out: &EventBuffer) -> Option<&str> {
        out.as_slice()
            .iter()
            .rev()
            .find(|record| record.event.event_type == INPUT_EVENT_TEXT)
            .map(text_of)
    }

    /// Concatenate every TEXT record, in wire order.
    fn joined_text(out: &EventBuffer) -> std::string::String {
        let mut joined = std::string::String::new();
        for record in out.as_slice() {
            if record.event.event_type == INPUT_EVENT_TEXT {
                joined.push_str(text_of(record));
            }
        }
        joined
    }

    #[test]
    fn azerty_a_press_and_release() {
        let mut kbd = KbdNormalizer::new();
        let mut seq = 0u64;
        let mut out = EventBuffer::new();
        out.clear(11);

        kbd.feed(0x10, &mut seq, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out.as_slice()[0].event.event_type, INPUT_EVENT_KEY);
        assert_eq!(out.as_slice()[0].event.code, 0x10);
        assert_eq!(out.as_slice()[0].event.value, 1);
        assert_eq!(out.as_slice()[0].event.device_id, KBD_DEVICE_ID);
        assert_eq!(out.as_slice()[0].event.timestamp_ns, 11);
        assert_eq!(last_text(&out), Some("a"));

        out.clear(12);
        kbd.feed(0x90, &mut seq, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out.as_slice()[0].event.value, 0);
        assert_eq!(count(&out, INPUT_EVENT_TEXT), 0);
    }

    #[test]
    fn shift_is_a_key_event_and_uppercases_text() {
        let mut kbd = KbdNormalizer::new();
        let mut seq = 0u64;
        let mut out = EventBuffer::new();
        out.clear(0);

        kbd.feed(0x2A, &mut seq, &mut out);
        kbd.feed(0x10, &mut seq, &mut out);
        assert_eq!(last_text(&out), Some("A"));
        assert_eq!(count(&out, INPUT_EVENT_KEY), 2);
    }

    #[test]
    fn dead_key_composes_on_later_press() {
        let mut kbd = KbdNormalizer::new();
        let mut seq = 0u64;
        let mut out = EventBuffer::new();
        out.clear(0);

        kbd.feed(0x1A, &mut seq, &mut out); // dead ^: KEY only
        assert_eq!(count(&out, INPUT_EVENT_TEXT), 0);
        kbd.feed(0x12, &mut seq, &mut out); // e: composes
        assert_eq!(last_text(&out), Some("ê"));
        assert_eq!(count(&out, INPUT_EVENT_KEY), 2);
    }

    #[test]
    fn dead_key_press_emits_key_only_and_release_keeps_it_pending() {
        let mut kbd = KbdNormalizer::new();
        let mut seq = 0u64;
        let mut out = EventBuffer::new();
        out.clear(0);

        // 0x1A (^ dead key): KEY only, no TEXT for the dead key itself.
        kbd.feed(0x1A, &mut seq, &mut out);
        assert_eq!(count(&out, INPUT_EVENT_KEY), 1);
        assert_eq!(count(&out, INPUT_EVENT_TEXT), 0);

        // Release must not clear the pending dead key.
        kbd.feed(0x9A, &mut seq, &mut out);
        assert_eq!(count(&out, INPUT_EVENT_TEXT), 0);
        assert_eq!(out.len(), 2);

        // 0x12 (e) still composes to ê after the release.
        kbd.feed(0x12, &mut seq, &mut out);
        assert_eq!(joined_text(&out), "ê");
    }

    #[test]
    fn dead_key_circumflex_press_release_then_e() {
        let mut kbd = KbdNormalizer::new();
        let mut seq = 0u64;
        let mut out = EventBuffer::new();
        out.clear(0);

        // AZERTY: ^ press/release, then e press/release.
        for sc in [0x1A, 0x9A, 0x12, 0x92] {
            kbd.feed(sc, &mut seq, &mut out);
        }
        assert_eq!(count(&out, INPUT_EVENT_TEXT), 1);
        assert_eq!(joined_text(&out), "ê");
    }

    #[test]
    fn dead_key_diaeresis_with_shift_then_e() {
        let mut kbd = KbdNormalizer::new();
        let mut seq = 0u64;
        let mut out = EventBuffer::new();
        out.clear(0);

        // Left Shift + 0x1A is the ¨ dead key; 0x12 is e.
        for sc in [0x2A, 0x1A, 0x9A, 0xAA, 0x12, 0x92] {
            kbd.feed(sc, &mut seq, &mut out);
        }
        assert_eq!(joined_text(&out), "ë");
    }

    #[test]
    fn extended_prefix_is_not_a_key() {
        let mut kbd = KbdNormalizer::new();
        let mut seq = 0u64;
        let mut out = EventBuffer::new();
        out.clear(0);

        kbd.feed(0xE0, &mut seq, &mut out);
        assert!(out.is_empty());
        kbd.feed(0x4B, &mut seq, &mut out);
        assert_eq!(out.as_slice()[0].event.code, 0x14B);
        assert_eq!(out.as_slice()[0].event.value, 1);
        // KEY_LEFT is 0xFA, in-band and not UTF-8: no TEXT record.
        assert_eq!(count(&out, INPUT_EVENT_TEXT), 0);
    }

    #[test]
    fn buffer_rejects_the_seventeenth_record() {
        let mut out = EventBuffer::new();
        out.clear(0);
        for index in 0..MAX_INPUT_RECORDS {
            assert!(out.push(NormalizedEvent {
                event_type: INPUT_EVENT_KEY,
                code: index as u16,
                value: 1,
                ..NormalizedEvent::default()
            }));
        }
        assert!(!out.push(NormalizedEvent {
            event_type: INPUT_EVENT_KEY,
            code: 17,
            value: 1,
            ..NormalizedEvent::default()
        }));
        assert_eq!(out.len(), MAX_INPUT_RECORDS);
    }

    #[test]
    fn text_chunks_never_split_utf8() {
        let mut out = EventBuffer::new();
        out.clear(0);
        let mut seq = 0u64;
        // 5 two-byte codepoints: 10 bytes, then 4 three-byte codepoints.
        let bytes = "ééééé€€€€".as_bytes();
        assert!(out.push_text(bytes, &mut seq));
        assert_eq!(count(&out, INPUT_EVENT_TEXT), 2);
        let mut joined = std::string::String::new();
        for record in out.as_slice() {
            joined.push_str(text_of(record));
        }
        assert_eq!(joined, "ééééé€€€€");
    }

    #[test]
    fn mouse_packet_motion_buttons_wheel() {
        let mut prev = 0u8;
        let mut seq = 0u64;
        let mut out = EventBuffer::new();
        out.clear(5);

        // dx = 2, dy = -2, left pressed, wheel +1.
        let packet = [0x02, 0x00, 0xFE, 0xFF, 0x00, 0x01, 0x01];
        mouse_packet(&packet, &mut prev, &mut seq, &mut out);

        let motion = &out.as_slice()[0];
        assert_eq!(motion.event.event_type, INPUT_EVENT_POINTER_MOTION);
        assert_eq!(motion.event.value, 2);
        assert_eq!(motion.event.code, 0xFFFE); // -2 as u16
        assert_eq!(motion.event.device_id, MOUSE_DEVICE_ID);

        assert_eq!(count(&out, INPUT_EVENT_POINTER_BUTTON), 1);
        let button = out
            .as_slice()
            .iter()
            .find(|record| record.event.event_type == INPUT_EVENT_POINTER_BUTTON)
            .unwrap();
        assert_eq!(button.event.code, 0);
        assert_eq!(button.event.value, 1);

        assert_eq!(count(&out, INPUT_EVENT_POINTER_AXIS), 1);
        let axis = out
            .as_slice()
            .iter()
            .find(|record| record.event.event_type == INPUT_EVENT_POINTER_AXIS)
            .unwrap();
        assert_eq!(axis.event.code, 0);
        assert_eq!(axis.event.value, 1);
        assert_eq!(prev, 1);

        // Idle packet: motion only.
        out.clear(6);
        prev = 0;
        let idle = [0u8; 7];
        mouse_packet(&idle, &mut prev, &mut seq, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(count(&out, INPUT_EVENT_POINTER_BUTTON), 0);
        assert_eq!(count(&out, INPUT_EVENT_POINTER_AXIS), 0);
    }
}
