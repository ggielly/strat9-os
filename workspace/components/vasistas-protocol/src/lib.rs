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

//! Native display protocol v1: header, opcodes, bodies and errors.
//!
//! Implements the wire format of Annexe A of
//! `docs/GUI_AUDIT_2026-11.md`, including every message body specified in
//! A.3.1.
//!
//! All fields are encoded and decoded explicitly, little-endian, one field at
//! a time. No pointer casts, no `transmute`, no `usize` in wire formats, no
//! allocation, no `unsafe`.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod commit;
pub mod constants;
pub mod error;
pub mod header;
pub mod message;
pub mod opcode;

pub use commit::{Commit, Rect, COMMIT_BODY_LEN, FLAG_FULL_DAMAGE, MAX_RECTS, RECT_LEN};
pub use constants::{
    CLOSE_REASON_DESTROYED, CLOSE_REASON_REQUESTED, CLOSE_REASON_SHUTDOWN, CURSOR_SHAPE_DEFAULT,
    CURSOR_SHAPE_POINTER, CURSOR_SHAPE_TEXT, ERROR_BAD_FLAGS, ERROR_BAD_FORMAT, ERROR_BAD_LENGTH,
    ERROR_BAD_OBJECT, ERROR_BAD_STATE, ERROR_INTERNAL, ERROR_NO_CREDIT, ERROR_QUOTA,
    ERROR_UNSUPPORTED, FORMAT_XRGB8888, IMPORT_FAILED, IMPORT_OK, INPUT_BATCH_FIXED_LEN,
    INPUT_EVENT_FOCUS_GAINED, INPUT_EVENT_FOCUS_LOST, INPUT_EVENT_KEY, INPUT_EVENT_POINTER_AXIS,
    INPUT_EVENT_POINTER_BUTTON, INPUT_EVENT_POINTER_ENTER, INPUT_EVENT_POINTER_LEAVE,
    INPUT_EVENT_POINTER_MOTION, INPUT_EVENT_TEXT, INPUT_FLAG_ABSOLUTE, INPUT_RECORD_LEN,
    INPUT_RESET_RESYNC, INPUT_RESET_SERVICE_CHANGED, INPUT_TEXT_LEN, MAX_ERROR_DETAIL,
    MAX_INPUT_RECORDS, MAX_MESSAGE_BYTES, MAX_NAME, MAX_PATH, MAX_SURFACE_DIM, MAX_TITLE,
    WINDOW_ACTION_LOWER, WINDOW_ACTION_MAXIMIZE, WINDOW_ACTION_MINIMIZE, WINDOW_ACTION_RAISE,
    WINDOW_ACTION_RESTORE,
};
pub use error::DecodeError;
pub use header::{Header, HEADER_LEN, MAGIC, VERSION_MAJOR, VERSION_MINOR};
pub use message::{Body, InputBatch, InputRecord};
pub use opcode::{
    Opcode, FEATURES_KNOWN, FEATURE_ARGB_PREMULTIPLIED, FEATURE_COPY_TILES, FEATURE_MULTI_OUTPUT,
    FEATURE_PRESENT_FEEDBACK, FEATURE_SHM_CPU, FEATURE_TEXT_INPUT,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden header: HELLO, no flag, no body, object 0, request id
    /// `0x1122_3344_5566_7788`.
    const GOLDEN_HEADER: [u8; HEADER_LEN] = [
        b'S', b'9', b'D', b'P', // magic
        0x01, 0x00, // major
        0x00, 0x00, // minor
        0x01, 0x00, // opcode = HELLO
        0x00, 0x00, // flags
        0x20, 0x00, 0x00, 0x00, // message_bytes = 32
        0, 0, 0, 0, 0, 0, 0, 0, // object_id
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // request_id
    ];

    fn golden_header() -> Header {
        Header {
            opcode: Opcode::HELLO.value(),
            flags: 0,
            message_bytes: HEADER_LEN as u32,
            object_id: 0,
            request_id: 0x1122_3344_5566_7788,
        }
    }

    fn rect(x: i32, y: i32, w: u32, h: u32) -> Rect {
        Rect { x, y, w, h }
    }

    fn commit_with(rects: &[Rect]) -> Commit {
        let mut commit = Commit::default();
        commit.buffer = 1;
        commit.ack_serial = 2;
        commit.commit_id = 3;
        commit.rect_count = rects.len() as u16;
        commit.rects[..rects.len()].copy_from_slice(rects);
        commit
    }

    #[test]
    fn header_golden_bytes_and_roundtrip() {
        let mut out = [0u8; HEADER_LEN];
        golden_header().encode(&mut out).unwrap();
        assert_eq!(out, GOLDEN_HEADER);

        let decoded = Header::decode(&GOLDEN_HEADER).unwrap();
        assert_eq!(decoded, golden_header());
        assert_eq!(MAGIC, u32::from_le_bytes(*b"S9DP"));
        assert_eq!(VERSION_MAJOR, 1);
        assert_eq!(VERSION_MINOR, 0);
    }

    #[test]
    fn header_decode_truncated_at_every_length() {
        for len in 0..HEADER_LEN {
            assert_eq!(
                Header::decode(&GOLDEN_HEADER[..len]),
                Err(DecodeError::Truncated),
                "len={len}"
            );
        }
    }

    #[test]
    fn header_rejects_bad_magic_and_version() {
        let mut bad_magic = GOLDEN_HEADER;
        bad_magic[0] = b'X';
        assert_eq!(Header::decode(&bad_magic), Err(DecodeError::BadMagic));

        let mut bad_major = GOLDEN_HEADER;
        bad_major[4] = 2;
        assert_eq!(
            Header::decode(&bad_major),
            Err(DecodeError::UnsupportedVersion)
        );

        let mut bad_minor = GOLDEN_HEADER;
        bad_minor[6] = 1;
        assert_eq!(
            Header::decode(&bad_minor),
            Err(DecodeError::UnsupportedVersion)
        );
    }

    #[test]
    fn header_rejects_bad_flags_and_short_message_bytes() {
        let mut bad_flags = GOLDEN_HEADER;
        bad_flags[10] = 1;
        assert_eq!(Header::decode(&bad_flags), Err(DecodeError::BadFlags));

        let mut short = GOLDEN_HEADER;
        short[12..16].copy_from_slice(&31u32.to_le_bytes());
        assert_eq!(Header::decode(&short), Err(DecodeError::SizeMismatch));

        let mut flags = golden_header();
        flags.flags = 0x8000;
        let mut out = [0u8; HEADER_LEN];
        assert_eq!(flags.encode(&mut out), Err(DecodeError::BadFlags));
        assert_eq!(flags.encode(&mut []), Err(DecodeError::Truncated));
    }

    #[test]
    fn header_decode_message_body_and_size_mismatch() {
        let header = Header {
            opcode: Opcode::PING.value(),
            flags: 0,
            message_bytes: (HEADER_LEN + 4) as u32,
            object_id: 7,
            request_id: 9,
        };
        let mut message = [0u8; HEADER_LEN + 4];
        header.encode(&mut message).unwrap();
        message[HEADER_LEN..].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

        let (decoded, body) = Header::decode_message(&message).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(body, &0xDEAD_BEEFu32.to_le_bytes()[..]);

        // Declared 32 bytes against 36 provided.
        assert_eq!(
            Header::decode_message(&message[..HEADER_LEN + 1]),
            Err(DecodeError::SizeMismatch)
        );

        let mut truncated = [0u8; HEADER_LEN + 3];
        truncated[..HEADER_LEN].copy_from_slice(&message[..HEADER_LEN]);
        assert_eq!(
            Header::decode_message(&truncated),
            Err(DecodeError::SizeMismatch)
        );
    }

    #[test]
    fn opcodes_and_features() {
        assert_eq!(Opcode::HELLO.value(), 0x0001);
        assert_eq!(Opcode::UNMAP_SURFACE.value(), 0x0031);
        assert_eq!(Opcode::WELCOME.value(), 0x8001);
        assert_eq!(Opcode::OUTPUT_REMOVED.value(), 0x8051);
        assert!(Opcode::FRAME_DONE.is_event());
        assert!(Opcode::OUTPUT_INFO.is_event());
        assert!(!Opcode::COMMIT.is_event());
        assert!(!Opcode::HELLO.is_event());
        assert_eq!(FEATURE_COPY_TILES, 1);
        assert_eq!(FEATURE_SHM_CPU, 2);
        assert_eq!(FEATURE_MULTI_OUTPUT, 4);
        assert_eq!(FEATURE_TEXT_INPUT, 8);
        assert_eq!(FEATURE_ARGB_PREMULTIPLIED, 16);
        assert_eq!(FEATURE_PRESENT_FEEDBACK, 32);
    }

    #[test]
    fn commit_roundtrip_zero_one_and_max_rects() {
        for count in [0usize, 1, MAX_RECTS] {
            let rects: [Rect; MAX_RECTS] =
                core::array::from_fn(|i| rect(i as i32, (i as i32) * 2, 4, 6));
            let commit = commit_with(&rects[..count]);
            let mut body = [0u8; COMMIT_BODY_LEN + RECT_LEN * MAX_RECTS];
            let len = commit.encoded_len();
            assert_eq!(len, COMMIT_BODY_LEN + RECT_LEN * count);
            commit.encode(&mut body[..len]).unwrap();

            let decoded = Commit::decode(&body[..len]).unwrap();
            assert_eq!(decoded, commit);
            assert_eq!(decoded.rects(), &rects[..count]);
        }

        // A full-damage commit has no rects and fits a single datagram.
        let mut full = Commit::default();
        full.flags = FLAG_FULL_DAMAGE;
        full.buffer = 0x0102_0304_0506_0708;
        let mut body = [0u8; COMMIT_BODY_LEN];
        full.encode(&mut body).unwrap();
        assert_eq!(Commit::decode(&body), Ok(full));
        assert!(full.is_full_damage());
        assert!(HEADER_LEN + COMMIT_BODY_LEN + MAX_RECTS * RECT_LEN <= 1008);
    }

    #[test]
    fn commit_rejects_too_many_rects() {
        let mut body = [0u8; COMMIT_BODY_LEN];
        body[28..30].copy_from_slice(&(MAX_RECTS as u16 + 1).to_le_bytes());
        assert_eq!(Commit::decode(&body), Err(DecodeError::TooManyRects));

        let mut commit = Commit::default();
        commit.rect_count = MAX_RECTS as u16 + 1;
        let mut out = [0u8; COMMIT_BODY_LEN + RECT_LEN * MAX_RECTS];
        assert_eq!(commit.encode(&mut out), Err(DecodeError::TooManyRects));
    }

    #[test]
    fn commit_rejects_every_truncated_prefix() {
        let rects = [rect(0, 0, 8, 8), rect(8, 8, 16, 16)];
        let commit = commit_with(&rects);
        let mut body = [0u8; COMMIT_BODY_LEN + RECT_LEN * 2];
        let len = commit.encoded_len();
        commit.encode(&mut body[..len]).unwrap();

        for prefix in 0..len {
            assert_eq!(
                Commit::decode(&body[..prefix]),
                Err(DecodeError::Truncated),
                "prefix={prefix}"
            );
        }
        // Trailing bytes are malformed too.
        let mut oversized = [0u8; COMMIT_BODY_LEN + RECT_LEN * 3];
        oversized[..len].copy_from_slice(&body[..len]);
        assert_eq!(Commit::decode(&oversized), Err(DecodeError::SizeMismatch));
    }

    #[test]
    fn commit_rejects_reserved_flags_and_damage_violations() {
        // Reserved u16 must be zero.
        let mut reserved = [0u8; COMMIT_BODY_LEN];
        reserved[30] = 1;
        assert_eq!(Commit::decode(&reserved), Err(DecodeError::ReservedNonZero));

        // Unknown flag bits.
        let mut flags = [0u8; COMMIT_BODY_LEN];
        flags[24] = 0x02;
        assert_eq!(Commit::decode(&flags), Err(DecodeError::BadFlags));

        // FULL_DAMAGE with rects present.
        let rects = [rect(0, 0, 1, 1)];
        let commit = commit_with(&rects);
        let mut body = [0u8; COMMIT_BODY_LEN + RECT_LEN];
        let len = commit.encoded_len();
        commit.encode(&mut body[..len]).unwrap();
        body[24] = FLAG_FULL_DAMAGE as u8;
        assert_eq!(Commit::decode(&body[..len]), Err(DecodeError::BadFlags));
    }

    #[test]
    fn commit_coordinate_bounds() {
        // End coordinate must stay within i32.
        assert_eq!(
            rect(i32::MAX, 0, 1, 0).check_extent(),
            Err(DecodeError::Overflow)
        );
        assert_eq!(
            rect(0, i32::MAX, 0, 1).check_extent(),
            Err(DecodeError::Overflow)
        );
        assert_eq!(
            rect(0, 0, 1 << 31, 0).check_extent(),
            Err(DecodeError::Overflow)
        );
        assert_eq!(
            rect(0, 0, u32::MAX, 0).check_extent(),
            Err(DecodeError::Overflow)
        );
        // Boundary and negative origins that still end inside i32 are fine.
        assert_eq!(rect(i32::MAX - 1, 0, 1, 0).check_extent(), Ok(()));
        assert_eq!(
            rect(i32::MAX - 1, i32::MAX - 1, 1, 1).check_extent(),
            Ok(())
        );
        assert_eq!(rect(-5, -5, 8, 8).check_extent(), Ok(()));
        assert_eq!(rect(i32::MIN, i32::MIN, 0, 0).check_extent(), Ok(()));

        // Both decode and encode enforce it.
        let commit = commit_with(&[rect(i32::MAX, 0, 1, 0)]);
        let mut body = [0u8; COMMIT_BODY_LEN + RECT_LEN];
        let len = commit.encoded_len();
        assert_eq!(commit.encode(&mut body[..len]), Err(DecodeError::Overflow));

        // Force a valid encode then corrupt the x field on the wire.
        let commit = commit_with(&[rect(0, 0, 1, 1)]);
        commit.encode(&mut body[..len]).unwrap();
        body[COMMIT_BODY_LEN..COMMIT_BODY_LEN + 4].copy_from_slice(&i32::MAX.to_le_bytes());
        assert_eq!(Commit::decode(&body[..len]), Err(DecodeError::Overflow));
    }

    #[test]
    fn pseudo_random_decodes_never_panic() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };

        let mut buf = [0u8; 512];
        for len in 0..=buf.len() {
            for byte in buf[..len].iter_mut() {
                *byte = next() as u8;
            }
            let slice = &buf[..len];
            let _ = Header::decode(slice);
            let _ = Header::decode_message(slice);
            let _ = Commit::decode(slice);

            // Also feed the pseudo-random opcode/flags through encode paths.
            let mut out = [0u8; 64];
            let header = Header {
                opcode: next() as u16,
                flags: next() as u16,
                message_bytes: next() as u32,
                object_id: next(),
                request_id: next(),
            };
            let _ = header.encode(&mut out);
        }
    }
}
