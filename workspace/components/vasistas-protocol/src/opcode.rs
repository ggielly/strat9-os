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

//! Opcodes, events and negotiable feature bits (Annexe A.3).
//!
//! Opcodes are a transparent `u16` newtype, not an enum: unknown values must
//! survive decoding so the server can answer `ERROR` instead of panicking.

/// Wire opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opcode(pub u16);

impl Opcode {
    // Requests.
    pub const HELLO: Opcode = Opcode(0x0001);
    pub const PING: Opcode = Opcode(0x0002);
    pub const GOODBYE: Opcode = Opcode(0x0003);
    pub const CREATE_SURFACE: Opcode = Opcode(0x0010);
    pub const DESTROY_SURFACE: Opcode = Opcode(0x0011);
    pub const SET_TITLE: Opcode = Opcode(0x0012);
    pub const REQUEST_WINDOW_ACTION: Opcode = Opcode(0x0013);
    pub const SET_CURSOR_SHAPE: Opcode = Opcode(0x0014);
    pub const REQUEST_RESIZE: Opcode = Opcode(0x0015);
    pub const SET_GEOMETRY: Opcode = Opcode(0x0016);
    pub const ALLOC_BUFFER: Opcode = Opcode(0x0020);
    pub const IMPORT_RESULT: Opcode = Opcode(0x0021);
    pub const DESTROY_BUFFER: Opcode = Opcode(0x0022);
    pub const WRITE_TILE: Opcode = Opcode(0x0023);
    pub const COMMIT: Opcode = Opcode(0x0030);
    pub const UNMAP_SURFACE: Opcode = Opcode(0x0031);

    // Events.
    pub const WELCOME: Opcode = Opcode(0x8001);
    pub const PONG: Opcode = Opcode(0x8002);
    pub const ERROR: Opcode = Opcode(0x8003);
    pub const ACK: Opcode = Opcode(0x8004);
    pub const SURFACE_CREATED: Opcode = Opcode(0x8010);
    pub const CONFIGURE: Opcode = Opcode(0x8011);
    pub const SURFACE_DESTROYED: Opcode = Opcode(0x8012);
    pub const CLOSE_REQUEST: Opcode = Opcode(0x8013);
    pub const GEOMETRY: Opcode = Opcode(0x8014);
    pub const BUFFER_CREATED: Opcode = Opcode(0x8020);
    pub const BUFFER_RELEASE: Opcode = Opcode(0x8021);
    pub const BUFFER_DESTROYED: Opcode = Opcode(0x8022);
    pub const FRAME_DONE: Opcode = Opcode(0x8030);
    pub const INPUT_BATCH: Opcode = Opcode(0x8040);
    pub const INPUT_RESET: Opcode = Opcode(0x8041);
    pub const OUTPUT_INFO: Opcode = Opcode(0x8050);
    pub const OUTPUT_REMOVED: Opcode = Opcode(0x8051);

    /// True when the opcode belongs to the server-to-client event range.
    pub const fn is_event(self) -> bool {
        self.0 & 0x8000 != 0
    }

    /// Raw wire value.
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// Server can present buffers by copying tiles (`COPY_TILES`).
pub const FEATURE_COPY_TILES: u32 = 1 << 0;
/// Buffers can be shared through CPU mappings (`SHM_CPU`).
pub const FEATURE_SHM_CPU: u32 = 1 << 1;
/// More than one output is available (`MULTI_OUTPUT`).
pub const FEATURE_MULTI_OUTPUT: u32 = 1 << 2;
/// Text input events are delivered (`TEXT_INPUT`).
pub const FEATURE_TEXT_INPUT: u32 = 1 << 3;
/// Buffers carry premultiplied ARGB (`ARGB_PREMULTIPLIED`).
pub const FEATURE_ARGB_PREMULTIPLIED: u32 = 1 << 4;
/// `FRAME_DONE` reports presentation feedback (`PRESENT_FEEDBACK`).
pub const FEATURE_PRESENT_FEEDBACK: u32 = 1 << 5;

/// Mask of every feature bit defined in v1 (`HELLO`/`WELCOME`).
pub const FEATURES_KNOWN: u32 = FEATURE_COPY_TILES
    | FEATURE_SHM_CPU
    | FEATURE_MULTI_OUTPUT
    | FEATURE_TEXT_INPUT
    | FEATURE_ARGB_PREMULTIPLIED
    | FEATURE_PRESENT_FEEDBACK;
