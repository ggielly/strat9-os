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

//! s9vm — machine-code payloads used by the host-side smoke tests.
//!
//! The payloads live in a pure module so they can be **decoded by the kernel's
//! own instruction decoder in a host test**, not only executed on a machine
//! that exposes hardware virtualization. A wrong payload encoding otherwise
//! only shows up as a triple fault at boot: the guest walks into zero-filled
//! memory and faults far away from the real problem, which is expensive to
//! diagnose on hardware.
//!
//! # Loader payload
//!
//! [`LOADER_CODE`] is the guest program of the image-loader phase: publish the
//! marker on the debug port, then halt.
//!
//! | Bytes | Instruction |
//! |---|---|
//! | `B0 <marker>` | `mov al, marker` |
//! | `E6 E9` | `out 0xE9, al` |
//! | `F4` | `hlt` |
//!
//! The I/O instruction uses the **immediate-port** form on purpose: in 64-bit
//! mode `BA` is `MOV r32, imm32` (five bytes), not `MOV DX, imm16`; the
//! register-port form would need a `66` operand-size prefix. A first version of
//! this payload used `BA E9 00 EE F4`, which the processor decoded as
//! `mov edx, 0xF4EE00E9`: the guest then ran into the zero-filled tail of its
//! page and triple-faulted at the page boundary.

/// Byte published by the loader-phase guest on the debug port.
pub const LOADER_MARKER: u8 = b'L';
/// I/O port the loader-phase guest writes its marker to.
pub const DEBUG_PORT: u16 = 0xE9;
/// Guest program of the image-loader phase (see the module documentation).
pub const LOADER_CODE: &[u8] = &[0xB0, LOADER_MARKER, 0xE6, DEBUG_PORT as u8, 0xF4];
/// `hlt` opcode, the last instruction of every payload.
pub const HLT: u8 = 0xF4;
