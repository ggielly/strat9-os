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

pub use strat9_abi::data::IpcMessage;
use strat9_abi::data::{IPC_MESSAGE_ALIGN, IPC_MESSAGE_SIZE};

use zerocopy::FromBytes;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes)]
pub struct IpcLabel {
    pub tier: u8,
    pub family: u8,
    pub compartment: u16,
}

/// Performs the ipc message from raw operation.
pub fn ipc_message_from_raw(buf: &[u8; IPC_MESSAGE_SIZE]) -> IpcMessage {
    // SAFETY: `buf` has exactly `IPC_MESSAGE_SIZE` bytes, matching `IpcMessage` size.
    unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const IpcMessage) }
}

/// Performs the ipc message to raw operation.
pub fn ipc_message_to_raw(msg: &IpcMessage, out: &mut [u8; IPC_MESSAGE_SIZE]) {
    // SAFETY: `out` has exactly `IPC_MESSAGE_SIZE` bytes, matching `IpcMessage` size.
    unsafe {
        core::ptr::copy_nonoverlapping(
            msg as *const _ as *const u8,
            out.as_mut_ptr(),
            IPC_MESSAGE_SIZE,
        );
    }
}

static_assertions::assert_eq_size!(IpcMessage, [u8; IPC_MESSAGE_SIZE]);
static_assertions::const_assert_eq!(core::mem::align_of::<IpcMessage>(), IPC_MESSAGE_ALIGN);
