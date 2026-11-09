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

#![no_std]

/// IPC opcodes for the network driver silo protocol.
///
/// A silo-hosted driver sends these to the kernel stub, which translates
/// them into `net_core::NetworkDevice` calls on the backing hardware.
pub mod opcodes {
    pub const NET_SEND: u32 = 0x40;
    pub const NET_RECV: u32 = 0x41;
    pub const NET_MAC_ADDR: u32 = 0x42;
    pub const NET_LINK_STATUS: u32 = 0x43;
    pub const NET_LIST_IFACES: u32 = 0x44;
}

/// Packet header prepended to IPC-transported frames.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetIpcHeader {
    pub opcode: u32,
    pub iface_id: u16,
    pub flags: u16,
    pub payload_len: u32,
}

/// Response header from kernel to silo.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetIpcReply {
    pub status: i32,
    pub payload_len: u32,
}
