//! L1 — network driver silo protocol: opcodes + IPC header layout.

use driver_net_proto::{opcodes, NetIpcHeader, NetIpcReply};

#[test]
fn opcodes_are_pinned() {
    assert_eq!(opcodes::NET_SEND, 0x40);
    assert_eq!(opcodes::NET_RECV, 0x41);
    assert_eq!(opcodes::NET_MAC_ADDR, 0x42);
    assert_eq!(opcodes::NET_LINK_STATUS, 0x43);
    assert_eq!(opcodes::NET_LIST_IFACES, 0x44);
}

#[test]
fn net_ipc_header_layout() {
    let h = NetIpcHeader {
        opcode: opcodes::NET_SEND,
        iface_id: 1,
        flags: 0,
        payload_len: 1514,
    };
    let base = &h as *const _ as usize;
    // opcode @0..4, iface @4..6, flags @6..8, len @8..12
    assert_eq!(&h.opcode as *const _ as usize - base, 0);
    assert_eq!(&h.iface_id as *const _ as usize - base, 4);
    assert_eq!(&h.flags as *const _ as usize - base, 6);
    assert_eq!(&h.payload_len as *const _ as usize - base, 8);
    assert_eq!(core::mem::size_of::<NetIpcHeader>(), 12);
}

#[test]
fn net_ipc_reply_layout() {
    let r = NetIpcReply { status: 0, payload_len: 42 };
    assert_eq!(core::mem::size_of::<NetIpcReply>(), 8);
    let base = &r as *const _ as usize;
    assert_eq!(&r.status as *const _ as usize - base, 0);
    assert_eq!(&r.payload_len as *const _ as usize - base, 4);
}
