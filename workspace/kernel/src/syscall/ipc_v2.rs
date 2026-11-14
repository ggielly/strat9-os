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

//! IPC ABI v2 syscalls 270–283 (§13).
//!
//! Namespace (281–283) is implemented here on top of the v2 namespace table
//! in [`crate::namespace::v2`]. MemObject (284–285) and async opcodes are
//! outside this module and are routed to `ENOSYS` by the dispatcher.

use crate::{
    ipc::v2::{
        endpoint::{
            self, CallSlot, CallState, Endpoint, InFlight, OwnedCap, PopOutcome, RecvItem,
            ReplyPayload,
        },
        handle::{Entry, HandleTable, ObjRef},
        memobj::MemObject,
        notif::Notification,
        quota::{self, charge_message},
        register_call,
    },
    memory::userslice::{UserPod, UserSliceRead, UserSliceReadWrite, UserSliceWrite},
    namespace::v2 as ns_v2,
    process::{current_task_clone, process::Process},
    silo::{
        current_task_may_proxy, current_task_sandboxed, enforce_path_for_current_task,
        enforce_registry_bind_for_current_task, enforce_registry_lookup_for_current_task,
        require_silo_admin, try_silo_id_for_task, IpcResource,
    },
    sync::scheduler_clock_ns,
    syscall::error::SyscallError,
};
use alloc::{string::String, sync::Arc, vec::Vec};
use core::mem::size_of;
use strat9_abi::ipc_v2::{
    CapXfer, Handle, MsgBuf, MsgHeader, EP_FLAG_FASTPATH, EP_FLAG_SENDER_SILO, EP_MINT, EP_RECV,
    EP_SEND, EP_XFER, GENERIC_RIGHTS_MASK, IPC_MAX_CAPS, IPC_MAX_DATA, IPC_NONBLOCK, MEM_MAP,
    MEM_READ, MEM_WRITE, MSG_KIND_CALL, MSG_KIND_REPLY, MSG_KIND_SEND, NOTIF_MINT, NOTIF_SIGNAL,
    NOTIF_WAIT, RIGHTS_SAME, RIGHT_DUPLICATE, RIGHT_INSPECT, RIGHT_TRANSFER, RIGHT_WAIT, XFER_COPY,
    XFER_MOVE,
};

// SAFETY: `MsgBuf` is `#[repr(C)]` and contains only integers; every bit
// pattern is a valid value.
unsafe impl UserPod for MsgBuf {}
// SAFETY: `MsgHeader` is `#[repr(C)]` and contains only integers/byte arrays;
// every bit pattern is a valid value.
unsafe impl UserPod for MsgHeader {}
// SAFETY: `CapXfer` is `#[repr(C)]` and contains only integers; every bit
// pattern is a valid value.
unsafe impl UserPod for CapXfer {}

/// One validated capability ready to be committed.
struct BuiltCap {
    cap: OwnedCap,
    mode: u32,
    source: Handle,
}

/// `SYS_NS_BIND` flag bit 0: replace an existing entry (§8).
pub const NS_BIND_REPLACE: u32 = 1;

/// Maximum namespace path length, matching the v1 bind path limit.
const NS_MAX_PATH: usize = 4096;

/// Copy a namespace path out of user memory.
///
/// The bytes are UTF-8, must be non-empty, must start with `/` and need no
/// NUL terminator.
fn read_ns_path(ptr: u64, len: u64) -> Result<String, SyscallError> {
    if ptr == 0 {
        return Err(SyscallError::Fault);
    }
    let len = usize::try_from(len).map_err(|_| SyscallError::InvalidArgument)?;
    if len == 0 || len > NS_MAX_PATH {
        return Err(SyscallError::InvalidArgument);
    }
    let raw = UserSliceRead::new(ptr, len)?.read_to_vec();
    let path = core::str::from_utf8(&raw).map_err(|_| SyscallError::InvalidArgument)?;
    if path.is_empty() || !path.starts_with('/') {
        return Err(SyscallError::InvalidArgument);
    }
    Ok(path.into())
}

/// Silo id of the calling task (`0` when unattributed).
fn current_silo_id() -> u32 {
    current_task_clone()
        .and_then(|task| try_silo_id_for_task(&task))
        .unwrap_or(0)
}

/// Whether the caller holds the silo admin capability.
fn caller_is_silo_admin() -> bool {
    require_silo_admin().is_ok()
}

/// Blocking policy of one syscall, from the common `flags`/`timeout_ns` pair.
#[derive(Clone, Copy)]
pub(crate) struct WaitSpec {
    /// `IPC_NONBLOCK`: never block, `EAGAIN` instead.
    pub(crate) nonblock: bool,
    /// Absolute deadline on [`scheduler_clock_ns`], or `None` (no timeout).
    pub(crate) deadline_ns: Option<u64>,
}

impl WaitSpec {
    /// Never block (async ring submissions).
    pub(crate) const NONBLOCK: WaitSpec = WaitSpec {
        nonblock: true,
        deadline_ns: None,
    };
}

/// Parse the common `flags`/`timeout_ns` pair (§13).
///
/// `timeout_ns == 0` means no timeout. `IPC_NONBLOCK` takes precedence over
/// `timeout_ns`. The deadline is computed once, at syscall entry, so a
/// `call` is bounded as a whole (send + wait for the reply), as §6.2 states.
/// Resolution is one scheduler tick.
fn parse_common(flags: u64, timeout_ns: u64) -> Result<WaitSpec, SyscallError> {
    let flags = flags as u32;
    if flags & !IPC_NONBLOCK != 0 {
        return Err(SyscallError::InvalidArgument);
    }
    let nonblock = flags & IPC_NONBLOCK != 0;
    let deadline_ns = if nonblock || timeout_ns == 0 {
        None
    } else {
        Some(scheduler_clock_ns().saturating_add(timeout_ns))
    };
    Ok(WaitSpec {
        nonblock,
        deadline_ns,
    })
}

fn read_msg_buf(ptr: u64) -> Result<MsgBuf, SyscallError> {
    Ok(UserSliceRead::new(ptr, size_of::<MsgBuf>())?.read_val::<MsgBuf>()?)
}

fn read_msg_header(ptr: u64) -> Result<MsgHeader, SyscallError> {
    Ok(UserSliceRead::new(ptr, size_of::<MsgHeader>())?.read_val::<MsgHeader>()?)
}

/// Validate a user-authored header (§4.1: kernel fields must be zero).
fn validate_user_header(header: &MsgHeader) -> Result<(), SyscallError> {
    if header.kind != 0
        || header._rsvd0 != [0; 3]
        || header._rsvd1 != 0
        || header.badge != 0
        || header.reply != 0
        || header.sender_silo != 0
        || header.data_len as usize > IPC_MAX_DATA
        || header.ncaps as usize > IPC_MAX_CAPS
    {
        return Err(SyscallError::InvalidArgument);
    }
    Ok(())
}

fn read_payload(buf: &MsgBuf, header: &MsgHeader) -> Result<Vec<u8>, SyscallError> {
    if header.data_len == 0 {
        return Ok(Vec::new());
    }
    if buf.data == 0 {
        return Err(SyscallError::InvalidArgument);
    }
    Ok(UserSliceRead::new(buf.data, header.data_len as usize)?.read_to_vec())
}

fn read_caps(buf: &MsgBuf, header: &MsgHeader) -> Result<Vec<CapXfer>, SyscallError> {
    let mut caps = Vec::with_capacity(header.ncaps as usize);
    if header.ncaps == 0 {
        return Ok(caps);
    }
    if buf.caps == 0 {
        return Err(SyscallError::InvalidArgument);
    }
    for i in 0..header.ncaps as u64 {
        let addr = buf
            .caps
            .checked_add(i * size_of::<CapXfer>() as u64)
            .ok_or(SyscallError::InvalidArgument)?;
        caps.push(UserSliceRead::new(addr, size_of::<CapXfer>())?.read_val::<CapXfer>()?);
    }
    Ok(caps)
}

/// Resolve every `CapXfer` against the caller's table without modifying it.
fn build_caps(table: &HandleTable, caps: &[CapXfer]) -> Result<Vec<BuiltCap>, SyscallError> {
    let mut out = Vec::with_capacity(caps.len());
    let mut moves: Vec<u64> = Vec::new();
    for c in caps {
        if c.mode != XFER_MOVE && c.mode != XFER_COPY {
            return Err(SyscallError::InvalidArgument);
        }
        let source = Handle::from_raw(c.handle);
        let entry = table.resolve(source, RIGHT_TRANSFER)?;
        // §6.2 rule 2: a Reply handle may only be delegated with XFER_MOVE.
        if matches!(&entry.obj, ObjRef::Reply(_)) && c.mode != XFER_MOVE {
            return Err(SyscallError::PermissionDenied);
        }
        if c.mode == XFER_COPY && entry.rights & RIGHT_DUPLICATE == 0 {
            return Err(SyscallError::PermissionDenied);
        }
        if c.mode == XFER_MOVE {
            if moves.contains(&c.handle) {
                return Err(SyscallError::InvalidArgument);
            }
            moves.push(c.handle);
        }
        let rights = if c.rights == RIGHTS_SAME {
            entry.rights
        } else {
            c.rights & entry.rights
        };
        out.push(BuiltCap {
            cap: OwnedCap {
                obj: entry.obj.clone(),
                rights,
                badge: entry.badge,
            },
            mode: c.mode,
            source,
        });
    }
    Ok(out)
}

fn endpoint_handle(
    process: &Process,
    raw: u64,
    required: u32,
) -> Result<(Entry, Arc<Endpoint>), SyscallError> {
    let table = process.ipc_v2.lock();
    let entry = table.resolve(Handle::from_raw(raw), required)?;
    let ep = match &entry.obj {
        ObjRef::Endpoint(ep) => ep.clone(),
        _ => return Err(SyscallError::BadHandle),
    };
    Ok((entry, ep))
}

fn notification_handle(
    process: &Process,
    raw: u64,
    required: u32,
) -> Result<(Entry, Arc<Notification>), SyscallError> {
    let table = process.ipc_v2.lock();
    let entry = table.resolve(Handle::from_raw(raw), required)?;
    let notif = match &entry.obj {
        ObjRef::Notif(notif) => notif.clone(),
        _ => return Err(SyscallError::BadHandle),
    };
    Ok((entry, notif))
}

fn write_header(ptr: u64, header: &MsgHeader) -> Result<(), SyscallError> {
    UserSliceReadWrite::new(ptr, size_of::<MsgHeader>())?
        .write_val(header)
        .map_err(Into::into)
}

fn write_caps(ptr: u64, caps: &[(Handle, u32, u32)]) -> Result<(), SyscallError> {
    for (i, (handle, rights, obj_type)) in caps.iter().enumerate() {
        let addr = ptr
            .checked_add(i as u64 * size_of::<CapXfer>() as u64)
            .ok_or(SyscallError::InvalidArgument)?;
        let wire = endpoint::installed_cap_wire(handle.raw(), *rights, *obj_type);
        UserSliceReadWrite::new(addr, size_of::<CapXfer>())?.write_val(&wire)?;
    }
    Ok(())
}

/// Install message capabilities into the receiver table. The message already
/// owns a reference to every object, so `insert` must not add another one.
///
/// The caller must have reserved `caps.len()` table slots: each successful
/// insert consumes one reserved unit. On the (unreachable) capacity failure
/// the remaining reservation and capabilities are released.
fn install_caps(
    process: &Process,
    caps: Vec<OwnedCap>,
) -> Result<Vec<(Handle, u32, u32)>, SyscallError> {
    let total = caps.len();
    // §8: without `RegistryMode::PROXY`, a silo cannot hold a foreign
    // `EP_MINT`; it is stripped on the way in (the handle stays usable).
    let may_proxy = total == 0 || current_task_may_proxy();
    let mut table = process.ipc_v2.lock();
    let mut installed = Vec::with_capacity(total);
    let mut iter = caps.into_iter();
    while let Some(cap) = iter.next() {
        let rights = match cap.obj {
            ObjRef::Endpoint(_) if !may_proxy => cap.rights & !EP_MINT,
            _ => cap.rights,
        };
        let obj_type = cap.obj.obj_type();
        match table.insert(rights, cap.obj.clone(), cap.badge) {
            Some(handle) => installed.push((handle, rights, obj_type)),
            None => {
                // Drop the unspent reservation (this cap + the rest) and every
                // capability that was not installed; the message is dropped.
                table.release_reservation(total - installed.len());
                drop(table);
                endpoint::release_cap(&cap);
                endpoint::release_caps(iter.collect());
                return Err(SyscallError::NoSpace);
            }
        }
    }
    Ok(installed)
}

/// Retain one reference per capability before the message/payload becomes
/// visible; every mode needs this because the kernel-side record owns a ref.
fn retain_built(built: &[BuiltCap]) {
    for b in built {
        endpoint::retain_cap(&b.cap);
    }
}

fn release_built(built: &[BuiltCap]) {
    for b in built {
        endpoint::release_cap(&b.cap);
    }
}

/// Apply the MOVE half of commit: remove the source handles. `remove` applies
/// the object-side effects (releasing the `EP_RECV` reference, cancelling a
/// moved Reply), so the reference retained by `retain_built` is now the one
/// owned by the message record. Do not release it here as well.
fn commit_moves(process: &Process, built: &[BuiltCap]) {
    let mut table = process.ipc_v2.lock();
    for b in built {
        if b.mode == XFER_MOVE {
            let _ = table.remove(b.source);
        }
    }
}

/// SYS_EP_CREATE (270).
pub fn sys_ep_create(process: &Process, depth: u64, flags: u64) -> Result<u64, SyscallError> {
    let flags = flags as u32;
    if flags & !(EP_FLAG_SENDER_SILO | EP_FLAG_FASTPATH) != 0 {
        return Err(SyscallError::InvalidArgument);
    }
    let owner_silo = current_task_clone()
        .and_then(|task| try_silo_id_for_task(&task))
        .unwrap_or(0);
    let charge = quota::charge_object(process, IpcResource::Endpoints)?;
    let ep = Endpoint::create(depth as u32, flags as u16, owner_silo, charge)?;
    let handle = process.ipc_v2.lock().insert(
        EP_RECV | EP_MINT | RIGHT_WAIT | RIGHT_INSPECT,
        ObjRef::Endpoint(ep.clone()),
        0,
    );
    let Some(handle) = handle else {
        // The creator's only EP_RECV reference is not installed: close now so
        // the endpoint does not leak with `recv_refs == 1`.
        ep.close();
        return Err(SyscallError::NoSpace);
    };
    Ok(handle.raw())
}

/// SYS_IPC_MINT (271).
pub fn sys_ipc_mint(
    process: &Process,
    raw: u64,
    badge: u64,
    rights: u64,
) -> Result<u64, SyscallError> {
    let rights = rights as u32;
    let mut table = process.ipc_v2.lock();
    let entry = table.resolve(Handle::from_raw(raw), 0)?;
    let (obj, new_rights) = match &entry.obj {
        ObjRef::Endpoint(ep) => {
            if entry.rights & EP_MINT == 0 {
                return Err(SyscallError::PermissionDenied);
            }
            (
                ObjRef::Endpoint(ep.clone()),
                EP_SEND | (rights & GENERIC_RIGHTS_MASK & entry.rights),
            )
        }
        ObjRef::Notif(notif) => {
            if entry.rights & NOTIF_MINT == 0 {
                return Err(SyscallError::PermissionDenied);
            }
            (
                ObjRef::Notif(notif.clone()),
                NOTIF_SIGNAL | (rights & GENERIC_RIGHTS_MASK & entry.rights),
            )
        }
        ObjRef::Reply(_) | ObjRef::Mem(_) => return Err(SyscallError::BadHandle),
    };
    let handle = table
        .insert(new_rights, obj, badge)
        .ok_or(SyscallError::NoSpace)?;
    Ok(handle.raw())
}

/// SYS_EP_SEND (272).
pub fn sys_ep_send(
    process: &Process,
    send_h: u64,
    buf_ptr: u64,
    flags: u64,
    timeout_ns: u64,
) -> Result<u64, SyscallError> {
    let wait = parse_common(flags, timeout_ns)?;
    let (entry, ep) = endpoint_handle(process, send_h, EP_SEND)?;

    let buf = read_msg_buf(buf_ptr)?;
    let mut header = read_msg_header(buf.hdr)?;
    validate_user_header(&header)?;
    let data = read_payload(&buf, &header)?;
    let caps_in = read_caps(&buf, &header)?;
    if !caps_in.is_empty() && entry.rights & EP_XFER == 0 {
        return Err(SyscallError::PermissionDenied);
    }
    // §8: a sandboxed silo may keep using the handles it holds but must not
    // transfer them out.
    if !caps_in.is_empty() && current_task_sandboxed() {
        return Err(SyscallError::PermissionDenied);
    }
    let built = {
        let table = process.ipc_v2.lock();
        build_caps(&table, &caps_in)?
    };

    let sender_silo = if ep.flags as u32 & EP_FLAG_SENDER_SILO != 0 {
        current_task_clone()
            .and_then(|task| try_silo_id_for_task(&task))
            .unwrap_or(0)
    } else {
        0
    };
    header.kind = MSG_KIND_SEND;
    header.badge = entry.badge;
    header.sender_silo = sender_silo;
    header.ncaps = built.len() as u16;

    let charge = charge_message(
        process,
        message_bytes(&header),
        built.len() as u64,
        wait.nonblock,
        wait.deadline_ns,
    )?;
    let mut inflight_caps = Vec::with_capacity(built.len());
    for b in &built {
        inflight_caps.push(b.cap.clone());
    }
    let msg = InFlight {
        header,
        data,
        caps: inflight_caps,
        call: None,
        charge,
    };
    retain_built(&built);
    if let Err(error) = ep.push(msg, wait.nonblock, wait.deadline_ns) {
        release_built(&built);
        return Err(error);
    }
    commit_moves(process, &built);
    Ok(0)
}

/// Queue accounting size of a message (§12): header + data.
fn message_bytes(header: &MsgHeader) -> u64 {
    size_of::<MsgHeader>() as u64 + u64::from(header.data_len)
}

/// SYS_EP_CALL (273).
pub fn sys_ep_call(
    process: &Process,
    send_h: u64,
    req_ptr: u64,
    resp_ptr: u64,
    flags: u64,
    timeout_ns: u64,
) -> Result<u64, SyscallError> {
    let wait = parse_common(flags, timeout_ns)?;
    let (slot, resp) = call_submit(process, send_h, req_ptr, resp_ptr, wait)?;

    // `IPC_NONBLOCK` only governs the enqueue: once committed, a call always
    // waits for its reply (bounded by the deadline, if any).
    let outcome = slot.waitq.wait_until_deadline(wait.deadline_ns, || {
        let state = *slot.state.lock();
        match state {
            CallState::Done => Some(Ok(())),
            CallState::Cancelled => Some(Err(SyscallError::Pipe)),
            // A signal interrupts a blocking call and cancels it (§6.2).
            _ if crate::process::signal::has_pending_signals() => {
                Some(Err(SyscallError::Interrupted))
            }
            _ => None,
        }
    });
    let outcome = outcome.unwrap_or(Err(SyscallError::TimedOut));
    if let Err(error) = outcome {
        if matches!(error, SyscallError::Interrupted | SyscallError::TimedOut) {
            // Cancels a queued/received call; if the reply raced in (`Done`),
            // reclaims its capabilities instead of leaking them (§6.2).
            endpoint::abandon_call(&slot);
        }
        return Err(error);
    }
    call_finish(process, &slot, &resp)
}

/// Validate and enqueue a call (first half of `SYS_EP_CALL`, shared with the
/// async `EpCall` opcode). Returns the linked call slot and the validated
/// response descriptor; the reply is collected by [`call_finish`].
pub(crate) fn call_submit(
    process: &Process,
    send_h: u64,
    req_ptr: u64,
    resp_ptr: u64,
    wait: WaitSpec,
) -> Result<(Arc<CallSlot>, MsgBuf), SyscallError> {
    let (entry, ep) = endpoint_handle(process, send_h, EP_SEND)?;

    let req = read_msg_buf(req_ptr)?;
    let resp = read_msg_buf(resp_ptr)?;
    let mut header = read_msg_header(req.hdr)?;
    validate_user_header(&header)?;
    let data = read_payload(&req, &header)?;
    let caps_in = read_caps(&req, &header)?;
    if !caps_in.is_empty() && entry.rights & EP_XFER == 0 {
        return Err(SyscallError::PermissionDenied);
    }
    // §8: a sandboxed silo must not transfer handles out.
    if !caps_in.is_empty() && current_task_sandboxed() {
        return Err(SyscallError::PermissionDenied);
    }
    // Validate the response buffers now; the copy-out happens on wake, still
    // in the caller's own address space.
    UserSliceWrite::new(resp.hdr, size_of::<MsgHeader>())?;
    if resp.data_cap != 0 {
        UserSliceWrite::new(resp.data, resp.data_cap.min(IPC_MAX_DATA as u32) as usize)?;
    }
    if resp.caps_cap != 0 {
        let len = resp.caps_cap.min(IPC_MAX_CAPS as u32) as usize * size_of::<CapXfer>();
        UserSliceWrite::new(resp.caps, len)?;
    }

    let built = {
        let table = process.ipc_v2.lock();
        build_caps(&table, &caps_in)?
    };
    let sender_silo = if ep.flags as u32 & EP_FLAG_SENDER_SILO != 0 {
        current_task_clone()
            .and_then(|task| try_silo_id_for_task(&task))
            .unwrap_or(0)
    } else {
        0
    };
    header.kind = MSG_KIND_CALL;
    header.badge = entry.badge;
    header.sender_silo = sender_silo;
    header.ncaps = built.len() as u16;

    let charge = charge_message(
        process,
        message_bytes(&header),
        built.len() as u64,
        wait.nonblock,
        wait.deadline_ns,
    )?;
    let caller = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let slot = Arc::new(CallSlot::new(ep.id(), Some(caller.id), resp));
    if ep.flags as u32 & EP_FLAG_FASTPATH != 0 {
        slot.fastpath
            .store(true, core::sync::atomic::Ordering::Release);
    }
    register_call(&slot);

    let mut inflight_caps = Vec::with_capacity(built.len());
    for b in &built {
        inflight_caps.push(b.cap.clone());
    }
    let msg = InFlight {
        header,
        data,
        caps: inflight_caps,
        call: Some(slot.clone()),
        charge,
    };
    retain_built(&built);
    if let Err(error) = ep.push(msg, wait.nonblock, wait.deadline_ns) {
        release_built(&built);
        endpoint::cancel_call(&slot);
        return Err(error);
    }
    commit_moves(process, &built);
    Ok((slot, resp))
}

/// Collect the reply of a completed call (second half of `SYS_EP_CALL`).
///
/// Must run in the **caller's** context (its address space receives the
/// copy-out). The slot must be `Done` or `Cancelled`.
pub(crate) fn call_finish(
    process: &Process,
    slot: &CallSlot,
    resp: &MsgBuf,
) -> Result<u64, SyscallError> {
    let resp = *resp;
    let payload = slot.reply.lock().take().ok_or(SyscallError::Pipe)?;
    // Reserve the reply capability slots before installing (§4.5 step 3).
    let reserved = payload.caps.len();
    if let Err(error) = process.ipc_v2.lock().reserve(reserved) {
        endpoint::release_caps(payload.caps);
        return Err(error);
    }
    if payload.data.len() > resp.data_cap as usize || payload.caps.len() > resp.caps_cap as usize {
        let mut err_header = payload.header;
        err_header.ncaps = payload.caps.len() as u16;
        let _ = write_header(resp.hdr, &err_header);
        process.ipc_v2.lock().release_reservation(reserved);
        endpoint::release_caps(payload.caps);
        return Err(SyscallError::MessageSize);
    }
    let installed = install_caps(process, payload.caps)?;
    let mut out_header = payload.header;
    out_header.kind = MSG_KIND_REPLY;
    out_header.ncaps = installed.len() as u16;
    write_header(resp.hdr, &out_header)?;
    if !payload.data.is_empty() {
        UserSliceWrite::new(resp.data, payload.data.len())?.copy_from(&payload.data);
    }
    write_caps(resp.caps, &installed)?;
    Ok(0)
}

/// SYS_EP_RECV (274).
pub fn sys_ep_recv(
    process: &Process,
    recv_h: u64,
    buf_ptr: u64,
    flags: u64,
    timeout_ns: u64,
) -> Result<u64, SyscallError> {
    let wait = parse_common(flags, timeout_ns)?;
    let (_, ep) = endpoint_handle(process, recv_h, EP_RECV)?;
    let buf = read_msg_buf(buf_ptr)?;

    // Validate every destination before dequeuing anything.
    let header_slice = UserSliceReadWrite::new(buf.hdr, size_of::<MsgHeader>())?;
    if buf.data_cap != 0 {
        UserSliceWrite::new(buf.data, buf.data_cap.min(IPC_MAX_DATA as u32) as usize)?;
    }
    if buf.caps_cap != 0 {
        let len = buf.caps_cap.min(IPC_MAX_CAPS as u32) as usize * size_of::<CapXfer>();
        UserSliceWrite::new(buf.caps, len)?;
    }
    // Reserve handle-table slots for the message we are about to take
    // (§4.5 step 3): `ncaps` plus one for a Reply handle. The peek is only a
    // first guess; `pop` re-checks the head against `needed` under the
    // endpoint lock, in the same critical section as the dequeue, and asks
    // for more (`NeedSlots`) if the head changed meanwhile (another receiver
    // thread took it, or the queue was empty and we blocked). The table lock
    // is never held across `pop`, so no lock is nested.
    let mut needed = ep
        .peek_plan()
        .map_or(0, |p| p.ncaps as usize + usize::from(p.has_call));
    process.ipc_v2.lock().reserve(needed)?;
    let item = loop {
        match ep.pop(
            buf.data_cap,
            buf.caps_cap,
            wait.nonblock,
            needed,
            wait.deadline_ns,
        ) {
            Ok(PopOutcome::Item(item)) => break item,
            Ok(PopOutcome::NeedSlots(more)) => {
                // `more > needed` by construction. Grow the reservation; if the
                // table cannot hold it, the message stays queued (`ENOSPC`).
                let mut table = process.ipc_v2.lock();
                if let Err(error) = table.reserve(more - needed) {
                    table.release_reservation(needed);
                    return Err(error);
                }
                needed = more;
            }
            Err(SyscallError::MessageSize) => {
                process.ipc_v2.lock().release_reservation(needed);
                if let Some((data_len, ncaps)) = ep.head_requirements() {
                    let mut required = MsgHeader::default();
                    required.data_len = data_len;
                    required.ncaps = ncaps;
                    let _ = header_slice.write_val(&required);
                }
                return Err(SyscallError::MessageSize);
            }
            Err(error) => {
                process.ipc_v2.lock().release_reservation(needed);
                return Err(error);
            }
        }
    };
    let RecvItem {
        mut header,
        data,
        caps,
        call,
        charge,
    } = item;
    // The message left the queue: release the sender's quota now, outside
    // every endpoint lock (this may wake senders blocked on the quota).
    drop(charge);

    // From here the message is dequeued; the reservation makes the installs
    // below unable to fail for capacity. This keeps delivery all-or-nothing.
    let caps_len = caps.len();
    let installed = match install_caps(process, caps) {
        Ok(installed) => installed,
        Err(error) => {
            // `install_caps` released its own share; drop the Reply slot.
            process
                .ipc_v2
                .lock()
                .release_reservation(needed.saturating_sub(caps_len));
            return Err(error);
        }
    };

    let reply_raw = if let Some(slot) = call {
        let generation = slot.gen.load(core::sync::atomic::Ordering::Acquire);
        let handle = process.ipc_v2.lock().insert(
            RIGHT_TRANSFER,
            ObjRef::Reply(slot.clone()),
            generation as u64,
        );
        match handle {
            Some(handle) => handle.raw(),
            None => {
                // Unreachable after `reserve`; do not leak the reservation.
                process
                    .ipc_v2
                    .lock()
                    .release_reservation(needed.saturating_sub(installed.len()));
                return Err(SyscallError::NoSpace);
            }
        }
    } else {
        0
    };
    // Release any reservation the delivery did not consume (e.g. a call
    // cancelled between peek and pop no longer carries a Reply handle).
    let consumed = installed.len() + usize::from(reply_raw != 0);
    process
        .ipc_v2
        .lock()
        .release_reservation(needed.saturating_sub(consumed));

    header.kind = if header.kind == 0 {
        MSG_KIND_SEND
    } else {
        header.kind
    };
    header.ncaps = installed.len() as u16;
    header.reply = reply_raw;
    header_slice.write_val(&header)?;
    if !data.is_empty() {
        UserSliceWrite::new(buf.data, data.len())?.copy_from(&data);
    }
    write_caps(buf.caps, &installed)?;
    Ok(header.kind as u64)
}

/// SYS_EP_REPLY (275).
pub fn sys_ep_reply(process: &Process, reply_h: u64, buf_ptr: u64) -> Result<u64, SyscallError> {
    let buf = read_msg_buf(buf_ptr)?;
    let mut header = read_msg_header(buf.hdr)?;
    validate_user_header(&header)?;
    let data = read_payload(&buf, &header)?;
    let caps_in = read_caps(&buf, &header)?;
    // §8: a sandboxed server must not export handles through a reply.
    if !caps_in.is_empty() && current_task_sandboxed() {
        return Err(SyscallError::PermissionDenied);
    }
    let built = {
        let table = process.ipc_v2.lock();
        build_caps(&table, &caps_in)?
    };

    let (slot, generation) = {
        let mut table = process.ipc_v2.lock();
        let entry = table.resolve(Handle::from_raw(reply_h), 0)?;
        let slot = match &entry.obj {
            ObjRef::Reply(slot) => slot.clone(),
            _ => return Err(SyscallError::BadHandle),
        };
        let generation = entry.badge as u32;
        // Reply handles are single-use: consume unconditionally. `remove_raw`
        // must not cancel the call this reply is about to complete.
        let _ = table.remove_raw(Handle::from_raw(reply_h))?;
        (slot, generation)
    };

    header.kind = MSG_KIND_REPLY;
    header.badge = 0;
    header.reply = 0;
    header.sender_silo = 0;
    header.ncaps = built.len() as u16;
    let mut payload_caps = Vec::with_capacity(built.len());
    for b in &built {
        payload_caps.push(b.cap.clone());
    }
    let payload = ReplyPayload {
        header,
        data,
        caps: payload_caps,
    };
    retain_built(&built);
    if let Err(error) = endpoint::deliver_reply(&slot, generation, payload) {
        release_built(&built);
        return Err(error);
    }
    commit_moves(process, &built);
    Ok(0)
}

/// SYS_EP_REPLY_RECV (276): complete the reply, then receive.
pub fn sys_ep_reply_recv(
    process: &Process,
    reply_h: u64,
    reply_buf: u64,
    recv_h: u64,
    recv_buf: u64,
    flags: u64,
    timeout_ns: u64,
) -> Result<u64, SyscallError> {
    sys_ep_reply(process, reply_h, reply_buf)?;
    sys_ep_recv(process, recv_h, recv_buf, flags, timeout_ns)
}

/// SYS_EP_BIND_NOTIF (277).
pub fn sys_ep_bind_notif(
    process: &Process,
    recv_h: u64,
    notif_h: u64,
) -> Result<u64, SyscallError> {
    let (_, ep) = endpoint_handle(process, recv_h, EP_RECV)?;
    let (_, notif) = notification_handle(process, notif_h, NOTIF_WAIT)?;
    ep.bind_notif(notif)?;
    Ok(0)
}

/// SYS_NOTIF_CREATE (278).
pub fn sys_notif_create(process: &Process, flags: u64) -> Result<u64, SyscallError> {
    let flags = flags as u32;
    if flags & !IPC_NONBLOCK != 0 {
        return Err(SyscallError::InvalidArgument);
    }
    let charge = quota::charge_object(process, IpcResource::Notifications)?;
    let notif = Notification::create_charged(charge);
    let handle = process
        .ipc_v2
        .lock()
        .insert(
            NOTIF_SIGNAL | NOTIF_WAIT | NOTIF_MINT | RIGHT_WAIT | RIGHT_INSPECT,
            ObjRef::Notif(notif),
            u64::MAX,
        )
        .ok_or(SyscallError::NoSpace)?;
    Ok(handle.raw())
}

/// SYS_NOTIF_SIGNAL (279).
pub fn sys_notif_signal(process: &Process, notif_h: u64, bits: u64) -> Result<u64, SyscallError> {
    let (entry, notif) = notification_handle(process, notif_h, NOTIF_SIGNAL)?;
    notif.signal(bits & entry.badge)?;
    Ok(0)
}

/// SYS_NOTIF_WAIT (280).
pub fn sys_notif_wait(
    process: &Process,
    notif_h: u64,
    out_ptr: u64,
    flags: u64,
    timeout_ns: u64,
) -> Result<u64, SyscallError> {
    let wait = parse_common(flags, timeout_ns)?;
    let (_, notif) = notification_handle(process, notif_h, NOTIF_WAIT)?;
    let bits = notif.wait(wait.nonblock, wait.deadline_ns)?;
    UserSliceReadWrite::new(out_ptr, size_of::<u64>())?.write_val(&bits)?;
    Ok(0)
}

/// SYS_NS_BIND (281): bind an endpoint to a namespace path (§8).
///
/// Binding has no side effect: no capability is seeded and no message is
/// queued. The entry is owned by the caller's silo.
pub fn sys_ns_bind(
    process: &Process,
    ep_h: u64,
    path_ptr: u64,
    path_len: u64,
    flags: u64,
) -> Result<u64, SyscallError> {
    let flags = flags as u32;
    if flags & !NS_BIND_REPLACE != 0 {
        return Err(SyscallError::InvalidArgument);
    }
    let path = read_ns_path(path_ptr, path_len)?;
    enforce_registry_bind_for_current_task()?;
    enforce_path_for_current_task(&path, false, false, false)?;
    let (_, ep) = endpoint_handle(process, ep_h, EP_RECV)?;
    let owner_silo = current_silo_id();
    ns_v2::bind(
        &path,
        ep,
        owner_silo,
        flags & NS_BIND_REPLACE != 0,
        caller_is_silo_admin(),
    )?;
    Ok(0)
}

/// SYS_NS_LOOKUP (282): obtain a fresh SEND handle for a bound path (§8).
///
/// The returned handle carries `EP_SEND` plus the requested generic rights it
/// is allowed to obtain; `EP_MINT` is never granted. Its badge is a fresh
/// boot-lifetime connection id.
pub fn sys_ns_lookup(
    process: &Process,
    path_ptr: u64,
    path_len: u64,
    rights: u64,
) -> Result<u64, SyscallError> {
    let path = read_ns_path(path_ptr, path_len)?;
    enforce_registry_lookup_for_current_task()?;
    enforce_path_for_current_task(&path, false, false, false)?;
    let ep = ns_v2::lookup_ep(&path).ok_or(SyscallError::NotFound)?;
    let rights = rights as u32;
    let rights =
        EP_SEND | (rights & (EP_SEND | EP_XFER | RIGHT_TRANSFER | RIGHT_DUPLICATE | RIGHT_WAIT));
    let handle = process
        .ipc_v2
        .lock()
        .insert(rights, ObjRef::Endpoint(ep), ns_v2::next_conn())
        .ok_or(SyscallError::NoSpace)?;
    Ok(handle.raw())
}

/// SYS_NS_UNBIND (283): remove a binding owned by the caller (§8).
///
/// Existing SEND handles keep working: they hold their own endpoint
/// reference.
pub fn sys_ns_unbind(
    _process: &Process,
    path_ptr: u64,
    path_len: u64,
) -> Result<u64, SyscallError> {
    let path = read_ns_path(path_ptr, path_len)?;
    ns_v2::unbind(&path, current_silo_id(), caller_is_silo_admin())?;
    Ok(0)
}

/// SYS_MEMOBJ_CREATE (284): allocate a zeroed memory object (§9.1).
///
/// `size` is rounded up to whole pages and bounded by `MEMOBJ_MAX_SIZE`;
/// `flags` must be zero. The backing is charged to the caller's silo memory
/// budget before any frame is allocated.
pub fn sys_memobj_create(process: &Process, size: u64, flags: u64) -> Result<u64, SyscallError> {
    if flags != 0 {
        return Err(SyscallError::InvalidArgument);
    }
    let size = crate::ipc::v2::memobj::page_round(size)?;
    let charge = quota::charge_memory(process, size)?;
    let obj = Arc::new(MemObject::create(size, charge)?);
    let handle = process
        .ipc_v2
        .lock()
        .insert(
            MEM_READ | MEM_WRITE | MEM_MAP | RIGHT_TRANSFER | RIGHT_DUPLICATE | RIGHT_INSPECT,
            ObjRef::Mem(obj),
            0,
        )
        .ok_or(SyscallError::NoSpace)?;
    Ok(handle.raw())
}

/// SYS_MEMOBJ_MAP (285): map a page-aligned window of a memory object.
///
/// `prot` (`MEMOBJ_PROT_*`) must be covered by the handle's `MEM_*` rights.
/// Returns the mapped address; unmapping uses `SYS_MUNMAP`.
pub fn sys_memobj_map(
    process: &Process,
    mem_h: u64,
    addr_hint: u64,
    offset: u64,
    len: u64,
    prot: u64,
) -> Result<u64, SyscallError> {
    let (rights, obj) = {
        let table = process.ipc_v2.lock();
        let entry = table.resolve(Handle::from_raw(mem_h), MEM_MAP)?;
        match &entry.obj {
            ObjRef::Mem(obj) => (entry.rights, obj.clone()),
            _ => return Err(SyscallError::BadHandle),
        }
    };
    let prot = u32::try_from(prot).map_err(|_| SyscallError::InvalidArgument)?;
    obj.map(
        &process.address_space_arc(),
        rights,
        addr_hint,
        offset,
        len,
        prot,
    )
}
