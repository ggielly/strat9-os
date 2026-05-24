//! SQE dispatch : routes submitted SQEs to the appropriate backend.
//!
//! Called from `SYS_ASYNC_ENTER` when `to_submit > 0`.  Walks the
//! submission queue and dispatches each SQE by opcode.

use crate::{
    ipc::message::{ipc_message_from_raw, ipc_message_to_raw, IpcMessage},
    memory::{UserSliceRead, UserSliceWrite},
    vfs::scheme::AsyncSubmitResult,
};

use super::{
    complete::{inc_in_flight_for_ring, push_completion_for_ring},
    ops::AsyncOp,
    ring::find_ring,
};

enum DispatchOutcome {
    CompletedInline,
    InFlight,
}

// Errno constants (no libc dependency)
const EBADF: i32 = -9;
const EFAULT: i32 = -14;
const EINVAL: i32 = -22;
const EIO: i32 = -5;
const ENOMSG: i32 = -42;

/// Process up to `count` pending SQEs from the given ring.
///
/// Returns the number of SQEs successfully processed.
pub fn drain_submissions(ring_id: u64, count: u32) -> u32 {
    let Some(ring) = find_ring(ring_id) else {
        return 0;
    };

    let head = ring.sq_head();
    let tail = ring.sq_tail();
    let mask = ring
        .sq_meta()
        .mask
        .load(core::sync::atomic::Ordering::Relaxed);
    let available = tail.wrapping_sub(head).min(count);
    if available == 0 {
        return 0;
    }

    for i in 0..available {
        let idx = (head.wrapping_add(i)) & mask;
        let sqe = unsafe { &*ring.sqe_at(idx) };
        match dispatch_one(sqe, &ring) {
            Err(e) => {
                push_completion_for_ring(&ring, sqe.user_data, e, 0);
            }
            Ok(DispatchOutcome::CompletedInline) => {}
            Ok(DispatchOutcome::InFlight) => {
                inc_in_flight_for_ring(&ring);
            }
        }
    }

    ring.sq_advance_head(available);
    available
}

/// Dispatch a single SQE by opcode.
fn dispatch_one(
    sqe: &super::ops::AsyncSqe,
    ring: &super::ring::Ring,
) -> Result<DispatchOutcome, i32> {
    let ring_id = ring.id;
    match sqe.opcode {
        // Nop : immediate success
        op if op == AsyncOp::Nop as u8 => {
            push_completion_for_ring(ring, sqe.user_data, 0, 0);
            Ok(DispatchOutcome::CompletedInline)
        }

        // VFS reads : resolve fd and submit through AsyncScheme.
        op if op == AsyncOp::Read as u8 => {
            let fd = sqe.fd as u32;
            let buf_vaddr = sqe.addr;
            let len = sqe.len as usize;

            // Resolve fd => (scheme, file_id)  (VFS pattern)
            let task = crate::process::current_task_clone().ok_or(EIO)?;
            let fd_table = unsafe { &*task.process.fd_table.get() };
            let file = fd_table.get(fd).map_err(|_| EBADF)?;
            let file_id = file.file_id();
            let scheme_ref: &dyn crate::vfs::scheme::Scheme = &**file.scheme();

            match scheme_ref.async_read(file_id, sqe.off, buf_vaddr, len, ring_id, sqe.user_data) {
                Ok(AsyncSubmitResult::Completed(n)) => {
                    push_completion_for_ring(ring, sqe.user_data, n, 0);
                    Ok(DispatchOutcome::CompletedInline)
                }
                Ok(AsyncSubmitResult::InFlight) => Ok(DispatchOutcome::InFlight),
                Err(err) => Err(err as i32),
            }
        }

        // VFS writes : resolve fd and submit through AsyncScheme.
        op if op == AsyncOp::Write as u8 => {
            let fd = sqe.fd as u32;
            let buf_vaddr = sqe.addr;
            let len = sqe.len as usize;

            let task = crate::process::current_task_clone().ok_or(EIO)?;
            let fd_table = unsafe { &*task.process.fd_table.get() };
            let file = fd_table.get(fd).map_err(|_| EBADF)?;
            let file_id = file.file_id();
            let scheme_ref: &dyn crate::vfs::scheme::Scheme = &**file.scheme();

            match scheme_ref.async_write(file_id, sqe.off, buf_vaddr, len, ring_id, sqe.user_data) {
                Ok(AsyncSubmitResult::Completed(n)) => {
                    push_completion_for_ring(ring, sqe.user_data, n, 0);
                    Ok(DispatchOutcome::CompletedInline)
                }
                Ok(AsyncSubmitResult::InFlight) => Ok(DispatchOutcome::InFlight),
                Err(err) => Err(err as i32),
            }
        }

        // IPC send : try_send message to port, push CQE with result
        op if op == AsyncOp::IpcSend as u8 => {
            let port_id = crate::ipc::PortId::from_u64(sqe.fd as u64);
            let Some(port) = crate::ipc::port::get_port(port_id) else {
                push_completion_for_ring(ring, sqe.user_data, EBADF, 0);
                return Ok(DispatchOutcome::CompletedInline);
            };
            let user_msg = UserSliceRead::new(sqe.addr, core::mem::size_of::<IpcMessage>())
                .map_err(|_| EFAULT)?;
            let mut raw = [0u8; 64];
            user_msg.copy_to(&mut raw);
            let msg = ipc_message_from_raw(&raw);
            let res_code = match port.try_send(msg) {
                Ok(()) => 0,
                Err(_) => ENOMSG,
            };
            push_completion_for_ring(ring, sqe.user_data, res_code, 0);
            Ok(DispatchOutcome::CompletedInline)
        }

        // IPC recv : try_recv message from port, copy to buffer, push CQE
        op if op == AsyncOp::IpcRecv as u8 => {
            let port_id = crate::ipc::PortId::from_u64(sqe.fd as u64);
            let Some(port) = crate::ipc::port::get_port(port_id) else {
                push_completion_for_ring(ring, sqe.user_data, EBADF, 0);
                return Ok(DispatchOutcome::CompletedInline);
            };
            match port.try_recv() {
                Ok(Some(msg)) => {
                    let user_msg =
                        UserSliceWrite::new(sqe.addr, core::mem::size_of::<IpcMessage>())
                            .map_err(|_| EFAULT)?;
                    let mut raw = [0u8; 64];
                    ipc_message_to_raw(&msg, &mut raw);
                    user_msg.copy_from(&raw);
                    push_completion_for_ring(ring, sqe.user_data, 64, 0);
                    Ok(DispatchOutcome::CompletedInline)
                }
                Ok(None) => {
                    push_completion_for_ring(ring, sqe.user_data, ENOMSG, 0);
                    Ok(DispatchOutcome::CompletedInline)
                }
                Err(_) => {
                    push_completion_for_ring(ring, sqe.user_data, EBADF, 0);
                    Ok(DispatchOutcome::CompletedInline)
                }
            }
        }

        // IPC call : send message + register async reply via ring CQE.
        //
        //   sqe.fd        = port handle (cap id)
        //   sqe.addr      = pointer to IpcMessage (request in, reply overwrites)
        //   sqe.user_data = correlation token (echoed in CQE on reply)
        //
        op if op == AsyncOp::IpcCall as u8 => {
            let port_id = crate::ipc::PortId::from_u64(sqe.fd as u64);
            let Some(port) = crate::ipc::port::get_port(port_id) else {
                push_completion_for_ring(ring, sqe.user_data, EBADF, 0);
                return Ok(DispatchOutcome::CompletedInline);
            };

            // Read the outgoing message from userspace.
            let user_msg = UserSliceRead::new(sqe.addr, core::mem::size_of::<IpcMessage>())
                .map_err(|_| EFAULT)?;
            let mut raw = [0u8; 64];
            user_msg.copy_to(&mut raw);
            let mut msg = ipc_message_from_raw(&raw);

            let task = crate::process::current_task_clone().ok_or(EIO)?;
            msg.sender = task.id.as_u64();

            port.try_send(msg).map_err(|_| ENOMSG)?;

            crate::ipc::reply::register_ring_call(
                task.id,
                port.owner,
                ring_id,
                sqe.user_data,
                sqe.addr,
            );

            Ok(DispatchOutcome::InFlight)
        }

        // Storage read : submit async AHCI/NVMe read, CQE arrives via the IRQ
        op if op == AsyncOp::StorageRead as u8 => {
            let port_idx = sqe.fd as u8;
            let lba = sqe.off;
            let byte_count = sqe.len;
            let user_buf_vaddr = sqe.addr;

            match crate::hardware::storage::ahci::submit_async_storage_op(
                port_idx,
                lba,
                byte_count,
                user_buf_vaddr,
                false, // read
                ring_id,
                sqe.user_data,
            ) {
                Ok(()) => Ok(DispatchOutcome::InFlight), // in-flight; CQE comes from IRQ handler
                Err(_) => {
                    push_completion_for_ring(ring, sqe.user_data, EIO, 0);
                    Ok(DispatchOutcome::CompletedInline)
                }
            }
        }

        // Storage write : submit async AHCI/NVMe write, CQE arrives via IRQ
        op if op == AsyncOp::StorageWrite as u8 => {
            let port_idx = sqe.fd as u8;
            let lba = sqe.off;
            let byte_count = sqe.len;
            let user_buf_vaddr = sqe.addr;

            match crate::hardware::storage::ahci::submit_async_storage_op(
                port_idx,
                lba,
                byte_count,
                user_buf_vaddr,
                true, // write
                ring_id,
                sqe.user_data,
            ) {
                Ok(()) => Ok(DispatchOutcome::InFlight), // in-flight; CQE comes from IRQ handler
                Err(_) => {
                    push_completion_for_ring(ring, sqe.user_data, EIO, 0);
                    Ok(DispatchOutcome::CompletedInline)
                }
            }
        }

        // Unknown opcode
        _ => Err(EINVAL),
    }
}
