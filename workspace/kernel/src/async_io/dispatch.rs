//! SQE dispatch : routes submitted SQEs to the appropriate backend.
//!
//! Called from `SYS_ASYNC_ENTER` when `to_submit > 0`.  Walks the
//! submission queue and dispatches each SQE by opcode.

use core::sync::atomic::Ordering;

use crate::ipc::message::IpcMessage;

use super::{
    complete::{inc_in_flight, push_completion},
    ops::AsyncOp,
    ring::find_ring,
};

// Errno constants (no libc dependency)
const EBADF: i32 = -9;
const EINVAL: i32 = -22;
const EIO: i32 = -5;
const ENOMSG: i32 = -42;

/// Process up to `count` pending SQEs from the given ring.
///
/// Returns the number of SQEs successfully processed.
pub fn drain_submissions(ring_id: u64, count: u32) -> u32 {
    let Some(ring_ptr) = find_ring(ring_id) else {
        return 0;
    };
    let ring = unsafe { &*ring_ptr };

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
        if let Err(e) = dispatch_one(sqe, ring_id) {
            push_completion(ring_id, sqe.user_data, e, 0);
        } else {
            inc_in_flight(ring_id);
        }
    }

    ring.sq_advance_head(available);
    available
}

/// Dispatch a single SQE by opcode.
fn dispatch_one(sqe: &super::ops::AsyncSqe, ring_id: u64) -> Result<(), i32> {
    match sqe.opcode {
        // Nop : immediate success
        op if op == AsyncOp::Nop as u8 => {
            push_completion(ring_id, sqe.user_data, 0, 0);
            Ok(())
        }

        // VFS reads : resolve fd, call scheme::read, push completion
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
            let _ = fd_table;
            let _ = task;

            let mut buf = unsafe { core::slice::from_raw_parts_mut(buf_vaddr as *mut u8, len) };

            let n = match scheme_ref.read(file_id, sqe.off, &mut buf) {
                Ok(n) => n as i32,
                Err(_) => EIO,
            };
            push_completion(ring_id, sqe.user_data, n, 0);
            Ok(())
        }

        // VFS writes : resolve fd, call scheme::write, push completion
        op if op == AsyncOp::Write as u8 => {
            let fd = sqe.fd as u32;
            let buf_vaddr = sqe.addr;
            let len = sqe.len as usize;

            let task = crate::process::current_task_clone().ok_or(EIO)?;
            let fd_table = unsafe { &*task.process.fd_table.get() };
            let file = fd_table.get(fd).map_err(|_| EBADF)?;
            let file_id = file.file_id();
            let scheme_ref: &dyn crate::vfs::scheme::Scheme = &**file.scheme();
            let _ = fd_table;
            let _ = task;

            let buf = unsafe { core::slice::from_raw_parts(buf_vaddr as *const u8, len) };

            let n = match scheme_ref.write(file_id, sqe.off, buf) {
                Ok(n) => n as i32,
                Err(_) => EIO,
            };
            push_completion(ring_id, sqe.user_data, n, 0);
            Ok(())
        }

        // IPC send : try_send message to port, push CQE with result
        op if op == AsyncOp::IpcSend as u8 => {
            let port_id = crate::ipc::PortId::from_u64(sqe.fd as u64);
            let Some(port) = crate::ipc::port::get_port(port_id) else {
                push_completion(ring_id, sqe.user_data, EBADF, 0);
                return Ok(());
            };
            let msg = unsafe { core::ptr::read_unaligned(sqe.addr as *const IpcMessage) };
            let res_code = match port.try_send(msg) {
                Ok(()) => 0,
                Err(_) => ENOMSG,
            };
            push_completion(ring_id, sqe.user_data, res_code, 0);
            Ok(())
        }

        // IPC recv : try_recv message from port, copy to buffer, push CQE
        op if op == AsyncOp::IpcRecv as u8 => {
            let port_id = crate::ipc::PortId::from_u64(sqe.fd as u64);
            let Some(port) = crate::ipc::port::get_port(port_id) else {
                push_completion(ring_id, sqe.user_data, EBADF, 0);
                return Ok(());
            };
            match port.try_recv() {
                Ok(Some(msg)) => {
                    unsafe {
                        core::ptr::write_unaligned(sqe.addr as *mut IpcMessage, msg);
                    }
                    push_completion(ring_id, sqe.user_data, 64, 0);
                    Ok(())
                }
                Ok(None) => {
                    push_completion(ring_id, sqe.user_data, ENOMSG, 0);
                    Ok(())
                }
                Err(_) => {
                    push_completion(ring_id, sqe.user_data, EBADF, 0);
                    Ok(())
                }
            }
        }

        // Storage read : submit async AHCI/NVMe read, CQE arrives via IRQ
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
                Ok(()) => Ok(()), // in-flight; CQE comes from IRQ handler
                Err(_) => {
                    push_completion(ring_id, sqe.user_data, EIO, 0);
                    Ok(())
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
                Ok(()) => Ok(()), // in-flight; CQE comes from IRQ handler
                Err(_) => {
                    push_completion(ring_id, sqe.user_data, EIO, 0);
                    Ok(())
                }
            }
        }

        // Unknown opcode
        _ => Err(EINVAL),
    }
}
