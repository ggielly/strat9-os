use crate::{
    memory::{UserSliceRead, UserSliceWrite},
    process::current_task_clone,
    syscall::error::SyscallError,
};

const POLLIN: i16 = 0x0001;
const POLLOUT: i16 = 0x0004;
const POLLNVAL: i16 = 0x0020;

const POLLFD_SIZE: usize = 8; // sizeof(pollfd) = i32 + i16 + i16

fn read_pollfd(buf: &[u8], i: usize) -> (i32, i16) {
    let off = i * POLLFD_SIZE;
    let fd = i32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
    let events = i16::from_le_bytes([buf[off + 4], buf[off + 5]]);
    (fd, events)
}

fn write_revents(buf: &mut [u8], i: usize, revents: i16) {
    let off = i * POLLFD_SIZE + 6;
    let bytes = revents.to_le_bytes();
    buf[off] = bytes[0];
    buf[off + 1] = bytes[1];
}

pub fn sys_poll(fds_ptr: u64, nfds: u64, _timeout_ms: u64) -> Result<u64, SyscallError> {
    if nfds == 0 {
        return Ok(0);
    }
    if nfds > 1024 {
        return Err(SyscallError::InvalidArgument);
    }
    let n = nfds as usize;
    let byte_len = n * POLLFD_SIZE;

    let task = current_task_clone().ok_or(SyscallError::Fault)?;
    let fd_table = unsafe { &*task.process.fd_table.get() };

    let reader = UserSliceRead::new(fds_ptr, byte_len)?;
    let mut buf = alloc::vec![0u8; byte_len];
    reader.copy_to(&mut buf);

    let mut ready_count = 0u64;
    for i in 0..n {
        let (fd, events) = read_pollfd(&buf, i);
        let revents = if fd < 0 {
            0i16
        } else {
            match fd_table.get(fd as u32) {
                Ok(_) => {
                    let mut r = 0i16;
                    if events & POLLIN != 0 { r |= POLLIN; }
                    if events & POLLOUT != 0 { r |= POLLOUT; }
                    r
                }
                Err(_) => POLLNVAL,
            }
        };
        write_revents(&mut buf, i, revents);
        if revents != 0 {
            ready_count += 1;
        }
    }

    let writer = UserSliceWrite::new(fds_ptr, byte_len)?;
    writer.copy_from(&buf);

    Ok(ready_count)
}
