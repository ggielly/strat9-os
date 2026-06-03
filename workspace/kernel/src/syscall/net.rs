//! Network syscall handlers.
//!
//! Implements the userspace networking interface: send, recv, and info.

use super::error::SyscallError;
use crate::memory::{UserSliceRead, UserSliceWrite};
use core::sync::atomic::{AtomicU32, Ordering};
use smallvec::SmallVec;

/// Most Ethernet frames, including ICMP echo, fit comfortably under 2 KiB.
/// Keep those on the stack to avoid hot-path heap churn in net send/recv syscalls.
const NET_INLINE_BUF_CAPACITY: usize = 2048;

/// Budget for logging network send errors to prevent log spam.
static NET_SEND_ERR_LOG_BUDGET: AtomicU32 = AtomicU32::new(32);
/// Budget for logging network receive errors to prevent log spam.
static NET_RECV_ERR_LOG_BUDGET: AtomicU32 = AtomicU32::new(32);
/// Budget for logging DHCP trace frames to prevent log spam.
static DHCP_TRACE_LOG_BUDGET: AtomicU32 = AtomicU32::new(64);

/// Parse and log a raw Ethernet frame if it looks like DHCP.
///
/// Only fires while the budget allows (64 frames), then goes silent.
fn trace_dhcp_frame(tag: &str, frame: &[u8]) {
    if DHCP_TRACE_LOG_BUDGET.fetch_sub(1, Ordering::Relaxed) == 0 {
        return;
    }
    if frame.len() < 14 {
        return;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 {
        return;
    }
    if frame.len() < 34 {
        return;
    }
    let ip_hlen = ((frame[14] & 0x0f) as usize) * 4;
    if ip_hlen < 20 || frame.len() < 14 + ip_hlen + 8 {
        return;
    }
    if frame[23] != 17 {
        return;
    }
    let udp = 14 + ip_hlen;
    let src_port = u16::from_be_bytes([frame[udp], frame[udp + 1]]);
    let dst_port = u16::from_be_bytes([frame[udp + 2], frame[udp + 3]]);
    let is_dhcp = (src_port == 68 && dst_port == 67) || (src_port == 67 && dst_port == 68);
    if !is_dhcp {
        return;
    }
    let mut xid: u32 = 0;
    let bootp = udp + 8;
    if frame.len() >= bootp + 8 {
        xid = u32::from_be_bytes([
            frame[bootp + 4],
            frame[bootp + 5],
            frame[bootp + 6],
            frame[bootp + 7],
        ]);
    }
    crate::serial_println!(
        "[dhcp-trace] {} src_port={} dst_port={} len={} xid=0x{:08x}",
        tag,
        src_port,
        dst_port,
        frame.len(),
        xid
    );
}

/// SYS_NET_RECV : Receive a raw Ethernet frame.
pub fn sys_net_recv(buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    let device = crate::hardware::nic::get_default_device().ok_or(SyscallError::Again)?;
    let buf_len = buf_len as usize;
    let mut kbuf = SmallVec::<[u8; NET_INLINE_BUF_CAPACITY]>::new();
    kbuf.resize(buf_len, 0u8);

    let n = match device.receive(&mut kbuf) {
        Ok(n) => n,
        Err(e) => {
            let se = SyscallError::from(e);
            if se != SyscallError::Again
                && NET_RECV_ERR_LOG_BUDGET.fetch_sub(1, Ordering::Relaxed) > 0
            {
                crate::serial_println!("[net-sys] recv error: {:?} -> {}", e, se.name());
            }
            return Err(se);
        }
    };
    trace_dhcp_frame("rx", &kbuf[..n]);

    let user = UserSliceWrite::new(buf_ptr, n)?;
    user.copy_from(&kbuf[..n]);
    Ok(n as u64)
}

/// SYS_NET_SEND : Transmit a raw Ethernet frame.
pub fn sys_net_send(buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    let device = crate::hardware::nic::get_default_device().ok_or(SyscallError::Again)?;
    let buf_len = buf_len as usize;
    let user = UserSliceRead::new(buf_ptr, buf_len)?;
    let mut kbuf = SmallVec::<[u8; NET_INLINE_BUF_CAPACITY]>::new();
    kbuf.resize(buf_len, 0u8);
    let copied = user.copy_to(&mut kbuf);
    if copied != buf_len {
        return Err(SyscallError::Fault);
    }
    trace_dhcp_frame("tx", &kbuf);

    if let Err(e) = device.transmit(&kbuf) {
        let se = SyscallError::from(e);
        if NET_SEND_ERR_LOG_BUDGET.fetch_sub(1, Ordering::Relaxed) > 0 {
            crate::serial_println!("[net-sys] send error: {:?} -> {}", e, se.name());
        }
        return Err(se);
    }

    Ok(buf_len as u64)
}

/// SYS_NET_INFO : Query network interface information.
///
/// `info_type` 0 returns the MAC address (6 bytes) into `buf_ptr`.
pub fn sys_net_info(info_type: u64, buf_ptr: u64) -> Result<u64, SyscallError> {
    let device = crate::hardware::nic::get_default_device().ok_or(SyscallError::Again)?;

    match info_type {
        0 => {
            let mac = device.mac_address();
            let user = UserSliceWrite::new(buf_ptr, 6)?;
            user.copy_from(&mac);
            Ok(6)
        }
        _ => Err(SyscallError::InvalidArgument),
    }
}
