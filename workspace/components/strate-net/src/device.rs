//! smoltcp device backend for strate-net.
//!
//! Two implementations:
//!
//! * [`SharedNetDevice`] — drives the kernel `NetQueue` region directly.
//!   RX/TX descriptors are read/written in mapped memory; no syscall and no
//!   copy between the kernel and the stack.
//! * [`LegacyNetDevice`] — the original `SYS_NET_RECV` / `SYS_NET_SEND`
//!   copy path, kept as a fallback when the shared region cannot be mapped.
//!
//! The `Device` trait is implemented once for the [`NetDevice`] enum so the
//! smoltcp `Interface` is monomorphised over a single type.

use core::sync::atomic::{AtomicBool, Ordering};
use core::sync::atomic::AtomicUsize;

use alloc::sync::Arc;

use smoltcp::{
    phy::{self, Device, DeviceCapabilities, Medium},
    time::Instant,
};
use strat9_abi::net::{NetFrameDesc, NetQueueHeader, NET_FRAME_SIZE};
use strate_net::syscalls::{call, net_recv, net_send, proc_yield, Error};

use crate::{log, log_errno, sleep_micros};

pub(crate) const MAX_FRAME_SIZE: usize = 1514;
const NET_SEND_RETRY_LIMIT: usize = 8;

static RX_ERR_LOG_BUDGET: AtomicUsize = AtomicUsize::new(16);
static TX_ERR_LOG_BUDGET: AtomicUsize = AtomicUsize::new(16);
static TX_SUCCESS_COUNT: AtomicUsize = AtomicUsize::new(0);
static TX_DROP_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Backend selected at startup.
pub(crate) enum NetDevice {
    Shared(SharedNetDevice),
    Legacy(LegacyNetDevice),
}

impl NetDevice {
    /// Build the shared-memory backend from `SYS_NET_QUEUE_MAP`.
    ///
    /// # Safety
    /// `header` must point to a valid `NetQueueHeader` mapped read/write.
    pub(crate) unsafe fn shared(
        dev_handle: u64,
        header: *mut NetQueueHeader,
        mac: [u8; 6],
    ) -> Self {
        NetDevice::Shared(SharedNetDevice {
            dev_handle,
            header,
            mac,
            tx_pending: Arc::new(AtomicBool::new(false)),
        })
    }

    pub(crate) fn legacy() -> Self {
        NetDevice::Legacy(LegacyNetDevice)
    }

    /// Flush pending TX descriptors to the device (one doorbell per poll).
    pub(crate) fn flush(&mut self) {
        if let NetDevice::Shared(device) = self {
            device.flush();
        }
    }

    pub(crate) fn mac(&self) -> [u8; 6] {
        match self {
            NetDevice::Shared(device) => device.mac,
            NetDevice::Legacy(_) => [0; 6],
        }
    }
}

impl Device for NetDevice {
    type RxToken<'a> = NetRxToken;
    type TxToken<'a> = NetTxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        match self {
            NetDevice::Shared(device) => device.receive_shared(),
            NetDevice::Legacy(_) => legacy_receive(),
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        match self {
            NetDevice::Shared(device) => device.transmit_shared(),
            NetDevice::Legacy(_) => Some(NetTxToken::Legacy(LegacyTxToken)),
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        // smoltcp expects the *medium* MTU here (Ethernet frame size); it
        // subtracts the 14-byte header to obtain the IP MTU (1500).
        caps.max_transmission_unit = MAX_FRAME_SIZE;
        caps.medium = Medium::Ethernet;
        caps.max_burst_size = Some(16);
        caps
    }
}

// ---------------------------------------------------------------------------
// Shared-memory backend
// ---------------------------------------------------------------------------

pub(crate) struct SharedNetDevice {
    dev_handle: u64,
    header: *mut NetQueueHeader,
    mac: [u8; 6],
    tx_pending: Arc<AtomicBool>,
}

// SAFETY: the shared header is only accessed through the ABI's single
// producer/consumer rings and atomics; `SharedNetDevice` is owned by the
// single strate-net poll thread.
unsafe impl Send for SharedNetDevice {}

impl SharedNetDevice {
    fn receive_shared(&mut self) -> Option<(NetRxToken, NetTxToken)> {
        // Allocate the TX token first: smoltcp uses it for immediate replies
        // (ACK, ICMP) and expects a writable buffer.
        let tx = self.transmit_shared()?;
        // SAFETY: `header` is a valid mapped region for the lifetime of the
        // device; the RX ring has a single consumer (this thread).
        let Some(desc) = (unsafe { (*self.header).rx_pop() }) else {
            if let NetTxToken::Shared(ref token) = tx {
                unsafe { (*self.header).free_tx_slot(token.slot) };
            }
            return None;
        };
        let Some(ptr) = self.slot_ptr(desc.slot) else {
            unsafe { (*self.header).free_rx_slot(desc.slot) };
            if let NetTxToken::Shared(ref token) = tx {
                unsafe { (*self.header).free_tx_slot(token.slot) };
            }
            return None;
        };
        let token = NetRxToken::Shared(SharedRxToken {
            header: self.header,
            slot: desc.slot,
            ptr,
            len: desc.len as usize,
        });
        Some((token, tx))
    }

    fn transmit_shared(&mut self) -> Option<NetTxToken> {
        let slot = unsafe { (*self.header).alloc_tx_slot() }?;
        let Some(ptr) = self.slot_ptr_tx(slot) else {
            unsafe { (*self.header).free_tx_slot(slot) };
            return None;
        };
        Some(NetTxToken::Shared(SharedTxToken {
            header: self.header,
            slot,
            ptr,
            pending: self.tx_pending.clone(),
        }))
    }

    fn tx_token(&self) -> NetTxToken {
        // Kept for symmetry; no caller should use an unallocated token.
        NetTxToken::Shared(SharedTxToken {
            header: self.header,
            slot: u32::MAX,
            ptr: core::ptr::null_mut(),
            pending: self.tx_pending.clone(),
        })
    }

    fn slot_ptr(&self, slot: u32) -> Option<*mut u8> {
        // SAFETY: header is valid; the ABI checks the slot range.
        Some(unsafe { (*self.header).rx_slot(slot) })
    }

    fn slot_ptr_tx(&self, slot: u32) -> Option<*mut u8> {
        // SAFETY: header is valid; the ABI checks the slot range.
        Some(unsafe { (*self.header).tx_slot(slot) })
    }

    pub(crate) fn flush(&mut self) {
        if self.tx_pending.swap(false, Ordering::AcqRel) {
            if call::net_kick(self.dev_handle as usize, 0).is_err() {
                // Keep the flag set so the next poll retries the doorbell.
                self.tx_pending.store(true, Ordering::Release);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Legacy copy backend
// ---------------------------------------------------------------------------

pub(crate) struct LegacyNetDevice;

fn legacy_receive() -> Option<(NetRxToken, NetTxToken)> {
    let mut buf = [0u8; MAX_FRAME_SIZE];
    match net_recv(&mut buf) {
        Ok(n) if n > 0 => {
            let len = core::cmp::min(n, MAX_FRAME_SIZE);
            Some((NetRxToken::Legacy(LegacyRxToken { buf, len }), NetTxToken::Legacy(LegacyTxToken)))
        }
        Err(e) => {
            if e.to_errno() != 11 && RX_ERR_LOG_BUDGET.load(Ordering::Relaxed) > 0 {
                RX_ERR_LOG_BUDGET.fetch_sub(1, Ordering::Relaxed);
                log_errno("[strate-net] net_recv errno=", e);
            }
            None
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

pub(crate) enum NetRxToken {
    Shared(SharedRxToken),
    Legacy(LegacyRxToken),
}

impl phy::RxToken for NetRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        match self {
            NetRxToken::Shared(token) => token.consume(f),
            NetRxToken::Legacy(token) => token.consume(f),
        }
    }
}

pub(crate) enum NetTxToken {
    Shared(SharedTxToken),
    Legacy(LegacyTxToken),
}

impl phy::TxToken for NetTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        match self {
            NetTxToken::Shared(token) => token.consume(len, f),
            NetTxToken::Legacy(token) => token.consume(len, f),
        }
    }
}

pub(crate) struct SharedRxToken {
    header: *mut NetQueueHeader,
    slot: u32,
    ptr: *mut u8,
    len: usize,
}

impl SharedRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        // SAFETY: the descriptor was popped from the RX ring and the slot is
        // owned by this consumer until `free_rx_slot`.
        let out = unsafe { f(core::slice::from_raw_parts(self.ptr, self.len)) };
        unsafe { (*self.header).free_rx_slot(self.slot) };
        out
    }
}

pub(crate) struct SharedTxToken {
    header: *mut NetQueueHeader,
    slot: u32,
    ptr: *mut u8,
    pending: Arc<AtomicBool>,
}

impl SharedTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        if self.slot == u32::MAX || len > NET_FRAME_SIZE {
            return f(&mut []);
        }
        // SAFETY: the slot was allocated for this token; the closure writes
        // at most `len` bytes into a `NET_FRAME_SIZE` slot.
        let out = unsafe { f(core::slice::from_raw_parts_mut(self.ptr, len)) };
        let desc = NetFrameDesc {
            slot: self.slot,
            len: len as u16,
            flags: strat9_abi::net::fd_flags::SOP
                | strat9_abi::net::fd_flags::EOP
                | strat9_abi::net::fd_flags::NEED_COMP,
            vlan: 0,
            rss: 0,
        };
        // SAFETY: single TX producer (this thread).
        if unsafe { (*self.header).tx_push(desc) } {
            self.pending.store(true, Ordering::Release);
        } else {
            unsafe { (*self.header).free_tx_slot(self.slot) };
            TX_DROP_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        out
    }
}

pub(crate) struct LegacyRxToken {
    buf: [u8; MAX_FRAME_SIZE],
    len: usize,
}

impl phy::RxToken for LegacyRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buf[..self.len])
    }
}

pub(crate) struct LegacyTxToken;

impl phy::TxToken for LegacyTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        if len > MAX_FRAME_SIZE {
            log("[strate-net] TX frame too large\n");
            return f(&mut []);
        }

        let mut buf = [0u8; MAX_FRAME_SIZE];
        let ret = f(&mut buf[..len]);
        let mut last_err = None;
        for attempt in 0..NET_SEND_RETRY_LIMIT {
            match net_send(&buf[..len]) {
                Ok(_) => {
                    TX_SUCCESS_COUNT.fetch_add(1, Ordering::Relaxed);
                    last_err = None;
                    break;
                }
                Err(e @ (Error::Again | Error::QueueFull)) => {
                    last_err = Some(e);
                    let _ = proc_yield();
                }
                Err(e @ Error::IoError) if attempt + 1 < NET_SEND_RETRY_LIMIT => {
                    last_err = Some(e);
                    sleep_micros(50);
                }
                Err(e) => {
                    last_err = Some(e);
                    break;
                }
            }
        }

        if let Some(e) = last_err {
            TX_DROP_COUNT.fetch_add(1, Ordering::Relaxed);
            if TX_ERR_LOG_BUDGET.load(Ordering::Relaxed) > 0 {
                TX_ERR_LOG_BUDGET.fetch_sub(1, Ordering::Relaxed);
                log_errno("[strate-net] net_send errno=", e);
            }
        }

        ret
    }
}
