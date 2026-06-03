use core::sync::atomic::{AtomicUsize, Ordering};

use smoltcp::{
    phy::{self, Device, DeviceCapabilities, Medium},
    time::Instant,
};
use strate_net::syscalls::{net_recv, net_send, proc_yield, Error};

use crate::{log, log_errno, sleep_micros};

pub(crate) const MAX_FRAME_SIZE: usize = 1514;

static RX_ERR_LOG_BUDGET: AtomicUsize = AtomicUsize::new(64);
static TX_ERR_LOG_BUDGET: AtomicUsize = AtomicUsize::new(64);
static TX_SUCCESS_COUNT: AtomicUsize = AtomicUsize::new(0);
static TX_DROP_COUNT: AtomicUsize = AtomicUsize::new(0);

const NET_SEND_RETRY_LIMIT: usize = 8;

pub(crate) struct Strat9NetDevice;

impl Device for Strat9NetDevice {
    type RxToken<'a> = Strat9RxToken;
    type TxToken<'a> = Strat9TxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut buf = [0u8; MAX_FRAME_SIZE];
        match net_recv(&mut buf) {
            Ok(n) if n > 0 => {
                let len = core::cmp::min(n, MAX_FRAME_SIZE);
                Some((Strat9RxToken { buf, len }, Strat9TxToken))
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

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(Strat9TxToken)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = MAX_FRAME_SIZE;
        caps.medium = Medium::Ethernet;
        caps.max_burst_size = Some(8);
        caps
    }
}

pub(crate) struct Strat9RxToken {
    buf: [u8; MAX_FRAME_SIZE],
    len: usize,
}

impl phy::RxToken for Strat9RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buf[..self.len])
    }
}

pub(crate) struct Strat9TxToken;

impl phy::TxToken for Strat9TxToken {
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
