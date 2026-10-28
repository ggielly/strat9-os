//! Minimal software L2 switch: ports, FDB, IOChain and shaping.
//!
//! ESXi funnels every packet through `Port_Input`, applies an `IOChain`, then
//! lets the portset class (the vSwitch) decide the egress port.  Strat9 does
//! not have a vSwitch yet; this module provides the same primitives so a
//! future guest-NIC model or a container bridge can share one implementation.
//!
//! It is deliberately independent from the NIC drivers: a `PortSink` is just
//! a callback that accepts an Ethernet frame.  The host stack
//! (`strate-net`) and a guest vNIC can both be sinks.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::SpinLock;

/// Local port identifier (16 bits portset + 16 bits port, like ESXi).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortId(pub u32);

impl PortId {
    pub const fn new(portset: u16, port: u16) -> Self {
        Self(((portset as u32) << 16) | port as u32)
    }

    pub const fn portset(self) -> u16 {
        (self.0 >> 16) as u16
    }

    pub const fn port(self) -> u16 {
        self.0 as u16
    }
}

/// A port's egress callback.
pub trait PortSink: Send + Sync {
    fn input(&self, frame: &[u8]);
}

/// A port attached to a `PortSet`.
pub struct Port {
    pub id: PortId,
    pub mac: [u8; 6],
    pub vlan: u16,
    pub sink: Arc<dyn PortSink>,
    pub stats: PortStats,
}

#[derive(Debug, Default)]
pub struct PortStats {
    pub rx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub drops: AtomicU64,
}

/// Result of a filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    Accept,
    Drop,
    /// Stop the chain and deliver to this local port (mirror/redirect).
    Redirect(PortId),
}

/// One filter in an `IOChain`.
pub trait Filter: Send + Sync {
    fn filter(&self, src: PortId, frame: &[u8]) -> FilterAction;
}

/// Ordered filter chain, like ESXi's `IOChain`.
#[derive(Default)]
pub struct IoChain {
    filters: Vec<Arc<dyn Filter>>,
}

impl IoChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, filter: Arc<dyn Filter>) {
        self.filters.push(filter);
    }

    pub fn run(&self, src: PortId, frame: &[u8]) -> FilterAction {
        for filter in &self.filters {
            match filter.filter(src, frame) {
                FilterAction::Accept => continue,
                other => return other,
            }
        }
        FilterAction::Accept
    }

    pub fn len(&self) -> usize {
        self.filters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }
}

/// Token bucket used by the shaper.
#[derive(Debug, Clone, Copy)]
pub struct TokenBucket {
    pub rate_bps: u64,
    pub burst_bytes: u64,
    tokens: u64,
    last_ns: u64,
}

impl TokenBucket {
    pub const fn new(rate_bps: u64, burst_bytes: u64) -> Self {
        Self {
            rate_bps,
            burst_bytes,
            tokens: burst_bytes,
            last_ns: 0,
        }
    }

    /// Refill and test whether `len` bytes may pass at `now_ns`.
    pub fn allow(&mut self, len: u64, now_ns: u64) -> bool {
        if self.rate_bps == 0 {
            return true;
        }
        if now_ns > self.last_ns {
            let elapsed = now_ns - self.last_ns;
            let added = (self.rate_bps as u128 * elapsed as u128 / 8_000_000_000u128) as u64;
            self.tokens = self.tokens.saturating_add(added).min(self.burst_bytes);
            self.last_ns = now_ns;
        }
        if self.tokens >= len {
            self.tokens -= len;
            true
        } else {
            false
        }
    }
}

/// A portset = one virtual switch.
pub struct PortSet {
    pub id: u16,
    pub ports: SpinLock<Vec<Option<Port>>>,
    /// Destination MAC → port.  Learned on ingress.
    pub fdb: SpinLock<BTreeMap<[u8; 6], PortId>>,
    pub chain: SpinLock<IoChain>,
    pub shaper: SpinLock<TokenBucket>,
}

impl PortSet {
    pub fn new(id: u16) -> Self {
        Self {
            id,
            ports: SpinLock::new(Vec::new()),
            fdb: SpinLock::new(BTreeMap::new()),
            chain: SpinLock::new(IoChain::new()),
            shaper: SpinLock::new(TokenBucket::new(0, 64 * 1024)),
        }
    }

    /// Attach a port.  Returns its `PortId`.
    pub fn add_port(&self, mac: [u8; 6], vlan: u16, sink: Arc<dyn PortSink>) -> PortId {
        let mut ports = self.ports.lock();
        let index = ports.len() as u16;
        let id = PortId::new(self.id, index);
        ports.push(Some(Port {
            id,
            mac,
            vlan,
            sink,
            stats: PortStats::default(),
        }));
        id
    }

    pub fn remove_port(&self, id: PortId) {
        let mut ports = self.ports.lock();
        if let Some(slot) = ports.get_mut(id.port() as usize) {
            *slot = None;
        }
        self.fdb
            .lock()
            .retain(|_, port| *port != id);
    }

    fn port_sink(&self, id: PortId) -> Option<Arc<dyn PortSink>> {
        self.ports
            .lock()
            .get(id.port() as usize)
            .and_then(|slot| slot.as_ref())
            .filter(|port| port.id == id)
            .map(|port| port.sink.clone())
    }

    /// Ingress a frame from `src`.
    ///
    /// Learning + VLAN check + IOChain + FDB lookup + flood.  This is the
    /// analogue of `Port_Input` + `devImpl.input` in ESXi.
    pub fn input(&self, src: PortId, frame: &[u8], now_ns: u64) -> bool {
        if frame.len() < 14 {
            return false;
        }
        let src_mac = [frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]];
        let dst_mac = [frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]];

        // Shaping before the switch, like NetSched.
        if !self.shaper.lock().allow(frame.len() as u64, now_ns) {
            if let Some(port) = self
                .ports
                .lock()
                .get(src.port() as usize)
                .and_then(|slot| slot.as_ref())
            {
                port.stats.drops.fetch_add(1, Ordering::Relaxed);
            }
            return false;
        }

        // VLAN isolation (0 = untagged/trunk, otherwise exact match).
        let ingress_vlan = self
            .ports
            .lock()
            .get(src.port() as usize)
            .and_then(|slot| slot.as_ref())
            .map(|port| port.vlan)
            .unwrap_or(0);

        match self.chain.lock().run(src, frame) {
            FilterAction::Drop => return false,
            FilterAction::Redirect(port) => {
                if let Some(sink) = self.port_sink(port) {
                    sink.input(frame);
                }
                return true;
            }
            FilterAction::Accept => {}
        }

        self.fdb.lock().insert(src_mac, src);

        let egress = self.fdb.lock().get(&dst_mac).copied();
        let broadcast = frame[0] & 1 != 0;
        let mut delivered = false;

        // Collect the sinks under the lock, then deliver without holding it:
        // a sink may re-enter the switch (loopback port, mirror, …).
        let targets: Vec<(PortId, Arc<dyn PortSink>)> = {
            let ports = self.ports.lock();
            let mut targets = Vec::new();
            match egress {
                Some(port) if port != src && !broadcast => {
                    if let Some(target) = ports
                        .get(port.port() as usize)
                        .and_then(|slot| slot.as_ref())
                        .filter(|p| p.vlan == 0 || p.vlan == ingress_vlan)
                    {
                        targets.push((target.id, target.sink.clone()));
                    }
                }
                _ => {
                    for slot in ports.iter().flatten() {
                        if slot.id == src {
                            continue;
                        }
                        if slot.vlan != 0 && slot.vlan != ingress_vlan {
                            continue;
                        }
                        targets.push((slot.id, slot.sink.clone()));
                    }
                }
            }
            if let Some(port) = ports.get(src.port() as usize).and_then(|slot| slot.as_ref()) {
                port.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                port.stats
                    .rx_bytes
                    .fetch_add(frame.len() as u64, Ordering::Relaxed);
            }
            targets
        };

        for (id, sink) in targets {
            sink.input(frame);
            delivered = true;
            let ports = self.ports.lock();
            if let Some(target) = ports.get(id.port() as usize).and_then(|slot| slot.as_ref()) {
                target.stats.tx_packets.fetch_add(1, Ordering::Relaxed);
                target
                    .stats
                    .tx_bytes
                    .fetch_add(frame.len() as u64, Ordering::Relaxed);
            }
        }
        delivered
    }
}
