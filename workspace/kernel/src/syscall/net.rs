//! Network syscall handlers.
//!
//! Two data planes coexist:
//!
//! * **legacy copy path** — `SYS_NET_SEND` / `SYS_NET_RECV` copy one frame
//!   through a 2 KiB stack buffer.  Kept for compatibility and for bring-up;
//! * **shared queue path** — `SYS_NET_QUEUE_MAP` maps the `NetQueue` region
//!   into the networking strate, which then drives the descriptor rings
//!   directly (`SYS_NET_KICK` / `SYS_NET_EVENT_WAIT`).
//!
//! Every entry point is capability-gated: the caller must hold a `Nic`
//! capability obtained with `SYS_NET_OPEN`.  Raw packet access is therefore
//! no longer ambient authority.

use super::error::SyscallError;
use crate::{
    capability::{get_capability_manager, CapId, CapPermissions, ResourceType},
    hardware::nic::{self, hotplug, net_queue::NetQueue},
    memory::{
        address_space::{VmaFlags, VmaPageSize, VmaType},
        UserSliceRead, UserSliceWrite,
    },
    process::current_task_clone,
    silo::{self, StrateFamily},
};
use core::sync::atomic::Ordering;
use strat9_abi::net::{
    event, features, link_flags, NetEvent, NetFrame, NetFrameDesc, NetLinkInfo, NetQueueInfo,
    NetQueueMap, NetStats, NET_FRAME_SIZE, NET_POOL_SLOTS, NET_RING_SLOTS,
};

/// Maximum frame accepted on the legacy path (Ethernet frame + VLAN).
const MAX_FRAME: usize = NET_FRAME_SIZE;
/// Minimum Ethernet frame (two MAC addresses + EtherType).
const MIN_FRAME: usize = 14;
/// Maximum number of frames in one batch syscall.
const MAX_BATCH: usize = 32;

// ---------------------------------------------------------------------------
// Capability helpers
// ---------------------------------------------------------------------------

fn nic_capability(handle: u64, required: CapPermissions) -> Result<usize, SyscallError> {
    silo::enforce_cap_for_current_task(handle)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: the capability table is owned by the current process and the
    // syscall runs with exclusive access to its own task.
    let caps = unsafe { &*task.process.capabilities.get() };
    let cap = caps
        .get_with_permissions(CapId::from_raw(handle), required)
        .ok_or(SyscallError::PermissionDenied)?;
    if cap.resource_type != ResourceType::Nic {
        return Err(SyscallError::BadHandle);
    }
    Ok(cap.resource)
}

/// Resolve the default NIC through the caller's `Nic` capability.
fn default_nic(required: CapPermissions) -> Result<alloc::sync::Arc<dyn nic::NetworkDevice>, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: same argument as above.
    let caps = unsafe { &*task.process.capabilities.get() };
    let cap = caps
        .find_by_type_with_permissions(ResourceType::Nic, required)
        .ok_or(SyscallError::PermissionDenied)?;
    nic::get_device_by_resource(cap.resource).ok_or(SyscallError::NotFound)
}

fn nic_from_handle(
    handle: u64,
    required: CapPermissions,
) -> Result<alloc::sync::Arc<dyn nic::NetworkDevice>, SyscallError> {
    let resource = nic_capability(handle, required)?;
    nic::get_device_by_resource(resource).ok_or(SyscallError::NotFound)
}

fn queue_from_handle(handle: u64, qid: u16) -> Result<alloc::sync::Arc<NetQueue>, SyscallError> {
    let _ = nic_capability(
        handle,
        CapPermissions {
            read: true,
            write: true,
            execute: false,
            grant: false,
            revoke: false,
        },
    )?;
    let guard = nic::data_plane().lock();
    guard
        .as_ref()
        .and_then(|dp| dp.clone_queue(qid as usize))
        .ok_or(SyscallError::BadHandle)
}

// ---------------------------------------------------------------------------
// Open / register / info
// ---------------------------------------------------------------------------

/// `SYS_NET_OPEN`: obtain a `Nic` capability for the default device.
///
/// Only `NET`, `DRV` and `SYS` silos may open the raw device.  The returned
/// handle is inserted into the caller's capability table; subsequent legacy
/// calls resolve it automatically.
pub fn sys_net_open() -> Result<u64, SyscallError> {
    let family = silo::current_task_family().ok_or(SyscallError::PermissionDenied)?;
    if !matches!(
        family,
        StrateFamily::NET | StrateFamily::DRV | StrateFamily::SYS
    ) {
        return Err(SyscallError::PermissionDenied);
    }

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: the capability table belongs to the current process.
    let caps = unsafe { &mut *task.process.capabilities.get() };

    // Idempotent: return the existing capability if already opened.
    let required = CapPermissions::read_write();
    if let Some(existing) = caps.find_by_type_with_permissions(ResourceType::Nic, required) {
        return Ok(existing.id.as_u64());
    }

    let (_dev, resource) = nic::default_device_with_id().ok_or(SyscallError::Again)?;
    let cap = get_capability_manager().create_capability(
        ResourceType::Nic,
        resource,
        CapPermissions {
            read: true,
            write: true,
            execute: false,
            grant: false,
            revoke: true,
        },
    );
    let id = caps.insert(cap);
    Ok(id.as_u64())
}

/// `SYS_NET_REGISTER`: register the calling task as the networking silo.
pub fn sys_net_register() -> Result<u64, SyscallError> {
    let _dev = default_nic(CapPermissions::read_write())?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    nic::register_strate_net_tid(task.id.as_u64());
    log::info!("[net] networking strate registered (tid={})", task.id.as_u64());
    Ok(0)
}

/// `SYS_NET_INFO`: query interface information.
///
/// `info_type`:
/// * 0 — MAC address (6 bytes)
/// * 1 — `NetLinkInfo`
/// * 2 — MTU (`u32`)
/// * 3 — link up (`u8`)
/// * 4 — queue count (`u32`)
pub fn sys_net_info(info_type: u64, buf_ptr: u64) -> Result<u64, SyscallError> {
    let dev = default_nic(CapPermissions {
        read: true,
        write: false,
        execute: false,
        grant: false,
        revoke: false,
    })?;

    match info_type {
        0 => {
            let mac = dev.mac_address();
            let user = UserSliceWrite::new(buf_ptr, mac.len())?;
            user.copy_from(&mac);
            Ok(mac.len() as u64)
        }
        1 => {
            let queue = {
                let guard = nic::data_plane().lock();
                guard.as_ref().and_then(|dp| dp.clone_queue(0))
            };
            let epoch = queue
                .as_ref()
                .map(|q| q.header().epoch.load(Ordering::Acquire))
                .unwrap_or(1);
            let mtu = queue
                .as_ref()
                .map(|q| q.header().mtu.load(Ordering::Acquire))
                .unwrap_or(1500);
            let info = NetLinkInfo {
                mac: dev.mac_address(),
                _pad: 0,
                mtu,
                flags: if dev.link_up() {
                    link_flags::UP | link_flags::CARRIER | link_flags::FULL_DUPLEX
                } else {
                    0
                },
                speed_mbps: 0,
                epoch,
            };
            let user = UserSliceWrite::new(buf_ptr, core::mem::size_of::<NetLinkInfo>())?;
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    &info as *const NetLinkInfo as *const u8,
                    core::mem::size_of::<NetLinkInfo>(),
                )
            };
            user.copy_from(bytes);
            Ok(core::mem::size_of::<NetLinkInfo>() as u64)
        }
        2 => {
            let mtu: u32 = dev.mtu() as u32;
            let user = UserSliceWrite::new(buf_ptr, 4)?;
            user.copy_from(&mtu.to_le_bytes());
            Ok(4)
        }
        3 => {
            let up = if dev.link_up() { 1u8 } else { 0u8 };
            let user = UserSliceWrite::new(buf_ptr, 1)?;
            user.copy_from(&[up]);
            Ok(1)
        }
        4 => {
            let count = nic::queue_count() as u32;
            let user = UserSliceWrite::new(buf_ptr, 4)?;
            user.copy_from(&count.to_le_bytes());
            Ok(4)
        }
        _ => Err(SyscallError::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Legacy one-frame path
// ---------------------------------------------------------------------------

fn validate_frame(len: usize) -> Result<(), SyscallError> {
    if !(MIN_FRAME..=MAX_FRAME).contains(&len) {
        return Err(SyscallError::MessageSize);
    }
    Ok(())
}

/// `SYS_NET_RECV`: receive one raw Ethernet frame.
pub fn sys_net_recv(buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    let _cap = default_nic(CapPermissions {
        read: true,
        write: false,
        execute: false,
        grant: false,
        revoke: false,
    })?;

    let requested = usize::try_from(buf_len).map_err(|_| SyscallError::InvalidArgument)?;
    if requested < MIN_FRAME {
        return Err(SyscallError::InvalidArgument);
    }
    let requested = requested.min(MAX_FRAME);

    let mut kbuf = [0u8; MAX_FRAME];
    let n = {
        let guard = nic::data_plane().lock();
        if let Some(dp) = guard.as_ref() {
            match dp.pop_rx(0, &mut kbuf[..requested]) {
                Ok(Some(n)) => n,
                Ok(None) => return Err(SyscallError::Again),
                Err(error) => return Err(error.into()),
            }
        } else {
            let dev = nic::get_default_device().ok_or(SyscallError::Again)?;
            match dev.receive(&mut kbuf[..requested]) {
                Ok(n) => n,
                Err(nic::NetError::NoPacket) => return Err(SyscallError::Again),
                Err(nic::NetError::LinkDown) => return Err(SyscallError::IoError),
                Err(_) => return Err(SyscallError::IoError),
            }
        }
    };

    if n == 0 || n > requested {
        return Err(SyscallError::IoError);
    }
    let user = UserSliceWrite::new(buf_ptr, n)?;
    user.copy_from(&kbuf[..n]);
    Ok(n as u64)
}

/// `SYS_NET_SEND`: transmit one raw Ethernet frame.
pub fn sys_net_send(buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    let _cap = default_nic(CapPermissions {
        read: false,
        write: true,
        execute: false,
        grant: false,
        revoke: false,
    })?;

    let len = usize::try_from(buf_len).map_err(|_| SyscallError::InvalidArgument)?;
    validate_frame(len)?;

    let user = UserSliceRead::new(buf_ptr, len)?;
    let mut kbuf = [0u8; MAX_FRAME];
    let copied = user.copy_to(&mut kbuf[..len]);
    if copied != len {
        return Err(SyscallError::Fault);
    }

    let mut present = false;
    let pushed = {
        let guard = nic::data_plane().lock();
        match guard.as_ref() {
            Some(dp) => {
                present = true;
                dp.push_tx(0, &kbuf[..len]).is_ok()
            }
            None => false,
        }
    };

    if present {
        if !pushed {
            // Backpressure: do not bypass the shared ring, or packets would
            // be reordered relative to frames already queued.
            return Err(SyscallError::Again);
        }
        // Keep the TX path independent from RX interrupts.  If the device
        // queue is full, the frame stays in the shared TX ring and will be
        // flushed by the next kick or IRQ.
        nic::flush_tx(0);
        return Ok(len as u64);
    }

    // No data plane: fall back to the direct driver path.
    let dev = nic::get_default_device().ok_or(SyscallError::Again)?;
    dev.transmit(&kbuf[..len])
        .map_err(|_| SyscallError::Again)?;
    Ok(len as u64)
}

// ---------------------------------------------------------------------------
// Shared-queue path
// ---------------------------------------------------------------------------

/// `SYS_NET_QUEUE_MAP`: map a `NetQueue` region into the caller.
pub fn sys_net_queue_map(dev: u64, qid: u64, out_ptr: u64) -> Result<u64, SyscallError> {
    let _resource = nic_capability(dev, CapPermissions::read_write())?;
    if qid > u16::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let queue = {
        let guard = nic::data_plane().lock();
        guard
            .as_ref()
            .and_then(|dp| dp.clone_queue(qid as usize))
            .ok_or(SyscallError::BadHandle)?
    };

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let ring = queue.region();
    if !queue.try_map(task.id.as_u64()) {
        return Err(SyscallError::AlreadyExists);
    }
    let result = (|| -> Result<u64, SyscallError> {
        let frames = ring.frame_phys_addrs();
        let mapping_caps = ring.mapping_cap_ids().to_vec();
        let pages = ring.page_count();
        let size = pages
            .checked_mul(4096)
            .ok_or(SyscallError::InvalidArgument)? as u64;

        let addr_space = task.process.address_space_arc();
        let base = addr_space
            .find_free_vma_range(crate::kaslr::mmap_base(), pages, VmaPageSize::Small)
            .ok_or(SyscallError::OutOfMemory)?;

        addr_space
            .map_shared_frames_with_cap_ids(
                base,
                &frames,
                Some(&mapping_caps),
                VmaFlags {
                    readable: true,
                    writable: true,
                    executable: false,
                    user_accessible: true,
                },
                VmaType::Anonymous,
            )
            .map_err(|_| SyscallError::OutOfMemory)?;

        let map = NetQueueMap {
            base,
            len: size,
            qid: qid as u16,
            frame_size: NET_FRAME_SIZE as u16,
            slots: NET_RING_SLOTS as u16,
            flags: 0,
        };
        let user = UserSliceWrite::new(out_ptr, core::mem::size_of::<NetQueueMap>())?;
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &map as *const NetQueueMap as *const u8,
                core::mem::size_of::<NetQueueMap>(),
            )
        };
        user.copy_from(bytes);
        queue.set_mapped_base(base);
        Ok(size)
    })();
    if result.is_err() {
        queue.unmap_reservation();
    }
    result
}

/// `SYS_NET_QUEUE_UNMAP`: unmap a shared queue region.
///
/// Called by a restarted strate before re-mapping.  The queue reservation is
/// released only after the PTEs are removed.
pub fn sys_net_queue_unmap(dev: u64, qid: u64) -> Result<u64, SyscallError> {
    let _resource = nic_capability(dev, CapPermissions::read_write())?;
    if qid > u16::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let queue = {
        let guard = nic::data_plane().lock();
        guard
            .as_ref()
            .and_then(|dp| dp.clone_queue(qid as usize))
            .ok_or(SyscallError::BadHandle)?
    };
    let base = queue.take_mapped_base();
    if base == 0 {
        return Ok(0);
    }
    let pages = queue.region().page_count();
    let size = (pages as u64)
        .checked_mul(4096)
        .ok_or(SyscallError::InvalidArgument)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    task.process
        .address_space_arc()
        .unmap_range(base, size)
        .map_err(|_| SyscallError::IoError)?;
    queue.unmap_reservation();
    Ok(0)
}

/// `SYS_NET_KICK`: drain the shared TX ring to the device.
pub fn sys_net_kick(dev: u64, qid: u64) -> Result<u64, SyscallError> {
    let _resource = nic_capability(
        dev,
        CapPermissions {
            read: false,
            write: true,
            execute: false,
            grant: false,
            revoke: false,
        },
    )?;
    if qid > u16::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    Ok(nic::flush_tx(qid as usize) as u64)
}

/// `SYS_NET_IRQ_BIND`: route queue RX events to an IPC port.
pub fn sys_net_irq_bind(dev: u64, qid: u64, port: u64) -> Result<u64, SyscallError> {
    if qid > u16::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let queue = queue_from_handle(dev, qid as u16)?;
    queue.port.store(port, Ordering::Release);
    // The actual IRQ registration is performed by the device manager when
    // MSI-X vectors are available; storing the port is enough for the poll
    // path, which notifies the queue event.
    Ok(0)
}

/// `SYS_NET_TX_PUBLISH`: publish a TX descriptor and kick the device.
pub fn sys_net_tx_publish(dev: u64, qid: u64) -> Result<u64, SyscallError> {
    sys_net_kick(dev, qid)
}

/// `SYS_NET_LINK`: query link state and MTU.
pub fn sys_net_link(dev: u64, out_ptr: u64) -> Result<u64, SyscallError> {
    let device = nic_from_handle(
        dev,
        CapPermissions {
            read: true,
            write: false,
            execute: false,
            grant: false,
            revoke: false,
        },
    )?;
    let queue = {
        let guard = nic::data_plane().lock();
        guard.as_ref().and_then(|dp| dp.clone_queue(0))
    };
    let epoch = queue
        .as_ref()
        .map(|q| q.header().epoch.load(Ordering::Acquire))
        .unwrap_or(1);
    let mtu = queue
        .as_ref()
        .map(|q| q.header().mtu.load(Ordering::Acquire))
        .unwrap_or_else(|| device.mtu() as u32);
    let info = NetLinkInfo {
        mac: device.mac_address(),
        _pad: 0,
        mtu,
        flags: if device.link_up() {
            link_flags::UP | link_flags::CARRIER | link_flags::FULL_DUPLEX
        } else {
            0
        },
        speed_mbps: 0,
        epoch,
    };
    let user = UserSliceWrite::new(out_ptr, core::mem::size_of::<NetLinkInfo>())?;
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &info as *const NetLinkInfo as *const u8,
            core::mem::size_of::<NetLinkInfo>(),
        )
    };
    user.copy_from(bytes);
    Ok(core::mem::size_of::<NetLinkInfo>() as u64)
}

/// `SYS_NET_RX_BATCH`: receive up to `count` frames.
///
/// The `frames` array is an array of `NetFrame` entries.  Each entry points
/// to a user buffer that receives one frame.  This is a compatibility
/// batching path; the shared queue remains the zero-copy path.
pub fn sys_net_rx_batch(dev: u64, frames_ptr: u64, count: u64) -> Result<u64, SyscallError> {
    let _resource = nic_capability(
        dev,
        CapPermissions {
            read: true,
            write: false,
            execute: false,
            grant: false,
            revoke: false,
        },
    )?;
    let count = (count as usize).min(MAX_BATCH);
    if count == 0 {
        return Ok(0);
    }
    let bytes = count
        .checked_mul(core::mem::size_of::<NetFrame>())
        .ok_or(SyscallError::InvalidArgument)?;
    let user = UserSliceRead::new(frames_ptr, bytes)?;
    let mut raw = alloc::vec![0u8; bytes];
    user.copy_to(&mut raw);

    let mut done = 0usize;
    for index in 0..count {
        let offset = index * core::mem::size_of::<NetFrame>();
        let frame = unsafe {
            core::ptr::read_unaligned(raw[offset..].as_ptr() as *const NetFrame)
        };
        if frame.len as usize > MAX_FRAME {
            return Err(SyscallError::MessageSize);
        }
        let mut kbuf = [0u8; MAX_FRAME];
        let n = {
            let guard = nic::data_plane().lock();
            match guard.as_ref() {
                Some(dp) => match dp.pop_rx(0, &mut kbuf[..frame.len as usize]) {
                    Ok(Some(n)) => n,
                    Ok(None) => break,
                    Err(_) => break,
                },
                None => break,
            }
        };
        let out = UserSliceWrite::new(frame.addr, n)?;
        out.copy_from(&kbuf[..n]);
        done += 1;
    }
    Ok(done as u64)
}

/// `SYS_NET_TX_BATCH`: transmit up to `count` frames, then kick once.
pub fn sys_net_tx_batch(dev: u64, frames_ptr: u64, count: u64) -> Result<u64, SyscallError> {
    let _resource = nic_capability(dev, CapPermissions::read_write())?;
    let count = (count as usize).min(MAX_BATCH);
    if count == 0 {
        return Ok(0);
    }
    let bytes = count
        .checked_mul(core::mem::size_of::<NetFrame>())
        .ok_or(SyscallError::InvalidArgument)?;
    let user = UserSliceRead::new(frames_ptr, bytes)?;
    let mut raw = alloc::vec![0u8; bytes];
    user.copy_to(&mut raw);

    let mut done = 0usize;
    for index in 0..count {
        let offset = index * core::mem::size_of::<NetFrame>();
        let frame = unsafe {
            core::ptr::read_unaligned(raw[offset..].as_ptr() as *const NetFrame)
        };
        let len = frame.len as usize;
        if !(MIN_FRAME..=MAX_FRAME).contains(&len) {
            return Err(SyscallError::MessageSize);
        }
        let src = UserSliceRead::new(frame.addr, len)?;
        let mut kbuf = [0u8; MAX_FRAME];
        if src.copy_to(&mut kbuf[..len]) != len {
            return Err(SyscallError::Fault);
        }
        let ok = {
            let guard = nic::data_plane().lock();
            match guard.as_ref() {
                Some(dp) => dp.push_tx(0, &kbuf[..len]).is_ok(),
                None => false,
            }
        };
        if !ok {
            break;
        }
        done += 1;
    }
    if done > 0 {
        nic::flush_tx(0);
    }
    Ok(done as u64)
}

/// `SYS_NET_QUEUE_INFO`: query features, epoch and counters.
pub fn sys_net_queue_info(dev: u64, qid: u64, out_ptr: u64) -> Result<u64, SyscallError> {
    if qid > u16::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let queue = queue_from_handle(dev, qid as u16)?;
    let header = queue.header();
    let info = NetQueueInfo {
        features: header.features.load(Ordering::Acquire),
        qid: queue.qid,
        slots: NET_RING_SLOTS as u16,
        frame_size: NET_FRAME_SIZE as u16,
        _pad0: 0,
        epoch: header.epoch.load(Ordering::Acquire),
        mtu: header.mtu.load(Ordering::Acquire),
        stats: NetStats {
            rx_packets: 0,
            rx_bytes: 0,
            rx_dropped: header.rx_dropped.load(Ordering::Relaxed),
            tx_packets: 0,
            tx_bytes: 0,
            tx_dropped: header.tx_dropped.load(Ordering::Relaxed),
            irqs: header.irq_count.load(Ordering::Relaxed),
            polls: header.poll_count.load(Ordering::Relaxed),
        },
    };
    let user = UserSliceWrite::new(out_ptr, core::mem::size_of::<NetQueueInfo>())?;
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &info as *const NetQueueInfo as *const u8,
            core::mem::size_of::<NetQueueInfo>(),
        )
    };
    user.copy_from(bytes);
    Ok(core::mem::size_of::<NetQueueInfo>() as u64)
}

/// `SYS_NET_EVENT_WAIT`: wait for or poll a queue event.
///
/// `timeout_ns == 0` polls and returns `EAGAIN` when no event is pending.
/// A non-zero timeout currently blocks until the next event: the caller
/// must use `SYS_NET_RX_BATCH` / the mapped ring to make progress.
pub fn sys_net_event_wait(dev: u64, qid: u64, timeout_ns: u64) -> Result<u64, SyscallError> {
    if qid > u16::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let queue = queue_from_handle(dev, qid as u16)?;
    let mut seen = 0u64;
    if timeout_ns == 0 {
        return if queue.event.poll(&mut seen) {
            Ok(1)
        } else {
            Err(SyscallError::Again)
        };
    }
    queue.event.wait(&mut seen);
    queue
        .header()
        .irq_count
        .fetch_add(1, Ordering::Relaxed);
    Ok(1)
}

/// `SYS_NET_FEATURES`: get or set negotiated features.
///
/// `set != 0` ORs `mask` into the current set and returns the new mask;
/// otherwise returns the current mask.
pub fn sys_net_features(dev: u64, mask: u64, set: u64) -> Result<u64, SyscallError> {
    let queue = queue_from_handle(dev, 0)?;
    let mut current = queue.feature_mask();
    if set != 0 {
        current |= mask & features::ALL;
        queue.set_features(current);
    }
    Ok(current)
}

/// Reset the per-queue event sequence.  Used by restarting strates.
pub fn sys_net_event_reset(dev: u64, qid: u64) -> Result<u64, SyscallError> {
    let queue = queue_from_handle(dev, qid as u16)?;
    // A new registration means the old wakeup was consumed.
    queue.event.notify();
    Ok(0)
}

/// `SYS_NET_DEVICE_EVENT`: drain one hotplug/link event.
pub fn sys_net_device_event(out_ptr: u64) -> Result<u64, SyscallError> {
    // Resolve the capability acquired with SYS_NET_OPEN.  The legacy ABI has
    // no handle argument, so the default NIC capability is used.
    let _device = default_nic(CapPermissions {
        read: true,
        write: false,
        execute: false,
        grant: false,
        revoke: false,
    })?;

    let Some(device_event) = hotplug::pop() else {
        return Err(SyscallError::Again);
    };
    let event = NetEvent {
        kind: device_event.kind,
        qid: 0,
        flags: 0,
        epoch: device_event.epoch,
        _pad: 0,
        data: device_event.resource,
    };
    let user = UserSliceWrite::new(out_ptr, core::mem::size_of::<NetEvent>())?;
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &event as *const NetEvent as *const u8,
            core::mem::size_of::<NetEvent>(),
        )
    };
    user.copy_from(bytes);
    Ok(0)
}

/// `SYS_NET_QUIESCE`: stop a device before hot-unplug/reset.
pub fn sys_net_quiesce(dev: u64) -> Result<u64, SyscallError> {
    let device = nic_from_handle(dev, CapPermissions::read_write())?;
    device.quiesce().map_err(|_| SyscallError::IoError)?;
    hotplug::push(hotplug::DeviceEvent::new(
        event::QUIESCE,
        nic::device_resource_id(&device) as u64,
        device.epoch(),
        0,
    ));
    Ok(0)
}

/// `SYS_NET_RESUME`: resume a quiesced device.
pub fn sys_net_resume(dev: u64) -> Result<u64, SyscallError> {
    let device = nic_from_handle(dev, CapPermissions::read_write())?;
    device.resume().map_err(|_| SyscallError::IoError)?;
    hotplug::push(hotplug::DeviceEvent::new(
        event::RESUME,
        nic::device_resource_id(&device) as u64,
        device.epoch(),
        0,
    ));
    Ok(0)
}

// Keep `NetEvent` and `event` referenced for the port notification path
// implemented by the device manager in P3.
const _: u32 = event::RX_READY;
const _: usize = core::mem::size_of::<NetEvent>();
const _: usize = core::mem::size_of::<NetFrameDesc>();
const _: usize = NET_POOL_SLOTS;
