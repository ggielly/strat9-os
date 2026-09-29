//! VirtIO Network Device driver
//!
//! Provides network I/O via VirtIO-net protocol for QEMU/KVM environments.
//! Implements the common [`crate::hardware::nic::NetworkDevice`] trait so
//! this driver plugs into the unified `/dev/net/` scheme.
//!
//! Reference: VirtIO spec v1.2, Section 5.1 (Network Device)
//! https://docs.oasis-open.org/virtio/virtio/v1.4/cs01/virtio-v1.4-cs01.html#x1-2700001

use crate::{
    arch::pci::{self, PciDevice},
    hardware::{
        nic as net,
        virtio::{
            common::{reg, VirtioDevice, Virtqueue},
            status,
        },
    },
    memory::{self, PhysFrame},
    sync::{FixedQueue, SpinLock},
};
use alloc::sync::Arc;
use core::{mem, ptr};
use endian_num::Le;
use net_core::{NetError, NetworkDevice};
use spin::RwLock as SpinRwLock;

const RX_FRAME_TRACK_CAPACITY: usize = 128;
const TX_FRAME_TRACK_CAPACITY: usize = 128;

/// VirtIO net device features
pub mod features {
    pub const VIRTIO_NET_F_CSUM: u32 = 1 << 0;
    pub const VIRTIO_NET_F_GUEST_CSUM: u32 = 1 << 1;
    pub const VIRTIO_NET_F_MAC: u32 = 1 << 5;
    pub const VIRTIO_NET_F_GSO: u32 = 1 << 6;
    pub const VIRTIO_NET_F_GUEST_TSO4: u32 = 1 << 7;
    pub const VIRTIO_NET_F_GUEST_TSO6: u32 = 1 << 8;
    pub const VIRTIO_NET_F_GUEST_ECN: u32 = 1 << 9;
    pub const VIRTIO_NET_F_GUEST_UFO: u32 = 1 << 10;
    pub const VIRTIO_NET_F_HOST_TSO4: u32 = 1 << 11;
    pub const VIRTIO_NET_F_HOST_TSO6: u32 = 1 << 12;
    pub const VIRTIO_NET_F_HOST_ECN: u32 = 1 << 13;
    pub const VIRTIO_NET_F_HOST_UFO: u32 = 1 << 14;
    pub const VIRTIO_NET_F_MRG_RXBUF: u32 = 1 << 15;
    pub const VIRTIO_NET_F_STATUS: u32 = 1 << 16;
    pub const VIRTIO_NET_F_CTRL_VQ: u32 = 1 << 17;
    pub const VIRTIO_NET_F_CTRL_RX: u32 = 1 << 18;
    pub const VIRTIO_NET_F_CTRL_VLAN: u32 = 1 << 19;
    pub const VIRTIO_NET_F_GUEST_ANNOUNCE: u32 = 1 << 21;
    pub const VIRTIO_NET_F_MQ: u32 = 1 << 22;
}

/// VirtIO net status flags
pub mod net_status {
    pub const VIRTIO_NET_S_LINK_UP: u16 = 1;
    pub const VIRTIO_NET_S_ANNOUNCE: u16 = 2;
}

/// VirtIO net header (prepended to every packet)
///
/// Fields are little-endian as mandated by the VirtIO spec
/// https://docs.oasis-open.org/virtio/virtio/v1.4/virtio-v1.4.html#x1-2810006
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioNetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: Le<u16>,
    pub gso_size: Le<u16>,
    pub csum_start: Le<u16>,
    pub csum_offset: Le<u16>,
    pub num_buffers: Le<u16>,
}

/// VirtIO Network Device driver
pub struct VirtioNetDevice {
    device: VirtioDevice,
    rx_queue: SpinLock<Virtqueue>,
    tx_queue: SpinLock<Virtqueue>,
    mac_address: [u8; 6],
    /// Size in bytes of the per-packet `virtio_net_hdr` this device was
    /// configured with: 12 with `MRG_RXBUF`, 10 without.
    ///
    /// Per-device rather than a process-wide static. Two NICs may negotiate
    /// different feature sets, and a shared value would mis-size every header
    /// of whichever device initialised last.
    hdr_size: usize,
    pub rx_frames: SpinLock<FixedQueue<(PhysFrame, u8), RX_FRAME_TRACK_CAPACITY>>,
    tx_frames: SpinLock<FixedQueue<(PhysFrame, u8), TX_FRAME_TRACK_CAPACITY>>,
}

// Send and Sync are safe because we use SpinLocks
unsafe impl Send for VirtioNetDevice {}
unsafe impl Sync for VirtioNetDevice {}

/// VirtIO net device-specific configuration layout (spec 5.1.1).
mod cfg {
    /// `struct virtio_net_hdr` starts here; the MAC address occupies 6 bytes.
    pub const MAC: u16 = 0;
    /// Device link status, a `u16`. Only `VIRTIO_NET_S_LINK_UP` (bit 0) and
    /// `VIRTIO_NET_S_ANNOUNCE` (bit 1) are defined, so a real device reads
    /// back 0..=3 here. That makes it a cheap validity check on the
    /// device-config base — far stronger than validating the MAC alone.
    pub const LINK_STATUS: u16 = 6;
}

/// Offsets to try for the start of the device-specific configuration inside
/// BAR0. [`reg::CONFIG_OFF`] is the spec value; the shifted entries cover
/// hypervisors that leave a few reserved bytes between the common config and
/// the device config.
const CFG_OFFSET_CANDIDATES: [u16; 3] = [reg::CONFIG_OFF, 0x18, 0x1C];

/// Read 6 bytes at `offset` in the device-config window and accept them only
/// if they look like a unicast MAC (not an all-ones/all-zeros unmapped read).
fn read_plausible_mac(device: &VirtioDevice, offset: u16, out: &mut [u8; 6]) -> bool {
    for i in 0..6 {
        out[i] = device.read_reg_u8(offset + i as u16);
    }
    *out != [0xFF; 6] && *out != [0x00; 6] && (out[0] & 0x01) == 0
}

/// Locate the device-specific configuration window inside BAR0.
///
/// The spec fixes it at [`reg::CONFIG_OFF`], but some QEMU configurations
/// expose it a few bytes later — the symptom is a window that reads back
/// all-`0xFF` where the MAC should be.
///
/// A candidate is accepted only when **both** the MAC looks like a unicast
/// address **and** the link-status field at `+6` reads within its two defined
/// bits. Requiring both makes a false positive on a misaligned window very
/// unlikely: at the wrong base the two fields overlap, and the `0xFF` fill of
/// an unmapped region already fails the MAC test.
///
/// Returns the offset and the MAC read at that offset.
fn probe_cfg_offset(device: &VirtioDevice) -> Option<(u16, [u8; 6])> {
    for &candidate in &CFG_OFFSET_CANDIDATES {
        let mut mac = [0u8; 6];
        if !read_plausible_mac(device, candidate, &mut mac) {
            continue;
        }
        let link = device.read_reg_u16(candidate + cfg::LINK_STATUS);
        if link & !0x3 != 0 {
            log::debug!(
                "virtio-net: rejecting cfg offset {:#x}: link status {:#06x} sets undefined bits",
                candidate,
                link
            );
            continue;
        }
        return Some((candidate, mac));
    }
    None
}

impl VirtioNetDevice {
    /// Initialize a VirtIO network device from a PCI device
    pub unsafe fn new(pci_dev: PciDevice) -> Result<Self, &'static str> {
        log::info!("VirtIO-net: Initializing device at {:?}", pci_dev.address);

        // Create VirtIO device
        let mut device = VirtioDevice::new(pci_dev)?;

        // Reset device
        device.reset();

        // Acknowledge device
        device.add_status(status::ACKNOWLEDGE as u8);

        // Indicate we know how to drive it
        device.add_status(status::DRIVER as u8);

        // Read and negotiate features
        let device_features = device.read_device_features();
        let needed = features::VIRTIO_NET_F_MAC | features::VIRTIO_NET_F_STATUS;
        // VIRTIO_NET_F_MRG_RXBUF: requested so the device uses the 12-byte
        // virtio_net_hdr_v1 layout (with num_buffers) that matches our
        // VirtioNetHeader struct. Without it the legacy 10-byte header would
        // shift every packet by 2 bytes, corrupting all data.
        let desired = needed | features::VIRTIO_NET_F_MRG_RXBUF;
        if device_features & needed != needed {
            return Err("Device lacks mandatory MAC/STATUS features");
        }
        let guest_features = device_features & desired;
        device.write_guest_features(guest_features);

        // Features OK
        device.add_status(status::FEATURES_OK as u8);

        // Double-check that FEATURES_OK stuck
        if device.get_status() & (status::FEATURES_OK as u8) == 0 {
            return Err("Device rejected our feature set");
        }

        // Header size follows from what we *negotiated*, i.e. the intersection
        // we just wrote. Re-reading HOST_FEATURES here would return the
        // device's full feature set, not the agreed subset, so a device that
        // offers MRG_RXBUF but whose negotiated set did not include it would
        // still be mis-sized.
        let hdr_size = if guest_features & features::VIRTIO_NET_F_MRG_RXBUF != 0 {
            mem::size_of::<VirtioNetHeader>()
        } else {
            // Legacy 10-byte header: the num_buffers field is absent.
            10
        };

        // Create virtqueues
        // Queue 0: RX (receive)
        // Queue 1: TX (transmit)
        let rx_queue = Virtqueue::new(128)?;
        let tx_queue = Virtqueue::new(128)?;

        // Setup queues with device
        device.setup_queue(0, &rx_queue);
        device.setup_queue(1, &tx_queue);

        // Locate the device-specific configuration window before touching it.
        // Diagnostic first: the legacy config window starts at io_base+0x14 and
        // an unmapped window reads back 0xFF, which is how a wrong BAR0 shows
        // up as a corrupted MAC.
        log::info!(
            "VirtIO-net: io_base={:#06x} raw[0x14..0x1c]={:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
            device.io_base,
            device.read_reg_u8(0x14),
            device.read_reg_u8(0x15),
            device.read_reg_u8(0x16),
            device.read_reg_u8(0x17),
            device.read_reg_u8(0x18),
            device.read_reg_u8(0x19),
            device.read_reg_u8(0x1a),
            device.read_reg_u8(0x1b),
        );

        let (cfg_offset, mac_address) = match probe_cfg_offset(&device) {
            Some(found) => {
                if found.0 != reg::CONFIG_OFF {
                    log::warn!(
                        "VirtIO-net: device config at io_base+{:#x} instead of the spec's {:#x} - \
                         hypervisor uses a shifted config window",
                        found.0,
                        reg::CONFIG_OFF
                    );
                }
                device.set_cfg_offset(found.0);
                found
            }
            None => {
                log::error!(
                    "VirtIO-net: no plausible MAC at io_base+{:#x}/{:#x}/{:#x} - config window unreadable",
                    CFG_OFFSET_CANDIDATES[0],
                    CFG_OFFSET_CANDIDATES[1],
                    CFG_OFFSET_CANDIDATES[2],
                );
                return Err("device config window unreadable (MAC)");
            }
        };

        log::info!(
            "VirtIO-net: MAC address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (cfg offset {:#x}, hdr {:#x}B)",
            mac_address[0],
            mac_address[1],
            mac_address[2],
            mac_address[3],
            mac_address[4],
            mac_address[5],
            cfg_offset,
            hdr_size,
        );

        // Driver ready: only now does the device start reporting link state.
        device.add_status(status::DRIVER_OK as u8);

        log::info!(
            "VirtIO-net: post-DRIVER_OK link status={:#06x} up={}",
            device.read_cfg_u16(cfg::LINK_STATUS),
            device.read_cfg_u16(cfg::LINK_STATUS) & net_status::VIRTIO_NET_S_LINK_UP as u16 != 0
        );

        let net_device = Self {
            device,
            rx_queue: SpinLock::new(rx_queue),
            tx_queue: SpinLock::new(tx_queue),
            mac_address,
            hdr_size,
            rx_frames: SpinLock::new(FixedQueue::new()),
            tx_frames: SpinLock::new(FixedQueue::new()),
        };

        // Fill RX queue with buffers
        net_device.refill_rx_queue()?;

        Ok(net_device)
    }

    /// Fill the RX queue with receive buffers
    fn refill_rx_queue(&self) -> Result<(), &'static str> {
        let mut rx_queue = self.rx_queue.lock();
        let mut rx_frames = self.rx_frames.lock();

        // We want to keep some buffers in the RX queue
        let current_filled = rx_frames.len();
        let target_filled = 64;
        let mut added = 0usize;

        if current_filled >= target_filled {
            return Ok(());
        }

        for _ in 0..(target_filled - current_filled) {
            // Allocate buffer for header + MTU
            let buf_size = self.hdr_size + net::MTU;
            let buf_pages = (buf_size + 4095) / 4096;
            let buf_order = buf_pages.next_power_of_two().trailing_zeros() as u8;

            let buf_frame = match crate::sync::with_irqs_disabled(|token| {
                memory::allocate_phys_contiguous(token, buf_order)
            }) {
                Ok(frame) => frame,
                Err(_) => break, // No more memory available
            };

            let buf_addr = buf_frame.start_address.as_u64();
            let virt_addr = crate::memory::phys_to_virt(buf_addr);

            // Zero the buffer (header needs to be zeroed mostly)
            unsafe {
                ptr::write_bytes(virt_addr as *mut u8, 0, buf_size);
            }

            // Add buffer to RX queue (device Writable)
            match rx_queue.add_buffer(&[(buf_addr, buf_size as u32, true)]) {
                Ok(_) => {
                    if rx_frames.push_back((buf_frame, buf_order)).is_err() {
                        crate::sync::with_irqs_disabled(|token| {
                            memory::free_phys_contiguous(token, buf_frame, buf_order);
                        });
                        break;
                    }
                    added += 1;
                }
                Err(_) => {
                    // Queue full, free the buffer
                    crate::sync::with_irqs_disabled(|token| {
                        memory::free_phys_contiguous(token, buf_frame, buf_order);
                    });
                    break;
                }
            }
        }

        // Notify device about new RX buffers
        if rx_queue.should_notify() {
            self.device.notify_queue(0);
        }

        if rx_frames.is_empty() && current_filled == 0 && added == 0 {
            return Err("Failed to allocate RX buffers");
        }

        Ok(())
    }

    /// Read the device link status.
    ///
    /// Read through the device-config window so the probed offset applies
    /// uniformly: a hardcoded `io_base + 26` is only correct on whichever
    /// branch of the offset probe happened to match, and silently returns
    /// MAC bytes on the other.
    pub fn read_link_status(&self) -> u16 {
        self.device.read_cfg_u16(cfg::LINK_STATUS)
    }
}

impl NetworkDevice for VirtioNetDevice {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "virtio-net"
    }

    /// Performs the receive operation.
    fn receive(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        let mut rx_queue = self.rx_queue.lock();

        // Check if there's a used buffer
        if !rx_queue.has_used() {
            return Err(NetError::NoPacket);
        }

        // Claim the backing frame BEFORE consuming the used entry: the used
        // ring and rx_frames are two parallel FIFOs, so the n-th consumed
        // descriptor owns the n-th frame. Consuming first would free a
        // descriptor with no buffer to match it.
        let (frame, order) = match self.rx_frames.lock().pop_front() {
            Some(f) => f,
            None => {
                // Descriptors are still queued but no buffer tracks them:
                // do not consume the used entry, or the rings desynchronise.
                log::warn!("[vtnet] rx: used entry without tracking frame");
                return Err(NetError::NotReady);
            }
        };

        let hdr_size = self.hdr_size;
        let (token, len) = match rx_queue.get_used() {
            Some(v) => v,
            None => {
                crate::sync::with_irqs_disabled(|t| {
                    memory::free_phys_contiguous(t, frame, order);
                });
                return Err(NetError::NoPacket);
            }
        };

        let _desc_index = token as usize;
        let _desc_table = rx_queue.desc_area(); // Physical address

        let buf_addr = frame.start_address.as_u64();
        let virt_addr = crate::memory::phys_to_virt(buf_addr);

        let header_ptr = virt_addr as *const VirtioNetHeader;
        let data_ptr = (virt_addr + hdr_size as u64) as *const u8;

        let header = unsafe { ptr::read(header_ptr) };
        let packet_len = (len as usize).saturating_sub(hdr_size);

        log::trace!(
            "[vtnet] rx: token={} len={} pkt={} flags={}",
            token,
            len,
            packet_len,
            header.flags,
        );

        if buf.len() < packet_len {
            // Buffer too small, packet lost
            crate::sync::with_irqs_disabled(|token| {
                memory::free_phys_contiguous(token, frame, order);
            });
            drop(rx_queue);
            // We still need to refill.
            let _ = self.refill_rx_queue();
            return Err(NetError::BufferTooSmall);
        }

        // Copy packet data
        if packet_len > 0 {
            unsafe {
                ptr::copy_nonoverlapping(data_ptr, buf.as_mut_ptr(), packet_len);
            }
        }

        // Free the frame
        crate::sync::with_irqs_disabled(|token| {
            memory::free_phys_contiguous(token, frame, order);
        });
        drop(rx_queue);

        // Refill RX queue
        let _ = self.refill_rx_queue();

        Ok(packet_len)
    }

    /// Performs the transmit operation.
    fn transmit(&self, buf: &[u8]) -> Result<(), NetError> {
        if buf.len() > net::MTU {
            return Err(NetError::BufferTooSmall);
        }

        // Allocate TX buffer (header + data)
        let buf_size = self.hdr_size + buf.len();
        let buf_pages = (buf_size + 4095) / 4096;
        let buf_order = buf_pages.next_power_of_two().trailing_zeros() as u8;

        let buf_frame = crate::sync::with_irqs_disabled(|token| {
            memory::allocate_phys_contiguous(token, buf_order)
        })
        .map_err(|_| NetError::NotReady)?;

        let buf_addr = buf_frame.start_address.as_u64();
        let virt_addr = crate::memory::phys_to_virt(buf_addr);

        let header_ptr = virt_addr as *mut VirtioNetHeader;
        let data_ptr = (virt_addr + self.hdr_size as u64) as *mut u8;

        // Write header
        unsafe {
            ptr::write(header_ptr, VirtioNetHeader::default());
            ptr::copy_nonoverlapping(buf.as_ptr(), data_ptr, buf.len());
        }

        // Submit to TX queue
        let mut tx_queue = self.tx_queue.lock();

        // Reclaim completed TX buffers before submitting.
        // The used ring is FIFO so draining here frees exactly the frames
        // that were pushed earlier in the same order.
        while let Some((_token, _len)) = tx_queue.get_used() {
            if let Some((_frame, order)) = self.tx_frames.lock().pop_front() {
                crate::sync::with_irqs_disabled(|token| {
                    memory::free_phys_contiguous(token, _frame, order);
                });
            }
        }

        let head = tx_queue
            .add_buffer(&[(buf_addr, buf_size as u32, false)]) // Device Readable
            .map_err(|_| {
                // Free buffer if queue is full
                crate::sync::with_irqs_disabled(|token| {
                    memory::free_phys_contiguous(token, buf_frame, buf_order);
                });
                NetError::TxQueueFull
            })?;

        if let Err(_) = self.tx_frames.lock().push_back((buf_frame, buf_order)) {
            // Tracking queue full : free the frame we just submitted
            // (the descriptor is already in the available ring but the
            // device hasn't seen it yet; get_used will reclaim it later
            // and we won't be able to free it.  This is a safety net.)
            crate::sync::with_irqs_disabled(|token| {
                memory::free_phys_contiguous(token, buf_frame, buf_order);
            });
        }

        log::trace!("[vtnet] tx: submit {} bytes @ {:#x}", buf_size, buf_addr);

        if tx_queue.should_notify() {
            self.device.notify_queue(1);
        }
        drop(tx_queue);

        Ok(())
    }

    /// Performs the mac address operation.
    fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    /// Performs the link up operation.
    fn link_up(&self) -> bool {
        let status = self.read_link_status();
        status & net_status::VIRTIO_NET_S_LINK_UP != 0
    }

    /// Ack the PCI/virtio ISR so the IRQ line can fire again.
    /// RX/TX ring draining is done by `nic::handle_interrupt()`.
    fn handle_interrupt(&self) {
        if self.device.read_isr_status() == 0 {
            return;
        }
        self.device.ack_interrupt();
    }

    /// Reclaim completed TX buffers and top up RX when polled without IRQ.
    fn poll(&self) {
        loop {
            let used = {
                let mut tx_queue = self.tx_queue.lock();
                tx_queue.get_used()
            };
            let Some((_token, _len)) = used else {
                break;
            };
            if let Some((_frame, order)) = self.tx_frames.lock().pop_front() {
                crate::sync::with_irqs_disabled(|token| {
                    memory::free_phys_contiguous(token, _frame, order);
                });
            }
        }
        let _ = self.refill_rx_queue();
    }
}

/// Global VirtIO network device
static VIRTIO_NET: SpinRwLock<Option<Arc<VirtioNetDevice>>> = SpinRwLock::new(None);

/// Initialize VirtIO network device and register it in the global net registry.
///
/// Idempotent: `hardware::init()` and the component `nic_init` both call this;
/// a second probe would reset the same PCI device and corrupt the first handle.
pub fn init() {
    if VIRTIO_NET.read().is_some() {
        return;
    }

    log::info!("VirtIO-net: Scanning for devices...");

    // Prefer strict class-based probe (network/ethernet), with fallback to
    // vendor+device for odd firmware/virtual setups.
    let pci_dev = match pci::probe_first(pci::ProbeCriteria {
        vendor_id: Some(pci::vendor::VIRTIO),
        device_id: Some(pci::device::VIRTIO_NET),
        class_code: Some(pci::class::NETWORK),
        subclass: Some(pci::net_subclass::ETHERNET),
        prog_if: None,
    })
    .or_else(|| pci::find_virtio_device(pci::device::VIRTIO_NET))
    {
        Some(dev) => dev,
        None => {
            log::warn!("VirtIO-net: No network device found");
            return;
        }
    };

    // Enable MSI-X => MSI => INTx before the device value is moved into
    // VirtioNetDevice::new(). Without this the N2 data plane never sees
    // RX/TX and DHCP can never complete.
    // msi::probe_and_enable takes hardware::pci_client::PciDevice (same as e1000).
    let client_dev = crate::hardware::pci_client::PciDevice {
        address: crate::hardware::pci_client::PciAddress::new(
            pci_dev.address.bus,
            pci_dev.address.device,
            pci_dev.address.function,
        ),
        vendor_id: pci_dev.vendor_id,
        device_id: pci_dev.device_id,
        class_code: pci_dev.class_code,
        subclass: pci_dev.subclass,
        prog_if: pci_dev.prog_if,
        revision: pci_dev.revision,
        header_type: pci_dev.header_type,
        interrupt_line: pci_dev.interrupt_line,
        interrupt_pin: pci_dev.interrupt_pin,
    };
    let (irq, vector) = crate::arch::msi::probe_and_enable(&client_dev, true);
    let msi_active =
        (client_dev.read_config_u16(pci::config::COMMAND) & pci::command::INTERRUPT_DISABLE) != 0;

    // Retry once like the e1000 driver: a stale INTERRUPT_DISABLE or a
    // missing bus-master bit from firmware makes the first attempt read back
    // an unmapped device-config window.
    let mut device = None;
    for attempt in 1..=2u32 {
        match unsafe { VirtioNetDevice::new(pci_dev) } {
            Ok(dev) => {
                log::info!("VirtIO-net: init ok on attempt {}", attempt);
                device = Some(dev);
                break;
            }
            Err(e) => {
                log::warn!("VirtIO-net: init attempt {} failed: {}", attempt, e);
                if attempt == 1 {
                    let mut cmd = client_dev.read_config_u16(pci::config::COMMAND);
                    cmd |= pci::command::BUS_MASTER | pci::command::IO_SPACE;
                    cmd &= !pci::command::INTERRUPT_DISABLE;
                    client_dev.write_config_u16(pci::config::COMMAND, cmd);
                    log::info!(
                        "VirtIO-net: reprogrammed PCI COMMAND={:#06x} (bus_master|io_space, intx enabled)",
                        cmd
                    );
                }
            }
        }
    }

    match device {
        Some(device) => {
            let arc = Arc::new(device);
            *VIRTIO_NET.write() = Some(arc.clone());
            let iface = net::register_device(arc.clone());

            // link_up() reads device config on every call, so the value
            // logged here reflects the post-negotiation state.
            log::info!(
                "[VirtIO-net] {}: link_up={} status_raw={:#06x}",
                iface,
                arc.link_up(),
                arc.read_link_status()
            );

            if msi_active {
                // MSI delivers to the vector programmed by probe_and_enable.
                // When interrupt_line is 0/0xFF that vector is still valid (≥ 0x20).
                crate::arch::idt::register_nic_irq(vector);
                let irq_for_eoi = if irq != 0 && irq != 0xFF { irq } else { vector };
                net::set_nic_device(arc, irq_for_eoi);
                log::info!(
                    "[VirtIO-net] {}: MSI/MSI-X active on vector {:#x}",
                    iface,
                    vector
                );
            } else if irq == 0 || irq == 0xFF {
                log::warn!(
                    "[VirtIO-net] {}: no valid IRQ line, running in polling mode",
                    iface
                );
            } else {
                crate::arch::ioapic::route_nic_irq(irq, vector);
                log::info!(
                    "[VirtIO-net] {}: INTx IRQ {} => vector {:#x}",
                    iface,
                    irq,
                    vector
                );
                crate::arch::idt::register_nic_irq(irq);
                net::set_nic_device(arc, irq);
            }
        }
        None => {
            log::error!("VirtIO-net: failed to initialize device after retries");
        }
    }
}

/// Get the VirtIO network device instance (if present).
pub fn get_device() -> Option<Arc<VirtioNetDevice>> {
    VIRTIO_NET.read().clone()
}
