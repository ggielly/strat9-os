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
            common::{VirtioDevice, Virtqueue},
            status,
        },
    },
    memory::{self, PhysFrame},
    sync::{FixedQueue, SpinLock},
};
use alloc::sync::Arc;
use core::{mem, ptr, sync::atomic::Ordering};
use endian_num::Le;
use net_core::{NetError, NetworkDevice};
use spin::RwLock as SpinRwLock;

/// VirtIO net header size (12 bytes with MRG_RXBUF, 10 bytes without).
/// Determined at runtime during feature negotiation.
static NET_HDR_SIZE: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(mem::size_of::<VirtioNetHeader>());
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
    pub rx_frames: SpinLock<FixedQueue<(PhysFrame, u8), RX_FRAME_TRACK_CAPACITY>>,
    tx_frames: SpinLock<FixedQueue<(PhysFrame, u8), TX_FRAME_TRACK_CAPACITY>>,
}

// Send and Sync are safe because we use SpinLocks
unsafe impl Send for VirtioNetDevice {}
unsafe impl Sync for VirtioNetDevice {}

impl VirtioNetDevice {
    /// Initialize a VirtIO network device from a PCI device
    pub unsafe fn new(pci_dev: PciDevice) -> Result<Self, &'static str> {
        log::info!("VirtIO-net: Initializing device at {:?}", pci_dev.address);

        // Create VirtIO device
        let device = VirtioDevice::new(pci_dev)?;

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

        // Read back negotiated features to determine actual header size.
        // With VIRTIO_NET_F_MRG_RXBUF the header is 12 bytes (virtio_net_hdr_v1);
        // without it the legacy 10-byte header (virtio_net_hdr) is used.
        let negotiated = device.read_device_features();
        if negotiated & features::VIRTIO_NET_F_MRG_RXBUF != 0 {
            NET_HDR_SIZE.store(mem::size_of::<VirtioNetHeader>(), Ordering::Release);
        } else {
            // Legacy 10-byte header: num_buffers field is absent.
            NET_HDR_SIZE.store(10, Ordering::Release);
        }

        // Create virtqueues
        // Queue 0: RX (receive)
        // Queue 1: TX (transmit)
        let rx_queue = Virtqueue::new(128)?;
        let tx_queue = Virtqueue::new(128)?;

        // Setup queues with device
        device.setup_queue(0, &rx_queue);
        device.setup_queue(1, &tx_queue);

        // Read MAC address from device config space
        // For legacy devices, MAC is at offset 20 + 0
        let mut mac_address = [0u8; 6];
        for i in 0..6 {
            mac_address[i] = device.read_reg_u8(20 + i as u16);
        }

        log::info!(
            "VirtIO-net: MAC address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac_address[0],
            mac_address[1],
            mac_address[2],
            mac_address[3],
            mac_address[4],
            mac_address[5]
        );

        // Driver ready
        device.add_status(status::DRIVER_OK as u8);

        let net_device = Self {
            device,
            rx_queue: SpinLock::new(rx_queue),
            tx_queue: SpinLock::new(tx_queue),
            mac_address,
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
            let buf_size = NET_HDR_SIZE.load(Ordering::Relaxed) + net::MTU;
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

    /// Read link status from device
    fn read_link_status(&self) -> u16 {
        // Status is at offset 6 in device-specific config (offset 20 + 6 = 26)
        self.device.read_reg_u16(26)
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

        let hdr_size = NET_HDR_SIZE.load(Ordering::Relaxed);
        let (token, len) = rx_queue.get_used().ok_or(NetError::NoPacket)?;

        let _desc_index = token as usize;
        let _desc_table = rx_queue.desc_area(); // Physical address

        let (frame, order) = self
            .rx_frames
            .lock()
            .pop_front()
            .ok_or(NetError::NotReady)?;

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
        let buf_size = NET_HDR_SIZE.load(Ordering::Relaxed) + buf.len();
        let buf_pages = (buf_size + 4095) / 4096;
        let buf_order = buf_pages.next_power_of_two().trailing_zeros() as u8;

        let buf_frame = crate::sync::with_irqs_disabled(|token| {
            memory::allocate_phys_contiguous(token, buf_order)
        })
        .map_err(|_| NetError::NotReady)?;

        let buf_addr = buf_frame.start_address.as_u64();
        let virt_addr = crate::memory::phys_to_virt(buf_addr);

        let header_ptr = virt_addr as *mut VirtioNetHeader;
        let data_ptr = (virt_addr + NET_HDR_SIZE.load(Ordering::Relaxed) as u64) as *mut u8;

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
            // Tracking queue full — free the frame we just submitted
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
}

/// Global VirtIO network device
static VIRTIO_NET: SpinRwLock<Option<Arc<VirtioNetDevice>>> = SpinRwLock::new(None);

/// Initialize VirtIO network device and register it in the global net registry.
pub fn init() {
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

    match unsafe { VirtioNetDevice::new(pci_dev) } {
        Ok(device) => {
            let arc = Arc::new(device);
            *VIRTIO_NET.write() = Some(arc.clone());
            net::register_device(arc);
        }
        Err(e) => {
            log::error!("VirtIO-net: Failed to initialize device: {}", e);
        }
    }
}

/// Get the VirtIO network device instance (if present).
pub fn get_device() -> Option<Arc<VirtioNetDevice>> {
    VIRTIO_NET.read().clone()
}
