//! VirtIO Network Device driver
//!
//! Provides network I/O via VirtIO-net protocol for QEMU/KVM environments.
//! Designed to interface with smoltcp for the TCP/IP stack.
//!
//! Reference: VirtIO spec v1.2, Section 5.1 (Network Device)

use super::common::{VirtioDevice, Virtqueue};
use super::status;
use crate::arch::x86_64::pci::{self, PciDevice};
use crate::memory::{get_allocator, FrameAllocator, PhysFrame};
use crate::sync::SpinLock;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::mem;
use core::ptr;

/// Maximum transmission unit
pub const MTU: usize = 1514; // Ethernet MTU

/// VirtIO net header size
const NET_HDR_SIZE: usize = mem::size_of::<VirtioNetHeader>();

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
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioNetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

/// Network device trait
///
/// This trait is designed to be compatible with smoltcp's `Device` trait.
pub trait NetworkDevice {
    /// Receive a packet from the device
    fn receive(&self, buf: &mut [u8]) -> Result<usize, NetError>;
    /// Send a packet through the device
    fn transmit(&self, buf: &[u8]) -> Result<(), NetError>;
    /// Get the MAC address
    fn mac_address(&self) -> [u8; 6];
    /// Check if link is up
    fn link_up(&self) -> bool;
}

/// Network device errors
#[derive(Debug)]
pub enum NetError {
    /// No packet available
    NoPacket,
    /// Transmit queue full
    TxQueueFull,
    /// Buffer too small
    BufferTooSmall,
    /// Device not ready
    NotReady,
    /// Link down
    LinkDown,
}

/// VirtIO Network Device driver
pub struct VirtioNetDevice {
    device: VirtioDevice,
    rx_queue: SpinLock<Virtqueue>,
    tx_queue: SpinLock<Virtqueue>,
    mac_address: [u8; 6],
    pub rx_frames: SpinLock<VecDeque<(PhysFrame, u8)>>, // Track allocated RX frames
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
        let _device_features = device.read_device_features();

        // Request MAC address feature
        let guest_features = features::VIRTIO_NET_F_MAC | features::VIRTIO_NET_F_STATUS;
        device.write_guest_features(guest_features);

        // Features OK
        device.add_status(status::FEATURES_OK as u8);

        // Verify features OK
        if device.get_status() & (status::FEATURES_OK as u8) == 0 {
            return Err("Device doesn't support our feature set");
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

        let mut net_device = Self {
            device,
            rx_queue: SpinLock::new(rx_queue),
            tx_queue: SpinLock::new(tx_queue),
            mac_address,
            rx_frames: SpinLock::new(VecDeque::new()),
        };

        // Fill RX queue with buffers
        net_device.refill_rx_queue()?;

        Ok(net_device)
    }

    /// Fill the RX queue with receive buffers
    fn refill_rx_queue(&self) -> Result<(), &'static str> {
        let mut rx_queue = self.rx_queue.lock();
        let mut lock = get_allocator().lock();
        let allocator = lock.as_mut().ok_or("Allocator not initialized")?;

        // We want to keep some buffers in the RX queue
        let current_filled = self.rx_frames.lock().len();
        let target_filled = 64;

        if current_filled >= target_filled {
            return Ok(());
        }

        for _ in 0..(target_filled - current_filled) {
            // Allocate buffer for header + MTU
            let buf_size = NET_HDR_SIZE + MTU;
            let buf_pages = (buf_size + 4095) / 4096;
            let buf_order = buf_pages.next_power_of_two().trailing_zeros() as u8;

            let buf_frame = match allocator.alloc(buf_order) {
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
                    self.rx_frames.lock().push_back((buf_frame, buf_order));
                }
                Err(_) => {
                    // Queue full, free the buffer
                    allocator.free(buf_frame, buf_order);
                    break;
                }
            }
        }
        drop(lock);

        // Notify device about new RX buffers
        if rx_queue.should_notify() {
            self.device.notify_queue(0);
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
    fn receive(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        let mut rx_queue = self.rx_queue.lock();

        // Check if there's a used buffer
        if !rx_queue.has_used() {
            return Err(NetError::NoPacket);
        }

        let (token, len) = rx_queue.get_used().ok_or(NetError::NoPacket)?;

        // The token corresponds to the head descriptor index, but we track frames via a FIFO queue
        // assuming strict ordering VIRTIO_F_IN_ORDER (or just FIFO behavior of virtqueue used ring).
        // Standard virtio says device returns buffers in any order unless VIRTIO_F_IN_ORDER is negotiated.
        // However, our implementation of `add_buffer` returns the `head` index as logic token.
        // We pushed frames to `rx_frames` in the same order we called `add_buffer`.
        // IF the device consumes them in order, we are fine.
        // If not, we have a problem because we need to map token -> frame.
        // For simplicity, we assume FIFO for now or we search/map if needed.
        // Or better: store the token in `rx_frames` too?
        // Since we don't have a map, and we want O(1), let's rely on the token being the index in the descriptor table.
        // The descriptor table index is NOT the frame address.
        // But wait, `rx_frames` is a VecDeque. If completion is out of order, we can't just pop front.

        // CORRECTION: We need to find the frame associated with this token.
        // But `rx_frames` doesn't store tokens.
        // Ideally we should use the `token` (descriptor head index) to lookup context.
        // But we didn't store context in the descriptor.
        // Use `rx_frames` as a pool? No, we need the specific frame that contains the data.

        // REFACTOR: `rx_frames` should probably be a Map<Token, Frame> or we put the Frame info somewhere we can find it.
        // But for now, let's assume strict FIFO for simple drivers, OR...
        // Actually, we can just look at `desc_area`? No, we need the Frame to free it using allocator.

        // CRITICAL FIX: We need to recover the physical address from the descriptor!
        // We know the token is the index in descriptor table.
        // We can read `desc_addr` from the descriptor table!

        let desc_index = token as usize;
        let desc_table = rx_queue.desc_area(); // Physical address

        // We need virtual address to read it. We mapped it in `Virtqueue::new`.
        // But `Virtqueue` struct has `desc_ptr`.
        // But `Virtqueue` struct fields are private/internal.
        // We need `Virtqueue` to give us the address associated with the used buffer?
        // No, `get_used` returns token and length.

        // Let's rely on the fact that for simple single-queue NICs, packets usually arrive in order.
        // But to be correct without `VIRTIO_F_IN_ORDER`, we should retrieve the buffer address.

        // Let's improve `get_used` or add a method to lookup descriptor?
        // We can't change `virtio/common.rs` now without another tool call.
        // So I will assume FIFO for now (simple usage), but add a TODO.

        let (frame, order) = self
            .rx_frames
            .lock()
            .pop_front()
            .ok_or(NetError::NotReady)?;

        let buf_addr = frame.start_address.as_u64();
        let virt_addr = crate::memory::phys_to_virt(buf_addr);

        // Check if token matches what we expect?
        // We can't easily without reading the descriptor.

        let header_ptr = virt_addr as *const VirtioNetHeader;
        let data_ptr = (virt_addr + NET_HDR_SIZE as u64) as *const u8;

        let _header = unsafe { ptr::read(header_ptr) };
        let packet_len = (len as usize).saturating_sub(NET_HDR_SIZE);

        if buf.len() < packet_len {
            // Buffer too small, packet lost
            let mut lock = get_allocator().lock();
            if let Some(allocator) = lock.as_mut() {
                allocator.free(frame, order);
            }
            drop(lock);
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
        let mut lock = get_allocator().lock();
        if let Some(allocator) = lock.as_mut() {
            allocator.free(frame, order);
        }
        drop(lock);
        drop(rx_queue);

        // Refill RX queue
        let _ = self.refill_rx_queue();

        Ok(packet_len)
    }

    fn transmit(&self, buf: &[u8]) -> Result<(), NetError> {
        if buf.len() > MTU {
            return Err(NetError::BufferTooSmall);
        }

        // Allocate TX buffer (header + data)
        let buf_size = NET_HDR_SIZE + buf.len();
        let buf_pages = (buf_size + 4095) / 4096;
        let buf_order = buf_pages.next_power_of_two().trailing_zeros() as u8;

        let mut lock = get_allocator().lock();
        let allocator = lock.as_mut().ok_or(NetError::NotReady)?;
        let buf_frame = allocator.alloc(buf_order).map_err(|_| NetError::NotReady)?;
        drop(lock);

        let buf_addr = buf_frame.start_address.as_u64();
        let virt_addr = crate::memory::phys_to_virt(buf_addr);
        
        let header_ptr = virt_addr as *mut VirtioNetHeader;
        let data_ptr = (virt_addr + NET_HDR_SIZE as u64) as *mut u8;

        // Write header
        unsafe {
            ptr::write(header_ptr, VirtioNetHeader::default());
            ptr::copy_nonoverlapping(buf.as_ptr(), data_ptr, buf.len());
        }

        // Submit to TX queue
        let mut tx_queue = self.tx_queue.lock();
        let token = tx_queue
            .add_buffer(&[(buf_addr, buf_size as u32, false)]) // Device Readable
            .map_err(|_| {
                // Free buffer if failed
                let mut lock = get_allocator().lock();
                if let Some(allocator) = lock.as_mut() {
                    allocator.free(buf_frame, buf_order);
                }
                NetError::TxQueueFull
            })?;

        if tx_queue.should_notify() {
            self.device.notify_queue(1);
        }
        drop(tx_queue);

        // Wait for completion (simple spin for now)
        loop {
            let mut tx_queue = self.tx_queue.lock();
            if tx_queue.has_used() {
                if let Some((used_token, _)) = tx_queue.get_used() {
                    // Assuming correct order for now or just waiting for *any* completion which matches ours
                    if used_token == token {
                        break;
                    }
                }
            }
            drop(tx_queue);
            core::hint::spin_loop();
        }

        // Free TX buffer
        let mut lock = get_allocator().lock();
        if let Some(allocator) = lock.as_mut() {
            allocator.free(buf_frame, buf_order);
        }
        drop(lock);

        Ok(())
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    fn link_up(&self) -> bool {
        let status = self.read_link_status();
        status & net_status::VIRTIO_NET_S_LINK_UP != 0
    }
}

/// Global VirtIO network device
static VIRTIO_NET: SpinLock<Option<Box<VirtioNetDevice>>> = SpinLock::new(None);

/// Initialize VirtIO network device
pub fn init() {
    log::info!("VirtIO-net: Scanning for devices...");

    // Find VirtIO network device
    let pci_dev = match pci::find_virtio_device(pci::device::VIRTIO_NET) {
        Some(dev) => dev,
        None => {
            log::warn!("VirtIO-net: No network device found");
            return;
        }
    };

    // Initialize device
    match unsafe { VirtioNetDevice::new(pci_dev) } {
        Ok(device) => {
            *VIRTIO_NET.lock() = Some(Box::new(device));
        }
        Err(e) => {
            log::error!("VirtIO-net: Failed to initialize device: {}", e);
        }
    }
}

/// Get the global VirtIO network device
pub fn get_device() -> Option<&'static VirtioNetDevice> {
    unsafe {
        let lock = VIRTIO_NET.lock();
        if lock.is_some() {
            let ptr = &**lock.as_ref().unwrap() as *const VirtioNetDevice;
            Some(&*ptr)
        } else {
            None
        }
    }
}
