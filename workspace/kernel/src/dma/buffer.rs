use crate::memory::{self, frame::get_meta, phys_to_virt, PhysFrame};
use x86_64::PhysAddr;

/// A pinned, contiguous DMA buffer.
///
/// Allocated from the buddy allocator with `allocate_phys_contiguous`.
/// The underlying frames are marked with the [`frame_flags::DMA`] flag,
/// preventing the buddy from recycling them while a transfer is in flight.
///
/// The buffer is automatically unpinned on [`Drop`], using RAII to
/// guarantee cleanup even on panic paths.
pub struct DmaBuffer {
    frame: PhysFrame,
    order: u8,
    phys: u64,
    virt: u64,
    /// Number of 4 KiB frames in this buffer.
    nframes: usize,
}

impl DmaBuffer {
    /// Allocate a DMA buffer large enough for `bytes`, pinned for the
    /// duration of the transfer.  The backing memory is contiguous in
    /// physical address space.
    ///
    /// The buffer is **not zeroed** (caller must overwrite every byte
    /// before the first read).
    pub fn alloc(bytes: usize) -> Result<Self, DmaError> {
        let nframes = (bytes + 4095) / 4096;
        let order = nframes.next_power_of_two().trailing_zeros() as u8;

        let frame =
            crate::sync::with_irqs_disabled(|token| memory::allocate_phys_contiguous(token, order))
                .map_err(|_| DmaError::Alloc)?;

        let phys = frame.start_address.as_u64();

        // Mark every frame in the range as DMA-pinned so the buddy
        // allocator will not reuse them until we unpin.
        for i in 0..(1usize << order) {
            let meta = get_meta(PhysAddr::new(phys + (i as u64) * 4096));
            meta.or_flags(memory::frame::frame_flags::DMA);
        }

        Ok(Self {
            frame,
            order,
            phys,
            virt: phys_to_virt(phys),
            nframes: 1usize << order,
        })
    }

    /// Physical base address : pass this to hardware DMA engines.
    #[inline]
    pub fn dma_addr(&self) -> PhysAddr {
        PhysAddr::new(self.phys)
    }

    /// Kernel virtual address (HHDM mapping) for CPU access.
    #[inline]
    pub fn virt_addr(&self) -> u64 {
        self.virt
    }

    /// Number of bytes allocated (always a multiple of 4096).
    #[inline]
    pub fn len_bytes(&self) -> usize {
        self.nframes * 4096
    }
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        // Clear the DMA flag so the buddy can reuse these frames.
        for i in 0..self.nframes {
            let meta = get_meta(PhysAddr::new(self.phys + (i as u64) * 4096));
            meta.and_flags(!memory::frame::frame_flags::DMA);
        }
        crate::sync::with_irqs_disabled(|token| {
            memory::free_phys_contiguous(token, self.frame, self.order);
        });
    }
}

// SAFETY: DmaBuffer owns a contiguous physical range; the virtual
// address is derived via the identity-like HHDM mapping and is valid
// for the lifetime of the buffer.
unsafe impl Send for DmaBuffer {}
unsafe impl Sync for DmaBuffer {}

// =============================================================================
// DmaError
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    /// Physical memory allocation failed.
    Alloc,
}
