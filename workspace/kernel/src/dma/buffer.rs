use crate::{
    arch::xshim::PhysAddr,
    hardware::iommu::{DmaProt, Domain},
    memory::{self, frame::get_meta, phys_to_virt, PhysFrame},
};
use alloc::sync::Arc;

/// Address constraints imposed by a device's DMA engine.
///
/// Legacy 32-bit devices can only address the low 4 GiB; some also require a
/// particular alignment.  The allocator uses this to reject a physically
/// contiguous range that the device could not address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaConstraint {
    /// Highest usable physical address (exclusive).
    pub max_phys: u64,
    /// Required alignment of the physical base.
    pub align: u64,
}

impl DmaConstraint {
    /// No restriction (64-bit capable device).
    pub const UNRESTRICTED: Self = Self {
        max_phys: u64::MAX,
        align: 1,
    };

    /// A device limited to a 32-bit DMA address space.
    pub const BITS32: Self = Self {
        max_phys: 1u64 << 32,
        align: 1,
    };

    /// True when `[phys, phys + len)` is addressable and correctly aligned.
    pub const fn fits(&self, phys: u64, len: u64) -> bool {
        let align = if self.align == 0 { 1 } else { self.align };
        phys % align == 0
            && match phys.checked_add(len) {
                Some(end) => end <= self.max_phys,
                None => false,
            }
    }
}

/// A pinned, contiguous DMA buffer.
///
/// Allocated from the buddy allocator with `allocate_phys_contiguous`.
/// The underlying frames are marked with the [`frame_flags::DMA`] flag,
/// preventing the buddy from recycling them while a transfer is in flight.
///
/// A buffer can optionally be attached to an IOMMU [`Domain`] with
/// [`DmaBuffer::map_to`] (or directly with [`DmaBuffer::alloc_in`]).  While it
/// is attached, the address the device must use is [`DmaBuffer::device_addr`]
/// (an IOVA) rather than the physical address.  Drivers that still expect a
/// physical address can keep using [`DmaBuffer::dma_addr`], which stays the
/// physical base for legacy paths such as AHCI.
///
/// The buffer is automatically unpinned (and unmapped) on [`Drop`], using RAII
/// to guarantee cleanup even on panic paths.
pub struct DmaBuffer {
    frame: PhysFrame,
    order: u8,
    phys: u64,
    virt: u64,
    /// Number of 4 KiB frames in this buffer.
    nframes: usize,
    /// Domain the buffer is mapped into, if any.
    domain: Option<Arc<Domain>>,
    /// IOVA returned by the domain, valid only while `domain` is set.
    iova: Option<u64>,
}

impl DmaBuffer {
    /// Allocate a DMA buffer large enough for `bytes`, pinned for the
    /// duration of the transfer.  The backing memory is contiguous in
    /// physical address space.
    ///
    /// The buffer is **not** zeroed (caller must overwrite every byte
    /// before the first read) and is **not** mapped into an IOMMU domain.
    pub fn alloc(bytes: usize) -> Result<Self, DmaError> {
        let (frame, order, phys) = allocate_frames(bytes)?;
        Ok(Self {
            frame,
            order,
            phys,
            virt: phys_to_virt(phys),
            nframes: 1usize << order,
            domain: None,
            iova: None,
        })
    }

    /// Allocate a DMA buffer satisfying `constraint`.
    ///
    /// The buddy allocator may hand out memory above a legacy device's address
    /// limit, so a few attempts are made before reporting
    /// [`DmaError::Constraint`].
    pub fn alloc_constrained(bytes: usize, constraint: DmaConstraint) -> Result<Self, DmaError> {
        for _ in 0..8 {
            let buffer = Self::alloc(bytes)?;
            if constraint.fits(buffer.phys, buffer.len_bytes() as u64) {
                return Ok(buffer);
            }
            drop(buffer);
        }
        Err(DmaError::Constraint)
    }

    /// Allocate a DMA buffer and immediately map it into `domain`.
    ///
    /// This is the preferred constructor for a device that is behind an
    /// IOMMU: the returned buffer is already coherent with the device's
    /// address space and will be unmapped automatically on drop.
    pub fn alloc_in(
        domain: Arc<Domain>,
        bytes: usize,
        prot: DmaProt,
    ) -> Result<Self, DmaError> {
        let mut buffer = Self::alloc(bytes)?;
        buffer.map_to(domain, prot)?;
        Ok(buffer)
    }

    /// Allocate a constrained buffer and map it into `domain`.
    pub fn alloc_constrained_in(
        domain: Arc<Domain>,
        bytes: usize,
        constraint: DmaConstraint,
        prot: DmaProt,
    ) -> Result<Self, DmaError> {
        let mut buffer = Self::alloc_constrained(bytes, constraint)?;
        buffer.map_to(domain, prot)?;
        Ok(buffer)
    }

    /// Map this buffer into `domain` and return the IOVA the device must use.
    ///
    /// Fails if the buffer is already attached to a domain.
    pub fn map_to(&mut self, domain: Arc<Domain>, prot: DmaProt) -> Result<u64, DmaError> {
        if self.domain.is_some() {
            return Err(DmaError::AlreadyMapped);
        }
        let iova = domain
            .map_auto(self.phys, self.len_bytes() as u64, prot)
            .map_err(DmaError::Iommu)?;
        self.domain = Some(domain);
        self.iova = Some(iova);
        Ok(iova)
    }

    /// Remove the buffer from its domain, if any.
    ///
    /// The physical frames stay pinned until the buffer itself is dropped.
    pub fn unmap(&mut self) -> Result<(), DmaError> {
        let (Some(domain), Some(iova)) = (self.domain.take(), self.iova.take()) else {
            return Err(DmaError::NotMapped);
        };
        domain
            .unmap(iova, self.len_bytes() as u64)
            .map_err(DmaError::Iommu)?;
        Ok(())
    }

    /// IOVA assigned to this buffer, when it is mapped into a domain.
    #[inline]
    pub fn iova(&self) -> Option<u64> {
        self.iova
    }

    /// Address the device must program for DMA.
    ///
    /// This is the IOVA when the buffer is mapped into a domain, and the
    /// physical address otherwise.
    #[inline]
    pub fn device_addr(&self) -> u64 {
        self.iova.unwrap_or(self.phys)
    }

    /// Physical base address.
    ///
    /// Kept for legacy drivers (AHCI) and for boot-time code running before
    /// any domain exists.  New IOMMU-aware drivers should use
    /// [`DmaBuffer::device_addr`] instead.
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

fn allocate_frames(bytes: usize) -> Result<(PhysFrame, u8, u64), DmaError> {
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

    Ok((frame, order, phys))
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        // Drop the IOMMU mapping first: a device must never keep a stale
        // translation pointing at frames the buddy is about to reuse.
        let _ = self.unmap();

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
// for the lifetime of the buffer.  Only Send is implemented : the
// hardware (DMA engine) writes into the buffer without CPU synchronisation,
// making &DmaBuffer across threads unsafe until an explicit fence.
unsafe impl Send for DmaBuffer {}

// =============================================================================
// DmaError
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    /// Physical memory allocation failed.
    Alloc,
    /// The buffer already belongs to an IOMMU domain.
    AlreadyMapped,
    /// The buffer is not attached to any domain.
    NotMapped,
    /// The IOMMU bookkeeping refused the mapping.
    Iommu(crate::hardware::iommu::IommuError),
    /// The allocator could not satisfy a [`DmaConstraint`].
    Constraint,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constraint_rejects_high_memory() {
        assert!(DmaConstraint::BITS32.fits(0x1000, 0x1000));
        assert!(!DmaConstraint::BITS32.fits(0xffff_f000, 0x2000));
        assert!(!DmaConstraint::BITS32.fits(u64::MAX - 1, 0x1000));
    }

    #[test]
    fn constraint_checks_alignment() {
        let aligned = DmaConstraint {
            max_phys: u64::MAX,
            align: 0x1000,
        };
        assert!(aligned.fits(0x2000, 0x1000));
        assert!(!aligned.fits(0x1800, 0x1000));
        assert!(DmaConstraint::UNRESTRICTED.fits(0x1234, 0x1000));
    }
}
