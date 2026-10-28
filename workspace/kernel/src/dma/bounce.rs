//! Bounce buffers for devices with restricted DMA address windows.
//!
//! A 32-bit-only device cannot address memory above 4 GiB.  When the generic
//! DMA buffer lives too high, this helper keeps a staging buffer inside the
//! device window and copies data across the boundary.
//!
//! The staging buffer is an ordinary [`DmaBuffer`], so it is pinned, can be
//! mapped into an IOMMU domain, and is unmapped automatically on drop.

use super::buffer::{DmaBuffer, DmaConstraint, DmaError};
use crate::hardware::iommu::{DmaProt, Domain};
use alloc::sync::Arc;
use core::ptr;

/// A DMA-visible staging buffer for a constrained device.
pub struct DmaBounce {
    staging: DmaBuffer,
    len: usize,
}

impl DmaBounce {
    /// Allocate a staging buffer of `len` bytes inside `constraint`.
    pub fn new(len: usize, constraint: DmaConstraint) -> Result<Self, DmaError> {
        Ok(Self {
            staging: DmaBuffer::alloc_constrained(len, constraint)?,
            len,
        })
    }

    /// Allocate a staging buffer already mapped into `domain`.
    pub fn new_in(
        domain: Arc<Domain>,
        len: usize,
        constraint: DmaConstraint,
        prot: DmaProt,
    ) -> Result<Self, DmaError> {
        let staging = DmaBuffer::alloc_constrained_in(domain, len, constraint, prot)?;
        Ok(Self { staging, len })
    }

    /// Copy `src` into the staging buffer (device read direction).
    pub fn load(&mut self, src: &[u8]) -> Result<(), DmaError> {
        if src.len() > self.staging.len_bytes() {
            return Err(DmaError::Constraint);
        }
        // SAFETY: both regions are valid for `src.len()` bytes and the staging
        // buffer is private to this object.
        unsafe {
            ptr::copy_nonoverlapping(
                src.as_ptr(),
                self.staging.virt_addr() as *mut u8,
                src.len(),
            );
        }
        self.len = src.len();
        Ok(())
    }

    /// Copy the staging buffer back into `dst` (device write direction).
    pub fn store(&self, dst: &mut [u8]) {
        let length = dst.len().min(self.len).min(self.staging.len_bytes());
        // SAFETY: as above, bounded by both buffers.
        unsafe {
            ptr::copy_nonoverlapping(
                self.staging.virt_addr() as *const u8,
                dst.as_mut_ptr(),
                length,
            );
        }
    }

    /// Address the device must program.
    pub fn device_addr(&self) -> u64 {
        self.staging.device_addr()
    }

    /// IOVA, when the staging buffer is mapped into a domain.
    pub fn iova(&self) -> Option<u64> {
        self.staging.iova()
    }

    /// Capacity of the staging buffer.
    pub fn capacity(&self) -> usize {
        self.staging.len_bytes()
    }

    /// Number of valid bytes currently staged.
    pub fn len(&self) -> usize {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constraint_rejects_high_memory() {
        assert!(DmaConstraint::BITS32.fits(0x1000, 0x1000));
        assert!(!DmaConstraint::BITS32.fits(0xffff_f000, 0x2000));
    }
}
