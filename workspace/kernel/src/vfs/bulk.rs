//! Bulk data ring shared between a scheme server and the kernel.
//!
//! The 1 KiB `IpcMessage` is fine for control operations but still forces
//! ~17 round trips for a 16 KiB stream read.  For stream handles, the kernel
//! allocates a page-backed ring, maps it into the **server** address space,
//! and tells the server its base through `OPCODE_BULK_SETUP`.  The server
//! writes/reads payloads directly in that ring; the kernel copies between the
//! ring and the client buffer.  One RPC moves up to `BULK_SIZE` bytes.
//!
//! The client never gets a mapping: this keeps the capability surface small
//! and lets the kernel enforce the fid ownership check on every operation.

use alloc::{sync::Arc, vec::Vec};
use core::ptr;

use crate::{
    ipc::shared_ring::{self, RingId, SharedRing},
    memory::{
        address_space::{AddressSpace, VmaFlags, VmaPageSize, VmaType},
        phys_to_virt,
    },
};

/// Default bulk ring size (32 KiB).  Chosen so the wire `data_len` (u16)
/// stays valid and so a single ring does not dominate a silo's memory quota.
pub const BULK_SIZE: usize = 32 * 1024;

/// A bulk ring mapped into a scheme server.
pub struct BulkHandle {
    ring_id: RingId,
    ring: Arc<SharedRing>,
    server_space: Arc<AddressSpace>,
    server_base: u64,
    size: usize,
    /// Kernel virtual address of each ring page.
    vas: Vec<u64>,
}

// SAFETY: the handle only exposes copy helpers; the ring is accessed by the
// server and the kernel under the fid ownership protocol.
unsafe impl Send for BulkHandle {}
unsafe impl Sync for BulkHandle {}

impl BulkHandle {
    /// Allocate a ring and map it into `server`.
    pub fn new(server: &crate::process::Task, size: usize) -> Result<Self, &'static str> {
        let ring_id = shared_ring::create_ring(size).map_err(|_| "bulk ring alloc failed")?;
        let ring = shared_ring::get_ring(ring_id).ok_or("bulk ring disappeared")?;
        let frames = ring.frame_phys_addrs();
        let mapping_caps = ring.mapping_cap_ids().to_vec();
        let pages = ring.page_count();
        let size = pages
            .checked_mul(4096)
            .ok_or("bulk ring size overflow")?;

        let server_space = server.process.address_space_arc();
        let base = server_space
            .find_free_vma_range(crate::kaslr::mmap_base(), pages, VmaPageSize::Small)
            .ok_or("no VMA for bulk ring")?;
        server_space
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
            .map_err(|_| "bulk ring map failed")?;

        let vas = frames
            .iter()
            .map(|pa| phys_to_virt(*pa) as u64)
            .collect::<Vec<_>>();

        Ok(Self {
            ring_id,
            ring,
            server_space,
            server_base: base,
            size,
            vas,
        })
    }

    pub fn server_base(&self) -> u64 {
        self.server_base
    }

    pub fn size(&self) -> usize {
        self.size
    }

    fn ptr_at(&self, offset: usize) -> Option<*mut u8> {
        if offset >= self.size {
            return None;
        }
        let page = offset / 4096;
        let delta = offset % 4096;
        self.vas.get(page).map(|base| (*base as *mut u8).add(delta))
    }

    /// Copy ring → caller buffer.
    pub fn copy_to(&self, dst: &mut [u8]) -> usize {
        let n = dst.len().min(self.size);
        let mut copied = 0usize;
        while copied < n {
            let page = copied / 4096;
            let delta = copied % 4096;
            let chunk = (4096 - delta).min(n - copied);
            let Some(src) = self.vas.get(page).map(|base| *base as *const u8) else {
                break;
            };
            // SAFETY: `src + delta` is inside a mapped ring page; `chunk`
            // stays within that page.
            unsafe {
                ptr::copy_nonoverlapping(src.add(delta), dst.as_mut_ptr().add(copied), chunk);
            }
            copied += chunk;
        }
        copied
    }

    /// Copy caller buffer → ring.
    pub fn copy_from(&self, src: &[u8]) -> usize {
        let n = src.len().min(self.size);
        let mut copied = 0usize;
        while copied < n {
            let page = copied / 4096;
            let delta = copied % 4096;
            let chunk = (4096 - delta).min(n - copied);
            let Some(dst) = self.vas.get(page).map(|base| *base as *mut u8) else {
                break;
            };
            // SAFETY: `dst + delta` is inside a mapped ring page.
            unsafe {
                ptr::copy_nonoverlapping(src.as_ptr().add(copied), dst.add(delta), chunk);
            }
            copied += chunk;
        }
        copied
    }
}

impl Drop for BulkHandle {
    fn drop(&mut self) {
        // Remove the server mapping before releasing the pages.
        let _ = self.server_space.unmap_range(self.server_base, self.size as u64);
        // Drop the registry entry; `ring` keeps the pages alive until here.
        let _ = shared_ring::destroy_ring(self.ring_id);
        let _ = &self.ring;
    }
}
