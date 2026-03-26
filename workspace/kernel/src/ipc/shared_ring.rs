use crate::{
    capability::CapId,
    memory::{
        allocate_mapping_cap_id, register_mapping_identity, release_owned_block,
        resolve_handle, revoke_mapping_cap_id, unregister_mapping_identity, PhysFrame,
    },
    sync::SpinLock,
};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RingId(pub u64);

impl RingId {
    /// Returns this as u64.
    pub fn as_u64(self) -> u64 {
        self.0
    }
    /// Builds this from u64.
    pub fn from_u64(raw: u64) -> Self {
        Self(raw)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RingError {
    #[error("invalid size")]
    InvalidSize,
    #[error("allocation failed")]
    Alloc,
    #[error("ring not found")]
    NotFound,
}

pub struct SharedRing {
    size: usize,
    frames: Vec<PhysFrame>,
    owner_cap_ids: Vec<CapId>,
    mapping_cap_ids: Vec<CapId>,
}

impl SharedRing {
    /// Performs the size operation.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Performs the page count operation.
    pub fn page_count(&self) -> usize {
        self.frames.len()
    }

    /// Performs the frame phys addrs operation.
    pub fn frame_phys_addrs(&self) -> Vec<u64> {
        self.frames
            .iter()
            .map(|f| f.start_address.as_u64())
            .collect()
    }

    /// Returns stable mapping identities for every page in the ring.
    pub fn mapping_cap_ids(&self) -> &[CapId] {
        &self.mapping_cap_ids
    }
}

impl Drop for SharedRing {
    /// Performs the drop operation.
    fn drop(&mut self) {
        for (frame, owner_cap_id) in self.frames.drain(..).zip(self.owner_cap_ids.drain(..)) {
            let handle = resolve_handle(frame.start_address);
            if let Some(block) = unregister_mapping_identity(handle, owner_cap_id) {
                release_owned_block(block);
            }
        }
    }
}

static NEXT_RING_ID: AtomicU64 = AtomicU64::new(1);
static RINGS: SpinLock<Option<BTreeMap<RingId, Arc<SharedRing>>>> = SpinLock::new(None);

/// Performs the ensure registry operation.
fn ensure_registry(guard: &mut Option<BTreeMap<RingId, Arc<SharedRing>>>) {
    if guard.is_none() {
        *guard = Some(BTreeMap::new());
    }
}

/// Creates ring.
pub fn create_ring(size: usize) -> Result<RingId, RingError> {
    if size == 0 {
        return Err(RingError::InvalidSize);
    }
    let page_count = (size.saturating_add(4095)) / 4096;
    if page_count == 0 {
        return Err(RingError::InvalidSize);
    }

    let mut frames = Vec::with_capacity(page_count);
    let mut alloc_failed = false;
    for _ in 0..page_count {
        let frame =
            match crate::sync::with_irqs_disabled(|token| crate::memory::allocate_frame(token)) {
                Ok(f) => f,
                Err(_) => {
                    alloc_failed = true;
                    break;
                }
            };
        let v = crate::memory::phys_to_virt(frame.start_address.as_u64());
        unsafe { core::ptr::write_bytes(v as *mut u8, 0, 4096) };
        frames.push(frame);
    }
    if alloc_failed {
        for rollback in frames.drain(..) {
            crate::sync::with_irqs_disabled(|token| crate::memory::free_frame(token, rollback));
        }
        return Err(RingError::Alloc);
    }

    let id = RingId(NEXT_RING_ID.fetch_add(1, Ordering::Relaxed));
    let owner_cap_ids = (0..page_count).map(|_| allocate_mapping_cap_id()).collect::<Vec<_>>();
    let mapping_cap_ids = (0..page_count).map(|_| allocate_mapping_cap_id()).collect();

    for (frame, owner_cap_id) in frames.iter().zip(owner_cap_ids.iter().copied()) {
        register_mapping_identity(resolve_handle(frame.start_address), owner_cap_id);
    }

    let ring = Arc::new(SharedRing {
        size,
        frames,
        owner_cap_ids,
        mapping_cap_ids,
    });

    let mut reg = RINGS.lock();
    ensure_registry(&mut *reg);
    reg.as_mut().unwrap().insert(id, ring);
    Ok(id)
}

/// Returns ring.
pub fn get_ring(id: RingId) -> Option<Arc<SharedRing>> {
    let reg = RINGS.lock();
    reg.as_ref().and_then(|map| map.get(&id).cloned())
}

/// Destroys ring.
pub fn destroy_ring(id: RingId) -> Result<(), RingError> {
    let mut reg = RINGS.lock();
    let map = reg.as_mut().ok_or(RingError::NotFound)?;

    // ==========================================================================
    // CRITICAL: BTreeMap corruption guard
    //
    // A corrupted heap can produce a BTreeMap whose internal node pointers are
    // invalid (e.g. NULL + offset 16 = 0x10), causing remove() to page-fault.
    // Sanity-check `len()` before mutating: the ring registry never holds more
    // than a few hundred entries under normal operation.  An absurd value
    // indicates that the BTreeMap header itself has been overwritten, and
    // calling remove() would immediately dereference a bad node pointer.
    //
    // In that case we bail early rather than crash.  The heap poison detector
    // in heap.rs will identify the corrupting allocation on the next alloc/free.
    // ==========================================================================
    let len = map.len();
    if len > 10_000 {
        crate::serial_println!(
            "\x1b[1;31m[ipc] RINGS BTreeMap corrupted: len={} for id={} \u{2014} aborting remove\x1b[0m",
            len, id.as_u64()
        );
        return Err(RingError::NotFound);
    }
    crate::serial_println!("[ipc] destroy_ring(id={}) map.len={}", id.as_u64(), len);

    let ring = map.remove(&id).ok_or(RingError::NotFound)?;
    drop(reg);

    for &cap_id in ring.mapping_cap_ids() {
        let _ = revoke_mapping_cap_id(cap_id);
    }
    Ok(())
}
