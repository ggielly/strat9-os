use crate::{
    memory::{get_allocator, frame::FrameAllocator, PhysFrame},
    sync::SpinLock,
};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RingId(pub u64);

impl RingId {
    pub fn as_u64(self) -> u64 {
        self.0
    }
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
}

impl SharedRing {
    pub fn size(&self) -> usize {
        self.size
    }

    pub fn page_count(&self) -> usize {
        self.frames.len()
    }

    pub fn frame_phys_addrs(&self) -> Vec<u64> {
        self.frames
            .iter()
            .map(|f| f.start_address.as_u64())
            .collect()
    }
}

impl Drop for SharedRing {
    fn drop(&mut self) {
        for frame in self.frames.drain(..) {
            crate::memory::cow::frame_dec_ref(frame);
        }
    }
}

static NEXT_RING_ID: AtomicU64 = AtomicU64::new(1);
static RINGS: SpinLock<Option<BTreeMap<RingId, Arc<SharedRing>>>> = SpinLock::new(None);

fn ensure_registry(guard: &mut Option<BTreeMap<RingId, Arc<SharedRing>>>) {
    if guard.is_none() {
        *guard = Some(BTreeMap::new());
    }
}

pub fn create_ring(size: usize) -> Result<RingId, RingError> {
    if size == 0 {
        return Err(RingError::InvalidSize);
    }
    let page_count = (size.saturating_add(4095)) / 4096;
    if page_count == 0 {
        return Err(RingError::InvalidSize);
    }

    let mut frames = Vec::with_capacity(page_count);
    let alloc_failed = {
        let mut guard = get_allocator().lock();
        let alloc = guard.as_mut().ok_or(RingError::Alloc)?;
        let mut failed = false;
        for _ in 0..page_count {
            let frame = match alloc.alloc_frame() {
                Ok(f) => f,
                Err(_) => {
                    failed = true;
                    break;
                }
            };
            let v = crate::memory::phys_to_virt(frame.start_address.as_u64());
            unsafe { core::ptr::write_bytes(v as *mut u8, 0, 4096) };
            crate::memory::cow::frame_inc_ref(frame);
            frames.push(frame);
        }
        failed
    };
    if alloc_failed {
        for rollback in frames.drain(..) {
            crate::memory::cow::frame_dec_ref(rollback);
        }
        return Err(RingError::Alloc);
    }

    let id = RingId(NEXT_RING_ID.fetch_add(1, Ordering::Relaxed));
    let ring = Arc::new(SharedRing { size, frames });

    let mut reg = RINGS.lock();
    ensure_registry(&mut *reg);
    reg.as_mut().unwrap().insert(id, ring);
    Ok(id)
}

pub fn get_ring(id: RingId) -> Option<Arc<SharedRing>> {
    let reg = RINGS.lock();
    reg.as_ref().and_then(|map| map.get(&id).cloned())
}

pub fn destroy_ring(id: RingId) -> Result<(), RingError> {
    let mut reg = RINGS.lock();
    let map = reg.as_mut().ok_or(RingError::NotFound)?;
    map.remove(&id).ok_or(RingError::NotFound)?;
    Ok(())
}
