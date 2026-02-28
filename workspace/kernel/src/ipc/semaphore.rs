use crate::sync::{SpinLock, WaitQueue};
use alloc::{collections::BTreeMap, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemId(pub u64);

impl SemId {
    pub fn as_u64(self) -> u64 {
        self.0
    }
    pub fn from_u64(raw: u64) -> Self {
        Self(raw)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SemaphoreError {
    #[error("would block")]
    WouldBlock,
    #[error("semaphore destroyed")]
    Destroyed,
    #[error("invalid initial value")]
    InvalidValue,
    #[error("semaphore not found")]
    NotFound,
}

pub struct PosixSemaphore {
    count: AtomicI32,
    destroyed: AtomicBool,
    waitq: WaitQueue,
}

impl PosixSemaphore {
    fn new(initial: u32) -> Self {
        Self {
            count: AtomicI32::new(initial as i32),
            destroyed: AtomicBool::new(false),
            waitq: WaitQueue::new(),
        }
    }

    pub fn wait(&self) -> Result<(), SemaphoreError> {
        self.waitq.wait_until(|| {
            if self.destroyed.load(Ordering::Acquire) {
                return Some(Err(SemaphoreError::Destroyed));
            }
            let cur = self.count.load(Ordering::Acquire);
            if cur <= 0 {
                return None;
            }
            match self.count.compare_exchange_weak(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => Some(Ok(())),
                Err(_) => None,
            }
        })
    }

    pub fn try_wait(&self) -> Result<(), SemaphoreError> {
        if self.destroyed.load(Ordering::Acquire) {
            return Err(SemaphoreError::Destroyed);
        }
        loop {
            let cur = self.count.load(Ordering::Acquire);
            if cur <= 0 {
                return Err(SemaphoreError::WouldBlock);
            }
            if self
                .count
                .compare_exchange_weak(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    pub fn post(&self) -> Result<(), SemaphoreError> {
        if self.destroyed.load(Ordering::Acquire) {
            return Err(SemaphoreError::Destroyed);
        }
        loop {
            let cur = self.count.load(Ordering::Acquire);
            if cur >= i32::MAX {
                return Err(SemaphoreError::InvalidValue);
            }
            if self.count.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                break;
            }
        }
        self.waitq.wake_one();
        Ok(())
    }

    pub fn destroy(&self) {
        self.destroyed.store(true, Ordering::Release);
        self.waitq.wake_all();
    }

    pub fn count(&self) -> i32 {
        self.count.load(Ordering::Acquire)
    }

    pub fn is_destroyed(&self) -> bool {
        self.destroyed.load(Ordering::Acquire)
    }
}

static NEXT_SEM_ID: AtomicU64 = AtomicU64::new(1);
static SEMAPHORES: SpinLock<Option<BTreeMap<SemId, Arc<PosixSemaphore>>>> = SpinLock::new(None);

fn ensure_registry(guard: &mut Option<BTreeMap<SemId, Arc<PosixSemaphore>>>) {
    if guard.is_none() {
        *guard = Some(BTreeMap::new());
    }
}

pub fn create_semaphore(initial: u32) -> Result<SemId, SemaphoreError> {
    if initial > i32::MAX as u32 {
        return Err(SemaphoreError::InvalidValue);
    }
    let id = SemId(NEXT_SEM_ID.fetch_add(1, Ordering::Relaxed));
    let sem = Arc::new(PosixSemaphore::new(initial));
    let mut reg = SEMAPHORES.lock();
    ensure_registry(&mut *reg);
    reg.as_mut().unwrap().insert(id, sem);
    Ok(id)
}

pub fn get_semaphore(id: SemId) -> Option<Arc<PosixSemaphore>> {
    let reg = SEMAPHORES.lock();
    reg.as_ref().and_then(|m| m.get(&id).cloned())
}

pub fn destroy_semaphore(id: SemId) -> Result<(), SemaphoreError> {
    let sem = {
        let mut reg = SEMAPHORES.lock();
        let map = reg.as_mut().ok_or(SemaphoreError::NotFound)?;
        map.remove(&id).ok_or(SemaphoreError::NotFound)?
    };
    sem.destroy();
    Ok(())
}
