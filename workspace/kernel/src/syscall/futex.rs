//! Futex (Fast Userspace Mutex) syscall handlers
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use core::arch::asm;
use core::sync::atomic::Ordering;

use super::error::SyscallError;
use crate::memory::userslice::{UserSliceRead, UserSliceReadWrite};
use crate::process::{block_current_task, current_task_id, wake_task};
use crate::sync::{SpinLock, SpinLockGuard};

struct FutexQueue {
    waiters: SpinLock<VecDeque<crate::process::TaskId>>,
}

impl FutexQueue {
    const fn new() -> Self {
        FutexQueue {
            waiters: SpinLock::new(VecDeque::new()),
        }
    }

    fn pop_waiter(&self) -> Option<crate::process::TaskId> {
        let mut waiters = self.waiters.lock();
        waiters.pop_front()
    }

    fn remove_waiter(&self, id: crate::process::TaskId) {
        let mut waiters = self.waiters.lock();
        if let Some(pos) = waiters.iter().position(|&x| x == id) {
            waiters.remove(pos);
        }
    }

    fn is_empty(&self) -> bool {
        self.waiters.lock().is_empty()
    }
}

static FUTEX_QUEUES: SpinLock<BTreeMap<u64, Arc<FutexQueue>>> =
    SpinLock::new(BTreeMap::new());

fn get_queue(addr: u64) -> Arc<FutexQueue> {
    let mut map = FUTEX_QUEUES.lock();
    map.entry(addr)
        .or_insert_with(|| Arc::new(FutexQueue::new()))
        .clone()
}

fn read_u32(addr: u64) -> Result<u32, SyscallError> {
    let slice = UserSliceRead::new(addr, core::mem::size_of::<u32>())
        .map_err(|_| SyscallError::Fault)?;
    slice.read_val::<u32>().map_err(|_| SyscallError::Fault)
}

#[inline]
unsafe fn atomic_cmpxchg_u32(ptr: *mut u32, expected: u32, desired: u32) -> u32 {
    let mut old = expected;
    unsafe {
        asm!(
            "lock cmpxchgl {desired:e}, [{ptr}]",
            ptr = in(reg) ptr,
            desired = in(reg) desired,
            inout("eax") old,
            options(nostack, preserves_flags),
        );
    }
    old
}

fn atomic_fetch_update_u32<F>(addr: u64, update: F) -> Result<u32, SyscallError>
where
    F: Fn(u32) -> u32,
{
    if (addr & 0x3) != 0 {
        return Err(SyscallError::InvalidArgument);
    }
    let _slice =
        UserSliceReadWrite::new(addr, core::mem::size_of::<u32>()).map_err(|_| SyscallError::Fault)?;
    let ptr = addr as *mut u32;
    let mut cur = unsafe { core::ptr::read_volatile(ptr) };
    loop {
        let new = update(cur);
        let observed = unsafe { atomic_cmpxchg_u32(ptr, cur, new) };
        if observed == cur {
            return Ok(cur);
        }
        cur = observed;
    }
}

fn lock_two_queues<'a>(
    addr1: u64,
    q1: &'a FutexQueue,
    addr2: u64,
    q2: &'a FutexQueue,
) -> (
    SpinLockGuard<'a, VecDeque<crate::process::TaskId>>,
    SpinLockGuard<'a, VecDeque<crate::process::TaskId>>,
) {
    if addr1 <= addr2 {
        let g1 = q1.waiters.lock();
        let g2 = q2.waiters.lock();
        (g1, g2)
    } else {
        let g2 = q2.waiters.lock();
        let g1 = q1.waiters.lock();
        (g1, g2)
    }
}

fn wake_from_queue(queue: &FutexQueue, max_wake: u32) -> u64 {
    let mut woke = 0u64;
    while woke < max_wake as u64 {
        if let Some(id) = queue.pop_waiter() {
            if wake_task(id) {
                woke += 1;
            }
        } else {
            break;
        }
    }
    woke
}

fn wake_from_waiters(waiters: &mut VecDeque<crate::process::TaskId>, max_wake: u32) -> u64 {
    let mut woke = 0u64;
    while woke < max_wake as u64 {
        if let Some(id) = waiters.pop_front() {
            if wake_task(id) {
                woke += 1;
            }
        } else {
            break;
        }
    }
    woke
}

fn do_requeue(addr1: u64, max_wake: u32, max_requeue: u32, addr2: u64) -> Result<u64, SyscallError> {
    if addr1 == addr2 {
        return sys_futex_wake(addr1, max_wake);
    }

    let queue1 = {
        let map = FUTEX_QUEUES.lock();
        map.get(&addr1).cloned()
    };
    let Some(queue1) = queue1 else {
        return Ok(0);
    };

    let queue2 = get_queue(addr2);

    let mut woke = 0u64;
    let mut requeued = 0u64;

    {
        let (mut w1, mut w2) = lock_two_queues(addr1, &queue1, addr2, &queue2);

        while woke < max_wake as u64 {
            if let Some(id) = w1.pop_front() {
                if wake_task(id) {
                    woke += 1;
                }
            } else {
                break;
            }
        }

        while requeued < max_requeue as u64 {
            if let Some(id) = w1.pop_front() {
                w2.push_back(id);
                requeued += 1;
            } else {
                break;
            }
        }
    }

    if queue1.is_empty() {
        let mut map = FUTEX_QUEUES.lock();
        map.remove(&addr1);
    }

    if queue2.is_empty() {
        let mut map = FUTEX_QUEUES.lock();
        map.remove(&addr2);
    }

    Ok(woke + requeued)
}

struct FutexWakeOpEncode {
    op: u32,
    is_oparg_shift: bool,
    cmp: u32,
    oparg: u32,
    cmparg: u32,
}

impl FutexWakeOpEncode {
    fn decode(bits: u32) -> Result<Self, SyscallError> {
        let is_oparg_shift = ((bits >> 31) & 1) == 1;
        let op = (bits >> 28) & 0x7;
        let cmp = (bits >> 24) & 0xF;
        let oparg = (bits >> 12) & 0xFFF;
        let cmparg = bits & 0xFFF;

        if op > 4 || cmp > 5 {
            return Err(SyscallError::InvalidArgument);
        }

        Ok(Self {
            op,
            is_oparg_shift,
            cmp,
            oparg,
            cmparg,
        })
    }

    fn effective_oparg(&self) -> u32 {
        if self.is_oparg_shift {
            1u32 << (self.oparg & 31)
        } else {
            self.oparg
        }
    }

    fn calculate_new_val(&self, old_val: u32) -> u32 {
        let oparg = self.effective_oparg();
        match self.op {
            0 => oparg,
            1 => oparg.wrapping_add(old_val),
            2 => oparg | old_val,
            3 => oparg & !old_val,
            4 => oparg ^ old_val,
            _ => old_val,
        }
    }

    fn should_wake(&self, old_val: u32) -> bool {
        match self.cmp {
            0 => old_val == self.cmparg,
            1 => old_val != self.cmparg,
            2 => old_val < self.cmparg,
            3 => old_val <= self.cmparg,
            4 => old_val > self.cmparg,
            5 => old_val >= self.cmparg,
            _ => false,
        }
    }
}

/// SYS_FUTEX_WAIT: Wait on a futex
pub fn sys_futex_wait(_addr: u64, _val: u32, _timeout_ns: u64) -> Result<u64, SyscallError> {
    let addr = _addr;
    let val = _val;
    let timeout_ns = _timeout_ns;
    let id = current_task_id().ok_or(SyscallError::PermissionDenied)?;
    let queue = get_queue(addr);

    if timeout_ns != 0 {
        let deadline = crate::syscall::time::current_time_ns().saturating_add(timeout_ns);
        if let Some(task) = crate::process::get_task_by_id(id) {
            task.wake_deadline_ns.store(deadline, Ordering::Relaxed);
        }
    }

    // Lost-wakeup hardening:
    // Hold the futex queue lock while validating the futex word and enqueuing.
    // This closes the race window between `check value` and `enqueue`.
    {
        let mut waiters = queue.waiters.lock();
        let cur = read_u32(addr)?;
        if cur != val {
            return Err(SyscallError::Again); // EAGAIN
        }
        waiters.push_back(id);
    }

    block_current_task();

    // Remove ourselves if still queued (timeout or spurious wake).
    queue.remove_waiter(id);

    if let Some(task) = crate::process::get_task_by_id(id) {
        let deadline = task.wake_deadline_ns.load(Ordering::Relaxed);
        task.wake_deadline_ns.store(0, Ordering::Relaxed);
        if timeout_ns != 0 && deadline != 0 {
            let now = crate::syscall::time::current_time_ns();
            if now >= deadline {
                return Err(SyscallError::TimedOut);
            }
        }
    }

    Ok(0)
}

/// SYS_FUTEX_WAKE: Wake waiters on a futex
pub fn sys_futex_wake(_addr: u64, _max_wake: u32) -> Result<u64, SyscallError> {
    let addr = _addr;
    let max_wake = _max_wake;
    let queue = {
        let map = FUTEX_QUEUES.lock();
        map.get(&addr).cloned()
    };

    let Some(queue) = queue else {
        return Ok(0);
    };

    let mut woke = 0u64;
    while woke < max_wake as u64 {
        if let Some(id) = queue.pop_waiter() {
            if wake_task(id) {
                woke += 1;
            }
        } else {
            break;
        }
    }

    if queue.is_empty() {
        let mut map = FUTEX_QUEUES.lock();
        map.remove(&addr);
    }

    Ok(woke)
}

/// SYS_FUTEX_REQUEUE: Requeue waiters from one futex to another
pub fn sys_futex_requeue(
    _addr1: u64,
    _max_wake: u32,
    _max_requeue: u32,
    _addr2: u64,
) -> Result<u64, SyscallError> {
    do_requeue(_addr1, _max_wake, _max_requeue, _addr2)
}

/// SYS_FUTEX_CMP_REQUEUE: Conditional requeue
pub fn sys_futex_cmp_requeue(
    _addr1: u64,
    _max_wake: u32,
    _max_requeue: u32,
    _addr2: u64,
    _expected_val: u32,
) -> Result<u64, SyscallError> {
    // Linux/Asterinas model: validate current value first, then perform the same
    // wake+requeue operation as FUTEX_REQUEUE.
    let cur = read_u32(_addr1)?;
    if cur != _expected_val {
        return Err(SyscallError::Again); // EAGAIN
    }
    do_requeue(_addr1, _max_wake, _max_requeue, _addr2)
}

/// SYS_FUTEX_WAKE_OP: Wake with atomic operation
pub fn sys_futex_wake_op(
    _addr1: u64,
    _max_wake1: u32,
    _max_wake2: u32,
    _addr2: u64,
    _op: u32,
) -> Result<u64, SyscallError> {
    let addr1 = _addr1;
    let addr2 = _addr2;
    let max_wake1 = _max_wake1;
    let max_wake2 = _max_wake2;
    let wake_op = FutexWakeOpEncode::decode(_op)?;

    // Materialize queues so wake and wait operations serialize on queue locks.
    let q1 = get_queue(addr1);
    let q2 = get_queue(addr2);

    let woke = if addr1 == addr2 {
        let mut waiters = q1.waiters.lock();
        let old = atomic_fetch_update_u32(addr2, |v| wake_op.calculate_new_val(v))?;
        let mut woke = wake_from_waiters(&mut waiters, max_wake1);
        if wake_op.should_wake(old) {
            woke += wake_from_waiters(&mut waiters, max_wake2);
        }
        woke
    } else {
        let (mut w1, mut w2) = lock_two_queues(addr1, &q1, addr2, &q2);
        let old = atomic_fetch_update_u32(addr2, |v| wake_op.calculate_new_val(v))?;
        let mut woke = wake_from_waiters(&mut w1, max_wake1);
        if wake_op.should_wake(old) {
            woke += wake_from_waiters(&mut w2, max_wake2);
        }
        woke
    };
    if q1.is_empty() {
        let mut map = FUTEX_QUEUES.lock();
        map.remove(&addr1);
    }
    if q2.is_empty() {
        let mut map = FUTEX_QUEUES.lock();
        map.remove(&addr2);
    }
    Ok(woke)
}
