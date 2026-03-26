use crate::{
    capability::CapabilityTable,
    memory::AddressSpace,
    process::{signal::SigActionData, task::SyncUnsafeCell},
    sync::SpinLock,
    vfs::FileDescriptorTable,
};
use alloc::{string::String, sync::Arc};
use core::sync::atomic::{AtomicU32, AtomicU64};

/// Represents a process (a group of threads sharing resources).
pub struct Process {
    /// Process identifier visible to userspace.
    pub pid: crate::process::Pid,

    /// Address space for this process
    pub address_space: SyncUnsafeCell<Arc<AddressSpace>>,
    /// Serializes replacement and cloning of the process address space Arc.
    pub address_space_lock: SpinLock<()>,
    /// File descriptor table for this process
    pub fd_table: SyncUnsafeCell<FileDescriptorTable>,
    /// Capabilities granted to this process
    pub capabilities: SyncUnsafeCell<CapabilityTable>,

    /// Signal actions (handlers) for this process
    pub signal_actions: SyncUnsafeCell<[SigActionData; 64]>,

    /// Program break (end of heap), in bytes. 0 = not yet initialised.
    pub brk: AtomicU64,
    /// mmap_hint: next candidate virtual address for anonymous mmap allocations
    pub mmap_hint: AtomicU64,

    /// Current working directory (POSIX, inherited by children).
    pub cwd: SyncUnsafeCell<String>,
    /// File creation mask (inherited by children, NOT reset by exec).
    pub umask: AtomicU32,
}

impl Process {
    /// Creates a new instance.
    pub fn new(pid: crate::process::Pid, address_space: Arc<AddressSpace>) -> Self {
        address_space.set_owner_pid(pid);
        Self {
            pid,
            address_space: SyncUnsafeCell::new(address_space),
            address_space_lock: SpinLock::new(()),
            fd_table: SyncUnsafeCell::new(FileDescriptorTable::new()),
            capabilities: SyncUnsafeCell::new(CapabilityTable::new()),
            signal_actions: SyncUnsafeCell::new([SigActionData::default(); 64]),
            brk: AtomicU64::new(0),
            mmap_hint: AtomicU64::new(0x0000_0000_6000_0000),
            cwd: SyncUnsafeCell::new(String::from("/")),
            umask: AtomicU32::new(0o022),
        }
    }

    /// Clone the current address-space Arc under the process slot lock.
    pub fn address_space_arc(&self) -> Arc<AddressSpace> {
        let _guard = self.address_space_lock.lock();
        unsafe { (&*self.address_space.get()).clone() }
    }

    /// Replace the current address-space Arc and return the previous value.
    pub fn replace_address_space(&self, new_address_space: Arc<AddressSpace>) -> Arc<AddressSpace> {
        let _guard = self.address_space_lock.lock();
        unsafe { core::mem::replace(&mut *self.address_space.get(), new_address_space) }
    }
}
