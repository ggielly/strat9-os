use alloc::sync::Arc;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, AtomicU64};
use crate::memory::AddressSpace;
use crate::vfs::FileDescriptorTable;
use crate::capability::CapabilityTable;
use crate::process::task::SyncUnsafeCell;
use crate::process::signal::SigActionData;

/// Represents a process (a group of threads sharing resources).
pub struct Process {
    /// Process identifier visible to userspace.
    pub pid: crate::process::Pid,
    
    /// Address space for this process
    pub address_space: SyncUnsafeCell<Arc<AddressSpace>>,
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
    pub fn new(
        pid: crate::process::Pid,
        address_space: Arc<AddressSpace>,
    ) -> Self {
        Self {
            pid,
            address_space: SyncUnsafeCell::new(address_space),
            fd_table: SyncUnsafeCell::new(FileDescriptorTable::new()),
            capabilities: SyncUnsafeCell::new(CapabilityTable::new()),
            signal_actions: SyncUnsafeCell::new([SigActionData::default(); 64]),
            brk: AtomicU64::new(0),
            mmap_hint: AtomicU64::new(0x0000_0000_6000_0000),
            cwd: SyncUnsafeCell::new(String::from("/")),
            umask: AtomicU32::new(0o022),
        }
    }
}
