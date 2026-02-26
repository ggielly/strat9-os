//! Capability-based Security System
//!
//! Implements a capability-based security model for Strat9-OS.
//! All kernel resources are accessed through unforgeable tokens (capabilities).

use crate::sync::SpinLock;
use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

/// Unique identifier for a capability
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapId(u64);

impl CapId {
    /// Generate a new unique capability ID
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        CapId(NEXT_ID.fetch_add(1, Ordering::SeqCst))
    }

    /// Convert a raw u64 into a CapId (used for syscall handles).
    pub fn from_raw(raw: u64) -> Self {
        CapId(raw)
    }

    /// Get the raw u64 value (for syscall return values).
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Types of kernel resources that can be accessed via capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    MemoryRegion,
    IoPortRange,
    InterruptLine,
    IpcPort,
    /// A typed MPMC sync-channel (SyncChan), accessed via SYS_CHAN_* syscalls.
    Channel,
    /// Shared-memory ring buffer for bulk IPC (SYS_IPC_RING_*).
    SharedRing,
    /// POSIX-like counting semaphore (SYS_SEM_*).
    Semaphore,
    Device,
    AddressSpace,
    Silo,
    Module,
    File,
    Nic,
    FileSystem,
    Console,
    Keyboard,
    Volume,
    Namespace,
}

/// Permissions associated with a capability
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    /// Allow granting this capability to other processes
    pub grant: bool,
    /// Allow revoking this capability
    pub revoke: bool,
}

impl CapPermissions {
    /// Create permissions with all rights disabled
    pub const fn none() -> Self {
        CapPermissions {
            read: false,
            write: false,
            execute: false,
            grant: false,
            revoke: false,
        }
    }

    /// Create permissions with read and write rights
    pub const fn read_write() -> Self {
        CapPermissions {
            read: true,
            write: true,
            execute: false,
            grant: false,
            revoke: false,
        }
    }

    /// Create permissions with all rights enabled
    pub const fn all() -> Self {
        CapPermissions {
            read: true,
            write: true,
            execute: true,
            grant: true,
            revoke: true,
        }
    }
}

/// A capability token that grants access to a kernel resource
#[derive(Debug, Clone)]
pub struct Capability {
    /// Unique identifier for this capability
    pub id: CapId,
    /// Type of resource this capability grants access to
    pub resource_type: ResourceType,
    /// Permissions associated with this capability
    pub permissions: CapPermissions,
    /// Reference to the actual resource (opaque to prevent direct access)
    pub resource: usize, // Actually a pointer to the resource, cast to usize
}

/// Table of capabilities for a process
pub struct CapabilityTable {
    /// Mapping from capability ID to capability
    capabilities: BTreeMap<CapId, Capability>,
}

impl Clone for CapabilityTable {
    fn clone(&self) -> Self {
        Self {
            capabilities: self.capabilities.clone(),
        }
    }
}

impl CapabilityTable {
    /// Create a new empty capability table
    pub fn new() -> Self {
        CapabilityTable {
            capabilities: BTreeMap::new(),
        }
    }

    /// Insert a capability into the table
    pub fn insert(&mut self, cap: Capability) -> CapId {
        let id = cap.id;
        self.capabilities.insert(id, cap);
        id
    }

    /// Remove a capability from the table
    pub fn remove(&mut self, id: CapId) -> Option<Capability> {
        self.capabilities.remove(&id)
    }

    /// Get a reference to a capability (no permission check).
    pub fn get(&self, id: CapId) -> Option<&Capability> {
        self.capabilities.get(&id)
    }

    /// Revoke all capabilities in this table and clear it.
    /// Does not allocate memory.
    pub fn revoke_all(&mut self) {
        let mgr = get_capability_manager();
        // BTreeMap::clear() does not allocate
        for (id, _) in self.capabilities.iter() {
            mgr.revoke_capability(*id);
        }
        self.capabilities.clear();
    }

    /// Check whether any capability of the given resource type has required permissions.
    pub fn has_resource_type_with_permissions(
        &self,
        resource_type: ResourceType,
        required: CapPermissions,
    ) -> bool {
        self.capabilities.values().any(|cap| {
            cap.resource_type == resource_type
                && (!required.read || cap.permissions.read)
                && (!required.write || cap.permissions.write)
                && (!required.execute || cap.permissions.execute)
                && (!required.grant || cap.permissions.grant)
                && (!required.revoke || cap.permissions.revoke)
        })
    }

    /// Check whether a specific resource has required permissions.
    pub fn has_resource_with_permissions(
        &self,
        resource_type: ResourceType,
        resource: usize,
        required: CapPermissions,
    ) -> bool {
        self.capabilities.values().any(|cap| {
            cap.resource_type == resource_type
                && cap.resource == resource
                && (!required.read || cap.permissions.read)
                && (!required.write || cap.permissions.write)
                && (!required.execute || cap.permissions.execute)
                && (!required.grant || cap.permissions.grant)
                && (!required.revoke || cap.permissions.revoke)
        })
    }

    /// Get a reference to a capability if it exists and has the required permissions
    pub fn get_with_permissions(&self, id: CapId, required: CapPermissions) -> Option<&Capability> {
        self.capabilities.get(&id).filter(|cap| {
            // Check if the capability has all required permissions
            (!required.read || cap.permissions.read)
                && (!required.write || cap.permissions.write)
                && (!required.execute || cap.permissions.execute)
                && (!required.grant || cap.permissions.grant)
                && (!required.revoke || cap.permissions.revoke)
        })
    }

    /// Get a mutable reference to a capability if it exists and has the required permissions
    pub fn get_mut_with_permissions(
        &mut self,
        id: CapId,
        required: CapPermissions,
    ) -> Option<&mut Capability> {
        if let Some(cap) = self.capabilities.get_mut(&id) {
            // Check if the capability has all required permissions
            if (!required.read || cap.permissions.read)
                && (!required.write || cap.permissions.write)
                && (!required.execute || cap.permissions.execute)
                && (!required.grant || cap.permissions.grant)
                && (!required.revoke || cap.permissions.revoke)
            {
                Some(cap)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Duplicate a capability (grant permission required)
    pub fn duplicate(&mut self, id: CapId) -> Option<Capability> {
        if let Some(cap) = self.capabilities.get(&id) {
            if cap.permissions.grant {
                // Create a new capability with the same properties
                Some(Capability {
                    id: CapId::new(),
                    resource_type: cap.resource_type,
                    permissions: cap.permissions,
                    resource: cap.resource,
                })
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Global capability manager
pub struct CapabilityManager {
    /// All capabilities in the system
    all_capabilities: SpinLock<BTreeMap<CapId, Capability>>,
}

impl CapabilityManager {
    /// Create a new capability manager
    pub fn new() -> Self {
        CapabilityManager {
            all_capabilities: SpinLock::new(BTreeMap::new()),
        }
    }

    /// Register a new resource and return a capability to access it
    pub fn create_capability(
        &self,
        resource_type: ResourceType,
        resource: usize,
        permissions: CapPermissions,
    ) -> Capability {
        let cap = Capability {
            id: CapId::new(),
            resource_type,
            permissions,
            resource,
        };

        self.all_capabilities.lock().insert(cap.id, cap.clone());
        cap
    }

    /// Revoke a capability (removes it from the global table)
    pub fn revoke_capability(&self, id: CapId) -> Option<Capability> {
        self.all_capabilities.lock().remove(&id)
    }
}

use spin::Once;

static CAPABILITY_MANAGER: Once<CapabilityManager> = Once::new();

/// Get a reference to the global capability manager
pub fn get_capability_manager() -> &'static CapabilityManager {
    CAPABILITY_MANAGER.call_once(CapabilityManager::new)
}
