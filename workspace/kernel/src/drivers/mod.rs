//! Driver implementations for Strat9-OS kernel
//!
//! Contains hardware driver implementations for various devices.
//!
//! # Architecture
//!
//! ```text
//! drivers/
//! ├── net/           Common NetworkDevice trait, device registry, NetScheme
//! │   ├── e1000      Intel E1000 Gigabit Ethernet (MMIO)
//! │   └── scheme     VFS scheme mounted at /dev/net/
//! └── virtio/        VirtIO device framework (QEMU/KVM)
//!     ├── block      VirtIO block device
//!     ├── net        VirtIO network device
//!     └── common     Shared virtqueue infrastructure
//! ```
//!
//! Every network driver implements [`net::NetworkDevice`] and is registered
//! in a global device table.  The [`net::scheme::NetScheme`] exposes all
//! registered interfaces through the VFS at `/dev/net/`.
//!
//! ## Silo integration
//!
//! A future "driver" silo can host user-space drivers.  The kernel stub
//! will translate IPC messages (opcodes in [`net::ipc_opcodes`]) into
//! [`net::NetworkDevice`] calls, keeping the VFS path identical.

pub mod net;
pub mod virtio;

/// Initialise all built-in drivers.
///
/// Called from the component system during the bootstrap stage.
pub fn init() {
    net::init();
}
