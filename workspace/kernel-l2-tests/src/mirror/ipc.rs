//! Mirror of kernel/src/ipc — pure modules only.
#[path = "../../../kernel/src/ipc/message.rs"]
pub mod message;
#[path = "../../../kernel/src/ipc/lockfree_ring.rs"]
pub mod lockfree_ring;
#[path = "../../../kernel/src/ipc/mailbox.rs"]
pub mod mailbox;

/// Minimal stand-in for the kernel transport traits used by LockFreeRing.
/// Signatures mirror kernel/src/ipc/transport.rs closely enough for the
/// included impl blocks to compile and behave identically.
pub mod transport {
    /// Isolation level of an IPC transport (mirror of kernel enum).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    #[repr(u8)]
    pub enum TransportLevel {
        TypeSafe = 1,
        LockFree = 2,
        Mmu = 3,
    }

    /// Capability descriptor (mirror of kernel struct).
    #[derive(Debug, Clone, Copy)]
    pub struct TransportCapabilities {
        pub max_message_size: usize,
        pub blocking: bool,
        pub zero_copy: bool,
        pub vectored: bool,
        pub directions: u8,
        pub estimated_cost_cycles: u32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum IpcError {
        NoReceiver,
        MessageTooLarge,
        WouldBlock,
        Closed,
        TransportFailed,
        BufferTooSmall,
    }

    /// Core trait — metadata only, exactly like kernel/src/ipc/transport.rs.
    pub trait IpcTransport: Send + Sync {
        fn level(&self) -> TransportLevel;
        fn capabilities(&self) -> TransportCapabilities;
        fn name(&self) -> &'static str;
    }

    /// Producer side : sends messages into the transport.
    pub trait IpcProducer: IpcTransport {
        fn send(&self, msg: &[u8]) -> Result<(), IpcError>;
        fn try_send(&self, msg: &[u8]) -> Result<(), IpcError>;

        fn send_vectored(&self, bufs: &[&[u8]]) -> Result<(), IpcError> {
            let total: usize = bufs.iter().map(|b| b.len()).sum();
            if total > self.capabilities().max_message_size {
                return Err(IpcError::MessageTooLarge);
            }
            let mut buf = alloc::vec![0u8; total];
            let mut offset = 0;
            for b in bufs {
                buf[offset..offset + b.len()].copy_from_slice(b);
                offset += b.len();
            }
            self.send(&buf)
        }
    }

    /// Consumer side : receives messages from the transport.
    pub trait IpcConsumer: IpcTransport {
        fn recv(&self, buf: &mut [u8]) -> Result<usize, IpcError>;
        fn try_recv(&self, buf: &mut [u8]) -> Result<Option<usize>, IpcError>;
    }

    pub trait IpcNotification: IpcTransport {
        fn notify_consumer(&self);
        fn notify_producer(&self);
        fn wait_notification(&self) -> Result<(), IpcError>;
    }
}

// Mirror of transport.rs impls for LockFreeRing (verbatim semantics).
impl IpcProducer for crate::ipc::lockfree_ring::LockFreeRing {
    fn send(&self, msg: &[u8]) -> Result<(), IpcError> {
        use crate::ipc::lockfree_ring::RingError;
        self.write(msg).map_err(|e| match e {
            RingError::Full => IpcError::WouldBlock,
            RingError::Empty => IpcError::WouldBlock,
            RingError::MessageTooLarge => IpcError::MessageTooLarge,
            _ => IpcError::Closed,
        })?;
        self.notify_consumer_raw();
        Ok(())
    }

    fn try_send(&self, msg: &[u8]) -> Result<(), IpcError> {
        use crate::ipc::lockfree_ring::RingError;
        self.write(msg).map_err(|e| match e {
            RingError::Full => IpcError::WouldBlock,
            RingError::Empty => IpcError::WouldBlock,
            RingError::MessageTooLarge => IpcError::MessageTooLarge,
            _ => IpcError::Closed,
        })?;
        self.notify_consumer_raw();
        Ok(())
    }
}

impl IpcConsumer for crate::ipc::lockfree_ring::LockFreeRing {
    fn recv(&self, buf: &mut [u8]) -> Result<usize, IpcError> {
        use crate::ipc::lockfree_ring::RingError;
        self.read(buf).map_err(|e| match e {
            RingError::Full => IpcError::WouldBlock,
            RingError::Empty => IpcError::WouldBlock,
            RingError::MessageTooLarge => IpcError::MessageTooLarge,
            _ => IpcError::Closed,
        })
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<usize>, IpcError> {
        use crate::ipc::lockfree_ring::RingError;
        self.try_read(buf).map_err(|e| match e {
            RingError::Full => IpcError::WouldBlock,
            RingError::Empty => IpcError::WouldBlock,
            RingError::MessageTooLarge => IpcError::MessageTooLarge,
            _ => IpcError::Closed,
        })
    }
}

// The kernel's metadata-only IpcTransport impl for LockFreeRing lives in
// transport.rs (not included here); reproduce it against the shim traits.
use transport::{IpcConsumer, IpcError, IpcProducer, IpcTransport, TransportCapabilities, TransportLevel};

impl IpcTransport for crate::ipc::lockfree_ring::LockFreeRing {
    fn level(&self) -> TransportLevel {
        TransportLevel::LockFree
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            max_message_size: 2048,
            blocking: true,
            zero_copy: true,
            vectored: true,
            directions: 2,
            estimated_cost_cycles: 400,
        }
    }

    fn name(&self) -> &'static str {
        "lockfree"
    }
}
