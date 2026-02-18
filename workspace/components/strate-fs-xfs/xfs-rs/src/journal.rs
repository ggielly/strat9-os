//! XFS Journal (Log) support.
//!
//! XFS uses a write-ahead log for metadata consistency. This module provides
//! basic journal support for write operations.
//!
//! ## Journal Structure
//!
//! The XFS journal consists of:
//! - Log header (superblock)
//! - Log records (transactions)
//! - Wrap-around handling
//!
//! For simplicity, this implementation provides a "fake" journal that
//! marks the filesystem as clean/dirty without full transaction support.

extern crate alloc;

use alloc::vec::Vec;

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

/// Journal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalState {
    /// Journal is clean (no uncommitted transactions).
    Clean,
    /// Journal has uncommitted transactions.
    Dirty,
    /// Journal needs recovery.
    NeedsRecovery,
}

/// Journal header (simplified).
#[derive(Debug, Clone)]
pub struct JournalHeader {
    /// Magic number.
    pub magic: u32,
    /// Cycle number (wrap counter).
    pub cycle: u32,
    /// Version.
    pub version: u32,
    /// Log sector size.
    pub sector_size: u32,
    /// Log length in sectors.
    pub length: u32,
    /// Head position.
    pub head: u64,
    /// Tail position.
    pub tail: u64,
    /// Filesystem UUID.
    pub uuid: [u8; 16],
}

/// Journal magic numbers.
pub const XFS_LOG_MAGIC: u32 = 0xFEEDBABE;

impl JournalHeader {
    /// Header size.
    pub const SIZE: usize = 512;

    /// Parse journal header from bytes.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }

        let magic = buffer.read_be_u32(0)?;
        if magic != XFS_LOG_MAGIC {
            return Err(FsError::InvalidMagic);
        }

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buffer[24..40]);

        Ok(Self {
            magic,
            cycle: buffer.read_be_u32(4)?,
            version: buffer.read_be_u32(8)?,
            sector_size: buffer.read_be_u32(12)?,
            length: buffer.read_be_u32(16)?,
            head: buffer.read_be_u64(40)?,
            tail: buffer.read_be_u64(48)?,
            uuid,
        })
    }

    /// Check if the journal is clean.
    pub fn is_clean(&self) -> bool {
        self.head == self.tail
    }
}

/// Transaction record header.
#[derive(Debug, Clone)]
pub struct TransactionHeader {
    /// Magic number.
    pub magic: u32,
    /// Transaction ID.
    pub tid: u32,
    /// Number of operations in this transaction.
    pub num_ops: u32,
    /// Length of this record.
    pub len: u32,
}

impl TransactionHeader {
    pub const MAGIC: u32 = 0x54524E53;
    pub const SIZE: usize = 16;

    // "TRNS"

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_be_bytes());
        buf[4..8].copy_from_slice(&self.tid.to_be_bytes());
        buf[8..12].copy_from_slice(&self.num_ops.to_be_bytes());
        buf[12..16].copy_from_slice(&self.len.to_be_bytes());
        buf
    }
}

/// Type of journal operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalOpType {
    /// Inode update.
    Inode = 1,
    /// Buffer (block) update.
    Buffer = 2,
    /// Extent update.
    Extent = 3,
    /// AG header update.
    AgHeader = 4,
    /// Superblock update.
    Superblock = 5,
    /// Commit record.
    Commit = 6,
}

/// A journal operation (simplified).
#[derive(Debug, Clone)]
pub struct JournalOp {
    /// Operation type.
    pub op_type: JournalOpType,
    /// Target (inode number, block number, etc.).
    pub target: u64,
    /// Offset within target.
    pub offset: u32,
    /// Length of data.
    pub len: u32,
    /// Old data (for undo).
    pub old_data: Vec<u8>,
    /// New data.
    pub new_data: Vec<u8>,
}

impl JournalOp {
    /// Create a new inode update operation.
    pub fn inode_update(inode: u64, old_data: Vec<u8>, new_data: Vec<u8>) -> Self {
        Self {
            op_type: JournalOpType::Inode,
            target: inode,
            offset: 0,
            len: new_data.len() as u32,
            old_data,
            new_data,
        }
    }

    /// Create a new block update operation.
    pub fn block_update(block: u64, offset: u32, old_data: Vec<u8>, new_data: Vec<u8>) -> Self {
        Self {
            op_type: JournalOpType::Buffer,
            target: block,
            offset,
            len: new_data.len() as u32,
            old_data,
            new_data,
        }
    }
}

/// Simple transaction builder.
#[derive(Debug)]
pub struct Transaction {
    /// Transaction ID.
    pub tid: u32,
    /// Operations in this transaction.
    pub ops: Vec<JournalOp>,
    /// Whether the transaction has been committed.
    pub committed: bool,
}

impl Transaction {
    /// Create a new transaction.
    pub fn new(tid: u32) -> Self {
        Self {
            tid,
            ops: Vec::new(),
            committed: false,
        }
    }

    /// Add an operation to this transaction.
    pub fn add_op(&mut self, op: JournalOp) {
        self.ops.push(op);
    }

    /// Check if the transaction is empty.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// Journal manager for write operations.
///
/// This is a simplified implementation that tracks dirty state
/// without full transaction logging.
#[derive(Debug)]
pub struct JournalManager {
    /// Whether the journal is enabled.
    enabled: bool,
    /// Current transaction ID.
    next_tid: u32,
    /// Active transaction (if any).
    active_transaction: Option<Transaction>,
    /// Journal state.
    state: JournalState,
}

impl JournalManager {
    /// Create a new journal manager.
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            next_tid: 1,
            active_transaction: None,
            state: JournalState::Clean,
        }
    }

    /// Check if journaling is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the current journal state.
    pub fn state(&self) -> JournalState {
        self.state
    }

    /// Begin a new transaction.
    pub fn begin_transaction(&mut self) -> FsResult<u32> {
        if self.active_transaction.is_some() {
            return Err(FsError::Corrupted); // Already in a transaction
        }

        let tid = self.next_tid;
        self.next_tid = self.next_tid.wrapping_add(1);
        self.active_transaction = Some(Transaction::new(tid));
        self.state = JournalState::Dirty;

        Ok(tid)
    }

    /// Add an operation to the current transaction.
    pub fn add_op(&mut self, op: JournalOp) -> FsResult<()> {
        match &mut self.active_transaction {
            Some(txn) => {
                txn.add_op(op);
                Ok(())
            }
            None => Err(FsError::Corrupted), // No active transaction
        }
    }

    /// Commit the current transaction.
    ///
    /// In a full implementation, this would:
    /// 1. Write all operations to the log
    /// 2. Write a commit record
    /// 3. Sync the log to disk
    /// 4. Apply the changes to the filesystem
    /// 5. Mark the transaction as complete
    pub fn commit_transaction(&mut self) -> FsResult<()> {
        match &mut self.active_transaction {
            Some(txn) => {
                txn.committed = true;
                self.active_transaction = None;
                // In a real implementation, we'd persist the journal here
                // and only mark clean after all writes are done
                Ok(())
            }
            None => Err(FsError::Corrupted),
        }
    }

    /// Abort the current transaction.
    pub fn abort_transaction(&mut self) -> FsResult<()> {
        self.active_transaction = None;
        // Note: state remains dirty until explicitly marked clean
        Ok(())
    }

    /// Mark the journal as clean (after sync).
    pub fn mark_clean(&mut self) {
        if self.active_transaction.is_none() {
            self.state = JournalState::Clean;
        }
    }

    /// Get the active transaction (for adding ops).
    pub fn active_transaction_mut(&mut self) -> Option<&mut Transaction> {
        self.active_transaction.as_mut()
    }
}

/// Create a simple sync marker (used when journaling is disabled).
#[derive(Debug)]
pub struct SyncMarker {
    /// Whether filesystem is dirty.
    pub dirty: bool,
    /// Last sync timestamp.
    pub last_sync: u64,
}

impl SyncMarker {
    pub fn new() -> Self {
        Self {
            dirty: false,
            last_sync: 0,
        }
    }

    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    pub fn mark_clean(&mut self, timestamp: u64) {
        self.dirty = false;
        self.last_sync = timestamp;
    }
}

impl Default for SyncMarker {
    fn default() -> Self {
        Self::new()
    }
}
