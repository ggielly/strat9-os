//! Block-device scheme — exposes raw disk devices under `/dev`.
//!
//! ## Namespace layout
//!
//! ```text
//! /dev/          — directory listing (this scheme root)
//! /dev/sda       — first SATA disk (AHCI port 0), raw byte-addressable
//! ```
//!
//! ## I/O model
//!
//! The AHCI driver operates on 512-byte sectors.  This scheme accepts
//! arbitrary byte offsets and lengths and performs the necessary
//! sector-aligned read/modify/write internally using a stack-allocated
//! 512-byte bounce buffer.
//!
//! ## VFS wiring
//!
//! `BlkDevScheme` implements the kernel `Scheme` trait so it can be mounted
//! with `vfs::mount::mount("/dev", Arc::new(BlkDevScheme))` during `vfs::init()`.

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{
    hardware::storage::{
        ahci,
        virtio_block::{BlockDevice, BlockError, SECTOR_SIZE},
    },
    syscall::error::SyscallError,
    vfs::scheme::{DirEntry, FileFlags, FileStat, OpenFlags, OpenResult, Scheme, DT_BLK, DT_CHR},
};

// ─── File-ID constants ────────────────────────────────────────────────────────

const FID_ROOT:   u64 = 0;
const FID_SDA:    u64 = 1;
const FID_VDA:    u64 = 2;
const FID_NULL:   u64 = 3;
const FID_ZERO:   u64 = 4;
const FID_RANDOM: u64 = 5;
const FID_URANDOM: u64 = 6;

// ─── xorshift64 fallback PRNG ────────────────────────────────────────────────
static PRNG_STATE: AtomicU64 = AtomicU64::new(0xdeadbeef_cafebabe);

fn prng_fill(buf: &mut [u8]) {
    if crate::hardware::virtio::rng::is_available() {
        let _ = crate::hardware::virtio::rng::read_entropy(buf);
        return;
    }
    let ticks = crate::process::scheduler::ticks();
    let mut state = PRNG_STATE.load(Ordering::Relaxed) ^ ticks;
    for chunk in buf.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let bytes = state.to_le_bytes();
        let n = chunk.len();
        chunk.copy_from_slice(&bytes[..n]);
    }
    PRNG_STATE.store(state, Ordering::Relaxed);
}

// ─── BlkDevScheme ─────────────────────────────────────────────────────────────

/// Kernel scheme that serves raw block devices as files under `/dev`.
pub struct BlkDevScheme;

impl BlkDevScheme {
    pub fn new() -> Self {
        BlkDevScheme
    }
}

impl Scheme for BlkDevScheme {
    // ── open ─────────────────────────────────────────────────────────────────

    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        match path.trim_start_matches('/') {
            "" => {
                // Root directory
                Ok(OpenResult {
                    file_id: FID_ROOT,
                    size: None,
                    flags: FileFlags::DIRECTORY,
                })
            }
            "sda" => {
                let dev = ahci::get_device().ok_or(SyscallError::NotFound)?;
                Ok(OpenResult {
                    file_id: FID_SDA,
                    size: Some(dev.sector_count() * SECTOR_SIZE as u64),
                    flags: FileFlags::DEVICE,
                })
            }
            "vda" => {
                let dev = crate::hardware::storage::virtio_block::get_device()
                    .ok_or(SyscallError::NotFound)?;
                Ok(OpenResult {
                    file_id: FID_VDA,
                    size: Some(dev.sector_count() * SECTOR_SIZE as u64),
                    flags: FileFlags::DEVICE,
                })
            }
            "null" => Ok(OpenResult { file_id: FID_NULL,   size: Some(0), flags: FileFlags::DEVICE }),
            "zero" => Ok(OpenResult { file_id: FID_ZERO,   size: None,   flags: FileFlags::DEVICE }),
            "random"  => Ok(OpenResult { file_id: FID_RANDOM,  size: None, flags: FileFlags::DEVICE }),
            "urandom" => Ok(OpenResult { file_id: FID_URANDOM, size: None, flags: FileFlags::DEVICE }),
            _ => Err(SyscallError::NotFound),
        }
    }

    // ── read ─────────────────────────────────────────────────────────────────

    fn read(&self, file_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        match file_id {
            FID_ROOT => {
                let mut listing = String::new();
                listing.push_str("null\nurandom\nzero\nrandom\n");
                if ahci::get_device().is_some() { listing.push_str("sda\n"); }
                if crate::hardware::storage::virtio_block::get_device().is_some() {
                    listing.push_str("vda\n");
                }
                let bytes = listing.as_bytes();
                let start = offset as usize;
                if start >= bytes.len() { return Ok(0); }
                let n = (bytes.len() - start).min(buf.len());
                buf[..n].copy_from_slice(&bytes[start..start + n]);
                Ok(n)
            }
            FID_NULL => Ok(0),
            FID_ZERO => { buf.fill(0); Ok(buf.len()) }
            FID_RANDOM | FID_URANDOM => { prng_fill(buf); Ok(buf.len()) }
            FID_SDA => {
                let dev = ahci::get_device().ok_or(SyscallError::BadHandle)?;
                sector_read(dev, offset, buf).map_err(|_| SyscallError::IoError)
            }
            FID_VDA => {
                let dev = crate::hardware::storage::virtio_block::get_device()
                    .ok_or(SyscallError::BadHandle)?;
                sector_read(dev, offset, buf).map_err(|_| SyscallError::IoError)
            }
            _ => Err(SyscallError::BadHandle),
        }
    }

    // ── write ────────────────────────────────────────────────────────────────

    fn write(&self, file_id: u64, offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        match file_id {
            FID_NULL => Ok(buf.len()),
            FID_ZERO | FID_RANDOM | FID_URANDOM => Err(SyscallError::PermissionDenied),
            FID_SDA => {
                let dev = ahci::get_device().ok_or(SyscallError::BadHandle)?;
                sector_write(dev, offset, buf).map_err(|_| SyscallError::IoError)
            }
            FID_VDA => {
                let dev = crate::hardware::storage::virtio_block::get_device()
                    .ok_or(SyscallError::BadHandle)?;
                sector_write(dev, offset, buf).map_err(|_| SyscallError::IoError)
            }
            _ => Err(SyscallError::PermissionDenied),
        }
    }

    // ── close ────────────────────────────────────────────────────────────────

    fn close(&self, _file_id: u64) -> Result<(), SyscallError> {
        Ok(()) // stateless: nothing to clean up
    }

    // ── size ─────────────────────────────────────────────────────────────────

    fn size(&self, file_id: u64) -> Result<u64, SyscallError> {
        if file_id == FID_SDA {
            let dev = ahci::get_device().ok_or(SyscallError::BadHandle)?;
            return Ok(dev.sector_count() * SECTOR_SIZE as u64);
        }
        if file_id == FID_VDA {
            let dev = crate::hardware::storage::virtio_block::get_device()
                .ok_or(SyscallError::BadHandle)?;
            return Ok(dev.sector_count() * SECTOR_SIZE as u64);
        }
        Err(SyscallError::BadHandle)
    }

    // ── stat ─────────────────────────────────────────────────────────────────

    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        match file_id {
            FID_ROOT => Ok(FileStat {
                st_ino: FID_ROOT,
                st_mode: 0o040_755,
                st_nlink: 2,
                st_size: 0,
                st_blksize: SECTOR_SIZE as u64,
                st_blocks: 0,
            }),
            FID_NULL => Ok(FileStat { st_ino: FID_NULL,   st_mode: 0o020_666, st_nlink: 1, st_size: 0,    st_blksize: 1, st_blocks: 0 }),
            FID_ZERO => Ok(FileStat { st_ino: FID_ZERO,   st_mode: 0o020_444, st_nlink: 1, st_size: 0,    st_blksize: 1, st_blocks: 0 }),
            FID_RANDOM  => Ok(FileStat { st_ino: FID_RANDOM,  st_mode: 0o020_444, st_nlink: 1, st_size: 0, st_blksize: 1, st_blocks: 0 }),
            FID_URANDOM => Ok(FileStat { st_ino: FID_URANDOM, st_mode: 0o020_444, st_nlink: 1, st_size: 0, st_blksize: 1, st_blocks: 0 }),
            FID_SDA => {
                let dev = ahci::get_device().ok_or(SyscallError::BadHandle)?;
                let size = dev.sector_count() * SECTOR_SIZE as u64;
                Ok(FileStat {
                    st_ino: FID_SDA,
                    st_mode: 0o060_660, // brw-rw---- (block device)
                    st_nlink: 1,
                    st_size: size,
                    st_blksize: SECTOR_SIZE as u64,
                    st_blocks: dev.sector_count(),
                })
            }
            FID_VDA => {
                let dev = crate::hardware::storage::virtio_block::get_device()
                    .ok_or(SyscallError::BadHandle)?;
                let size = dev.sector_count() * SECTOR_SIZE as u64;
                Ok(FileStat {
                    st_ino: FID_VDA,
                    st_mode: 0o060_660,
                    st_nlink: 1,
                    st_size: size,
                    st_blksize: SECTOR_SIZE as u64,
                    st_blocks: dev.sector_count(),
                })
            }
            _ => Err(SyscallError::BadHandle),
        }
    }

    // ── readdir ──────────────────────────────────────────────────────────────

    fn readdir(&self, file_id: u64) -> Result<Vec<DirEntry>, SyscallError> {
        if file_id != FID_ROOT {
            return Err(SyscallError::InvalidArgument);
        }
        let mut entries = Vec::new();
        entries.push(DirEntry { ino: FID_NULL,   file_type: DT_CHR, name: String::from("null") });
        entries.push(DirEntry { ino: FID_ZERO,   file_type: DT_CHR, name: String::from("zero") });
        entries.push(DirEntry { ino: FID_RANDOM,  file_type: DT_CHR, name: String::from("random") });
        entries.push(DirEntry { ino: FID_URANDOM, file_type: DT_CHR, name: String::from("urandom") });
        if ahci::get_device().is_some() {
            entries.push(DirEntry { ino: FID_SDA, file_type: DT_BLK, name: String::from("sda") });
        }
        if crate::hardware::storage::virtio_block::get_device().is_some() {
            entries.push(DirEntry { ino: FID_VDA, file_type: DT_BLK, name: String::from("vda") });
        }
        Ok(entries)
    }
}

// ─── Byte-offset <==> sector I/O helpers ────────────────────────────────────────

/// Read `buf.len()` bytes from the block device starting at byte `offset`.
///
/// Handles unaligned starts and ends by reading the affected sectors into a
/// 512-byte stack buffer and copying only the requested range.
fn sector_read<D: BlockDevice>(dev: &D, offset: u64, buf: &mut [u8]) -> Result<usize, BlockError> {
    let total = buf.len();
    if total == 0 {
        return Ok(0);
    }

    let disk_size = BlockDevice::sector_count(dev) * SECTOR_SIZE as u64;
    if offset >= disk_size {
        return Ok(0); // EOF
    }

    let mut buf_pos: usize = 0;
    let mut byte_off: u64 = offset;
    // Clamp to disk boundary
    let end = (offset + total as u64).min(disk_size);

    while byte_off < end {
        let sector = byte_off / SECTOR_SIZE as u64;
        let sector_off = (byte_off % SECTOR_SIZE as u64) as usize;
        let available = (SECTOR_SIZE - sector_off).min((end - byte_off) as usize);

        let mut tmp = [0u8; SECTOR_SIZE];
        dev.read_sector(sector, &mut tmp)?;

        buf[buf_pos..buf_pos + available].copy_from_slice(&tmp[sector_off..sector_off + available]);

        buf_pos += available;
        byte_off += available as u64;
    }

    Ok(buf_pos)
}

/// Write `data` bytes to the block device starting at byte `offset`.
///
/// For partial-sector writes the affected sector is first read, patched in
/// memory, then written back (read-modify-write).
fn sector_write<D: BlockDevice>(dev: &D, offset: u64, data: &[u8]) -> Result<usize, BlockError> {
    let total = data.len();
    if total == 0 {
        return Ok(0);
    }

    let disk_size = BlockDevice::sector_count(dev) * SECTOR_SIZE as u64;
    if offset >= disk_size {
        return Err(BlockError::InvalidSector);
    }
    let end = (offset + total as u64).min(disk_size);

    let mut data_pos: usize = 0;
    let mut byte_off: u64 = offset;

    while data_pos < total && byte_off < end {
        let sector = byte_off / SECTOR_SIZE as u64;
        let sector_off = (byte_off % SECTOR_SIZE as u64) as usize;
        let remaining = (end - byte_off) as usize;
        let to_write = (SECTOR_SIZE - sector_off).min(remaining);

        // Read-modify-write for partial sectors; full-sector writes skip the read
        let mut tmp = [0u8; SECTOR_SIZE];
        if sector_off != 0 || to_write != SECTOR_SIZE {
            dev.read_sector(sector, &mut tmp)?;
        }

        tmp[sector_off..sector_off + to_write]
            .copy_from_slice(&data[data_pos..data_pos + to_write]);
        dev.write_sector(sector, &tmp)?;

        data_pos += to_write;
        byte_off += to_write as u64;
    }

    Ok(data_pos)
}
