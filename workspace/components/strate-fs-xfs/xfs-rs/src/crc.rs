//! CRC32C for XFS v5 metadata validation.
//!
//! XFS v5 uses CRC32C (Castagnoli polynomial) to verify metadata integrity.
//! This module wraps the `crc32c` crate which provides:
//! - **Hardware acceleration** via SSE4.2 intrinsics (fastest, ~10x speedup)
//! - **Software fallback** with optimized lookup tables
//!
//! Fully `no_std` compatible.

/// Calculate CRC32C checksum for XFS metadata.
///
/// Follows XFS conventions: starts with 0xFFFFFFFF, inverts final result.
/// The `crc32c` crate handles SSE4.2 detection automatically.
///
/// # Arguments
/// * `data` - Byte slice to checksum
///
/// # Returns
/// The final CRC32C value as used in XFS v5 metadata
#[inline]
pub fn xfs_crc32c(data: &[u8]) -> u32 {
    crc32c::crc32c(data)
}

/// Calculate CRC32C with runtime CPU feature detection.
///
/// Identical to `xfs_crc32c` — the `crc32c` crate already uses hardware
/// acceleration when SSE4.2 is available at compile time.
///
/// # Arguments
/// * `data` - Byte slice to checksum
#[cfg(feature = "std")]
#[inline]
pub fn xfs_crc32c_runtime_detect(data: &[u8]) -> u32 {
    crc32c::crc32c(data)
}

/// Calculate CRC32C for a superblock.
///
/// The CRC field itself must be zeroed before calculation.
///
/// # Arguments
/// * `sb_bytes` - Superblock bytes (typically 512 bytes)
pub fn superblock_crc(sb_bytes: &[u8]) -> u32 {
    xfs_crc32c(sb_bytes)
}

/// Calculate CRC32C for a superblock with fixed size.
///
/// # Arguments
/// * `sb_bytes` - Superblock bytes array (512 bytes)
pub fn superblock_crc_fixed(sb_bytes: &[u8; 512]) -> u32 {
    xfs_crc32c(sb_bytes)
}

/// Calculate CRC32C for an inode (v3/v5).
///
/// The CRC field itself must be zeroed before calculation.
///
/// # Arguments
/// * `inode_bytes` - Full inode bytes with CRC field zeroed
pub fn inode_crc(inode_bytes: &[u8]) -> u32 {
    xfs_crc32c(inode_bytes)
}

/// Zero out the CRC field in a buffer and recalculate.
///
/// # Arguments
/// * `buf` - Mutable buffer with data
/// * `crc_offset` - Offset of the 4-byte CRC field
///
/// # Returns
/// The new CRC value (also written into the buffer)
pub fn recalculate_crc(buf: &mut [u8], crc_offset: usize) -> Option<u32> {
    if crc_offset + 4 > buf.len() {
        return None;
    }

    buf[crc_offset..crc_offset + 4].fill(0);
    let crc = xfs_crc32c(buf);
    buf[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_be_bytes());
    Some(crc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32c_empty() {
        let crc = xfs_crc32c(&[]);
        assert_eq!(crc, 0);
    }

    #[test]
    fn test_crc32c_known_value() {
        let data = b"123456789";
        let crc = xfs_crc32c(data);
        assert_eq!(crc, 0xE3069283);
    }

    #[test]
    fn test_recalculate_crc() {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        let crc = recalculate_crc(&mut buf, 8).unwrap();
        let stored = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        assert_eq!(crc, stored);
    }

    #[test]
    fn test_xfs_superblock_crc() {
        let mut sb = [0u8; 512];
        sb[0] = b'X';
        sb[1] = b'F';
        sb[2] = b'S';
        sb[3] = b'B';
        let _crc = superblock_crc(&sb);
        let mut sb_with_crc = sb;
        let offset = 0xE0;
        if offset + 4 <= sb_with_crc.len() {
            let calculated = recalculate_crc(&mut sb_with_crc, offset).unwrap();
            let stored = u32::from_be_bytes([
                sb_with_crc[offset],
                sb_with_crc[offset + 1],
                sb_with_crc[offset + 2],
                sb_with_crc[offset + 3],
            ]);
            assert_eq!(calculated, stored);
        }
    }

    #[test]
    fn test_inode_crc_consistency() {
        let mut inode = [0u8; 256];
        inode[0x98..0xA0].copy_from_slice(&12345u64.to_be_bytes());
        inode[0xA0..0xB0].copy_from_slice(&[0xAAu8; 16]);
        let crc1 = inode_crc(&inode);
        let mut inode_with_crc = inode;
        let crc2 = recalculate_crc(&mut inode_with_crc, 0x64).unwrap();
        assert_eq!(crc1, crc2);
    }
}
