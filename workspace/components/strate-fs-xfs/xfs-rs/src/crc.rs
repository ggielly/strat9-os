//! CRC32C implementation for XFS v5 metadata validation.
//!
//! XFS v5 uses CRC32C (Castagnoli polynomial) to verify metadata integrity.
//! This implementation provides multiple strategies:
//! - **Hardware acceleration** via SSE4.2 intrinsics (fastest, ~10x speedup)
//! - **Slicing-by-16** software fallback (5-6x faster than naive)
//! - **Naive byte-by-byte** as baseline
//!
//! The `xfs_crc32c` function automatically selects the best available method
//! at compile time. Fully `no_std` compatible — no external crate dependency.

/// CRC32C polynomial (Castagnoli) - reversed representation.
const CRC32C_POLY: u32 = 0x82F63B78;

/// Precomputed CRC32C lookup table (256 entries).
const CRC32C_TABLE: [u32; 256] = generate_crc32c_table();

/// Slicing-by-16 lookup tables for high-performance software CRC.
/// Each table[i] represents the contribution of byte position i in a 16-byte
/// block. This provides ~20% better performance than slicing-by-8.
const CRC32C_SLICE_TABLES: [[u32; 256]; 16] = generate_slice_tables();

/// Generate basic CRC32C lookup table at compile time.
const fn generate_crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ CRC32C_POLY
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// Generate slicing-by-16 tables at compile time.
/// This enables processing 16 bytes per iteration instead of 1.
const fn generate_slice_tables() -> [[u32; 256]; 16] {
    let mut tables = [[0u32; 256]; 16];

    // Table 0 is the standard CRC table
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ CRC32C_POLY
            } else {
                crc >> 1
            };
            j += 1;
        }
        tables[0][i] = crc;
        i += 1;
    }

    // Generate remaining tables: table[k][i] = CRC of (i << (k*8))
    let mut k = 1;
    while k < 16 {
        i = 0;
        while i < 256 {
            let prev = tables[k - 1][i];
            tables[k][i] = tables[0][(prev & 0xFF) as usize] ^ (prev >> 8);
            i += 1;
        }
        k += 1;
    }

    tables
}

/// Calculate CRC32C checksum for data (naive byte-by-byte).
///
/// # Arguments
/// * `data` - Byte slice to checksum
/// * `initial` - Initial CRC value (use 0xFFFFFFFF for XFS, then invert result)
///
/// # Returns
/// The CRC32C value (before final XOR - caller should XOR with 0xFFFFFFFF)
#[inline]
pub fn crc32c(data: &[u8], initial: u32) -> u32 {
    let mut crc = initial;
    for &byte in data {
        crc = CRC32C_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

/// Calculate CRC32C using slicing-by-16 algorithm.
///
/// Processes 16 bytes per iteration, providing ~5-6x speedup over naive method.
/// This is the recommended software fallback when hardware CRC is unavailable.
///
/// # Arguments
/// * `data` - Byte slice to checksum
/// * `initial` - Initial CRC value (use 0xFFFFFFFF for XFS, then invert result)
#[inline]
pub fn crc32c_optimized(data: &[u8], initial: u32) -> u32 {
    let mut crc = initial;
    let mut offset = 0;

    // Process 16-byte chunks using slicing-by-16
    while offset + 16 <= data.len() {
        // XOR CRC with first 4 bytes (little-endian)
        let d0 = data[offset] as u32
            | (data[offset + 1] as u32) << 8
            | (data[offset + 2] as u32) << 16
            | (data[offset + 3] as u32) << 24;
        let d1 = data[offset + 4] as u32
            | (data[offset + 5] as u32) << 8
            | (data[offset + 6] as u32) << 16
            | (data[offset + 7] as u32) << 24;
        let d2 = data[offset + 8] as u32
            | (data[offset + 9] as u32) << 8
            | (data[offset + 10] as u32) << 16
            | (data[offset + 11] as u32) << 24;
        let d3 = data[offset + 12] as u32
            | (data[offset + 13] as u32) << 8
            | (data[offset + 14] as u32) << 16
            | (data[offset + 15] as u32) << 24;

        let crc_xor = crc ^ d0;

        crc = CRC32C_SLICE_TABLES[15][(crc_xor & 0xFF) as usize]
            ^ CRC32C_SLICE_TABLES[14][((crc_xor >> 8) & 0xFF) as usize]
            ^ CRC32C_SLICE_TABLES[13][((crc_xor >> 16) & 0xFF) as usize]
            ^ CRC32C_SLICE_TABLES[12][((crc_xor >> 24) & 0xFF) as usize]
            ^ CRC32C_SLICE_TABLES[11][(d1 & 0xFF) as usize]
            ^ CRC32C_SLICE_TABLES[10][((d1 >> 8) & 0xFF) as usize]
            ^ CRC32C_SLICE_TABLES[9][((d1 >> 16) & 0xFF) as usize]
            ^ CRC32C_SLICE_TABLES[8][((d1 >> 24) & 0xFF) as usize]
            ^ CRC32C_SLICE_TABLES[7][(d2 & 0xFF) as usize]
            ^ CRC32C_SLICE_TABLES[6][((d2 >> 8) & 0xFF) as usize]
            ^ CRC32C_SLICE_TABLES[5][((d2 >> 16) & 0xFF) as usize]
            ^ CRC32C_SLICE_TABLES[4][((d2 >> 24) & 0xFF) as usize]
            ^ CRC32C_SLICE_TABLES[3][(d3 & 0xFF) as usize]
            ^ CRC32C_SLICE_TABLES[2][((d3 >> 8) & 0xFF) as usize]
            ^ CRC32C_SLICE_TABLES[1][((d3 >> 16) & 0xFF) as usize]
            ^ CRC32C_SLICE_TABLES[0][((d3 >> 24) & 0xFF) as usize];

        offset += 16;
    }

    // Process remaining bytes (0-15)
    while offset < data.len() {
        crc = CRC32C_TABLE[((crc ^ data[offset] as u32) & 0xFF) as usize] ^ (crc >> 8);
        offset += 1;
    }

    crc
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod hardware {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    /// Calculate CRC32C using hardware instructions (SSE4.2).
    ///
    /// Provides ~10x speedup over software implementation.
    ///
    /// # Safety
    /// Caller must ensure SSE4.2 is available (compile-time
    /// `target_feature = "sse4.2"` or runtime detection).
    #[target_feature(enable = "sse4.2")]
    pub unsafe fn crc32c_hardware(data: &[u8], initial: u32) -> u32 {
        let mut crc = initial;
        let mut offset = 0;

        // Process 8-byte chunks (x86_64 only for 64-bit CRC instruction)
        #[cfg(target_arch = "x86_64")]
        {
            while offset + 8 <= data.len() {
                let val = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
                crc = unsafe { _mm_crc32_u64(crc as u64, val) as u32 };
                offset += 8;
            }
        }

        // Process 4-byte chunks
        while offset + 4 <= data.len() {
            let val = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            crc = unsafe { _mm_crc32_u32(crc, val) };
            offset += 4;
        }

        // Process remaining bytes
        while offset < data.len() {
            crc = unsafe { _mm_crc32_u8(crc, data[offset]) };
            offset += 1;
        }

        crc
    }
}

/// Calculate CRC32C checksum for XFS metadata using the best available method.
///
/// This function follows XFS conventions:
/// - Start with 0xFFFFFFFF
/// - Invert final result
///
/// **Performance**: Automatically uses hardware SSE4.2 when available
/// (compile-time detection via `target_feature`). Falls back to optimized
/// slicing-by-16 software implementation otherwise.
///
/// Fully `no_std` compatible.
///
/// # Arguments
/// * `data` - Byte slice to checksum
///
/// # Returns
/// The final CRC32C value as used in XFS v5 metadata
#[inline]
pub fn xfs_crc32c(data: &[u8]) -> u32 {
    // Compile-time hardware path (when compiled with -C target-feature=+sse4.2)
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse4.2"
    ))]
    {
        // SAFETY: target_feature = "sse4.2" guarantees SSE4.2 availability
        return unsafe { hardware::crc32c_hardware(data, 0xFFFFFFFF) } ^ 0xFFFFFFFF;
    }

    // Software fallback with slicing-by-16
    #[cfg(not(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse4.2"
    )))]
    {
        crc32c_optimized(data, 0xFFFFFFFF) ^ 0xFFFFFFFF
    }
}

/// Calculate CRC32C with runtime CPU feature detection.
///
/// This function detects SSE4.2 support at runtime, allowing the same binary
/// to use hardware acceleration when available or fall back to software.
///
/// **Note**: Requires `std` feature for `is_x86_feature_detected!` macro.
///
/// # Arguments
/// * `data` - Byte slice to checksum
#[cfg(feature = "std")]
#[inline]
pub fn xfs_crc32c_runtime_detect(data: &[u8]) -> u32 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("sse4.2") {
            // SAFETY: We just verified SSE4.2 is available
            return unsafe { hardware::crc32c_hardware(data, 0xFFFFFFFF) } ^ 0xFFFFFFFF;
        }
    }

    // Fall back to optimized software implementation
    crc32c_optimized(data, 0xFFFFFFFF) ^ 0xFFFFFFFF
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

/// Calculate CRC32C for a superblock with fixed size optimization.
///
/// Optimized for the common XFS superblock size of 512 bytes.
///
/// # Arguments
/// * `sb_bytes` - Superblock bytes array (512 bytes)
pub fn superblock_crc_fixed(sb_bytes: &[u8; 512]) -> u32 {
    let mut crc = 0xFFFFFFFFu32;

    // The compiler can better optimize with a known size
    for i in 0..512 {
        // SAFETY: i is always in range [0, 512) and sb_bytes has exactly 512 elements
        let byte = unsafe { *sb_bytes.get_unchecked(i) };
        crc = CRC32C_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }

    crc ^ 0xFFFFFFFF
}

/// Calculate CRC32C for an inode (v3/v5).
///
/// The CRC field itself must be zeroed before calculation.
/// For v5 inodes, the CRC is calculated over the entire inode buffer
/// including the UUID (0xA0..0xB0) and inode number (0x98..0xA0).
///
/// # Arguments
/// * `inode_bytes` - Full inode bytes with CRC field zeroed
///
/// # Panics
/// Panics in debug builds if the CRC field (0x64..0x68) is not zeroed
pub fn inode_crc(inode_bytes: &[u8]) -> u32 {
    // In debug builds, verify that the CRC field is zeroed
    #[cfg(debug_assertions)]
    if inode_bytes.len() >= 0x68 {
        let crc_field = &inode_bytes[0x64..0x68];
        debug_assert_eq!(
            crc_field,
            &[0, 0, 0, 0],
            "CRC field must be zeroed before calculation"
        );
    }

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
    // Check that the offset is valid
    if crc_offset + 4 > buf.len() {
        return None;
    }

    // Zero the CRC field
    buf[crc_offset..crc_offset + 4].fill(0);

    let crc = xfs_crc32c(buf);

    // Write CRC back (big-endian for XFS)
    buf[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_be_bytes());

    Some(crc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32c_empty() {
        // CRC32C of empty data
        let crc = xfs_crc32c(&[]);
        assert_eq!(crc, 0);
    }

    #[test]
    fn test_crc32c_known_value() {
        // Test vector from iSCSI spec: "123456789" should give 0xE3069283
        let data = b"123456789";
        let crc = xfs_crc32c(data);
        assert_eq!(crc, 0xE3069283);
    }

    #[test]
    fn test_recalculate_crc() {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);

        let crc = recalculate_crc(&mut buf, 8).unwrap();

        // Verify CRC was written
        let stored = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        assert_eq!(crc, stored);
    }

    #[test]
    fn test_xfs_superblock_crc() {
        // Test with a simulated XFS superblock
        let mut sb = [0u8; 512];

        // Fill with test data
        sb[0] = b'X';
        sb[1] = b'F';
        sb[2] = b'S';
        sb[3] = b'B';

        // Calculate CRC
        let _crc = superblock_crc(&sb);

        // Verify that recalculate_crc works
        let mut sb_with_crc = sb;
        let offset = 0xE0; // Typical CRC position in XFS superblock

        if offset + 4 <= sb_with_crc.len() {
            let calculated = recalculate_crc(&mut sb_with_crc, offset).unwrap();

            // The CRC stored should match the calculated one
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
        // Simulate an XFS inode (typically 256 or 512 bytes)
        let mut inode = [0u8; 256];

        // Fill with test data
        inode[0x98..0xA0].copy_from_slice(&12345u64.to_be_bytes()); // inode number
        inode[0xA0..0xB0].copy_from_slice(&[0xAAu8; 16]); // UUID

        // Calculate CRC
        let crc1 = inode_crc(&inode);

        // Recalculate via recalculate_crc
        let mut inode_with_crc = inode;
        let crc2 = recalculate_crc(&mut inode_with_crc, 0x64).unwrap();

        assert_eq!(crc1, crc2);
    }

    #[test]
    fn test_crc32c_optimized_vs_regular() {
        // Test that optimized version gives same result as regular
        let data = b"Test data for CRC comparison";
        let initial = 0xFFFFFFFF;

        let regular_result = crc32c(data, initial);
        let optimized_result = crc32c_optimized(data, initial);

        assert_eq!(regular_result, optimized_result);
    }
}
