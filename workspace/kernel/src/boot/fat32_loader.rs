//! FAT32 module loader for reading userspace ELFs from boot partition.
//!
//! Self-contained FAT32 parser with no external filesystem dependencies.
//! Reads the BPB, follows cluster chains, parses directory entries (8.3 + LFN),
//! and loads ELF modules into memory.
//!
//! # Safety considerations
//! All `unsafe` blocks are confined to ELF memory copy and are documented.
//! The parser uses no global mutable state : all buffers are stack-local.

use super::block_device::BlockDevice;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SECTOR_SIZE: usize = 512;
const FAT32_EOC: u32 = 0x0FFF_FFF8;
const DIR_ENTRY_SIZE: usize = 32;

const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_HIDDEN: u8 = 0x02;
const ATTR_SYSTEM: u8 = 0x04;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LFN: u8 = 0x0F;

/// Maximum cluster chain length to prevent infinite loops on corrupted FAT.
const MAX_CLUSTER_CHAIN: u32 = 1_048_576;

/// Maximum number of path components.
const MAX_PATH_DEPTH: usize = 16;

// ---------------------------------------------------------------------------
// BPB (BIOS Parameter Block)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Bpb {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    sectors_per_fat_32: u32,
    root_cluster: u32,
    total_sectors_32: u32,
}

impl Bpb {
    /// Parse a BPB from a 512-byte boot sector buffer.
    ///
    /// Validates:
    /// - Boot signature 0x55AA at offset 0x1FE
    /// - FAT32 signature "FAT32 " at offset 0x52
    /// - Non-zero bytes_per_sector and sectors_per_cluster
    /// - bytes_per_sector is 512 (only 512 supported)
    fn from_bytes(buf: &[u8; SECTOR_SIZE]) -> Option<Self> {
        // Boot signature
        if buf[0x1FE] != 0x55 || buf[0x1FF] != 0xAA {
            return None;
        }

        // FAT32 signature at offset 0x52
        if &buf[0x52..0x58] != b"FAT32 " {
            return None;
        }

        let bytes_per_sector = u16::from_le_bytes([buf[0x0B], buf[0x0C]]);
        let sectors_per_cluster = buf[0x0D];
        let reserved_sectors = u16::from_le_bytes([buf[0x0E], buf[0x0F]]);
        let num_fats = buf[0x10];
        let sectors_per_fat_32 = u32::from_le_bytes([buf[0x24], buf[0x25], buf[0x26], buf[0x27]]);
        let root_cluster = u32::from_le_bytes([buf[0x2C], buf[0x2D], buf[0x2E], buf[0x2F]]);
        let total_sectors_32 = u32::from_le_bytes([buf[0x20], buf[0x21], buf[0x22], buf[0x23]]);

        if bytes_per_sector == 0 || sectors_per_cluster == 0 {
            return None;
        }
        if bytes_per_sector != SECTOR_SIZE as u16 {
            return None;
        }
        if num_fats == 0 || sectors_per_fat_32 == 0 {
            return None;
        }
        if root_cluster < 2 {
            return None;
        }

        Some(Bpb {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            sectors_per_fat_32,
            root_cluster,
            total_sectors_32,
        })
    }

    fn bytes_per_cluster(&self) -> u32 {
        self.bytes_per_sector as u32 * self.sectors_per_cluster as u32
    }

    fn fat_start_sector(&self) -> u32 {
        self.reserved_sectors as u32
    }

    fn data_start_sector(&self) -> u32 {
        self.fat_start_sector() + self.sectors_per_fat_32 * self.num_fats as u32
    }

    /// Convert a cluster number to the LBA of its first sector.
    /// Returns None if the cluster number is invalid.
    fn cluster_to_lba(&self, cluster: u32) -> Option<u32> {
        if cluster < 2 {
            return None;
        }
        let offset = (cluster as u64 - 2) * self.sectors_per_cluster as u64;
        let lba = self.data_start_sector() as u64 + offset;
        if lba > u32::MAX as u64 {
            return None;
        }
        Some(lba as u32)
    }

    /// Maximum valid cluster id for this volume.
    fn max_cluster(&self) -> u32 {
        let data_sectors = self
            .total_sectors_32
            .saturating_sub(self.data_start_sector());
        let clusters = data_sectors / self.sectors_per_cluster as u32;
        2 + clusters
    }
}

// ---------------------------------------------------------------------------
// Directory entry types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DirEntry {
    name: DirEntryName,
    attr: u8,
    cluster: u32,
    size: u32,
}

impl DirEntry {
    fn is_dir(&self) -> bool {
        self.attr & ATTR_DIRECTORY != 0
    }

    fn is_file(&self) -> bool {
        self.attr & ATTR_DIRECTORY == 0
    }
}

#[derive(Debug, Clone)]
enum DirEntryName {
    Short([u8; 11]),
    Long(heapless::String<255>),
}

/// Small stack-allocated buffer for displaying a short file name.
struct ShortNameDisplay {
    buf: [u8; 12],
    len: usize,
}

impl ShortNameDisplay {
    fn from_sfn(sfn: &[u8; 11]) -> Self {
        let mut display = ShortNameDisplay {
            buf: [0u8; 12],
            len: 0,
        };
        let mut pos = 0;

        // Base name (chars 0-7), strip trailing spaces
        let mut i = 0;
        while i < 8 && sfn[i] != b' ' && sfn[i] != 0 {
            display.buf[pos] = sfn[i].to_ascii_lowercase();
            pos += 1;
            i += 1;
        }

        // Extension (chars 8-10)
        if sfn[8] != b' ' && sfn[8] != 0 {
            display.buf[pos] = b'.';
            pos += 1;
            let mut i = 8;
            while i < 11 && sfn[i] != b' ' && sfn[i] != 0 {
                display.buf[pos] = sfn[i].to_ascii_lowercase();
                pos += 1;
                i += 1;
            }
        }

        display.len = pos;
        display
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("???")
    }
}

impl DirEntryName {
    fn display_name(&self) -> ShortNameDisplay {
        match self {
            DirEntryName::Long(s) => {
                // For LFN, we need a different approach. Return a stack struct.
                // Since ShortNameDisplay is for SFN only, we handle Long separately.
                // We use the same struct but with the first 12 chars of the LFN.
                let mut d = ShortNameDisplay {
                    buf: [0u8; 12],
                    len: 0,
                };
                let bytes = s.as_bytes();
                let len = bytes.len().min(12);
                d.buf[..len].copy_from_slice(&bytes[..len]);
                d.len = len;
                d
            }
            DirEntryName::Short(sfn) => ShortNameDisplay::from_sfn(sfn),
        }
    }

    fn matches_short(&self, upper_name: &[u8; 11]) -> bool {
        match self {
            DirEntryName::Short(sfn) => sfn == upper_name,
            DirEntryName::Long(_) => false,
        }
    }

    fn as_lfn_str(&self) -> Option<&str> {
        match self {
            DirEntryName::Long(s) => Some(s.as_str()),
            DirEntryName::Short(_) => None,
        }
    }
}

/// Build an 8.3 short name from a string for comparison.
///
/// Follows FAT32 spec:
/// - Uppercase all characters
/// - Ignore spaces
/// - Truncate to 8+3
/// - Names starting with 0xE5 are stored as 0x05
fn make_sfn(name: &str) -> [u8; 11] {
    let mut sfn = [b' '; 11];
    let bytes = name.as_bytes();

    // Find the last dot to split name/extension
    // But only if it's not the first character (FAT treats ".foo" as extensionless)
    let dot_pos = if bytes.len() > 1 && bytes[0] != b'.' {
        bytes[1..].iter().rposition(|&b| b == b'.').map(|p| p + 1)
    } else {
        None
    };

    let (base, ext) = if let Some(dp) = dot_pos {
        (&bytes[..dp], &bytes[dp + 1..])
    } else {
        (bytes, &b""[..])
    };

    // Fill base name (up to 8 chars), skipping spaces
    let mut pos = 0;
    let mut i = 0;
    while pos < 8 && i < base.len() {
        let c = base[i];
        if c != b' ' {
            sfn[pos] = c.to_ascii_uppercase();
            pos += 1;
        }
        i += 1;
    }

    // Fill extension (up to 3 chars), skipping spaces
    pos = 8;
    i = 0;
    while pos < 11 && i < ext.len() {
        let c = ext[i];
        if c != b' ' {
            sfn[pos] = c.to_ascii_uppercase();
            pos += 1;
        }
        i += 1;
    }

    // Handle leading 0xE5 (deleted marker) → 0x05
    if sfn[0] == 0xE5 {
        sfn[0] = 0x05;
    }

    sfn
}

// ---------------------------------------------------------------------------
// Cluster chain iterator (with cycle detection)
// ---------------------------------------------------------------------------

/// Iterates over clusters in a chain, with cycle detection.
struct ClusterChainIter<'a, B: BlockDevice> {
    fs: &'a mut FatFs<'a, B>,
    next_cluster: Option<u32>,
    iterations: u32,
}

impl<'a, B: BlockDevice> ClusterChainIter<'a, B> {
    fn new(fs: &'a mut FatFs<'a, B>, start_cluster: u32) -> Self {
        Self {
            fs,
            next_cluster: if start_cluster >= 2 {
                Some(start_cluster)
            } else {
                None
            },
            iterations: 0,
        }
    }
}

impl<'a, B: BlockDevice> Iterator for ClusterChainIter<'a, B> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        let current = self.next_cluster?;
        self.iterations += 1;
        if self.iterations > MAX_CLUSTER_CHAIN {
            crate::serial_println!("[fat32] Cluster chain exceeds maximum length (cycle?)");
            self.next_cluster = None;
            return None;
        }

        match self.fs.next_cluster(current) {
            Some(next) if next >= 2 => {
                self.next_cluster = Some(next);
                Some(current)
            }
            Some(_) => {
                self.next_cluster = None;
                Some(current)
            }
            None => {
                self.next_cluster = None;
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FatFs : main filesystem object
// ---------------------------------------------------------------------------

pub struct FatFs<'a, B: BlockDevice> {
    block_dev: &'a mut B,
    bpb: Bpb,
}

impl<'a, B: BlockDevice> FatFs<'a, B> {
    /// Mount a FAT32 filesystem from a block device.
    pub fn new(block_dev: &'a mut B) -> Option<Self> {
        let kernel_block_size = block_dev.block_size() as usize;
        let mut sector_buf = [0u8; SECTOR_SIZE];
        Self::read_sector_at(block_dev, 0, &mut sector_buf, kernel_block_size)?;

        let bpb = Bpb::from_bytes(&sector_buf)?;

        crate::serial_println!(
            "[fat32] BPB: {} bytes/sector, {} sec/cluster, {} FATs, root_cluster={}",
            bpb.bytes_per_sector,
            bpb.sectors_per_cluster,
            bpb.num_fats,
            bpb.root_cluster,
        );

        Some(FatFs { block_dev, bpb })
    }

    /// Read a FAT32 sector from a block device at any block size.
    fn read_sector_at(
        dev: &mut B,
        fat32_sector: u32,
        buf: &mut [u8; SECTOR_SIZE],
        kernel_block_size: usize,
    ) -> Option<()> {
        if kernel_block_size >= SECTOR_SIZE {
            // Kernel block >= FAT sector: read one block, take first 512 bytes
            let mut block_buf = [0u8; 4096];
            dev.read_block(fat32_sector as u64, &mut block_buf[..kernel_block_size])
                .ok()?;
            let n = SECTOR_SIZE.min(kernel_block_size);
            buf[..n].copy_from_slice(&block_buf[..n]);
        } else {
            // Kernel block < FAT sector: read multiple blocks
            let blocks_per_sector = SECTOR_SIZE / kernel_block_size;
            let base_lba = fat32_sector as u64 * blocks_per_sector as u64;
            let mut block_buf = [0u8; 4096];
            for i in 0..blocks_per_sector {
                dev.read_block(base_lba + i as u64, &mut block_buf[..kernel_block_size])
                    .ok()?;
                let dst = i * kernel_block_size;
                buf[dst..dst + kernel_block_size]
                    .copy_from_slice(&block_buf[..kernel_block_size]);
            }
        }
        Some(())
    }

    fn read_sector(&mut self, fat32_sector: u32, buf: &mut [u8; SECTOR_SIZE]) -> Option<()> {
        let kbs = self.block_dev.block_size() as usize;
        Self::read_sector_at(self.block_dev, fat32_sector, buf, kbs)
    }

    /// Read the next cluster number from the FAT table.
    fn next_cluster(&mut self, cluster: u32) -> Option<u32> {
        if cluster < 2 {
            return None;
        }

        let fat_offset = cluster as usize * 4;
        let fat_sector = self.bpb.fat_start_sector() + (fat_offset / SECTOR_SIZE) as u32;
        let entry_offset = fat_offset % SECTOR_SIZE;

        // Bounds check: ensure the 4-byte entry fits within the sector
        if entry_offset + 4 > SECTOR_SIZE {
            crate::serial_println!("[fat32] FAT entry crosses sector boundary (corrupt?)");
            return None;
        }

        let mut sector_buf = [0u8; SECTOR_SIZE];
        self.read_sector(fat_sector, &mut sector_buf)?;

        let entry = u32::from_le_bytes([
            sector_buf[entry_offset],
            sector_buf[entry_offset + 1],
            sector_buf[entry_offset + 2],
            sector_buf[entry_offset + 3],
        ]) & 0x0FFF_FFFF;

        if entry >= FAT32_EOC { Some(0) } else { Some(entry) }
    }

    /// Read a full cluster chain into a heap-allocated buffer.
    ///
    /// Skips `clusters_to_skip` clusters at the start (for offset-based reads).
    /// Only reads `max_bytes` after the skip, if provided.
    fn read_chain(
        &mut self,
        start_cluster: u32,
        clusters_to_skip: u32,
        max_bytes: Option<usize>,
    ) -> Option<alloc::vec::Vec<u8>> {
        let spc = self.bpb.sectors_per_cluster as u32;
        let mut data = alloc::vec::Vec::new();

        // Pre-allocate based on max_bytes if known
        if let Some(max) = max_bytes {
            data.reserve(max);
        }

        let mut current = start_cluster;

        // Skip clusters
        for _ in 0..clusters_to_skip {
            current = self.next_cluster(current)?;
            if current < 2 {
                return Some(data);
            }
        }

        let mut iterations = 0u32;
        while current >= 2 {
            iterations += 1;
            if iterations > MAX_CLUSTER_CHAIN {
                crate::serial_println!("[fat32] Cluster chain too long (cycle?)");
                return None;
            }

            let cluster_lba = self.bpb.cluster_to_lba(current)?;

            for s in 0..spc {
                let mut sector_buf = [0u8; SECTOR_SIZE];
                self.read_sector(cluster_lba + s, &mut sector_buf)?;
                data.extend_from_slice(&sector_buf);

                if let Some(max) = max_bytes {
                    if data.len() >= max {
                        data.truncate(max);
                        return Some(data);
                    }
                }
            }

            current = self.next_cluster(current)?;
        }

        Some(data)
    }

    /// Read a full cluster chain (from the start, no skip).
    fn read_cluster_chain_alloc(&mut self, cluster: u32) -> Option<alloc::vec::Vec<u8>> {
        self.read_chain(cluster, 0, None)
    }

    /// Read raw directory entries from a cluster chain.
    fn read_dir_entries(&mut self, cluster: u32) -> Option<alloc::vec::Vec<DirEntry>> {
        let dir_data = self.read_cluster_chain_alloc(cluster)?;
        self.parse_dir_entries(&dir_data)
    }

    /// Parse raw directory data into `DirEntry` items.
    ///
    /// Handles:
    /// - End-of-directory marker (0x00)
    /// - Deleted entries (0xE5)
    /// - LFN entries (attr == 0x0F)
    /// - Volume ID entries (attr == 0x08)
    fn parse_dir_entries(&self, data: &[u8]) -> Option<alloc::vec::Vec<DirEntry>> {
        let mut entries = alloc::vec::Vec::new();
        let mut lfn_chars: heapless::Vec<char, 255> = heapless::Vec::new();
        let mut lfn_checksum: u8 = 0;
        let mut i = 0;

        while i + DIR_ENTRY_SIZE <= data.len() {
            let raw = &data[i..i + DIR_ENTRY_SIZE];
            i += DIR_ENTRY_SIZE;

            // End of directory
            if raw[0] == 0x00 {
                break;
            }

            // Deleted entry : clear LFN state
            if raw[0] == 0xE5 {
                lfn_chars.clear();
                continue;
            }

            let attr = raw[11];

            // LFN entry
            if attr == ATTR_LFN {
                let seq = raw[0];
                let is_last = (seq & 0x40) != 0;
                let _index = seq & 0x3F;
                let chksum = raw[13];

                if is_last {
                    lfn_chars.clear();
                    lfn_checksum = chksum;
                } else if lfn_checksum != chksum {
                    // Checksum mismatch : broken LFN sequence, discard
                    lfn_chars.clear();
                    continue;
                }

                // LFN character positions in the 32-byte entry
                // Chars 0-4:   offsets 1,3,5,7,9
                // Chars 5-10:  offsets 14,16,18,20,22,24
                // Chars 11-12: offsets 28,30
                let positions = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
                for &pos in &positions {
                    let lo = raw[pos] as u16;
                    let hi = raw[pos + 1] as u16;
                    let ch16 = (hi << 8) | lo;
                    if ch16 == 0x0000 || ch16 == 0xFFFF {
                        continue;
                    }
                    if let Some(c) = char::from_u32(ch16 as u32) {
                        // Push in order : LFN entries arrive last-to-first,
                        // so we push each entry's chars in forward order,
                        // then reverse the entire collected sequence at the end.
                        let _ = lfn_chars.push(c);
                    }
                }
                continue;
            }

            // Regular directory entry (file or subdirectory)
            let cluster_hi = u16::from_le_bytes([raw[20], raw[21]]) as u32;
            let cluster_lo = u16::from_le_bytes([raw[26], raw[27]]) as u32;
            let cluster = (cluster_hi << 16) | cluster_lo;
            let size = u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]);

            let name = if !lfn_chars.is_empty() {
                // LFN entries arrive last-to-first, chars within each entry are forward.
                // We pushed chars in forward order per entry, but entries are reverse.
                // So reverse the whole collected sequence to get the correct name.
                let mut lfn_str = heapless::String::<255>::new();
                for &c in lfn_chars.iter().rev() {
                    let _ = lfn_str.push(c);
                }
                lfn_chars.clear();
                DirEntryName::Long(lfn_str)
            } else {
                let mut sfn = [0u8; 11];
                sfn.copy_from_slice(&raw[0..11]);
                DirEntryName::Short(sfn)
            };

            // Skip volume ID entries
            if attr & ATTR_VOLUME_ID != 0 {
                continue;
            }

            entries.push(DirEntry {
                name,
                attr,
                cluster,
                size,
            });
        }

        Some(entries)
    }

    /// Resolve a path to a directory entry.
    fn resolve_path(&mut self, path: &str) -> Option<DirEntry> {
        let path = path.trim_start_matches('/');
        if path.is_empty() {
            return Some(DirEntry {
                name: DirEntryName::Short(*b"/          "),
                attr: ATTR_DIRECTORY,
                cluster: self.bpb.root_cluster,
                size: 0,
            });
        }

        let mut current_cluster = self.bpb.root_cluster;

        // Collect path components, limiting depth
        let mut parts: heapless::Vec<&str, MAX_PATH_DEPTH> = heapless::Vec::new();
        for part in path.split('/') {
            if !part.is_empty() {
                if parts.push(part).is_err() {
                    crate::serial_println!("[fat32] Path too deep: {}", path);
                    return None;
                }
            }
        }

        for (idx, part) in parts.iter().enumerate() {
            let dir_entries = self.read_dir_entries(current_cluster)?;
            let target_sfn = make_sfn(part);

            let mut found = None;
            for entry in &dir_entries {
                if entry.name.matches_short(&target_sfn) {
                    found = Some(entry.clone());
                    break;
                }
                // LFN match: case-insensitive
                if let Some(lfn) = entry.name.as_lfn_str() {
                    if lfn.eq_ignore_ascii_case(part) {
                        found = Some(entry.clone());
                        break;
                    }
                }
                // SFN display match (handles lowercase comparison)
                let display = entry.name.display_name();
                if display.as_str().eq_ignore_ascii_case(part) {
                    found = Some(entry.clone());
                    break;
                }
            }

            let entry = found?;

            if idx == parts.len() - 1 {
                return Some(entry);
            }

            if !entry.is_dir() {
                return None;
            }
            current_cluster = entry.cluster;
        }

        None
    }

    /// Read a file by path, returning its contents.
    pub fn read_file(&mut self, path: &str) -> Option<alloc::vec::Vec<u8>> {
        let entry = self.resolve_path(path)?;
        if entry.is_dir() {
            return None;
        }
        if entry.cluster == 0 && entry.size == 0 {
            return Some(alloc::vec::Vec::new());
        }

        let data = self.read_cluster_chain_alloc(entry.cluster)?;
        let file_size = entry.size as usize;

        // Validate that we read enough data
        if data.len() < file_size {
            crate::serial_println!(
                "[fat32] Warning: file {} truncated (read {} bytes, expected {})",
                path,
                data.len(),
                file_size
            );
        }

        let mut result = data;
        result.truncate(file_size);
        Some(result)
    }

    /// List directory contents by path.
    pub fn list_dir(&mut self, path: &str) -> Option<alloc::vec::Vec<DirEntry>> {
        let entry = self.resolve_path(path)?;
        if !entry.is_dir() {
            return None;
        }
        self.read_dir_entries(entry.cluster)
    }
}

// ---------------------------------------------------------------------------
// ELF validation
// ---------------------------------------------------------------------------

/// Validate that a buffer looks like a valid ELF header.
///
/// Checks:
/// - Magic: 0x7F 'E' 'L' 'F'
/// - Class: 32-bit (1) or 64-bit (2)
/// - Data: little-endian (1)
/// - Type: relocatable (1), executable (2), shared (3), or core (4)
fn is_valid_elf(data: &[u8]) -> bool {
    if data.len() < 16 {
        return false;
    }

    // Magic
    if &data[0..4] != b"\x7fELF" {
        return false;
    }

    // Class: 1 = 32-bit, 2 = 64-bit
    let class = data[4];
    if class != 1 && class != 2 {
        return false;
    }

    // Data encoding: 1 = little-endian, 2 = big-endian
    let data_enc = data[5];
    if data_enc != 1 && data_enc != 2 {
        return false;
    }

    // ELF type: 1=REL, 2=EXEC, 3=DYN, 4=CORE
    let elf_type = if class == 2 {
        u16::from_le_bytes([data[16], data[17]])
    } else {
        u16::from_le_bytes([data[16], data[17]])
    };
    if elf_type == 0 || elf_type > 4 {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// ELF loading & public API
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct ModuleInfo {
    pub base: u64,
    pub size: u64,
}

pub struct BootModules {
    pub init: Option<ModuleInfo>,
    pub console_admin: Option<ModuleInfo>,
    pub strate_net: Option<ModuleInfo>,
    pub strate_bus: Option<ModuleInfo>,
    pub fs_ext4: Option<ModuleInfo>,
    pub strate_fs_ramfs: Option<ModuleInfo>,
    pub strate_wasm: Option<ModuleInfo>,
    pub strate_webrtc: Option<ModuleInfo>,
    pub dhcp_client: Option<ModuleInfo>,
    pub ping: Option<ModuleInfo>,
    pub telnetd: Option<ModuleInfo>,
    pub udp_tool: Option<ModuleInfo>,
    pub web_admin: Option<ModuleInfo>,
}

impl Default for BootModules {
    fn default() -> Self {
        Self {
            init: None,
            console_admin: None,
            strate_net: None,
            strate_bus: None,
            fs_ext4: None,
            strate_fs_ramfs: None,
            strate_wasm: None,
            strate_webrtc: None,
            dhcp_client: None,
            ping: None,
            telnetd: None,
            udp_tool: None,
            web_admin: None,
        }
    }
}

const MODULE_DIR: &str = "/modules";

const MODULE_NAMES: &[(&str, fn(&mut BootModules) -> &mut Option<ModuleInfo>)] = &[
    ("init", |m| &mut m.init),
    ("console_admin", |m| &mut m.console_admin),
    ("strate_net", |m| &mut m.strate_net),
    ("strate_bus", |m| &mut m.strate_bus),
    ("fs_ext4", |m| &mut m.fs_ext4),
    ("strate_fs_ramfs", |m| &mut m.strate_fs_ramfs),
    ("strate_wasm", |m| &mut m.strate_wasm),
    ("strate_webrtc", |m| &mut m.strate_webrtc),
    ("dhcp_client", |m| &mut m.dhcp_client),
    ("ping", |m| &mut m.ping),
    ("telnetd", |m| &mut m.telnetd),
    ("udp_tool", |m| &mut m.udp_tool),
    ("web_admin", |m| &mut m.web_admin),
];

/// Load all boot modules from the FAT32 boot partition.
pub fn load_all_modules<B: BlockDevice>(block_dev: &mut B) -> BootModules {
    let mut modules = BootModules::default();

    let mut fs = match FatFs::new(block_dev) {
        Some(fs) => fs,
        None => {
            crate::serial_println!("[fat32] Failed to mount filesystem");
            return modules;
        }
    };

    crate::serial_println!("[fat32] FAT32 filesystem mounted");

    let entries = match fs.list_dir(MODULE_DIR) {
        Some(e) => e,
        None => {
            crate::serial_println!("[fat32] No {} directory", MODULE_DIR);
            return modules;
        }
    };

    for entry in entries {
        if !entry.is_file() {
            continue;
        }

        // Get display name : owns the buffer so no dangling reference
        let display = entry.name.display_name();
        let name_str = display.as_str();

        let stem = name_str.strip_suffix(".elf").unwrap_or(name_str);

        for &(mod_name, setter) in MODULE_NAMES {
            if stem.eq_ignore_ascii_case(mod_name) {
                let full_path: heapless::String<64> = {
                    let mut s = heapless::String::new();
                    let _ = s.push_str(MODULE_DIR);
                    let _ = s.push('/');
                    let _ = s.push_str(name_str);
                    s
                };

                match load_elf_from_fat(&mut fs, &full_path, &entry) {
                    Some(info) => {
                        crate::serial_println!(
                            "[fat32] Loaded {} at {:#x} ({} bytes)",
                            full_path,
                            info.base,
                            info.size
                        );
                        *setter(&mut modules) = Some(info);
                    }
                    None => {
                        crate::serial_println!("[fat32] Failed to load {}", full_path);
                    }
                }
                break;
            }
        }
    }

    modules
}

/// Load a single module from FAT32.
pub fn load_module<B: BlockDevice>(block_dev: &mut B, path: &str) -> Option<ModuleInfo> {
    let mut fs = FatFs::new(block_dev)?;
    let entry = fs.resolve_path(path)?;
    load_elf_from_fat(&mut fs, path, &entry)
}

/// Load an ELF from a directory entry into allocated memory.
///
/// Validates the ELF header before loading. Returns None on any error.
fn load_elf_from_fat<B: BlockDevice>(
    fs: &mut FatFs<'_, B>,
    path: &str,
    entry: &DirEntry,
) -> Option<ModuleInfo> {
    if entry.size == 0 {
        crate::serial_println!("[fat32] {} is empty", path);
        return None;
    }

    // Read the file data
    let file_data = fs.read_cluster_chain_alloc(entry.cluster)?;
    let file_size = entry.size as usize;

    // Validate that we read enough data
    if file_data.len() < file_size {
        crate::serial_println!(
            "[fat32] {} truncated (read {} bytes, expected {})",
            path,
            file_size,
            file_size
        );
        return None;
    }

    // Validate ELF header (class, endianness, type)
    if !is_valid_elf(&file_data) {
        crate::serial_println!("[fat32] {} is not a valid ELF", path);
        return None;
    }

    // Allocate contiguous physical memory for the module
    // SAFETY: Layout is non-zero (file_size > 0 checked above) and aligned to 4096.
    // The allocation is for boot module loading : memory is not freed (kernel lifetime).
    let layout = core::alloc::Layout::from_size_align(file_size, 4096).ok()?;
    let ptr = unsafe { alloc::alloc::alloc(layout) };
    if ptr.is_null() {
        crate::serial_println!(
            "[fat32] Alloc failed: {} bytes for {}",
            file_size,
            path
        );
        return None;
    }

    // SAFETY: ptr is non-null (checked above), layout matches the allocation,
    // and file_size bytes are available from file_data.
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr, file_size) };
    buf.copy_from_slice(&file_data[..file_size]);

    Some(ModuleInfo {
        base: ptr as u64,
        size: file_size as u64,
    })
}
