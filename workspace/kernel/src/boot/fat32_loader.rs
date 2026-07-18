//! FAT32 module loader for reading userspace ELFs from boot partition.
//!
//! Self-contained FAT32 parser with no external filesystem dependencies.
//! Reads the BPB, follows cluster chains, parses directory entries (8.3 + LFN),
//! and loads ELF modules into memory.

use super::block_device::BlockDevice;
use core::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SECTOR_SIZE: usize = 512;
const FAT32_EOC: u32 = 0x0FFF_FFF8;
const FAT32_EOC_MAX: u32 = 0x0FFF_FFFF;
const FAT32_FREE_CLUSTER: u32 = 0;
const DIR_ENTRY_SIZE: usize = 32;
const LFN_CHARS_PER_ENTRY: usize = 13;

/// FAT directory entry attribute flags
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_LFN: u8 = 0x0F;
const ATTR_VOLUME_ID: u8 = 0x08;

// ---------------------------------------------------------------------------
// BPB (BIOS Parameter Block)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Bpb {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    total_sectors_16: u16,
    sectors_per_fat_32: u32,
    root_cluster: u32,
    fs_info_sector: u16,
    total_sectors_32: u32,
}

impl Bpb {
    /// Parse a BPB from a 512-byte boot sector buffer.
    fn from_bytes(buf: &[u8; SECTOR_SIZE]) -> Option<Self> {
        // Verify boot signature at offset 0x1FE
        if buf[0x1FE] != 0x55 || buf[0x1FF] != 0xAA {
            return None;
        }

        let bytes_per_sector = u16::from_le_bytes([buf[0x0B], buf[0x0C]]);
        let sectors_per_cluster = buf[0x0D];
        let reserved_sectors = u16::from_le_bytes([buf[0x0E], buf[0x0F]]);
        let num_fats = buf[0x10];
        let total_sectors_16 = u16::from_le_bytes([buf[0x13], buf[0x14]]);

        // FAT32-specific fields
        let sectors_per_fat_32 = u32::from_le_bytes([buf[0x24], buf[0x25], buf[0x26], buf[0x27]]);
        let root_cluster = u32::from_le_bytes([buf[0x2C], buf[0x2D], buf[0x2E], buf[0x2F]]);
        let fs_info_sector = u16::from_le_bytes([buf[0x30], buf[0x31]]);
        let total_sectors_32 = u32::from_le_bytes([buf[0x20], buf[0x21], buf[0x22], buf[0x23]]);

        if bytes_per_sector == 0 || sectors_per_cluster == 0 {
            return None;
        }

        Some(Bpb {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            total_sectors_16,
            sectors_per_fat_32,
            root_cluster,
            fs_info_sector,
            total_sectors_32,
        })
    }

    fn bytes_per_cluster(&self) -> u32 {
        self.bytes_per_sector as u32 * self.sectors_per_cluster as u32
    }

    fn total_sectors(&self) -> u32 {
        if self.total_sectors_16 != 0 {
            self.total_sectors_16 as u32
        } else {
            self.total_sectors_32
        }
    }

    fn fat_start_sector(&self) -> u32 {
        self.reserved_sectors as u32
    }

    fn data_start_sector(&self) -> u32 {
        self.fat_start_sector() + self.sectors_per_fat_32 * self.num_fats as u32
    }

    /// Convert a cluster number to the LBA of its first sector.
    fn cluster_to_lba(&self, cluster: u32) -> u32 {
        self.data_start_sector() + (cluster - 2) * self.sectors_per_cluster as u32
    }
}

// ---------------------------------------------------------------------------
// Directory entry types
// ---------------------------------------------------------------------------

/// A parsed directory entry (either file or directory).
#[derive(Debug, Clone)]
struct DirEntry {
    name: DirEntryName,
    attr: u8,
    cluster: u32,
    size: u32,
}

/// The name of a directory entry (may be 8.3 short or LFN).
#[derive(Debug, Clone)]
enum DirEntryName {
    /// Short name (8.3 format, e.g. "HELLO.TXT")
    Short([u8; 11]),
    /// Long file name (Unicode, up to 255 chars)
    Long(heapless::String<255>),
}

impl DirEntryName {
    fn display_name(&self) -> &str {
        match self {
            DirEntryName::Short(sfn) => {
                // We store displayable name in the static buffer approach;
                // for now return a slice view. The caller should use
                // `matches_short_name` for comparisons.
                // SAFETY: We return a str reference into a stack buffer.
                // Use a small buffer on the stack for the formatted name.
                static mut NAME_BUF: [u8; 12] = [0u8; 12];
                // SAFETY: Single-threaded boot context, no concurrent access.
                let buf = unsafe { &mut NAME_BUF };
                let mut pos = 0;
                // Copy base name (first 8 chars), strip trailing spaces
                let mut i = 0;
                while i < 8 && sfn[i] != b' ' && sfn[i] != 0 {
                    buf[pos] = sfn[i];
                    pos += 1;
                    i += 1;
                }
                // Extension (chars 8-10)
                if sfn[8] != b' ' && sfn[8] != 0 {
                    buf[pos] = b'.';
                    pos += 1;
                    let mut i = 8;
                    while i < 11 && sfn[i] != b' ' && sfn[i] != 0 {
                        buf[pos] = sfn[i];
                        pos += 1;
                        i += 1;
                    }
                }
                core::str::from_utf8(&buf[..pos]).unwrap_or("???")
            }
            DirEntryName::Long(s) => s.as_str(),
        }
    }

    fn matches_short(&self, upper_name: &[u8; 11]) -> bool {
        match self {
            DirEntryName::Short(sfn) => sfn == upper_name,
            DirEntryName::Long(_) => false,
        }
    }
}

/// Build an 8.3 short name from a string for comparison.
fn make_sfn(name: &str) -> [u8; 11] {
    let mut sfn = [b' '; 11];
    let name_upper = name.as_bytes();
    let mut pos = 0;

    // Find the last dot to split name/extension
    let dot_pos = name_upper.iter().rposition(|&b| b == b'.');

    let (base, ext) = if let Some(dp) = dot_pos {
        (&name_upper[..dp], &name_upper[dp + 1..])
    } else {
        (name_upper, &b""[..])
    };

    // Fill base name (up to 8 chars)
    let mut i = 0;
    while pos < 8 && i < base.len() {
        let c = base[i];
        if c != b'.' && c != b' ' {
            sfn[pos] = c.to_ascii_uppercase();
            pos += 1;
        }
        i += 1;
    }

    // Fill extension (up to 3 chars)
    pos = 8;
    let mut i = 0;
    while pos < 11 && i < ext.len() {
        let c = ext[i];
        if c != b'.' && c != b' ' {
            sfn[pos] = c.to_ascii_uppercase();
            pos += 1;
        }
        i += 1;
    }

    sfn
}

// ---------------------------------------------------------------------------
// Cluster chain iterator
// ---------------------------------------------------------------------------

struct ClusterChain<'a, B: BlockDevice> {
    fs: &'a FatFs<'a, B>,
    next_cluster: Option<u32>,
}

impl<'a, B: BlockDevice> ClusterChain<'a, B> {
    fn new(fs: &'a FatFs<'a, B>, start_cluster: u32) -> Self {
        Self {
            fs,
            next_cluster: if start_cluster >= 2 {
                Some(start_cluster)
            } else {
                None
            },
        }
    }
}

impl<'a, B: BlockDevice> Iterator for ClusterChain<'a, B> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        let current = self.next_cluster?;
        match self.fs.next_cluster(current) {
            Ok(next) => {
                self.next_cluster = if next >= 2 { Some(next) } else { None };
                Some(current)
            }
            Err(_) => {
                self.next_cluster = None;
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FatFs — main filesystem object
// ---------------------------------------------------------------------------

/// A FAT32 filesystem mounted over a block device.
pub struct FatFs<'a, B: BlockDevice> {
    block_dev: &'a mut B,
    bpb: Bpb,
    /// Number of kernel blocks per FAT32 sector.
    blocks_per_sector: u32,
}

impl<'a, B: BlockDevice> FatFs<'a, B> {
    /// Mount a FAT32 filesystem from a block device.
    ///
    /// Reads the boot sector from LBA 0 and validates the BPB.
    pub fn new(block_dev: &'a mut B) -> Option<Self> {
        let kernel_block_size = block_dev.block_size() as usize;

        // Read the boot sector (first sector, LBA 0)
        let mut sector_buf = [0u8; SECTOR_SIZE];
        Self::read_sector_at(block_dev, 0, &mut sector_buf, kernel_block_size)?;

        let bpb = Bpb::from_bytes(&sector_buf)?;

        crate::serial_println!(
            "[fat32] BPB: {} bytes/sector, {} sec/cluster, {} reserved, {} FATs, root_cluster={}",
            bpb.bytes_per_sector,
            bpb.sectors_per_cluster,
            bpb.reserved_sectors,
            bpb.num_fats,
            bpb.root_cluster,
        );

        if bpb.bytes_per_sector != SECTOR_SIZE as u16 {
            crate::serial_println!(
                "[fat32] Unsupported sector size: {} (expected 512)",
                bpb.bytes_per_sector
            );
            return None;
        }

        let blocks_per_sector = (SECTOR_SIZE / kernel_block_size) as u32;
        if blocks_per_sector == 0 {
            crate::serial_println!("[fat32] Kernel block size {} > FAT sector size 512", kernel_block_size);
            return None;
        }

        Some(FatFs {
            block_dev,
            bpb,
            blocks_per_sector,
        })
    }

    /// Read a FAT32 sector into `buf` (must be >= 512 bytes).
    ///
    /// Translates FAT32 sector number to kernel LBA.
    fn read_sector(&mut self, fat32_sector: u32, buf: &mut [u8; SECTOR_SIZE]) -> Option<()> {
        Self::read_sector_at(self.block_dev, fat32_sector, buf, self.bpb.bytes_per_sector as usize)
    }

    /// Read a FAT32 sector from an arbitrary block device.
    fn read_sector_at(
        dev: &mut B,
        fat32_sector: u32,
        buf: &mut [u8; SECTOR_SIZE],
        kernel_block_size: usize,
    ) -> Option<()> {
        if kernel_block_size >= SECTOR_SIZE {
            // Kernel block is >= FAT sector: read one block, take first 512 bytes
            let lba = fat32_sector as u64;
            let mut block_buf = [0u8; 4096];
            dev.read_block(lba, &mut block_buf[..kernel_block_size]).ok()?;
            let copy_len = SECTOR_SIZE.min(kernel_block_size);
            buf[..copy_len].copy_from_slice(&block_buf[..copy_len]);
            Some(())
        } else {
            // Kernel block is < FAT sector: read multiple blocks
            let blocks_per_sector = SECTOR_SIZE / kernel_block_size;
            let base_lba = fat32_sector as u64 * blocks_per_sector as u64;
            let mut block_buf = [0u8; 4096];
            for i in 0..blocks_per_sector {
                dev.read_block(base_lba + i as u64, &mut block_buf[..kernel_block_size])
                    .ok()?;
                let dst_start = i * kernel_block_size;
                let dst_end = dst_start + kernel_block_size;
                if dst_end <= SECTOR_SIZE {
                    buf[dst_start..dst_end].copy_from_slice(&block_buf[..kernel_block_size]);
                }
            }
            Some(())
        }
    }

    /// Read the next cluster number from the FAT table.
    fn next_cluster(&mut self, cluster: u32) -> Result<u32, ()> {
        let fat_offset = cluster * 4; // 4 bytes per FAT32 entry
        let fat_sector = self.bpb.fat_start_sector() + fat_offset / SECTOR_SIZE as u32;
        let entry_offset = (fat_offset % SECTOR_SIZE as u32) as usize;

        let mut sector_buf = [0u8; SECTOR_SIZE];
        self.read_sector(fat_sector, &mut sector_buf)?;

        let entry = u32::from_le_bytes([
            sector_buf[entry_offset],
            sector_buf[entry_offset + 1],
            sector_buf[entry_offset + 2],
            sector_buf[entry_offset + 3],
        ]) & 0x0FFF_FFFF;

        if entry >= FAT32_EOC {
            Ok(0) // End of chain
        } else {
            Ok(entry)
        }
    }

    /// Read raw data from a cluster chain starting at `cluster`, into `buf`.
    ///
    /// Reads `buf.len()` bytes, following the cluster chain as needed.
    /// Returns the number of bytes actually read.
    fn read_cluster_chain(
        &mut self,
        start_cluster: u32,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let bpc = self.bpb.bytes_per_cluster() as u64;
        if bpc == 0 {
            return Err(());
        }

        // Skip clusters to reach the requested offset
        let clusters_to_skip = (offset / bpc) as u32;
        let offset_in_cluster = (offset % bpc) as usize;

        let mut cluster = start_cluster;
        for _ in 0..clusters_to_skip {
            cluster = self.next_cluster(cluster)?;
            if cluster == 0 {
                return Ok(0);
            }
        }

        let mut total_read = 0usize;
        let mut buf_pos = 0usize;
        let mut skip = offset_in_cluster;
        let mut current_cluster = cluster;

        while buf_pos < buf.len() && current_cluster >= 2 {
            let cluster_lba = self.bpb.cluster_to_lba(current_cluster);
            let bytes_per_cluster = self.bpb.bytes_per_cluster() as usize;

            // Read cluster sector by sector
            let sectors_per_cluster = self.bpb.sectors_per_cluster as u32;
            for s in 0..sectors_per_cluster {
                if buf_pos >= buf.len() {
                    break;
                }

                let mut sector_buf = [0u8; SECTOR_SIZE];
                self.read_sector(cluster_lba + s, &mut sector_buf)?;

                let data = if skip > 0 {
                    let skip_amount = skip.min(SECTOR_SIZE);
                    skip -= skip_amount;
                    &sector_buf[skip_amount..]
                } else {
                    &sector_buf[..]
                };

                let remaining = buf.len() - buf_pos;
                let to_copy = data.len().min(remaining);
                buf[buf_pos..buf_pos + to_copy].copy_from_slice(&data[..to_copy]);
                buf_pos += to_copy;
                total_read += to_copy;
            }

            current_cluster = self.next_cluster(current_cluster)?;
        }

        Ok(total_read)
    }

    /// Read an entire cluster chain into a heap-allocated buffer.
    fn read_cluster_chain_alloc(&mut self, cluster: u32) -> Option<alloc::vec::Vec<u8>> {
        let bpc = self.bpb.bytes_per_cluster() as usize;
        let mut data = alloc::vec::Vec::new();

        let mut current = cluster;
        while current >= 2 {
            let cluster_lba = self.bpb.cluster_to_lba(current);
            let sectors_per_cluster = self.bpb.sectors_per_cluster as u32;

            for s in 0..sectors_per_cluster {
                let mut sector_buf = [0u8; SECTOR_SIZE];
                self.read_sector(cluster_lba + s, &mut sector_buf)?;
                data.extend_from_slice(&sector_buf);
            }

            current = self.next_cluster(current).ok()?;
            // Safety limit to prevent runaway chains
            if data.len() > 128 * 1024 * 1024 {
                crate::serial_println!("[fat32] Cluster chain too long, aborting");
                return None;
            }
        }

        Some(data)
    }

    /// Read directory entries from a cluster chain.
    fn read_dir_entries(&mut self, cluster: u32) -> Option<alloc::vec::Vec<DirEntry>> {
        let dir_data = self.read_cluster_chain_alloc(cluster)?;
        self.parse_dir_entries(&dir_data)
    }

    /// Parse raw directory data into `DirEntry` items.
    fn parse_dir_entries(&self, data: &[u8]) -> Option<alloc::vec::Vec<DirEntry>> {
        let mut entries = alloc::vec::Vec::new();
        let mut lfn_buf = heapless::String::<255>::new();
        let mut i = 0;

        while i + DIR_ENTRY_SIZE <= data.len() {
            let raw = &data[i..i + DIR_ENTRY_SIZE];
            i += DIR_ENTRY_SIZE;

            // End of directory
            if raw[0] == 0x00 {
                break;
            }

            // Deleted entry
            if raw[0] == 0xE5 {
                lfn_buf.clear();
                continue;
            }

            let attr = raw[11];

            if attr == ATTR_LFN {
                // Long file name entry
                let seq = raw[0];
                let is_last = (seq & 0x40) != 0;
                let _index = seq & 0x3F;

                if is_last {
                    lfn_buf.clear();
                }

                // Extract 13 UTF-16 characters from positions 1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30
                let lfn_positions = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
                for &pos in &lfn_positions {
                    let lo = raw[pos] as u16;
                    let hi = raw[pos + 1] as u16;
                    let ch = (hi << 8) | lo;
                    if ch == 0x0000 || ch == 0xFFFF {
                        // ignore padding
                    } else if let Some(c) = char::from_u32(ch as u32) {
                        // Prepend since LFN entries are in reverse order
                        // We collect them forward by pushing, then reverse at the end
                        let mut tmp = heapless::String::<255>::new();
                        let _ = tmp.push(c);
                        let _ = tmp.push_str(lfn_buf.as_str());
                        lfn_buf = tmp;
                    }
                }
                continue;
            }

            // Regular entry (file or directory)
            let cluster_hi = u16::from_le_bytes([raw[20], raw[21]]) as u32;
            let cluster_lo = u16::from_le_bytes([raw[26], raw[27]]) as u32;
            let cluster = (cluster_hi << 16) | cluster_lo;
            let size = u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]);

            let name = if !lfn_buf.is_empty() {
                let n = DirEntryName::Long(lfn_buf.clone());
                lfn_buf.clear();
                n
            } else {
                let mut sfn = [0u8; 11];
                sfn.copy_from_slice(&raw[0..11]);
                DirEntryName::Short(sfn)
            };

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
            // Return root directory pseudo-entry
            return Some(DirEntry {
                name: DirEntryName::Short(*b"/           "),
                attr: ATTR_DIRECTORY,
                cluster: self.bpb.root_cluster,
                size: 0,
            });
        }

        let mut current_cluster = self.bpb.root_cluster;
        let mut parts = path.split('/');

        loop {
            let part = parts.next()?;
            let entries = self.read_dir_entries(current_cluster)?;

            let target_sfn = make_sfn(part);
            let mut found = None;

            for entry in &entries {
                if entry.attr & ATTR_VOLUME_ID != 0 {
                    continue;
                }
                if entry.name.matches_short(&target_sfn)
                    || entry.name.display_name().eq_ignore_ascii_case(part)
                {
                    found = Some(entry.clone());
                    break;
                }
            }

            let entry = found?;
            if parts.peek().is_none() {
                return Some(entry);
            }

            // Must be a directory to continue traversing
            if entry.attr & ATTR_DIRECTORY == 0 {
                return None;
            }
            current_cluster = entry.cluster;
        }
    }

    /// Open a file by path and return its data.
    pub fn read_file(&mut self, path: &str) -> Option<alloc::vec::Vec<u8>> {
        let entry = self.resolve_path(path)?;
        if entry.attr & ATTR_DIRECTORY != 0 {
            return None;
        }
        if entry.cluster == 0 && entry.size == 0 {
            return Some(alloc::vec::Vec::new());
        }
        self.read_cluster_chain_alloc(entry.cluster)
            .map(|mut data| {
                data.truncate(entry.size as usize);
                data
            })
    }

    /// List directory contents by path.
    pub fn list_dir(&mut self, path: &str) -> Option<alloc::vec::Vec<DirEntry>> {
        let entry = self.resolve_path(path)?;
        if entry.attr & ATTR_DIRECTORY == 0 {
            return None;
        }
        self.read_dir_entries(entry.cluster)
    }
}

// ---------------------------------------------------------------------------
// ELF loading
// ---------------------------------------------------------------------------

/// Module information loaded from FAT32
#[derive(Debug, Clone, Copy)]
pub struct ModuleInfo {
    /// Physical address of the loaded module in memory
    pub base: u64,
    /// Size of the module in bytes
    pub size: u64,
}

/// Boot modules loaded from FAT32 partition
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
            crate::serial_println!("[fat32] No {} directory found", MODULE_DIR);
            return modules;
        }
    };

    for entry in entries {
        if entry.attr & ATTR_DIRECTORY != 0 {
            continue;
        }

        let name = entry.name.display_name();
        let stem = name.strip_suffix(".elf").unwrap_or(name);

        for &(mod_name, setter) in MODULE_NAMES {
            if stem.eq_ignore_ascii_case(mod_name) {
                let full_path = alloc::format!("{}/{}", MODULE_DIR, name);
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

/// Load an ELF file from a directory entry into allocated memory.
fn load_elf_from_fat<B: BlockDevice>(
    fs: &mut FatFs<'_, B>,
    path: &str,
    entry: &DirEntry,
) -> Option<ModuleInfo> {
    if entry.size == 0 {
        return None;
    }

    // Read the file data
    let mut file_data = fs.read_cluster_chain_alloc(entry.cluster)?;
    file_data.truncate(entry.size as usize);

    // Verify ELF magic
    if file_data.len() < 4 || &file_data[..4] != b"\x7fELF" {
        crate::serial_println!("[fat32] {} is not an ELF (bad magic)", path);
        return None;
    }

    let file_size = file_data.len();

    // Allocate contiguous physical memory for the module
    let layout = core::alloc::Layout::from_size_align(file_size, 4096).ok()?;
    let ptr = unsafe { alloc::alloc::alloc(layout) };
    if ptr.is_null() {
        crate::serial_println!(
            "[fat32] Failed to allocate {} bytes for {}",
            file_size,
            path
        );
        return None;
    }

    // Copy ELF data into the allocated buffer
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr, file_size) };
    buf.copy_from_slice(&file_data);

    Some(ModuleInfo {
        base: ptr as u64,
        size: file_size as u64,
    })
}
