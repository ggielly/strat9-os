//! FAT32 module loader for reading userspace ELFs from boot partition.
//!
//! Self-contained FAT32 parser with no external filesystem dependencies.
//! Reads the BPB, follows cluster chains, parses directory entries (8.3 + LFN),
//! and loads ELF modules into memory.

use super::block_device::BlockDevice;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SECTOR_SIZE: usize = 512;
const FAT32_EOC: u32 = 0x0FFF_FFF8;
const DIR_ENTRY_SIZE: usize = 32;

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
    sectors_per_fat_32: u32,
    root_cluster: u32,
    total_sectors_32: u32,
}

impl Bpb {
    fn from_bytes(buf: &[u8; SECTOR_SIZE]) -> Option<Self> {
        if buf[0x1FE] != 0x55 || buf[0x1FF] != 0xAA {
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

    fn cluster_to_lba(&self, cluster: u32) -> u32 {
        self.data_start_sector() + (cluster - 2) * self.sectors_per_cluster as u32
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

#[derive(Debug, Clone)]
enum DirEntryName {
    Short([u8; 11]),
    Long(heapless::String<255>),
}

impl DirEntryName {
    fn display_name(&self) -> &str {
        match self {
            DirEntryName::Long(s) => s.as_str(),
            DirEntryName::Short(sfn) => {
                static mut NAME_BUF: [u8; 12] = [0u8; 12];
                let buf = unsafe { &mut NAME_BUF };
                let mut pos = 0;
                let mut i = 0;
                while i < 8 && sfn[i] != b' ' && sfn[i] != 0 {
                    buf[pos] = sfn[i].to_ascii_lowercase();
                    pos += 1;
                    i += 1;
                }
                if sfn[8] != b' ' && sfn[8] != 0 {
                    buf[pos] = b'.';
                    pos += 1;
                    let mut i = 8;
                    while i < 11 && sfn[i] != b' ' && sfn[i] != 0 {
                        buf[pos] = sfn[i].to_ascii_lowercase();
                        pos += 1;
                        i += 1;
                    }
                }
                core::str::from_utf8(&buf[..pos]).unwrap_or("???")
            }
        }
    }

    fn matches_short(&self, upper_name: &[u8; 11]) -> bool {
        match self {
            DirEntryName::Short(sfn) => sfn == upper_name,
            DirEntryName::Long(_) => false,
        }
    }
}

fn make_sfn(name: &str) -> [u8; 11] {
    let mut sfn = [b' '; 11];
    let bytes = name.as_bytes();
    let dot_pos = bytes.iter().rposition(|&b| b == b'.');
    let (base, ext) = if let Some(dp) = dot_pos {
        (&bytes[..dp], &bytes[dp + 1..])
    } else {
        (bytes, &b""[..])
    };

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

    sfn
}

// ---------------------------------------------------------------------------
// FatFs — main filesystem object
// ---------------------------------------------------------------------------

pub struct FatFs<'a, B: BlockDevice> {
    block_dev: &'a mut B,
    bpb: Bpb,
}

impl<'a, B: BlockDevice> FatFs<'a, B> {
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

        if bpb.bytes_per_sector != SECTOR_SIZE as u16 {
            crate::serial_println!("[fat32] Unsupported sector size {}", bpb.bytes_per_sector);
            return None;
        }

        Some(FatFs { block_dev, bpb })
    }

    fn read_sector_at(
        dev: &mut B,
        fat32_sector: u32,
        buf: &mut [u8; SECTOR_SIZE],
        kernel_block_size: usize,
    ) -> Option<()> {
        if kernel_block_size >= SECTOR_SIZE {
            let mut block_buf = [0u8; 4096];
            dev.read_block(fat32_sector as u64, &mut block_buf[..kernel_block_size])
                .ok()?;
            let n = SECTOR_SIZE.min(kernel_block_size);
            buf[..n].copy_from_slice(&block_buf[..n]);
        } else {
            let blocks_per_sector = SECTOR_SIZE / kernel_block_size;
            let base_lba = fat32_sector as u64 * blocks_per_sector as u64;
            let mut block_buf = [0u8; 4096];
            for i in 0..blocks_per_sector {
                dev.read_block(base_lba + i as u64, &mut block_buf[..kernel_block_size])
                    .ok()?;
                let dst = i * kernel_block_size;
                buf[dst..dst + kernel_block_size].copy_from_slice(&block_buf[..kernel_block_size]);
            }
        }
        Some(())
    }

    fn read_sector(&mut self, fat32_sector: u32, buf: &mut [u8; SECTOR_SIZE]) -> Option<()> {
        let kbs = self.block_dev.block_size() as usize;
        Self::read_sector_at(self.block_dev, fat32_sector, buf, kbs)
    }

    fn next_cluster(&mut self, cluster: u32) -> Option<u32> {
        let fat_offset = cluster * 4;
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

        if entry >= FAT32_EOC { Some(0) } else { Some(entry) }
    }

    fn read_cluster_chain_alloc(&mut self, cluster: u32) -> Option<alloc::vec::Vec<u8>> {
        let mut data = alloc::vec::Vec::new();
        let mut current = cluster;

        while current >= 2 {
            let cluster_lba = self.bpb.cluster_to_lba(current);
            let spc = self.bpb.sectors_per_cluster as u32;

            for s in 0..spc {
                let mut sector_buf = [0u8; SECTOR_SIZE];
                self.read_sector(cluster_lba + s, &mut sector_buf)?;
                data.extend_from_slice(&sector_buf);
            }

            current = self.next_cluster(current)?;
            if data.len() > 128 * 1024 * 1024 {
                crate::serial_println!("[fat32] Cluster chain too long");
                return None;
            }
        }

        Some(data)
    }

    fn read_dir_entries(&mut self, cluster: u32) -> Option<alloc::vec::Vec<DirEntry>> {
        let dir_data = self.read_cluster_chain_alloc(cluster)?;
        self.parse_dir_entries(&dir_data)
    }

    fn parse_dir_entries(&self, data: &[u8]) -> Option<alloc::vec::Vec<DirEntry>> {
        let mut entries = alloc::vec::Vec::new();
        let mut lfn_buf = heapless::String::<255>::new();
        let mut i = 0;

        while i + DIR_ENTRY_SIZE <= data.len() {
            let raw = &data[i..i + DIR_ENTRY_SIZE];
            i += DIR_ENTRY_SIZE;

            if raw[0] == 0x00 {
                break;
            }
            if raw[0] == 0xE5 {
                lfn_buf.clear();
                continue;
            }

            let attr = raw[11];

            if attr == ATTR_LFN {
                let seq = raw[0];
                let is_last = (seq & 0x40) != 0;
                if is_last {
                    lfn_buf.clear();
                }

                let positions = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
                for &pos in &positions {
                    let lo = raw[pos] as u16;
                    let hi = raw[pos + 1] as u16;
                    let ch = (hi << 8) | lo;
                    if ch != 0x0000 && ch != 0xFFFF {
                        if let Some(c) = char::from_u32(ch as u32) {
                            // Prepend (LFN entries arrive in reverse order)
                            let mut tmp = heapless::String::<255>::new();
                            let _ = tmp.push(c);
                            let _ = tmp.push_str(lfn_buf.as_str());
                            lfn_buf = tmp;
                        }
                    }
                }
                continue;
            }

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

            entries.push(DirEntry { name, attr, cluster, size });
        }

        Some(entries)
    }

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
        let parts: heapless::Vec<&str, 16> = path.split('/').filter(|s| !s.is_empty()).collect();

        for (idx, part) in parts.iter().enumerate() {
            let dir_entries = self.read_dir_entries(current_cluster)?;
            let target_sfn = make_sfn(part);

            let mut found = None;
            for entry in &dir_entries {
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

            if idx == parts.len() - 1 {
                return Some(entry);
            }

            if entry.attr & ATTR_DIRECTORY == 0 {
                return None;
            }
            current_cluster = entry.cluster;
        }

        None
    }

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

    pub fn list_dir(&mut self, path: &str) -> Option<alloc::vec::Vec<DirEntry>> {
        let entry = self.resolve_path(path)?;
        if entry.attr & ATTR_DIRECTORY == 0 {
            return None;
        }
        self.read_dir_entries(entry.cluster)
    }
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

fn load_elf_from_fat<B: BlockDevice>(
    fs: &mut FatFs<'_, B>,
    path: &str,
    entry: &DirEntry,
) -> Option<ModuleInfo> {
    if entry.size == 0 {
        return None;
    }

    let file_data = fs.read_cluster_chain_alloc(entry.cluster)?;
    let file_size = entry.size as usize;
    if file_data.len() < 4 || &file_data[..4] != b"\x7fELF" {
        crate::serial_println!("[fat32] {} is not an ELF", path);
        return None;
    }

    let layout = core::alloc::Layout::from_size_align(file_size, 4096).ok()?;
    let ptr = unsafe { alloc::alloc::alloc(layout) };
    if ptr.is_null() {
        crate::serial_println!("[fat32] Alloc failed: {} bytes for {}", file_size, path);
        return None;
    }

    let buf = unsafe { core::slice::from_raw_parts_mut(ptr, file_size) };
    let copy_len = file_size.min(file_data.len());
    buf[..copy_len].copy_from_slice(&file_data[..copy_len]);

    Some(ModuleInfo {
        base: ptr as u64,
        size: file_size as u64,
    })
}
