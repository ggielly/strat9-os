//! Multi-driver VFS scheme served at `/bus/`.
//!
//! Each successfully-initialised bus driver appears as a sub-directory:
//!
//! ```text
//! /bus/                     -> list of registered driver names + pci/
//! /bus/pci/inventory        -> PCI device table
//! /bus/pci/count            -> number of PCI devices
//! /bus/pci/rescan           -> (write-only) refresh PCI cache
//! /bus/pci/find/<vid>/<did> -> find devices by vendor/device
//! /bus/pci/cfg/<b:d.f>/<off>/<w>  -> raw PCI config read
//! /bus/<driver>/            -> driver info (compatible, errors, …)
//! /bus/<driver>/status      -> driver status
//! /bus/<driver>/error_count -> driver error count
//! /bus/<driver>/reg/<hex>   -> read/write a driver register
//! /bus/<driver>/<child>     -> child-device info (if the driver reports any)
//! ```

use alloc::{boxed::Box, collections::BTreeMap, format, string::String, vec::Vec};
use strat9_syscall::{
    call,
    data::{
        DT_DIR, DT_REG, IpcMessage, IPC_FILE_FLAG_DIRECTORY, OPCODE_CLOSE, OPCODE_OPEN,
        OPCODE_READ, OPCODE_READDIR, OPCODE_WRITE, PCI_MATCH_DEVICE_ID, PCI_MATCH_VENDOR_ID,
        PciAddress, PciDeviceInfo, PciProbeCriteria,
    },
    error::{EBADF, EINVAL, EIO, ENOMEM, ENOENT, ENOSYS, ENOTDIR},
};

use crate::BusDriver;

/// Upper bound on simultaneously open handles.
/// Prevents a single client from exhausting server memory by opening
/// handles in a loop without closing them (DoS on the scheme server).
const MAX_OPEN_HANDLES: usize = 256;

// VFS scheme opcodes (OPCODE_*) are re-exported from strat9-abi via
// strat9-syscall: the wire contract must have a single source of truth,
// not per-server copies. Reply type: see `IpcMessage::REPLY_MSG_TYPE`.
const STATUS_OK: u32 = 0;

/// Fixed reply prologue of a READ reply: `status` (4) + `count` (4).
const READ_HEADER_SIZE: usize = 8;
/// Fixed reply prologue of a READDIR reply: `status` (4) + `next_cursor`
/// (2) + `count` (1) + `size` (1), written at payload offsets 0..8.
const READDIR_HEADER_SIZE: usize = 8;
/// Max inline data bytes carried by a READ reply:
/// full payload minus the `status`/`count` prefix.
const READ_DATA_CAPACITY: usize = IpcMessage::PAYLOAD_CAPACITY - READ_HEADER_SIZE;
/// Max bytes usable for readdir entries: full payload minus the fixed
/// reply prologue (`next_cursor` + `count` + `size`, written at 4..8).
const READDIR_DATA_CAPACITY: usize = IpcMessage::PAYLOAD_CAPACITY - READDIR_HEADER_SIZE;

// === Path constants ========================================================

/// Driver-specific paths (relative to the driver prefix).
const DRV_STATUS: &str = "status";
const DRV_ERROR_COUNT: &str = "error_count";
const DRV_SUSPEND: &str = "suspend";
const DRV_RESUME: &str = "resume";
const DRV_REG_PREFIX: &str = "reg/";

/// Top-level paths.
const PCI_PREFIX: &str = "pci";

// === Handle ================================================================

enum HandleKind {
    /// Root : listing drivers + pci.
    Root,
    /// PCI sub-tree.
    Pci(String),
    /// A specific driver, with an optional sub-path.
    Driver { driver_idx: usize, sub_path: String },
}

struct OpenHandle {
    kind: HandleKind,
    /// PID/TID of the process that opened this handle.
    ///
    /// All subsequent operations on the handle must come from the same
    /// sender; any other sender gets `EBADF`. Without this check, any
    /// process that guesses a `file_id` could read driver registers or
    /// write PCI config across processes.
    owner: u64,
}

// === Server ================================================================

pub struct BusSchemeServer {
    drivers: Vec<(String, Box<dyn BusDriver>)>,
    port_handle: u64,
    handles: BTreeMap<u64, OpenHandle>,
    next_id: u64,
    pci_cache: Vec<PciDeviceInfo>,
}

impl BusSchemeServer {
    /// Creates a new instance.
    pub fn new(drivers: Vec<(String, Box<dyn BusDriver>)>, port_handle: u64) -> Self {
        Self {
            drivers,
            port_handle,
            handles: BTreeMap::new(),
            next_id: 1,
            pci_cache: Vec::new(),
        }
    }

    // === PCI cache (shared) =================================================

    /// Performs the refresh pci cache operation.
    ///
    /// Returns `Ok(count)` with the number of devices found, or `Err(())` if the
    /// underlying `pci_enum` syscall failed (cache remains unchanged).
    pub fn refresh_pci_cache(&mut self) -> Result<usize, ()> {
        let criteria = PciProbeCriteria {
            match_flags: 0,
            vendor_id: 0,
            device_id: 0,
            class_code: 0,
            subclass: 0,
            prog_if: 0,
            _reserved: 0,
        };
        let mut buf = alloc::vec![PciDeviceInfo {
            address: PciAddress {
                bus: 0,
                device: 0,
                function: 0,
                _reserved: 0,
            },
            vendor_id: 0,
            device_id: 0,
            class_code: 0,
            subclass: 0,
            prog_if: 0,
            revision: 0,
            header_type: 0,
            interrupt_line: 0,
            interrupt_pin: 0,
            _reserved: 0,
        }; 256];
        match call::pci_enum(&criteria, &mut buf) {
            Ok(n) => {
                let count = n.min(buf.len());
                self.pci_cache.clear();
                self.pci_cache.extend_from_slice(&buf[..count]);
                Ok(self.pci_cache.len())
            }
            Err(_) => Err(()),
        }
    }

    // === Reply helpers =====================================================

    fn ok_reply(sender: u64) -> IpcMessage {
        IpcMessage::status_reply(sender, STATUS_OK)
    }

    fn err_reply(sender: u64, code: usize) -> IpcMessage {
        IpcMessage::status_reply(sender, code as u32)
    }

    fn alloc_id(&mut self) -> Option<u64> {
        let id = self.next_id;
        // Never wrap: reusing ids after u64::MAX could alias handles that
        // are still open. Fail cleanly instead.
        if id == u64::MAX {
            return None;
        }
        self.next_id = id + 1;
        Some(id)
    }

    // === Path resolution ===================================================

    /// Split a normalised path into a driver index + sub-path, or detect PCI / root.
    fn resolve_driver_path<'a>(&self, path: &'a str) -> Option<(usize, &'a str)> {
        let (first, rest) = path.split_once('/').unwrap_or((path, ""));
        for (i, (name, _)) in self.drivers.iter().enumerate() {
            if first == name.as_str() {
                return Some((i, rest));
            }
        }
        None
    }

    fn is_pci_path(path: &str) -> bool {
        path == PCI_PREFIX || path.starts_with("pci/")
    }

    // === Path existence ===================================================

    fn path_exists(&self, path: &str) -> bool {
        // Root is always valid
        if path.is_empty() {
            return true;
        }
        // PCI paths
        if Self::is_pci_path(path) {
            return true;
        }
        // Driver paths
        if let Some((idx, sub)) = self.resolve_driver_path(path) {
            if sub.is_empty()
                || sub == DRV_STATUS
                || sub == DRV_ERROR_COUNT
                || sub == DRV_SUSPEND
                || sub == DRV_RESUME
            {
                return true;
            }
            if sub.starts_with(DRV_REG_PREFIX) {
                return Self::parse_reg_offset(sub).is_some();
            }
            // Child device check
            if self.drivers[idx].1.children().iter().any(|c| c.name == sub) {
                return true;
            }
            return false;
        }
        false
    }

    fn parse_reg_offset(path: &str) -> Option<usize> {
        let reg_str = path.strip_prefix(DRV_REG_PREFIX)?;
        Self::parse_hex_usize(reg_str)
    }

    /// Parse an unsigned hex value, rejecting inputs `from_str_radix`
    /// would otherwise accept:
    /// - sign prefixes (`"+1f"`, `"-1f"`),
    /// - repeated `0x` prefixes (`"0x0x10"`, previously stripped in a loop).
    fn parse_hex_usize(s: &str) -> Option<usize> {
        let digits = s.strip_prefix("0x").unwrap_or(s);
        if digits.is_empty() || digits.starts_with(['+', '-']) {
            return None;
        }
        usize::from_str_radix(digits, 16).ok()
    }

    fn parse_hex_u8(s: &str) -> Option<u8> {
        Self::parse_hex_usize(s)?.try_into().ok()
    }

    fn parse_hex_u16(s: &str) -> Option<u16> {
        Self::parse_hex_usize(s)?.try_into().ok()
    }

    // === Open ================================================================

    fn handle_open(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let path_len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
        if path_len > IpcMessage::OPEN_INLINE_CAPACITY {
            return Self::err_reply(sender, EINVAL);
        }
        let path_bytes = &payload[6..6 + path_len];
        let raw_path = match core::str::from_utf8(path_bytes) {
            Ok(s) => s,
            Err(_) => return Self::err_reply(sender, EINVAL),
        };
        let path = match Self::normalize_path(raw_path) {
            Some(p) => p,
            // `..` escaping the namespace root.
            None => return Self::err_reply(sender, EINVAL),
        };
        if !self.path_exists(&path) {
            return Self::err_reply(sender, ENOENT);
        }

        let file_id = match self.alloc_id() {
            Some(id) => id,
            // Handle id space exhausted.
            None => return Self::err_reply(sender, ENOMEM),
        };
        if self.handles.len() >= MAX_OPEN_HANDLES {
            return Self::err_reply(sender, ENOMEM);
        }
        let is_dir;
        let kind = if path.is_empty() {
            is_dir = true;
            HandleKind::Root
        } else if Self::is_pci_path(&path) {
            // `path.is_empty()` is unreachable here: the Root branch above
            // already handles it.
            is_dir = path == PCI_PREFIX || path == "pci/find" || path == "pci/cfg";
            HandleKind::Pci(path)
        } else if let Some((idx, sub)) = self.resolve_driver_path(&path) {
            is_dir = sub.is_empty();
            HandleKind::Driver {
                driver_idx: idx,
                sub_path: String::from(sub),
            }
        } else {
            return Self::err_reply(sender, ENOENT);
        };

        self.handles.insert(file_id, OpenHandle { kind, owner: sender });

        let mut reply = Self::ok_reply(sender);
        reply.payload[4..12].copy_from_slice(&file_id.to_le_bytes());
        reply.payload[12..20].copy_from_slice(&0u64.to_le_bytes());
        reply.payload[20..24].copy_from_slice(
            &(if is_dir { IPC_FILE_FLAG_DIRECTORY } else { 0 }).to_le_bytes(),
        );
        reply
    }

    // === Read ================================================================

    fn handle_read(&self, sender: u64, payload: &[u8]) -> IpcMessage {
        let file_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
        let offset = u64::from_le_bytes(payload[8..16].try_into().unwrap());

        let handle = match self.handles.get(&file_id) {
            Some(h) if h.owner == sender => h,
            _ => return Self::err_reply(sender, EBADF),
        };

        let content = self.generate_read_content(&handle.kind, offset as usize);
        // Use the full remaining payload capacity (240 - 8 header bytes),
        // not an arbitrary cap: each wasted byte costs one extra IPC
        // round-trip per read.
        let max = READ_DATA_CAPACITY;
        let n = content.len().min(max);

        let mut reply = Self::ok_reply(sender);
        reply.payload[4..8].copy_from_slice(&(n as u32).to_le_bytes());
        reply.payload[8..8 + n].copy_from_slice(&content[..n]);
        reply
    }

    fn generate_read_content(&self, kind: &HandleKind, offset: usize) -> Vec<u8> {
        let data = match kind {
            HandleKind::Root => {
                let mut s = format!("drivers registered: {}\n", self.drivers.len());
                for (name, d) in &self.drivers {
                    s.push_str(&format!("  {} (compat: {:?})\n", name, d.compatible()));
                }
                s.into_bytes()
            }
            HandleKind::Pci(path) => self.read_pci_content(path),
            HandleKind::Driver {
                driver_idx,
                sub_path,
            } => {
                let driver = &self.drivers[*driver_idx].1;
                let name = &self.drivers[*driver_idx].0;
                self.read_driver_content(driver, name, sub_path)
            }
        };

        if offset >= data.len() {
            Vec::new()
        } else {
            data[offset..].to_vec()
        }
    }

    fn read_pci_content(&self, path: &str) -> Vec<u8> {
        match path {
            "" | PCI_PREFIX => b"inventory\ncount\nrescan\nfind\ncfg\n".to_vec(),
            "pci/find" => b"usage: /bus/pci/find/<vendor>/<device>\n".to_vec(),
            "pci/cfg" => b"usage: /bus/pci/cfg/<bb:dd.f>/<offset>/<width>\n".to_vec(),
            "pci/inventory" => self.render_inventory(),
            "pci/count" => format!("{}\n", self.pci_cache.len()).into_bytes(),
            path if path.starts_with("pci/find/") => {
                let Some((vendor_id, device_id)) = Self::parse_find_path(path) else {
                    return b"invalid path\n".to_vec();
                };
                let criteria = PciProbeCriteria {
                    match_flags: PCI_MATCH_VENDOR_ID | PCI_MATCH_DEVICE_ID,
                    vendor_id,
                    device_id,
                    class_code: 0,
                    subclass: 0,
                    prog_if: 0,
                    _reserved: 0,
                };
                let mut matches = alloc::vec![PciDeviceInfo {
                    address: PciAddress {
                        bus: 0,
                        device: 0,
                        function: 0,
                        _reserved: 0,
                    },
                    vendor_id: 0,
                    device_id: 0,
                    class_code: 0,
                    subclass: 0,
                    prog_if: 0,
                    revision: 0,
                    header_type: 0,
                    interrupt_line: 0,
                    interrupt_pin: 0,
                    _reserved: 0,
                }; 64];
                match call::pci_enum(&criteria, &mut matches) {
                    Ok(n) => {
                        let mut out = alloc::vec::Vec::new();
                        for d in matches.into_iter().take(n) {
                            let line = format!(
                                "{:02x}:{:02x}.{} {:04x}:{:04x}\n",
                                d.address.bus,
                                d.address.device,
                                d.address.function,
                                d.vendor_id,
                                d.device_id
                            );
                            out.extend_from_slice(line.as_bytes());
                        }
                        if out.is_empty() {
                            b"none\n".to_vec()
                        } else {
                            out
                        }
                    }
                    Err(_) => b"error\n".to_vec(),
                }
            }
            path if path.starts_with("pci/cfg/") => {
                let Some((addr, reg, width)) = Self::parse_cfg_path(path) else {
                    return b"invalid path\n".to_vec();
                };
                match call::pci_cfg_read(&addr, reg, width) {
                    Ok(v) => format!("0x{:08x}\n", v as u32).into_bytes(),
                    Err(_) => b"error\n".to_vec(),
                }
            }
            _ => b"unknown\n".to_vec(),
        }
    }

    fn read_driver_content(
        &self,
        driver: &Box<dyn BusDriver>,
        name: &str,
        sub_path: &str,
    ) -> Vec<u8> {
        match sub_path {
            "" => {
                let mut s = format!("driver: {}\n", name);
                for c in driver.compatible() {
                    s.push_str(&format!("compatible: {}\n", c));
                }
                s.push_str(&format!("errors: {}\n", driver.error_count()));
                s.into_bytes()
            }
            DRV_STATUS => {
                format!("driver: {}\nerrors: {}\n", name, driver.error_count()).into_bytes()
            }
            DRV_ERROR_COUNT => format!("{}\n", driver.error_count()).into_bytes(),
            s if s.starts_with(DRV_REG_PREFIX) => {
                if let Some(reg_offset) = Self::parse_reg_offset(s) {
                    match driver.read_reg(reg_offset) {
                        Ok(val) => format!("0x{:08x}\n", val).into_bytes(),
                        Err(_) => b"error\n".to_vec(),
                    }
                } else {
                    b"invalid register\n".to_vec()
                }
            }
            child_name => {
                // Child device info
                if let Some(child) = driver.children().iter().find(|c| c.name == child_name) {
                    format!(
                        "name: {}\nbase: 0x{:x}\nsize: {}\n",
                        child.name, child.base_addr, child.size
                    )
                    .into_bytes()
                } else {
                    b"unknown\n".to_vec()
                }
            }
        }
    }

    // === Write ================================================================

    fn handle_write(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let file_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
        let len = u16::from_le_bytes([payload[16], payload[17]]) as usize;

        let kind = match self.handles.get(&file_id) {
            Some(h) if h.owner == sender => &h.kind,
            _ => return Self::err_reply(sender, EBADF),
        };

        if len > IpcMessage::WRITE_INLINE_CAPACITY {
            return Self::err_reply(sender, EINVAL);
        }

        match kind {
            HandleKind::Pci(path) if *path == "pci/rescan" => {
                if self.refresh_pci_cache().is_err() {
                    return Self::err_reply(sender, EIO);
                }
            }
            HandleKind::Pci(path) if path.starts_with("pci/cfg/") => {
                let Some((addr, reg, width)) = Self::parse_cfg_path(path) else {
                    return Self::err_reply(sender, EINVAL);
                };
                if len < 4 {
                    return Self::err_reply(sender, EINVAL);
                }
                let val = u32::from_le_bytes([payload[18], payload[19], payload[20], payload[21]]);
                if call::pci_cfg_write(&addr, reg, width, val).is_err() {
                    return Self::err_reply(sender, EINVAL);
                }
            }
            HandleKind::Driver {
                driver_idx,
                sub_path,
            } if sub_path == DRV_SUSPEND => {
                if self.drivers[*driver_idx].1.suspend().is_err() {
                    return Self::err_reply(sender, EIO);
                }
            }
            HandleKind::Driver {
                driver_idx,
                sub_path,
            } if sub_path == DRV_RESUME => {
                if self.drivers[*driver_idx].1.resume().is_err() {
                    return Self::err_reply(sender, EIO);
                }
            }
            HandleKind::Driver {
                driver_idx,
                sub_path,
            } if sub_path.starts_with(DRV_REG_PREFIX) => {
                let Some(reg_offset) = Self::parse_reg_offset(sub_path) else {
                    return Self::err_reply(sender, EINVAL);
                };
                if len < 4 {
                    return Self::err_reply(sender, EINVAL);
                }
                let val = u32::from_le_bytes([payload[18], payload[19], payload[20], payload[21]]);
                if self.drivers[*driver_idx]
                    .1
                    .write_reg(reg_offset, val)
                    .is_err()
                {
                    return Self::err_reply(sender, EINVAL);
                }
            }
            _ => return Self::err_reply(sender, ENOSYS),
        }

        let mut reply = Self::ok_reply(sender);
        reply.payload[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        reply
    }

    // === Close ================================================================

    fn handle_close(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let file_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
        // Only the owner may close its own handle; a foreign close attempt
        // must not destroy another client's handle.
        if matches!(self.handles.get(&file_id), Some(h) if h.owner == sender)
            && self.handles.remove(&file_id).is_some()
        {
            Self::ok_reply(sender)
        } else {
            Self::err_reply(sender, EBADF)
        }
    }

    // === Read dir ================================================================

    fn handle_readdir(&self, sender: u64, payload: &[u8]) -> IpcMessage {
        let file_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
        let handle = match self.handles.get(&file_id) {
            Some(h) if h.owner == sender => h,
            _ => return Self::err_reply(sender, EBADF),
        };

        let entries: Vec<(u64, u8, String)> = match &handle.kind {
            HandleKind::Root => {
                let mut e = alloc::vec![(1u64, DT_DIR, String::from(PCI_PREFIX))];
                for (i, (name, _)) in self.drivers.iter().enumerate() {
                    e.push(((i + 2) as u64, DT_DIR, name.clone()));
                }
                e
            }
            HandleKind::Pci(path) => match path.as_str() {
                "" | PCI_PREFIX => alloc::vec![
                    (4u64, DT_REG, String::from("inventory")),
                    (5u64, DT_REG, String::from("count")),
                    (6u64, DT_REG, String::from("rescan")),
                    (7u64, DT_DIR, String::from("find")),
                    (8u64, DT_DIR, String::from("cfg")),
                ],
                "pci/find" | "pci/cfg" => alloc::vec![],
                _ => return Self::err_reply(sender, ENOTDIR),
            },
            HandleKind::Driver {
                driver_idx,
                sub_path,
            } if sub_path.is_empty() => {
                let driver = &self.drivers[*driver_idx].1;
                let mut e = alloc::vec![
                    (1u64, DT_REG, String::from(DRV_STATUS)),
                    (2u64, DT_REG, String::from(DRV_ERROR_COUNT)),
                    (3u64, DT_REG, String::from(DRV_SUSPEND)),
                    (4u64, DT_REG, String::from(DRV_RESUME)),
                ];
                for (i, child) in driver.children().iter().enumerate() {
                    e.push(((i + 5) as u64, DT_REG, child.name.clone()));
                }
                e
            }
            _ => return Self::err_reply(sender, ENOTDIR),
        };

        let mut reply = Self::ok_reply(sender);
        let cursor = u16::from_le_bytes([payload[8], payload[9]]) as usize;
        if cursor >= entries.len() && !entries.is_empty() {
            reply.payload[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
            reply.payload[6] = 0;
            reply.payload[7] = 0;
            return reply;
        }

        let mut offset = 8usize;
        let mut count = 0u8;
        let mut next_cursor = u16::MAX;
        let mut index = cursor;

        for (ino, file_type, name) in &entries[cursor..] {
            let name_bytes = name.as_bytes();
            let entry_size = 10 + name_bytes.len();
            // Fill the whole payload (entries start at offset 8).
            if offset + entry_size > IpcMessage::PAYLOAD_CAPACITY {
                next_cursor = index.min(u16::MAX as usize) as u16;
                break;
            }
            reply.payload[offset..offset + 8].copy_from_slice(&ino.to_le_bytes());
            reply.payload[offset + 8] = *file_type;
            reply.payload[offset + 9] = name_bytes.len() as u8;
            let end = offset + 10 + name_bytes.len();
            reply.payload[offset + 10..end].copy_from_slice(name_bytes);
            offset = end;
            // With a 240-byte payload and >= 10 bytes per entry, count can
            // never exceed 24: the u8 field cannot overflow.
            count += 1;
            index += 1;
        }

        reply.payload[4..6].copy_from_slice(&next_cursor.to_le_bytes());
        reply.payload[6] = count;
        reply.payload[7] = (offset - READDIR_HEADER_SIZE) as u8;
        reply
    }

    // === Serve ================================================================

    /// Performs the serve operation.
    pub fn serve(&mut self) -> ! {
        loop {
            let mut msg = IpcMessage::new(0);
            if call::ipc_recv(self.port_handle as usize, &mut msg).is_err() {
                let _ = call::sched_yield();
                continue;
            }

            let reply = match msg.msg_type {
                OPCODE_OPEN => self.handle_open(msg.sender, &msg.payload),
                OPCODE_READ => self.handle_read(msg.sender, &msg.payload),
                OPCODE_WRITE => self.handle_write(msg.sender, &msg.payload),
                OPCODE_CLOSE => self.handle_close(msg.sender, &msg.payload),
                OPCODE_READDIR => self.handle_readdir(msg.sender, &msg.payload),
                _ => Self::err_reply(msg.sender, ENOSYS),
            };
            let _ = call::ipc_reply(&reply);
        }
    }

    // === Static helpers ========================================================

    /// Normalise a client-supplied path for the `/bus` namespace:
    /// - collapses repeated `/`,
    /// - drops `.` segments,
    /// - resolves `..` lexically (returns `None` if it escapes the root).
    ///
    /// The root is the empty string. Without this, a path such as
    /// `pci/../<driver>/reg/x` could bypass naive prefix matching if
    /// sub-tree resolution ever becomes recursive.
    fn normalize_path(path: &str) -> Option<String> {
        let mut segments: Vec<&str> = Vec::new();
        for seg in path.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    segments.pop()?;
                }
                s => segments.push(s),
            }
        }
        Some(segments.join("/"))
    }

    fn parse_pci_bdf(s: &str) -> Option<PciAddress> {
        let (bus_s, rest) = s.split_once(':')?;
        let (dev_s, fun_s) = rest.split_once('.')?;
        let bus = Self::parse_hex_u8(bus_s)?;
        let device = Self::parse_hex_u8(dev_s)?;
        let function = Self::parse_hex_u8(fun_s)?;
        if device > 31 || function > 7 {
            return None;
        }
        Some(PciAddress {
            bus,
            device,
            function,
            _reserved: 0,
        })
    }

    fn parse_cfg_path(path: &str) -> Option<(PciAddress, u8, u8)> {
        let mut parts = path.strip_prefix("pci/cfg/")?.split('/');
        let bdf = parts.next()?;
        let off = parts.next()?;
        let width = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        let addr = Self::parse_pci_bdf(bdf)?;
        let offset = Self::parse_hex_u8(off)?;
        let width = width.parse::<u8>().ok()?;
        if !matches!(width, 1 | 2 | 4) {
            return None;
        }
        Some((addr, offset, width))
    }

    fn parse_find_path(path: &str) -> Option<(u16, u16)> {
        let mut parts = path.strip_prefix("pci/find/")?.split('/');
        let ven = Self::parse_hex_u16(parts.next()?)?;
        let dev = Self::parse_hex_u16(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        Some((ven, dev))
    }

    fn render_inventory(&self) -> Vec<u8> {
        let mut out = alloc::vec::Vec::new();
        out.extend_from_slice(b"bus:dev.fn vendor:device class:sub prog_if rev irq\n");
        for d in &self.pci_cache {
            let line = format!(
                "{:02x}:{:02x}.{} {:04x}:{:04x} {:02x}:{:02x} {:02x} {:02x} {}\n",
                d.address.bus,
                d.address.device,
                d.address.function,
                d.vendor_id,
                d.device_id,
                d.class_code,
                d.subclass,
                d.prog_if,
                d.revision,
                d.interrupt_line
            );
            out.extend_from_slice(line.as_bytes());
        }
        out
    }
}
