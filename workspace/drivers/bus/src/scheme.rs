use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use strat9_syscall::{
    call,
    data::{
        DT_DIR, DT_REG, IpcMessage, PCI_MATCH_DEVICE_ID, PCI_MATCH_VENDOR_ID, PciAddress,
        PciDeviceInfo, PciProbeCriteria,
    },
    error::{EBADF, EINVAL, ENOENT, ENOSYS, ENOTDIR},
};

use crate::BusDriver;

const OPCODE_OPEN: u32 = 0x01;
const OPCODE_READ: u32 = 0x02;
const OPCODE_WRITE: u32 = 0x03;
const OPCODE_CLOSE: u32 = 0x04;
const OPCODE_READDIR: u32 = 0x08;
const REPLY_MSG_TYPE: u32 = 0x80;
const STATUS_OK: u32 = 0;
const FILEFLAG_DIRECTORY: u32 = 1;

struct OpenHandle {
    path: String,
}

pub struct BusSchemeServer<D: BusDriver> {
    driver: D,
    port_handle: u64,
    handles: BTreeMap<u64, OpenHandle>,
    next_id: u64,
    pci_cache: Vec<PciDeviceInfo>,
}

impl<D: BusDriver> BusSchemeServer<D> {
    /// Creates a new instance.
    pub fn new(driver: D, port_handle: u64) -> Self {
        Self {
            driver,
            port_handle,
            handles: BTreeMap::new(),
            next_id: 1,
            pci_cache: Vec::new(),
        }
    }

    /// Performs the with pci cache operation.
    pub fn with_pci_cache(mut self, cache: Vec<PciDeviceInfo>) -> Self {
        self.pci_cache = cache;
        self
    }

    /// Performs the ok reply operation.
    fn ok_reply(sender: u64) -> IpcMessage {
        let mut reply = IpcMessage::new(REPLY_MSG_TYPE);
        reply.sender = sender;
        reply.payload[0..4].copy_from_slice(&STATUS_OK.to_le_bytes());
        reply
    }

    /// Performs the err reply operation.
    fn err_reply(sender: u64, code: usize) -> IpcMessage {
        let mut reply = IpcMessage::new(REPLY_MSG_TYPE);
        reply.sender = sender;
        reply.payload[0..4].copy_from_slice(&(code as u32).to_le_bytes());
        reply
    }

    /// Parses hex u8.
    fn parse_hex_u8(s: &str) -> Option<u8> {
        u8::from_str_radix(s.trim_start_matches("0x"), 16).ok()
    }

    /// Parses hex u16.
    fn parse_hex_u16(s: &str) -> Option<u16> {
        u16::from_str_radix(s.trim_start_matches("0x"), 16).ok()
    }

    /// Parses pci bdf.
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

    /// Parses cfg path.
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

    /// Parses find path.
    fn parse_find_path(path: &str) -> Option<(u16, u16)> {
        let mut parts = path.strip_prefix("pci/find/")?.split('/');
        let ven = Self::parse_hex_u16(parts.next()?)?;
        let dev = Self::parse_hex_u16(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        Some((ven, dev))
    }

    /// Performs the refresh pci cache operation.
    pub fn refresh_pci_cache(&mut self) {
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
        if let Ok(n) = call::pci_enum(&criteria, &mut buf) {
            self.pci_cache.clear();
            self.pci_cache.extend_from_slice(&buf[..n.min(buf.len())]);
        }
    }

    /// Performs the render inventory operation.
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

    /// Handles open.
    fn handle_open(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let path_len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
        if path_len > 42 {
            return Self::err_reply(sender, EINVAL);
        }
        let path_bytes = &payload[6..6 + path_len];
        let raw_path = match core::str::from_utf8(path_bytes) {
            Ok(s) => s,
            Err(_) => return Self::err_reply(sender, EINVAL),
        };
        let path = Self::normalize_path(raw_path);
        if !self.path_exists(&path) {
            return Self::err_reply(sender, ENOENT);
        }

        let file_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.handles
            .insert(file_id, OpenHandle { path: path.clone() });

        let mut reply = Self::ok_reply(sender);
        reply.payload[4..12].copy_from_slice(&file_id.to_le_bytes());
        reply.payload[12..20].copy_from_slice(&0u64.to_le_bytes());
        let flags = if path.is_empty() || path == "pci" || path == "pci/find" || path == "pci/cfg" {
            FILEFLAG_DIRECTORY
        } else {
            0
        };
        reply.payload[20..24].copy_from_slice(&flags.to_le_bytes());
        reply
    }

    /// Handles read.
    fn handle_read(&self, sender: u64, payload: &[u8]) -> IpcMessage {
        let file_id = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        let offset = u64::from_le_bytes([
            payload[8],
            payload[9],
            payload[10],
            payload[11],
            payload[12],
            payload[13],
            payload[14],
            payload[15],
        ]);

        let handle = match self.handles.get(&file_id) {
            Some(h) => h,
            None => return Self::err_reply(sender, EBADF),
        };

        let content = self.generate_read_content(&handle.path, offset as usize);
        let n = content.len().min(40);

        let mut reply = Self::ok_reply(sender);
        reply.payload[4..8].copy_from_slice(&(n as u32).to_le_bytes());
        reply.payload[8..8 + n].copy_from_slice(&content[..n]);
        reply
    }

    /// Performs the generate read content operation.
    fn generate_read_content(&self, path: &str, offset: usize) -> Vec<u8> {
        if let Some(child) = self.driver.children().into_iter().find(|c| c.name == path) {
            let text = format!(
                "name: {}\nbase: 0x{:x}\nsize: {}\n",
                child.name, child.base_addr, child.size
            );
            let bytes = text.into_bytes();
            return if offset >= bytes.len() {
                Vec::new()
            } else {
                bytes[offset..].to_vec()
            };
        }

        let data = match path {
            "" | "/" => {
                let mut s = format!("driver: {}\n", self.driver.name());
                for c in self.driver.compatible() {
                    s.push_str(&format!("compatible: {}\n", c));
                }
                s.push_str(&format!("errors: {}\n", self.driver.error_count()));
                s.into_bytes()
            }
            "status" => format!(
                "driver: {}\nerrors: {}\n",
                self.driver.name(),
                self.driver.error_count()
            )
            .into_bytes(),
            "error_count" => format!("{}\n", self.driver.error_count()).into_bytes(),
            "pci" => b"inventory\ncount\nrescan\nfind\ncfg\n".to_vec(),
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
            _ => {
                if let Some(reg_str) = path.strip_prefix("reg/") {
                    if let Ok(reg_offset) =
                        usize::from_str_radix(reg_str.trim_start_matches("0x"), 16)
                    {
                        match self.driver.read_reg(reg_offset) {
                            Ok(val) => format!("0x{:08x}\n", val).into_bytes(),
                            Err(_) => b"error\n".to_vec(),
                        }
                    } else {
                        b"invalid register\n".to_vec()
                    }
                } else {
                    b"unknown path\n".to_vec()
                }
            }
        };

        if offset >= data.len() {
            Vec::new()
        } else {
            data[offset..].to_vec()
        }
    }

    /// Performs the normalize path operation.
    fn normalize_path(path: &str) -> String {
        if path.is_empty() || path == "/" {
            return String::new();
        }
        let trimmed = path.trim_matches('/');
        String::from(trimmed)
    }

    /// Parses reg offset.
    fn parse_reg_offset(path: &str) -> Option<usize> {
        let reg_str = path.strip_prefix("reg/")?;
        if reg_str.is_empty() {
            return None;
        }
        usize::from_str_radix(reg_str.trim_start_matches("0x"), 16).ok()
    }

    /// Performs the path exists operation.
    fn path_exists(&self, path: &str) -> bool {
        if path.is_empty()
            || path == "status"
            || path == "error_count"
            || path == "pci"
            || path == "pci/inventory"
            || path == "pci/count"
            || path == "pci/rescan"
            || path == "pci/find"
            || path == "pci/cfg"
        {
            return true;
        }
        if path.starts_with("pci/find/") {
            return Self::parse_find_path(path).is_some();
        }
        if path.starts_with("pci/cfg/") {
            return Self::parse_cfg_path(path).is_some();
        }
        if Self::parse_reg_offset(path).is_some() {
            return true;
        }
        self.driver.children().iter().any(|c| c.name == path)
    }

    /// Handles write.
    fn handle_write(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let file_id = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        let len = u16::from_le_bytes([payload[16], payload[17]]) as usize;

        if !self.handles.contains_key(&file_id) {
            return Self::err_reply(sender, EBADF);
        }

        if len > 30 {
            return Self::err_reply(sender, EINVAL);
        }

        let handle = match self.handles.get(&file_id) {
            Some(h) => h,
            None => return Self::err_reply(sender, EBADF),
        };

        if handle.path == "pci/rescan" {
            self.refresh_pci_cache();
        } else if let Some((addr, reg, width)) = Self::parse_cfg_path(&handle.path) {
            if len < 4 {
                return Self::err_reply(sender, EINVAL);
            }
            let val = u32::from_le_bytes([payload[18], payload[19], payload[20], payload[21]]);
            if call::pci_cfg_write(&addr, reg, width, val).is_err() {
                return Self::err_reply(sender, EINVAL);
            }
        } else {
            let reg_str = match handle.path.strip_prefix("reg/") {
                Some(s) => s,
                None => return Self::err_reply(sender, ENOSYS),
            };
            let reg_offset = match usize::from_str_radix(reg_str.trim_start_matches("0x"), 16) {
                Ok(v) => v,
                Err(_) => return Self::err_reply(sender, EINVAL),
            };
            if len < 4 {
                return Self::err_reply(sender, EINVAL);
            }
            let val = u32::from_le_bytes([payload[18], payload[19], payload[20], payload[21]]);
            if self.driver.write_reg(reg_offset, val).is_err() {
                return Self::err_reply(sender, EINVAL);
            }
        }

        let mut reply = Self::ok_reply(sender);
        reply.payload[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        reply
    }

    /// Handles close.
    fn handle_close(&mut self, sender: u64, payload: &[u8]) -> IpcMessage {
        let file_id = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        if self.handles.remove(&file_id).is_some() {
            Self::ok_reply(sender)
        } else {
            Self::err_reply(sender, EBADF)
        }
    }

    /// Handles readdir.
    fn handle_readdir(&self, sender: u64, payload: &[u8]) -> IpcMessage {
        let file_id = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        let handle = match self.handles.get(&file_id) {
            Some(h) => h,
            None => return Self::err_reply(sender, EBADF),
        };

        let entries: Vec<(u64, u8, String)> = if handle.path.is_empty() {
            let mut e = alloc::vec![
                (1u64, DT_REG, String::from("status")),
                (2u64, DT_REG, String::from("error_count")),
                (3u64, DT_DIR, String::from("pci")),
            ];
            for c in self.driver.children() {
                e.push((c.base_addr, DT_REG, c.name));
            }
            e
        } else if handle.path == "pci" {
            alloc::vec![
                (4u64, DT_REG, String::from("inventory")),
                (5u64, DT_REG, String::from("count")),
                (6u64, DT_REG, String::from("rescan")),
                (7u64, DT_DIR, String::from("find")),
                (8u64, DT_DIR, String::from("cfg")),
            ]
        } else if handle.path == "pci/find" || handle.path == "pci/cfg" {
            alloc::vec![]
        } else {
            return Self::err_reply(sender, ENOTDIR);
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
            if offset + entry_size > 48 {
                let candidate = index.min(u16::MAX as usize) as u16;
                next_cursor = candidate;
                break;
            }
            reply.payload[offset..offset + 8].copy_from_slice(&ino.to_le_bytes());
            reply.payload[offset + 8] = *file_type;
            reply.payload[offset + 9] = name_bytes.len() as u8;
            let end = offset + 10 + name_bytes.len();
            reply.payload[offset + 10..end].copy_from_slice(name_bytes);
            offset = end;
            count += 1;
            index += 1;
        }

        reply.payload[4..6].copy_from_slice(&next_cursor.to_le_bytes());
        reply.payload[6] = count;
        reply.payload[7] = (offset - 8) as u8;
        reply
    }

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
}
