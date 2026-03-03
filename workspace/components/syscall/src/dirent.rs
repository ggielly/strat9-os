use core::fmt;
pub use strat9_abi::data::DirentHeader;

#[derive(Debug, Clone, Copy)]
pub struct Dirent {
    pub ino: u64,
    pub type_: u8,
    pub name_len: u16,
    pub name: [u8; 256],
}

impl Dirent {
    pub fn new(ino: u64, type_: u8, name: &[u8]) -> Self {
        let mut d = Self {
            ino,
            type_,
            name_len: 0,
            name: [0; 256],
        };
        let len = core::cmp::min(name.len(), 255);
        d.name[..len].copy_from_slice(&name[..len]);
        d.name_len = len as u16;
        d
    }

    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

impl fmt::Display for Dirent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            core::str::from_utf8(self.name()).unwrap_or("<invalid>")
        )
    }
}

pub struct DirentIter<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> DirentIter<'a> {
    pub fn new(buf: &'a [u8], valid_len: usize) -> Self {
        let valid_len = core::cmp::min(valid_len, buf.len());
        Self {
            buf: &buf[..valid_len],
            offset: 0,
        }
    }
}

impl<'a> Iterator for DirentIter<'a> {
    type Item = Dirent;

    fn next(&mut self) -> Option<Dirent> {
        if self.offset + DirentHeader::SIZE > self.buf.len() {
            return None;
        }
        let hdr = &self.buf[self.offset..self.offset + DirentHeader::SIZE];
        let ino = u64::from_le_bytes(hdr[0..8].try_into().ok()?);
        let file_type = hdr[8];
        let name_len = u16::from_le_bytes(hdr[9..11].try_into().ok()?);
        let name_start = self.offset + DirentHeader::SIZE;
        let name_end = name_start + name_len as usize;
        if name_end + 1 > self.buf.len() {
            return None;
        }
        let mut d = Dirent::new(ino, file_type, &self.buf[name_start..name_end]);
        d.name_len = core::cmp::min(name_len, 255);
        self.offset = name_end + 1; // skip NUL
        Some(d)
    }
}
