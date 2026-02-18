use core::fmt;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Dirent {
    pub next: usize,
    pub ino: u64,
    pub type_: u8,
    pub name: [u8; 256],
}

impl Dirent {
    pub fn new(ino: u64, type_: u8, name: &[u8]) -> Self {
        let mut dirent = Self {
            next: 0,
            ino,
            type_,
            name: [0; 256],
        };

        let len = core::cmp::min(name.len(), 255);
        dirent.name[..len].copy_from_slice(&name[..len]);

        dirent
    }

    pub fn name(&self) -> &[u8] {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(256);
        &self.name[..len]
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
