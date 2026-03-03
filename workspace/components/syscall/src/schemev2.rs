#[derive(Debug, Clone, Copy)]
#[repr(C)]
/// Fixed-size ABI representation of a registered scheme.
pub struct SchemeV2 {
    pub name: [u8; 256],
    pub id: u32,
    pub flags: u32,
}

impl SchemeV2 {
    /// Create a scheme descriptor from name, id and flags.
    pub fn new(name: &str, id: u32, flags: u32) -> Self {
        let mut scheme = Self {
            name: [0; 256],
            id,
            flags,
        };

        let name_bytes = name.as_bytes();
        let len = core::cmp::min(name_bytes.len(), 255);
        scheme.name[..len].copy_from_slice(&name_bytes[..len]);

        scheme
    }

    /// Return the scheme name up to the first NUL byte.
    pub fn name(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(256);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }
}
