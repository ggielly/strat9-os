//! Exact UCS-2 paths for the subset of filenames representable by the boot ABI.
use strat9_abi::boot::validate_module_name;

const PREFIX: &[u8] = b"\\boot\\initfs\\";

#[derive(Debug)]
pub struct ModuleFileName {
    name: [u8; 64],
    path: [u16; PREFIX.len() + 64],
    len: usize,
}

impl ModuleFileName {
    /// `raw` excludes the firmware's terminating NUL. Rejection is lossless:
    /// no character is removed, normalized or truncated to make a name fit.
    pub fn new(raw: &[u16]) -> Result<Self, &'static str> {
        if raw.is_empty() || raw.len() > 63 {
            return Err("module name must contain 1 to 63 UCS-2 characters");
        }
        let mut result = Self {
            name: [0; 64],
            path: [0; PREFIX.len() + 64],
            len: raw.len(),
        };
        for (dst, &ch) in result.name.iter_mut().zip(raw) {
            *dst = u8::try_from(ch).map_err(|_| "non-ASCII module name")?;
        }
        validate_module_name(&result.name[..raw.len()])?;
        for (dst, &byte) in result.path.iter_mut().zip(PREFIX) {
            *dst = byte as u16;
        }
        result.path[PREFIX.len()..PREFIX.len() + raw.len()].copy_from_slice(raw);
        Ok(result)
    }

    pub fn path(&self) -> &[u16] {
        &self.path[..PREFIX.len() + self.len + 1]
    }

    pub fn abi_name(&self) -> [u8; 64] {
        self.name
    }

    pub fn as_str(&self) -> &str {
        // Construction only accepts ASCII and name/length cannot be modified.
        core::str::from_utf8(&self.name[..self.len]).unwrap()
    }
}
