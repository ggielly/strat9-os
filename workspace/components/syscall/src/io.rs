#[derive(Debug)]
/// Minimal sequential reader wrapper over a syscall file descriptor.
pub struct IoReader {
    pub fd: usize,
    pub offset: usize,
}

#[derive(Debug)]
/// Minimal sequential writer wrapper over a syscall file descriptor.
pub struct IoWriter {
    pub fd: usize,
    pub offset: usize,
}

impl IoReader {
    /// Create a reader bound to `fd`.
    pub fn new(fd: usize) -> Self {
        Self { fd, offset: 0 }
    }

    #[cfg(feature = "userspace")]
    /// Read bytes from the underlying file descriptor.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, super::error::Error> {
        super::call::read(self.fd, buf)
    }
}

impl IoWriter {
    /// Create a writer bound to `fd`.
    pub fn new(fd: usize) -> Self {
        Self { fd, offset: 0 }
    }

    #[cfg(feature = "userspace")]
    /// Write bytes to the underlying file descriptor.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, super::error::Error> {
        super::call::write(self.fd, buf)
    }
}
