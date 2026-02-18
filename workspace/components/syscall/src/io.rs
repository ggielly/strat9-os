

#[derive(Debug)]
pub struct IoReader {
    pub fd: usize,
    pub offset: usize,
}

#[derive(Debug)]
pub struct IoWriter {
    pub fd: usize,
    pub offset: usize,
}

impl IoReader {
    pub fn new(fd: usize) -> Self {
        Self { fd, offset: 0 }
    }

    #[cfg(feature = "userspace")]
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, super::error::Error> {
        super::call::read(self.fd, buf)
    }
}

impl IoWriter {
    pub fn new(fd: usize) -> Self {
        Self { fd, offset: 0 }
    }

    #[cfg(feature = "userspace")]
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, super::error::Error> {
        super::call::write(self.fd, buf)
    }
}
