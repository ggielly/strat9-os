/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

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
