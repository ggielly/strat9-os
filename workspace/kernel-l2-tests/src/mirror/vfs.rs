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

//! Mirror of kernel/src/vfs : scheme protocol core + router.
#[path = "../../../kernel/src/vfs/scheme.rs"]
pub mod scheme;
#[path = "../../../kernel/src/vfs/file.rs"]
pub mod file;
#[path = "../../../kernel/src/vfs/fd.rs"]
pub mod fd;
#[path = "../../../kernel/src/vfs/pipe.rs"]
pub mod pipe;
/// Shim for kernel/src/vfs/mount.rs (runtime mount table needs full VFS).
pub mod mount {
    use alloc::sync::Arc;
    use crate::syscall::error::SyscallError;
    use crate::vfs::scheme::DynScheme;

    /// Host stand-in: the runtime mount table is out of scope; tests must
    /// not rely on mounts succeeding.
    pub fn mount(_path: &str, _scheme: crate::vfs::scheme::DynScheme) -> Result<(), SyscallError> {
        Ok(())
    }
}

#[path = "../../../kernel/src/vfs/scheme_router.rs"]
pub mod scheme_router;

pub use scheme::{DynScheme, IpcScheme, KernelScheme};
pub use scheme_router::*;
