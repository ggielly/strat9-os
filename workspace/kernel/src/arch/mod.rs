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

// The x86_64 backend must only be compiled when targeting x86_64: the
// `x86_64` crate and its inline asm do not exist on other architectures.
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

/// Architecture-neutral IOMMU backend interface (discovery + activation).
pub mod iommu;

#[cfg(target_arch = "x86_64")]
pub mod facade;

#[cfg(target_arch = "x86_64")]
pub use facade::*;

#[cfg(target_arch = "riscv64")]
pub mod facade_riscv;

#[cfg(target_arch = "riscv64")]
pub use crate::arch::facade_riscv::*;

/// riscv64 stub of the `x86_64` crate surface (runtime-panicking).
/// Aliased as `crate::arch::x86_64` so call-sites not yet migrated keep
/// resolving; every item traps at runtime until its jalon lands.
#[cfg(target_arch = "riscv64")]
pub mod x86_64_stub {
    include!("xshim_riscv_stub.rs");
}

#[cfg(target_arch = "riscv64")]
pub use x86_64_stub as x86_64;

/// Neutral shim mirroring the used subset of the `x86_64` crate
/// (address types, page sizes, paging flags). Available on all arches:
/// on x86_64 it re-exports the real crate types, elsewhere it provides
/// neutral equivalents.
pub mod xshim;
