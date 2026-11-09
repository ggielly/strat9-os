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

//! FPU/SSE state preservation around SIMD pixel operations.
//!
//! The SSE2 fill/blit paths clobber XMM registers, which would corrupt the
//! floating-point state of an interrupted thread (or of the caller) when a
//! draw happens from an interrupt context. [`FpuGuard`] saves the live
//! x87/SSE state on construction and restores it on drop.
//!
//! Only the legacy 512-byte FXSAVE area is captured. AVX (YMM) registers are
//! therefore *not* preserved: streaming/AVX code must not be introduced until
//! this guard switches to XSAVE/XRSTOR.

/// Saves the caller's FPU/SSE state and restores it when dropped.
pub struct FpuGuard {
    #[allow(dead_code)]
    area: FxArea,
}

/// 512-byte FXSAVE area, 16-byte aligned as required by `fxsave`/`fxrstor`.
#[cfg(target_arch = "x86_64")]
#[repr(align(16))]
struct FxArea([u8; 512]);

/// Placeholder on architectures without an x86 FPU save area.
#[cfg(not(target_arch = "x86_64"))]
struct FxArea;

impl FpuGuard {
    /// Capture the current FPU/SSE state.
    #[inline]
    pub fn save() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            let mut area = FxArea([0u8; 512]);
            let ptr = area.0.as_mut_ptr();
            debug_assert_eq!(ptr as usize % 16, 0, "FXSAVE area must be 16-byte aligned");
            // SAFETY: `area` is 16-byte aligned and 512 bytes long, as required
            // by FXSAVE. The instruction only writes to that area; omitting
            // `nomem` keeps the compiler from moving memory accesses across it.
            unsafe {
                core::arch::asm!("fxsave [{ptr}]", ptr = in(reg) ptr, options(nostack));
            }
            Self { area }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            Self { area: FxArea }
        }
    }
}

impl Drop for FpuGuard {
    #[inline]
    fn drop(&mut self) {
        #[cfg(target_arch = "x86_64")]
        {
            let ptr = self.area.0.as_ptr();
            debug_assert_eq!(ptr as usize % 16, 0, "FXRSTOR area must be 16-byte aligned");
            // SAFETY: the area was filled by `save()` and is still 16-byte
            // aligned. FXRSTOR only reads from it.
            unsafe {
                core::arch::asm!("fxrstor [{ptr}]", ptr = in(reg) ptr, options(nostack));
            }
        }
    }
}
