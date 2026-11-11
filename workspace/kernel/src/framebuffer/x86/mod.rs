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

//! SIMD pixel operations for x86_64.
//!
//! Currently exposes the SSE2 (+SSSE3 convert) implementations only.
//!
//! AVX2/AVX512 variants are TEMPORARILY removed: nightly
//! `1.100.0-nightly (c656540d, LLVM 23.1-rust)` mis-compiles the custom
//! `x86_64-unknown-none` target by emitting `+soft-float` into every
//! function's target-features, which makes X86 instruction selection abort
//! on 256-bit intrinsics (`llvm.x86.avx2.pshuf.b`) with:
//!   "Do not know how to split the result of this operator!"
//! Restore `avx2`/`avx512` once the toolchain issue is resolved. Cached SSE2
//! remains available. The `*_nt` entry points currently alias the cached SSE2
//! paths: `_mm_stream_si128` trips the same LLVM bug on this target, and WC
//! memory already combines stores without cache-line allocation.

use crate::framebuffer::{generic, FramebufferOps};
pub mod sse2;

pub fn detect_and_init_ops() -> FramebufferOps {
    let cpuid = raw_cpuid::CpuId::new();

    let has_sse41 = cpuid
        .get_feature_info()
        .map_or(false, |info| info.has_sse41());

    let has_sse2 = cpuid
        .get_feature_info()
        .map_or(false, |info| info.has_sse2());

    if has_sse41 || has_sse2 {
        // `_mm_loadu_si128` / `_mm_storeu_si128` are NOT inlined on this target:
        // the pinned nightly compiles `x86_64-unknown-none` with `+soft-float`,
        // so `__m128i` cannot travel in XMM registers and the intrinsics become
        // out-of-line helpers. Those helpers are miscompiled: they copy the
        // vector byte by byte and drop one lane (observed: 0x0011EE33 stored as
        // 0x00110033, i.e. the green channel). Ops that *load* pixels therefore
        // avoid 128-bit intrinsics: `fill` is a broadcast constant store with no
        // vector load, and `blit`/`blit_nt` use `rep movsq` (8-byte stores).
        // `blend`/`convert` stay on the scalar path.
        //
        // Restore the SSE2 blit/blend/convert once the toolchain lowers the
        // 128-bit load/store intrinsics correctly (same underlying issue as the
        // disabled `_mm_stream_si128` paths below).
        FramebufferOps {
            fill: sse2::fill_sse2,
            blit: sse2::blit_q,
            blend: generic::blend_generic,
            convert: generic::convert_bgr_to_argb_generic,
            fill_nt: sse2::fill_nt_sse2,
            blit_nt: sse2::blit_q,
        }
    } else {
        FramebufferOps {
            fill: generic::fill_generic,
            blit: generic::blit_generic,
            blend: generic::blend_generic,
            convert: generic::convert_bgr_to_argb_generic,
            fill_nt: generic::fill_nt_generic,
            blit_nt: generic::blit_nt_generic,
        }
    }
}
