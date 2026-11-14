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

//! SHA-256 (FIPS 180-4) over the audited RustCrypto implementation.
//!
//! Used to compare the `sha256` declared in the boot configuration with the
//! bytes actually loaded for a strate. The hasher streams the input, so a
//! multi-megabyte strate costs no extra buffer, and `sha2` is built with
//! `force-soft` so the component target (`x86_64-unknown-none`, `no_std`)
//! needs neither SIMD intrinsics nor runtime CPU detection.

use alloc::string::String;
use core::fmt::Write;
use sha2::{Digest, Sha256};

/// Computes the SHA-256 digest of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Lowercase hexadecimal representation of a digest.
pub fn hex(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_vector() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc_vector() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    #[test]
    fn million_a_vector() {
        // FIPS 180-4 / NIST CAVP long message: proves the hasher streams
        // several blocks instead of relying on a padded-copy shortcut.
        let input = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha256(&input)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }
    fn fifty_six_byte_vector() {
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(input.len(), 56);
        assert_eq!(
            hex(&sha256(input)),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }
}
