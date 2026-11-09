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

//! SHA-1, HMAC-SHA1 and PBKDF2-HMAC-SHA1.
//!
//! SHA-1 is not used as a general-purpose hash here: WPA2-PSK mandates it for
//! the passphrase KDF (PBKDF2), the PTK derivation PRF and the EAPOL-Key MIC.

pub const SHA1_DIGEST_LEN: usize = 20;
pub const SHA1_BLOCK_LEN: usize = 64;

#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    len: u64,
    buf: [u8; SHA1_BLOCK_LEN],
    buf_len: usize,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    pub const fn new() -> Self {
        Self {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            len: 0,
            buf: [0u8; SHA1_BLOCK_LEN],
            buf_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.buf_len != 0 {
            let take = core::cmp::min(SHA1_BLOCK_LEN - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == SHA1_BLOCK_LEN {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= SHA1_BLOCK_LEN {
            let mut block = [0u8; SHA1_BLOCK_LEN];
            block.copy_from_slice(&data[..SHA1_BLOCK_LEN]);
            self.compress(&block);
            data = &data[SHA1_BLOCK_LEN..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finish(mut self) -> [u8; SHA1_DIGEST_LEN] {
        let bit_len = self.len.wrapping_mul(8);
        let mut pad = [0u8; SHA1_BLOCK_LEN + 8];
        pad[0] = 0x80;
        let pad_len = if self.buf_len < 56 {
            56 - self.buf_len
        } else {
            120 - self.buf_len
        };
        self.update(&pad[..pad_len]);
        // `update` padded to 56 bytes; append the big-endian length.
        let mut len_block = [0u8; 8];
        len_block.copy_from_slice(&bit_len.to_be_bytes());
        self.len = self.len.wrapping_sub(pad_len as u64);
        self.update(&len_block);

        let mut out = [0u8; SHA1_DIGEST_LEN];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; SHA1_BLOCK_LEN]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

/// One-shot SHA-1.
pub fn sha1(data: &[u8]) -> [u8; SHA1_DIGEST_LEN] {
    let mut h = Sha1::new();
    h.update(data);
    h.finish()
}

/// HMAC-SHA1 (RFC 2104).
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; SHA1_DIGEST_LEN] {
    let mut k = [0u8; SHA1_BLOCK_LEN];
    if key.len() > SHA1_BLOCK_LEN {
        let d = sha1(key);
        k[..SHA1_DIGEST_LEN].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; SHA1_BLOCK_LEN];
    let mut opad = [0x5cu8; SHA1_BLOCK_LEN];
    for i in 0..SHA1_BLOCK_LEN {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha1::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_digest = inner.finish();

    let mut outer = Sha1::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    outer.finish()
}

/// PBKDF2-HMAC-SHA1 (RFC 2898) with a fixed 32-byte output, which is exactly
/// what WPA2-PSK needs.
pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let mut block_index: u32 = 1;
    let mut offset = 0usize;
    while offset < out.len() {
        let mut msg = [0u8; 256];
        let msg_len = salt.len().min(250);
        msg[..msg_len].copy_from_slice(&salt[..msg_len]);
        msg[msg_len..msg_len + 4].copy_from_slice(&block_index.to_be_bytes());
        let mut u = hmac_sha1(password, &msg[..msg_len + 4]);
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha1(password, &u);
            for i in 0..SHA1_DIGEST_LEN {
                t[i] ^= u[i];
            }
        }
        let take = core::cmp::min(SHA1_DIGEST_LEN, out.len() - offset);
        out[offset..offset + take].copy_from_slice(&t[..take]);
        offset += take;
        block_index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        for b in bytes {
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    }

    #[test]
    fn sha1_vectors() {
        assert_eq!(
            to_hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            to_hex(&sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            to_hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn hmac_sha1_rfc2202() {
        let key = [0x0bu8; 20];
        let out = hmac_sha1(&key, b"Hi There");
        assert_eq!(to_hex(&out), "b617318655057264e28bc0b6fb378c8ef146be00");
    }

    #[test]
    fn pbkdf2_rfc6070() {
        let mut out = [0u8; 20];
        pbkdf2_hmac_sha1(b"password", b"salt", 4096, &mut out);
        assert_eq!(to_hex(&out), "4b007901b765489abead49d926f721d065a429c1");
    }
}
