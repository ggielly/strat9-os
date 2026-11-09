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

//! AES-CCM as used by CCMP (WPA2).
//!
//! CCMP fixes the CCM parameters to `L = 2` (2-byte length field) and
//! `M = 8` (8-byte MIC).  The 13-byte nonce is built by the caller from the
//! 802.11 header (priority octet, transmitter address, packet number).

use super::aes::Aes128;

/// Encrypt `data` in place and write the 8-byte MIC.
///
/// `nonce` must be 13 bytes.  `aad` is the CCMP additional authenticated
/// data (masked 802.11 header).
pub fn ccm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    data: &mut [u8],
    mic: &mut [u8; 8],
) {
    let aes = Aes128::new(key);
    let mut mac = [0u8; 16];
    cbc_mac(&aes, nonce, aad, data, &mut mac);

    // Encrypt-then-MAC: MIC over the MAC state, encrypted with A0.
    let mut a0 = ctr_block(nonce, 0);
    aes.encrypt_block(&mut a0);
    for i in 0..8 {
        mic[i] = mac[i] ^ a0[i];
    }

    ctr_crypt(&aes, nonce, data);
}

/// Decrypt `data` in place and verify the MIC.  Returns `false` (and does not
/// guarantee plaintext) when authentication fails.
pub fn ccm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    data: &mut [u8],
    mic: &[u8; 8],
) -> bool {
    let aes = Aes128::new(key);
    // CCM decrypts the payload first, then computes the MAC over plaintext.
    ctr_crypt(&aes, nonce, data);

    let mut mac = [0u8; 16];
    cbc_mac(&aes, nonce, aad, data, &mut mac);
    let mut a0 = ctr_block(nonce, 0);
    aes.encrypt_block(&mut a0);
    let mut diff = 0u8;
    for i in 0..8 {
        diff |= (mac[i] ^ a0[i]) ^ mic[i];
    }
    diff == 0
}

fn ctr_block(nonce: &[u8; 13], counter: u16) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0] = 1; // L - 1, L = 2
    b[1..14].copy_from_slice(nonce);
    b[14..16].copy_from_slice(&counter.to_be_bytes());
    b
}

fn cbc_mac(aes: &Aes128, nonce: &[u8; 13], aad: &[u8], data: &[u8], out: &mut [u8; 16]) {
    // B0: Adata | (M-2)/2 | L-1, nonce, message length (L bytes).
    let mut b0 = [0u8; 16];
    b0[0] = 0x40 | (((8 - 2) / 2) << 3) | 1;
    b0[1..14].copy_from_slice(nonce);
    let len = data.len() as u16;
    b0[14..16].copy_from_slice(&len.to_be_bytes());
    let mut state = b0;
    aes.encrypt_block(&mut state);

    // AAD length encoding for L=2, then the AAD itself zero-padded.
    if !aad.is_empty() {
        let mut block = [0u8; 16];
        let alen = aad.len() as u16;
        block[0..2].copy_from_slice(&alen.to_be_bytes());
        let mut pos = 2usize;
        let mut off = 0usize;
        while off < aad.len() {
            let take = core::cmp::min(16 - pos, aad.len() - off);
            block[pos..pos + take].copy_from_slice(&aad[off..off + take]);
            pos += take;
            off += take;
            if pos == 16 {
                for i in 0..16 {
                    state[i] ^= block[i];
                }
                aes.encrypt_block(&mut state);
                block = [0u8; 16];
                pos = 0;
            }
        }
        if pos != 0 {
            for i in 0..16 {
                state[i] ^= block[i];
            }
            aes.encrypt_block(&mut state);
        }
    }

    // Plaintext, zero-padded.
    let mut off = 0usize;
    while off < data.len() {
        let take = core::cmp::min(16, data.len() - off);
        let mut block = [0u8; 16];
        block[..take].copy_from_slice(&data[off..off + take]);
        for i in 0..16 {
            state[i] ^= block[i];
        }
        aes.encrypt_block(&mut state);
        off += take;
    }
    *out = state;
}

fn ctr_crypt(aes: &Aes128, nonce: &[u8; 13], data: &mut [u8]) {
    let mut counter: u16 = 1;
    let mut off = 0usize;
    while off < data.len() {
        let mut ks = ctr_block(nonce, counter);
        aes.encrypt_block(&mut ks);
        let take = core::cmp::min(16, data.len() - off);
        for i in 0..take {
            data[off + i] ^= ks[i];
        }
        off += take;
        counter = counter.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str, out: &mut [u8]) {
        for (i, c) in s.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap();
        }
    }

    #[test]
    fn rfc3610_vector_l2_m8() {
        let mut key = [0u8; 16];
        hex("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF", &mut key);
        let mut nonce = [0u8; 13];
        hex("00000003020100A0A1A2A3A4A5", &mut nonce);
        let mut aad = [0u8; 8];
        hex("0001020304050607", &mut aad);
        let mut data = [0u8; 23];
        hex("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E", &mut data);
        let mut mic = [0u8; 8];
        ccm_encrypt(&key, &nonce, &aad, &mut data, &mut mic);

        let mut expected_ct = [0u8; 23];
        hex(
            "588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384",
            &mut expected_ct,
        );
        assert_eq!(data, expected_ct);
        let mut expected_mic = [0u8; 8];
        hex("17E8D12CFDF926E0", &mut expected_mic);
        assert_eq!(mic, expected_mic);

        assert!(ccm_decrypt(&key, &nonce, &aad, &mut data, &mic));
        let mut expected_pt = [0u8; 23];
        hex(
            "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
            &mut expected_pt,
        );
        assert_eq!(data, expected_pt);
    }

    #[test]
    fn tampered_ccmp_is_rejected() {
        let key = [0x11u8; 16];
        let nonce = [0x22u8; 13];
        let aad = [0x33u8; 24];
        let mut data = [0x44u8; 40];
        let mut mic = [0u8; 8];
        ccm_encrypt(&key, &nonce, &aad, &mut data, &mut mic);
        data[0] ^= 0x80;
        let mut cipher = data;
        assert!(!ccm_decrypt(&key, &nonce, &aad, &mut cipher, &mic));
    }
}
