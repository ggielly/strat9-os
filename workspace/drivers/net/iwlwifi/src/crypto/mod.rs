//! Self-contained `no_std` crypto used by the WPA2 supplicant and CCMP.
//!
//! The kernel and the driver core must not depend on `std`/`alloc`-heavy
//! crypto crates, so the few primitives WPA2-PSK actually needs are
//! implemented here:
//!
//! | Primitive | Used by |
//! |-----------|---------|
//! | SHA-1 + HMAC-SHA1 | PBKDF2 (PMK), PRF (PTK), EAPOL MIC |
//! | PBKDF2-HMAC-SHA1 | WPA2 passphrase -> PMK |
//! | AES-128 | CCMP, NIST key unwrap |
//! | AES-CCM (M=8, L=2) | CCMP data confidentiality |
//! | AES key unwrap | encrypted EAPOL-Key data (GTK) |
//!
//! Only AES-128 is implemented: CCMP and WPA2-PSK always use 128-bit keys.

pub mod aes;
pub mod ccmp;
pub mod sha1;

pub use aes::{aes128_decrypt_block, aes128_encrypt_block, key_unwrap, Aes128};
pub use ccmp::{ccm_decrypt, ccm_encrypt};
pub use sha1::{hmac_sha1, pbkdf2_hmac_sha1, sha1, SHA1_DIGEST_LEN};

/// WPA2 PTK length for CCMP (KCK 16 + KEK 16 + TK 16).
pub const PTK_LEN: usize = 48;
/// PMK length for WPA2-PSK.
pub const PMK_LEN: usize = 32;
/// CCMP key length.
pub const CCMP_KEY_LEN: usize = 16;
/// CCMP MIC length.
pub const CCMP_MIC_LEN: usize = 8;

/// WPA2 PRF (IEEE 802.11-2016, 12.7.1.2) with HMAC-SHA1.
///
/// `label` is the ASCII label without the trailing NUL, `context` is the
/// concatenation of the address/nonce fields in the order defined by the
/// caller.  Produces `out.len()` bytes.
pub fn wpa2_prf(prf_key: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    let mut offset = 0usize;
    let mut counter: u8 = 0;
    while offset < out.len() {
        let mut msg = [0u8; 512];
        let mut len = 0usize;
        msg[len..len + label.len()].copy_from_slice(label);
        len += label.len();
        msg[len] = 0; // NUL separator
        len += 1;
        msg[len..len + context.len()].copy_from_slice(context);
        len += context.len();
        msg[len] = counter;
        len += 1;

        let mac = hmac_sha1(prf_key, &msg[..len]);
        let take = core::cmp::min(mac.len(), out.len() - offset);
        out[offset..offset + take].copy_from_slice(&mac[..take]);
        offset += take;
        counter = counter.wrapping_add(1);
    }
}

/// Derive the WPA2 pairwise master key from a passphrase and SSID.
///
/// This is PBKDF2-HMAC-SHA1 with 4096 iterations and a 32-byte output, as
/// specified by IEEE 802.11-2016, 12.7.1.3.
pub fn derive_pmk(passphrase: &[u8], ssid: &[u8]) -> [u8; PMK_LEN] {
    let mut pmk = [0u8; PMK_LEN];
    pbkdf2_hmac_sha1(passphrase, ssid, 4096, &mut pmk);
    pmk
}

/// Derive the 48-byte CCMP PTK from the PMK, both MAC addresses and both
/// nonces.
///
/// The PRF context is `min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) ||
/// max(ANonce,SNonce)` (802.11-2016, 12.7.1.2).
pub fn derive_ptk(
    pmk: &[u8],
    supplicant_mac: &[u8; 6],
    authenticator_mac: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
) -> [u8; PTK_LEN] {
    let mut ctx = [0u8; 76];
    let (a, b) = if supplicant_mac < authenticator_mac {
        (supplicant_mac, authenticator_mac)
    } else {
        (authenticator_mac, supplicant_mac)
    };
    ctx[0..6].copy_from_slice(a);
    ctx[6..12].copy_from_slice(b);
    let (na, nb) = if anonce < snonce {
        (anonce, snonce)
    } else {
        (snonce, anonce)
    };
    ctx[12..44].copy_from_slice(na);
    ctx[44..76].copy_from_slice(nb);

    let mut ptk = [0u8; PTK_LEN];
    wpa2_prf(pmk, b"Pairwise key expansion", &ctx, &mut ptk);
    ptk
}

#[cfg(test)]
mod tests {
    use super::*;

    // IEEE 802.11-2016 / WPA2 test vectors.
    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, c) in s.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap();
        }
        out
    }

    #[test]
    fn pmk_rfc_vector() {
        // IEEE 802.11 test vector: passphrase "password", SSID "IEEE".
        let pmk = derive_pmk(b"password", b"IEEE");
        assert_eq!(
            pmk,
            [
                0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b, 0x90, 0xb3,
                0x8a, 0x5f, 0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2, 0x3a, 0xed,
                0x76, 0x2e, 0x97, 0x10, 0xa1, 0x2e,
            ]
        );
    }

    #[test]
    fn ptk_matches_reference_layout() {
        let pmk = derive_pmk(b"password", b"IEEE");
        let aa = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let spa = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
        let anonce = hex32("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        let snonce = hex32("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
        let ptk = derive_ptk(&pmk, &spa, &aa, &anonce, &snonce);
        // Stable self-consistency: swapping MAC/nonce order must not change PTK.
        let ptk2 = derive_ptk(&pmk, &aa, &spa, &snonce, &anonce);
        assert_eq!(ptk, ptk2);
        assert_ne!(ptk[0..16], ptk[16..32]);
    }

    #[test]
    fn prf_is_independent_of_output_slicing() {
        let mut whole = [0u8; 48];
        let mut part = [0u8; 48];
        wpa2_prf(b"key", b"label", b"context", &mut whole);
        wpa2_prf(b"key", b"label", b"context", &mut part[..20]);
        // First 20 bytes are a prefix of the full output.
        assert_eq!(whole[..20], part[..20]);
    }
}
