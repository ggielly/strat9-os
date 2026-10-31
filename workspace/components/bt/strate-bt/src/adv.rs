//! Advertising data and advertising parameter payload builders.

use crate::gatt::NUS_SERVICE_UUID;

pub const AD_FLAGS: u8 = 0x01;
pub const AD_UUID128_COMPLETE: u8 = 0x07;
pub const AD_LOCAL_NAME_SHORT: u8 = 0x08;

pub const LE_GENERAL_DISCOVERABLE: u8 = 0x02;
pub const BR_EDR_NOT_SUPPORTED: u8 = 0x04;

pub const ADV_IND: u8 = 0x00;
pub const ADV_NONCONN_IND: u8 = 0x03;
pub const OWN_ADDR_PUBLIC: u8 = 0x00;
pub const CHANNEL_ALL: u8 = 0x07;

pub const LOCAL_NAME: &[u8] = b"S9-DUMP";

pub const ADV_MIN_INTERVAL: u16 = 0x00A0; // 100 ms
pub const ADV_MAX_INTERVAL: u16 = 0x00A0;

/// Build the advertising data block (no HCI length prefix).
///
/// Layout: flags, complete list of 128-bit service UUIDs (NUS), shortened
/// local name.  Total is 30 bytes, fitting the 31-byte legacy limit.
pub fn build_adv_data(out: &mut [u8]) -> Option<usize> {
    let mut n = 0usize;

    // Flags.
    if out.len() < n + 3 {
        return None;
    }
    out[n] = 2;
    out[n + 1] = AD_FLAGS;
    out[n + 2] = LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED;
    n += 3;

    // Complete 128-bit service UUID list (one UUID).
    if out.len() < n + 2 + NUS_SERVICE_UUID.len() {
        return None;
    }
    out[n] = (1 + NUS_SERVICE_UUID.len()) as u8;
    out[n + 1] = AD_UUID128_COMPLETE;
    out[n + 2..n + 2 + NUS_SERVICE_UUID.len()].copy_from_slice(&NUS_SERVICE_UUID);
    n += 2 + NUS_SERVICE_UUID.len();

    // Shortened local name.
    if out.len() < n + 2 + LOCAL_NAME.len() {
        return None;
    }
    out[n] = (1 + LOCAL_NAME.len()) as u8;
    out[n + 1] = AD_LOCAL_NAME_SHORT;
    out[n + 2..n + 2 + LOCAL_NAME.len()].copy_from_slice(LOCAL_NAME);
    n += 2 + LOCAL_NAME.len();

    if n > 31 {
        None
    } else {
        Some(n)
    }
}

/// Build the 15-byte LE Set Advertising Parameters payload.
pub fn build_adv_params(out: &mut [u8]) -> Option<usize> {
    if out.len() < 15 {
        return None;
    }
    out[0..2].copy_from_slice(&ADV_MIN_INTERVAL.to_le_bytes());
    out[2..4].copy_from_slice(&ADV_MAX_INTERVAL.to_le_bytes());
    out[4] = ADV_IND;
    out[5] = OWN_ADDR_PUBLIC;
    out[6] = 0x00; // peer address type
    out[7..13].fill(0);
    out[13] = CHANNEL_ALL;
    out[14] = 0x00; // filter policy
    Some(15)
}

/// Build the one-byte LE Set Advertising Enable payload.
pub fn build_adv_enable(out: &mut [u8], enable: bool) -> Option<usize> {
    if out.is_empty() {
        return None;
    }
    out[0] = enable as u8;
    Some(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertising_data_exact_bytes() {
        let mut out = [0u8; 31];
        let n = build_adv_data(&mut out).unwrap();
        assert_eq!(n, 30);
        assert!(n <= 31);

        let mut expect = [0u8; 30];
        expect[0..3].copy_from_slice(&[0x02, 0x01, 0x06]);
        expect[3] = 0x11;
        expect[4] = 0x07;
        expect[5..21].copy_from_slice(&NUS_SERVICE_UUID);
        expect[21] = 0x08;
        expect[22] = 0x08;
        expect[23..30].copy_from_slice(b"S9-DUMP");
        assert_eq!(&out[..n], &expect);
    }

    #[test]
    fn advertising_data_rejects_short_buffer() {
        let mut small = [0u8; 29];
        assert!(build_adv_data(&mut small).is_none());
        let mut exact = [0u8; 30];
        assert_eq!(build_adv_data(&mut exact), Some(30));
    }

    #[test]
    fn params_exact_bytes() {
        let mut out = [0u8; 15];
        let n = build_adv_params(&mut out).unwrap();
        assert_eq!(n, 15);
        assert_eq!(
            &out[..n],
            &[
                0xA0, 0x00, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x07, 0x00,
            ]
        );
        assert!(build_adv_params(&mut out[..14]).is_none());
    }

    #[test]
    fn enable_payload() {
        let mut out = [0u8; 1];
        assert_eq!(build_adv_enable(&mut out, true), Some(1));
        assert_eq!(out[0], 1);
        assert_eq!(build_adv_enable(&mut out, false), Some(1));
        assert_eq!(out[0], 0);
        assert_eq!(build_adv_enable(&mut [], true), None);
    }
}
