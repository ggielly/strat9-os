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

//! L2CAP B-frame framing.  Only the fixed ATT CID is used for the GATT
//! peripheral; dynamic channel setup is intentionally out of scope.

pub const CID_SIGNALING: u16 = 0x0001;
pub const CID_ATT: u16 = 0x0004;
pub const CID_LE_SIGNALING: u16 = 0x0005;
pub const CID_SMP: u16 = 0x0006;

pub const HEADER_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    BadLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Length of the information payload (excluding this header).
    pub length: u16,
    pub cid: u16,
}

/// Parse one complete L2CAP B-frame.  The buffer must contain exactly the
/// announced frame; trailing bytes are rejected.
pub fn parse(frame: &[u8]) -> Result<(Header, &[u8]), ParseError> {
    if frame.len() < HEADER_LEN {
        return Err(ParseError::Truncated);
    }
    let length = u16::from_le_bytes([frame[0], frame[1]]);
    let cid = u16::from_le_bytes([frame[2], frame[3]]);
    let end = HEADER_LEN
        .checked_add(length as usize)
        .ok_or(ParseError::BadLength)?;
    if frame.len() < end {
        return Err(ParseError::Truncated);
    }
    if frame.len() != end {
        return Err(ParseError::BadLength);
    }
    Ok((Header { length, cid }, &frame[HEADER_LEN..end]))
}

/// Build a B-frame for an arbitrary CID.
pub fn build(cid: u16, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    if payload.len() > u16::MAX as usize {
        return None;
    }
    let n = HEADER_LEN + payload.len();
    if out.len() < n {
        return None;
    }
    out[0..2].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    out[2..4].copy_from_slice(&cid.to_le_bytes());
    out[4..n].copy_from_slice(payload);
    Some(n)
}

/// Build an ATT B-frame.  `mtu` is the negotiated ATT MTU: an ATT PDU larger
/// than the MTU is rejected.
pub fn build_att(att_payload: &[u8], out: &mut [u8]) -> Option<usize> {
    build_att_mtu(att_payload, u16::MAX, out)
}

pub fn build_att_mtu(att_payload: &[u8], mtu: u16, out: &mut [u8]) -> Option<usize> {
    if att_payload.len() > mtu as usize {
        return None;
    }
    build(CID_ATT, att_payload, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_parses_att_frame() {
        let mut buf = [0u8; 32];
        let n = build_att(&[0x02, 0xf7, 0x00], &mut buf).unwrap();
        assert_eq!(n, 7);
        assert_eq!(&buf[..7], &[0x03, 0x00, 0x04, 0x00, 0x02, 0xf7, 0x00]);

        let (h, payload) = parse(&buf[..n]).unwrap();
        assert_eq!(h.length, 3);
        assert_eq!(h.cid, CID_ATT);
        assert_eq!(payload, &[0x02, 0xf7, 0x00]);
    }

    #[test]
    fn cid_constants_are_distinct() {
        assert_eq!(CID_SIGNALING, 0x0001);
        assert_eq!(CID_ATT, 0x0004);
        assert_eq!(CID_LE_SIGNALING, 0x0005);
        assert_eq!(CID_SMP, 0x0006);
    }

    #[test]
    fn mtu_bounds_att_frame() {
        let mut buf = [0u8; 32];
        assert!(build_att_mtu(&[0u8; 24], 23, &mut buf).is_none());
        assert!(build_att_mtu(&[0u8; 23], 23, &mut buf).is_some());
        assert!(build_att(&[0u8; 8], &mut buf[..5]).is_none());
    }

    #[test]
    fn rejects_bad_frames() {
        assert_eq!(parse(&[]), Err(ParseError::Truncated));
        assert_eq!(parse(&[0x05, 0x00, 0x04, 0x00]), Err(ParseError::Truncated));
        assert_eq!(
            parse(&[0x01, 0x00, 0x04, 0x00, 0xaa, 0xbb]),
            Err(ParseError::BadLength)
        );
    }
}
