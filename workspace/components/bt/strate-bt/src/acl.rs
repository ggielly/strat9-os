//! HCI ACL fragment reassembly and fragmentation into L2CAP PDUs.

use crate::hci::{AclHeader, H4_ACL};

/// Largest L2CAP PDU we accept from the controller.
pub const MAX_L2CAP_PDU: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclError {
    /// The announced L2CAP length does not fit the bounded buffer.
    Overflow,
    /// More bytes arrived after the L2CAP PDU was already complete.
    TooMuchData,
    UnexpectedStart,
    UnexpectedContinuation,
    HandleMismatch,
    InvalidBoundary,
    TruncatedL2cap,
    OutOfSpace,
    MtuTooSmall,
}

/// Reassembles ACL fragments from one connection into complete L2CAP frames.
pub struct AclReassembler {
    buf: [u8; MAX_L2CAP_PDU],
    len: usize,
    total: usize,
    handle: u16,
    active: bool,
}

impl Default for AclReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl AclReassembler {
    pub const fn new() -> Self {
        Self {
            buf: [0; MAX_L2CAP_PDU],
            len: 0,
            total: 0,
            handle: 0,
            active: false,
        }
    }

    pub fn reset(&mut self) {
        self.len = 0;
        self.total = 0;
        self.active = false;
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Borrow the completed frame.  Only valid after `push` returned
    /// `Ok(Some(_))`.
    pub fn frame(&self) -> &[u8] {
        &self.buf[..self.total]
    }

    /// Feed one ACL fragment.  Returns the total frame length when the L2CAP
    /// PDU is complete, `None` while more fragments are needed.
    pub fn push(
        &mut self,
        header: AclHeader,
        payload: &[u8],
    ) -> Result<Option<usize>, AclError> {
        if payload.len() != header.data_len as usize {
            return Err(AclError::TruncatedL2cap);
        }

        match header.packet_boundary() {
            0b00 | 0b10 => {
                if self.active {
                    // The previous PDU was never completed: a gap in the
                    // fragment stream is unrecoverable.
                    self.reset();
                    return Err(AclError::UnexpectedStart);
                }
                if payload.len() < 4 {
                    return Err(AclError::TruncatedL2cap);
                }
                let l2cap_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
                let total = 4usize
                    .checked_add(l2cap_len)
                    .ok_or(AclError::Overflow)?;
                if total > MAX_L2CAP_PDU {
                    return Err(AclError::Overflow);
                }
                if payload.len() > total {
                    return Err(AclError::TooMuchData);
                }
                self.buf[..payload.len()].copy_from_slice(payload);
                self.len = payload.len();
                self.total = total;
                self.handle = header.handle;
                self.active = true;
                if self.len == self.total {
                    self.active = false;
                    Ok(Some(self.total))
                } else {
                    Ok(None)
                }
            }
            0b01 => {
                if !self.active {
                    return Err(AclError::UnexpectedContinuation);
                }
                if header.handle != self.handle {
                    self.reset();
                    return Err(AclError::HandleMismatch);
                }
                let end = self
                    .len
                    .checked_add(payload.len())
                    .ok_or(AclError::Overflow)?;
                if end > self.total {
                    self.reset();
                    return Err(AclError::TooMuchData);
                }
                self.buf[self.len..end].copy_from_slice(payload);
                self.len = end;
                if self.len == self.total {
                    self.active = false;
                    Ok(Some(self.total))
                } else {
                    Ok(None)
                }
            }
            _ => Err(AclError::InvalidBoundary),
        }
    }
}

/// Fragment one L2CAP PDU into H4 ACL packets.  `max_payload` is the
/// controller ACL data payload limit (not including the 4-byte ACL header).
/// The first fragment uses PB=0b10 when `flushable`, otherwise PB=0b00;
/// following fragments use PB=0b01.
pub fn fragment(
    handle: u16,
    pdu: &[u8],
    max_payload: usize,
    flushable: bool,
    out: &mut [u8],
) -> Result<usize, AclError> {
    if pdu.is_empty() {
        return Ok(0);
    }
    if max_payload < 4 {
        return Err(AclError::MtuTooSmall);
    }

    let mut written = 0usize;
    let mut off = 0usize;
    let mut first = true;
    while off < pdu.len() {
        let take = core::cmp::min(max_payload, pdu.len() - off);
        let need = 5 + take;
        if written + need > out.len() {
            return Err(AclError::OutOfSpace);
        }
        let pb: u16 = if first {
            if flushable {
                0b10
            } else {
                0b00
            }
        } else {
            0b01
        };
        let flags = (handle & 0x0fff) | (pb << 12);
        out[written] = H4_ACL;
        out[written + 1..written + 3].copy_from_slice(&flags.to_le_bytes());
        out[written + 3..written + 5].copy_from_slice(&(take as u16).to_le_bytes());
        out[written + 5..written + need].copy_from_slice(&pdu[off..off + take]);
        written += need;
        off += take;
        first = false;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l2cap;

    fn header(handle: u16, pb: u8, len: usize) -> AclHeader {
        AclHeader::new(handle, pb, 0, len as u16)
    }

    fn pdu(payload_len: usize) -> [u8; 64] {
        let mut p = [0u8; 64];
        p[0] = (payload_len & 0xff) as u8;
        p[1] = (payload_len >> 8) as u8;
        p[2] = 0x04;
        p[3] = 0x00;
        for (i, b) in p[4..4 + payload_len].iter_mut().enumerate() {
            *b = i as u8;
        }
        p
    }

    #[test]
    fn one_fragment_roundtrip() {
        let p = pdu(10);
        let frame = &p[..14];
        let mut out = [0u8; 64];
        let n = fragment(0x0040, frame, 20, false, &mut out).unwrap();
        assert_eq!(n, 5 + 14);
        assert_eq!(out[0], H4_ACL);
        assert_eq!(&out[1..3], &[0x40, 0x00]); // PB=0b00
        assert_eq!(&out[3..5], &[14, 0]);

        let mut r = AclReassembler::new();
        let h = header(0x40, 0, 14);
        assert_eq!(r.push(h, &out[5..n]).unwrap(), Some(14));
        assert_eq!(r.frame(), frame);
    }

    #[test]
    fn three_fragments_roundtrip() {
        let p = pdu(20);
        let frame = &p[..24];
        let mut out = [0u8; 128];
        let n = fragment(0x0040, frame, 8, false, &mut out).unwrap();

        let mut r = AclReassembler::new();
        let mut off = 0usize;
        let mut done = None;
        let mut frag = 0;
        while off < n {
            let dlen = u16::from_le_bytes([out[off + 3], out[off + 4]]) as usize;
            let flags = u16::from_le_bytes([out[off + 1], out[off + 2]]);
            let pb = ((flags >> 12) & 3) as u8;
            if frag == 0 {
                assert_eq!(pb, 0);
            } else {
                assert_eq!(pb, 1);
            }
            let h = AclHeader::new(flags & 0x0fff, pb, 0, dlen as u16);
            done = r.push(h, &out[off + 5..off + 5 + dlen]).unwrap();
            off += 5 + dlen;
            frag += 1;
        }
        assert_eq!(frag, 3);
        assert_eq!(done, Some(24));
        assert_eq!(r.frame(), frame);
    }

    #[test]
    fn exact_boundary_fragment() {
        let p = pdu(4);
        let mut out = [0u8; 32];
        let n = fragment(1, &p[..8], 8, false, &mut out).unwrap();
        assert_eq!(n, 13); // single fragment
        let mut r = AclReassembler::new();
        assert_eq!(r.push(header(1, 0, 8), &out[5..n]).unwrap(), Some(8));
    }

    #[test]
    fn interleaved_handles_are_rejected() {
        let mut r = AclReassembler::new();
        let p = pdu(8);
        assert_eq!(
            r.push(header(0x40, 0, 6), &p[..6]).unwrap(),
            None
        );
        assert_eq!(
            r.push(header(0x41, 1, 6), &p[6..12]),
            Err(AclError::HandleMismatch)
        );
    }

    #[test]
    fn overflow_and_gaps() {
        let mut r = AclReassembler::new();
        let mut big = [0u8; 8];
        big[0] = 0xff;
        big[1] = 0xff; // 65535-byte L2CAP PDU
        big[2] = 0x04;
        big[3] = 0x00;
        assert_eq!(
            r.push(header(1, 0, 8), &big),
            Err(AclError::Overflow)
        );

        let p = pdu(8);
        assert_eq!(r.push(header(1, 1, 4), &p[..4]), Err(AclError::UnexpectedContinuation));
        assert_eq!(r.push(header(1, 0, 4), &p[..4]).unwrap(), None);
        assert_eq!(r.push(header(1, 0, 4), &p[4..8]), Err(AclError::UnexpectedStart));
    }

    #[test]
    fn too_much_data_and_bad_boundary() {
        let p = pdu(2);
        let mut r = AclReassembler::new();
        assert_eq!(r.push(header(1, 0, 7), &p[..7]), Err(AclError::TooMuchData));

        let p = pdu(8);
        assert_eq!(r.push(header(1, 3, 4), &p[..4]), Err(AclError::InvalidBoundary));
        assert_eq!(r.push(header(1, 1, 4), &p[..4]), Err(AclError::UnexpectedContinuation));
    }

    #[test]
    fn fragment_rejects_tiny_mtu_and_small_output() {
        let p = pdu(4);
        let mut out = [0u8; 32];
        assert_eq!(
            fragment(1, &p[..8], 3, false, &mut out),
            Err(AclError::MtuTooSmall)
        );
        assert_eq!(
            fragment(1, &p[..8], 8, false, &mut out[..10]),
            Err(AclError::OutOfSpace)
        );
    }

    #[test]
    fn flushable_start_uses_pb_10() {
        let p = pdu(4);
        let mut out = [0u8; 32];
        let n = fragment(0x40, &p[..8], 8, true, &mut out).unwrap();
        let flags = u16::from_le_bytes([out[1], out[2]]);
        assert_eq!((flags >> 12) & 3, 0b10);
        let mut r = AclReassembler::new();
        assert_eq!(r.push(header(0x40, 2, n - 5), &out[5..n]).unwrap(), Some(8));
    }

    #[test]
    fn l2cap_build_and_reassemble() {
        let att = [0x02, 0xf7, 0x00];
        let mut l2 = [0u8; 16];
        let ln = l2cap::build_att(&att, &mut l2).unwrap();
        let mut out = [0u8; 64];
        let n = fragment(0x40, &l2[..ln], 5, false, &mut out).unwrap();
        let mut r = AclReassembler::new();
        let mut done = None;
        let mut off = 0;
        while off < n {
            let dlen = u16::from_le_bytes([out[off + 3], out[off + 4]]) as usize;
            let flags = u16::from_le_bytes([out[off + 1], out[off + 2]]);
            let pb = ((flags >> 12) & 3) as u8;
            done = r.push(AclHeader::new(flags & 0x0fff, pb, 0, dlen as u16), &out[off + 5..off + 5 + dlen]).unwrap();
            off += 5 + dlen;
        }
        assert_eq!(done, Some(ln));
        assert_eq!(r.frame(), &l2[..ln]);
    }
}
