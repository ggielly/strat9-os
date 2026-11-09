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

//! Log dump framing over NUS TX notifications.
//!
//! Frame: `[type u8][seq u32 LE][payload...]` (5-byte header).  With an ATT
//! notification header of 3 bytes, a frame payload is at most
//! `att_mtu - 3 - 5` bytes.

pub const TYPE_DATA: u8 = 0xD0;
pub const TYPE_DROP: u8 = 0xD1;
pub const TYPE_HELLO: u8 = 0xD2;

pub const HEADER_LEN: usize = 5;
pub const DEFAULT_ATT_MTU: u16 = 23;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: u8,
    pub seq: u32,
    pub payload: &'a [u8],
}

/// Decode one frame, validating the 5-byte header.
pub fn decode(frame: &[u8]) -> Option<Frame<'_>> {
    if frame.len() < HEADER_LEN {
        return None;
    }
    Some(Frame {
        kind: frame[0],
        seq: u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]),
        payload: &frame[HEADER_LEN..],
    })
}

pub struct Dumper {
    mtu: u16,
    seq: u32,
    hello_sent: bool,
}

impl Default for Dumper {
    fn default() -> Self {
        Self::new()
    }
}

impl Dumper {
    pub const fn new() -> Self {
        Self {
            mtu: DEFAULT_ATT_MTU,
            seq: 0,
            hello_sent: false,
        }
    }

    pub fn reset(&mut self) {
        self.seq = 0;
        self.hello_sent = false;
        self.mtu = DEFAULT_ATT_MTU;
    }

    pub fn set_mtu(&mut self, mtu: u16) {
        self.mtu = mtu.max(8);
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    pub fn seq(&self) -> u32 {
        self.seq
    }

    /// Bytes of log payload per DATA frame.  Never below 1.
    pub fn chunk_size(&self) -> usize {
        let n = self.mtu as usize;
        if n > 8 {
            n - 8
        } else {
            1
        }
    }

    fn emit(&mut self, kind: u8, payload: &[u8], out: &mut [u8]) -> Option<usize> {
        let n = HEADER_LEN + payload.len();
        if out.len() < n {
            return None;
        }
        out[0] = kind;
        out[1..5].copy_from_slice(&self.seq.to_le_bytes());
        out[5..n].copy_from_slice(payload);
        self.seq = self.seq.wrapping_add(1);
        Some(n)
    }

    /// Produce the next notification frame from `data`.
    ///
    /// The first call emits HELLO (seq 0).  Subsequent calls emit DATA frames;
    /// `cursor` is caller-owned and must start at 0 for each new input slice.
    /// Returns `None` when the input slice is exhausted.
    pub fn next_frame(
        &mut self,
        data: &[u8],
        out: &mut [u8],
        cursor: &mut usize,
    ) -> Option<usize> {
        if !self.hello_sent {
            self.hello_sent = true;
            return self.emit(TYPE_HELLO, &[], out);
        }
        if *cursor >= data.len() {
            return None;
        }
        let n = core::cmp::min(self.chunk_size(), data.len() - *cursor);
        let frame_len = self.emit(TYPE_DATA, &data[*cursor..*cursor + n], out)?;
        *cursor += n;
        Some(frame_len)
    }

    /// Encode a DROP notice with the number of bytes lost by the log ring.
    pub fn drop_frame(&mut self, lost: u32, out: &mut [u8]) -> Option<usize> {
        self.emit(TYPE_DROP, &lost.to_le_bytes(), out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(mut d: Dumper, data: &[u8], out: &mut [u8]) -> (usize, usize, usize) {
        let mut cursor = 0usize;
        let mut frames = 0usize;
        let mut payload = 0usize;
        let mut seq = 0u32;
        while let Some(n) = d.next_frame(data, out, &mut cursor) {
            let f = decode(&out[..n]).unwrap();
            assert_eq!(f.seq, seq);
            seq += 1;
            frames += 1;
            if f.kind == TYPE_DATA {
                payload += f.payload.len();
            }
        }
        (frames, payload, cursor)
    }

    #[test]
    fn chunking_at_mtu_23() {
        let d = Dumper::new();
        assert_eq!(d.chunk_size(), 15);
        let mut out = [0u8; 32];
        let data = [0xABu8; 40];
        let (frames, payload, cursor) = collect(d, &data, &mut out);
        // HELLO + 3 DATA frames (15 + 15 + 10).
        assert_eq!(frames, 4);
        assert_eq!(payload, 40);
        assert_eq!(cursor, 40);
    }

    #[test]
    fn chunking_at_mtu_247() {
        let mut d = Dumper::new();
        d.set_mtu(247);
        assert_eq!(d.chunk_size(), 239);
        let mut out = [0u8; 256];
        let data = [0x5Au8; 500];
        let (frames, payload, cursor) = collect(d, &data, &mut out);
        // HELLO + 239 + 239 + 22.
        assert_eq!(frames, 4);
        assert_eq!(payload, 500);
        assert_eq!(cursor, 500);
    }

    #[test]
    fn hello_is_first_and_seq_is_continuous() {
        let mut d = Dumper::new();
        let mut out = [0u8; 32];
        let mut cursor = 0;
        let n = d.next_frame(&[1, 2, 3], &mut out, &mut cursor).unwrap();
        let f = decode(&out[..n]).unwrap();
        assert_eq!(f.kind, TYPE_HELLO);
        assert_eq!(f.seq, 0);
        assert!(f.payload.is_empty());
        assert_eq!(cursor, 0);

        let n = d.next_frame(&[1, 2, 3], &mut out, &mut cursor).unwrap();
        let f = decode(&out[..n]).unwrap();
        assert_eq!(f.kind, TYPE_DATA);
        assert_eq!(f.seq, 1);
        assert_eq!(f.payload, &[1, 2, 3]);
        assert_eq!(cursor, 3);
        assert_eq!(d.next_frame(&[1, 2, 3], &mut out, &mut cursor), None);
    }

    #[test]
    fn drop_encoding() {
        let mut d = Dumper::new();
        let mut out = [0u8; 16];
        let n = d.drop_frame(0x1122_3344, &mut out).unwrap();
        assert_eq!(n, 9);
        assert_eq!(&out[..9], &[TYPE_DROP, 0x00, 0, 0, 0, 0x44, 0x33, 0x22, 0x11]);
        let f = decode(&out[..n]).unwrap();
        assert_eq!(f.kind, TYPE_DROP);
        assert_eq!(u32::from_le_bytes(f.payload.try_into().unwrap()), 0x1122_3344);
        assert_eq!(d.seq(), 1);
    }

    #[test]
    fn round_trip_decoder_reassembles_payload() {
        let mut d = Dumper::new();
        d.set_mtu(23);
        let data: [u8; 31] = core::array::from_fn(|i| i as u8);
        let mut out = [0u8; 32];
        let mut cursor = 0usize;
        let mut decoded = [0u8; 64];
        let mut len = 0usize;
        let mut kinds = [0u8; 8];
        let mut frames = 0usize;
        while let Some(n) = d.next_frame(&data, &mut out, &mut cursor) {
            let f = decode(&out[..n]).unwrap();
            kinds[frames] = f.kind;
            frames += 1;
            if f.kind == TYPE_DATA {
                decoded[len..len + f.payload.len()].copy_from_slice(f.payload);
                len += f.payload.len();
            }
        }
        assert_eq!(frames, 4); // HELLO + 15 + 15 + 1
        assert_eq!(kinds[0], TYPE_HELLO);
        assert_eq!(&decoded[..len], &data);
    }

    #[test]
    fn exact_boundary_and_tiny_mtu() {
        let mut d = Dumper::new();
        let mut out = [0u8; 32];
        let mut cursor = 0;
        d.next_frame(&[0u8; 15], &mut out, &mut cursor).unwrap(); // HELLO
        let n = d.next_frame(&[7u8; 15], &mut out, &mut cursor).unwrap();
        let f = decode(&out[..n]).unwrap();
        assert_eq!(f.payload.len(), 15);
        assert_eq!(cursor, 15);
        assert_eq!(d.next_frame(&[7u8; 15], &mut out, &mut cursor), None);

        d.set_mtu(4);
        assert_eq!(d.chunk_size(), 1);
        assert_eq!(d.mtu(), 8);
    }

    #[test]
    fn short_output_is_rejected_without_consuming_seq() {
        let mut d = Dumper::new();
        let mut out = [0u8; 8];
        let mut cursor = 0;
        assert_eq!(d.next_frame(&[0u8; 4], &mut out, &mut cursor), Some(5)); // HELLO
        assert_eq!(d.next_frame(&[0u8; 4], &mut out, &mut cursor), None); // 5+4 > 8
        assert_eq!(cursor, 0);
        assert_eq!(d.seq(), 1);
    }

    #[test]
    fn decode_rejects_short_frames() {
        assert!(decode(&[]).is_none());
        assert!(decode(&[0xD0, 0, 0, 0]).is_none());
        let f = decode(&[0xD0, 1, 0, 0, 0, 9]).unwrap();
        assert_eq!(f.kind, TYPE_DATA);
        assert_eq!(f.seq, 1);
        assert_eq!(f.payload, &[9]);
    }
}
