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

//! MediaTek WMT framing over HCI vendor commands.
//!
//! Command: HCI opcode `0xFC6F`, parameters
//! `[dir=1][op][dlen u16 = data.len()+1][flag][data...]`.
//! Event: the controller delivers it through a vendor control-IN request
//! (`0xC0/1/0x0030/0/64`), *not* through the HCI interrupt endpoint.
//! Buffer layout: `[evt=0xE4][plen][dir][op][dlen u16][flag][data...]`.

pub const HCI_OP_WMT: u16 = 0xFC6F;
pub const EVT_WMT: u8 = 0xE4;

pub const OP_PATCH_DWNLD: u8 = 0x01;
pub const OP_FUNC_CTRL: u8 = 0x06;
pub const OP_RST: u8 = 0x07;
pub const OP_SEMAPHORE: u8 = 0x17;

/// Builds the WMT command parameters (without the H4/HCI header).
pub fn build(op: u8, flag: u8, data: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = 5usize.checked_add(data.len())?;
    if out.len() < n || data.len() + 1 > u16::MAX as usize {
        return None;
    }
    out[0] = 1; // direction: host -> controller
    out[1] = op;
    out[2..4].copy_from_slice(&((data.len() + 1) as u16).to_le_bytes());
    out[4] = flag;
    out[5..n].copy_from_slice(data);
    Some(n)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event<'a> {
    pub op: u8,
    pub flag: u8,
    pub data: &'a [u8],
}

/// Parses the raw vendor control-IN buffer.
pub fn parse_event(buf: &[u8]) -> Option<Event<'_>> {
    // Tolerate an H4 type byte if a caller prepended it.
    let buf = if buf.first() == Some(&0x04) && buf.get(1) == Some(&EVT_WMT) {
        &buf[1..]
    } else {
        buf
    };
    if buf.len() < 7 || buf[0] != EVT_WMT {
        return None;
    }
    let plen = buf[1] as usize;
    if plen < 5 || buf.len() < 2 + plen {
        return None;
    }
    let wmt = &buf[2..2 + plen];
    let dlen = u16::from_le_bytes([wmt[2], wmt[3]]) as usize;
    // dlen counts the flag byte plus the data.
    let data_len = dlen.saturating_sub(1).min(wmt.len().saturating_sub(5));
    Some(Event {
        op: wmt[1],
        flag: wmt[4],
        data: &wmt[5..5 + data_len],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_layout() {
        let mut out = [0u8; 32];
        let n = build(OP_PATCH_DWNLD, 1, &[0xAA, 0xBB, 0xCC], &mut out).unwrap();
        assert_eq!(n, 8);
        assert_eq!(
            &out[..8],
            &[1, 1, 4, 0, 1, 0xAA, 0xBB, 0xCC]
        );
    }

    #[test]
    fn event_layout() {
        // evt, plen=6, dir, op, dlen=2, flag, data
        let buf = [0xE4, 6, 0, OP_PATCH_DWNLD, 2, 0, 2, 0x55];
        let e = parse_event(&buf).unwrap();
        assert_eq!(e.op, OP_PATCH_DWNLD);
        assert_eq!(e.flag, 2);
        assert_eq!(e.data, &[0x55]);
    }

    #[test]
    fn event_without_data_and_h4_prefix() {
        let buf = [0x04, 0xE4, 5, 0, OP_FUNC_CTRL, 1, 0, 0];
        let e = parse_event(&buf).unwrap();
        assert_eq!(e.op, OP_FUNC_CTRL);
        assert_eq!(e.flag, 0);
        assert!(e.data.is_empty());
    }

    #[test]
    fn malformed_events_are_rejected() {
        assert!(parse_event(&[]).is_none());
        assert!(parse_event(&[0xE4, 1, 0]).is_none());
        assert!(parse_event(&[0xE5, 5, 0, 1, 1, 0, 0]).is_none());
    }
}
