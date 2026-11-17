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

//! `InputBatch` body (A.5).
//!
//! | Offset | Field         | Type |
//! |--------|---------------|------|
//! | 0      | `count`       | u16  |
//! | 2      | reserved = 0  | u16  |
//! | 4      | `focus_epoch` | u32  |
//! | 8      | `count` records | 48 bytes each |
//!
//! The body length is exactly `8 + 48 * count`, with `count <= 16`.

use crate::constants::*;
use crate::error::InputError;
use crate::record::InputRecord;

/// A decoded input batch. Fixed capacity: no allocation.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct InputBatch {
    pub count: u16,
    pub reserved: u16,
    pub focus_epoch: u32,
    pub records: [InputRecord; MAX_INPUT_RECORDS],
}

impl core::fmt::Debug for InputBatch {
    /// Redacted: records, and therefore text bytes, are never printed.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InputBatch")
            .field("count", &self.count)
            .field("focus_epoch", &self.focus_epoch)
            .finish()
    }
}

impl InputBatch {
    /// The `count` valid records, in wire order.
    pub fn records(&self) -> &[InputRecord] {
        &self.records[..(self.count as usize).min(MAX_INPUT_RECORDS)]
    }

    fn checked_len(&self) -> Result<usize, InputError> {
        if self.count as usize > MAX_INPUT_RECORDS {
            return Err(InputError::TooManyRecords);
        }
        if self.reserved != 0 {
            return Err(InputError::BadValue);
        }
        Ok(INPUT_BATCH_FIXED_LEN + INPUT_RECORD_LEN * self.count as usize)
    }

    /// Decode a batch body. The length must be exactly `8 + 48 * count`.
    pub fn decode(body: &[u8]) -> Result<InputBatch, InputError> {
        if body.len() < INPUT_BATCH_FIXED_LEN {
            return Err(InputError::Truncated);
        }

        let count = u16::from_le_bytes([body[0], body[1]]);
        let reserved = u16::from_le_bytes([body[2], body[3]]);
        let focus_epoch = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
        if count as usize > MAX_INPUT_RECORDS {
            return Err(InputError::TooManyRecords);
        }
        if reserved != 0 {
            return Err(InputError::BadValue);
        }

        let required = INPUT_BATCH_FIXED_LEN + INPUT_RECORD_LEN * count as usize;
        if body.len() < required {
            return Err(InputError::Truncated);
        }
        if body.len() > required {
            return Err(InputError::SizeMismatch);
        }

        let mut records = [InputRecord::default(); MAX_INPUT_RECORDS];
        for (index, record) in records.iter_mut().enumerate().take(count as usize) {
            let at = INPUT_BATCH_FIXED_LEN + index * INPUT_RECORD_LEN;
            *record = InputRecord::decode(&body[at..at + INPUT_RECORD_LEN])?;
        }

        Ok(InputBatch {
            count,
            reserved,
            focus_epoch,
            records,
        })
    }

    /// Encode this batch into `out`, which must hold at least
    /// [`InputBatch::encoded_len`] bytes. Returns the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, InputError> {
        let len = self.checked_len()?;
        for record in self.records() {
            record.check()?;
        }
        if out.len() < len {
            return Err(InputError::Truncated);
        }

        out[0..2].copy_from_slice(&self.count.to_le_bytes());
        out[2..4].copy_from_slice(&0u16.to_le_bytes());
        out[4..8].copy_from_slice(&self.focus_epoch.to_le_bytes());
        for (index, record) in self.records().iter().enumerate() {
            let at = INPUT_BATCH_FIXED_LEN + index * INPUT_RECORD_LEN;
            record.encode(&mut out[at..at + INPUT_RECORD_LEN])?;
        }
        Ok(len)
    }

    /// Exact encoded length of this batch.
    pub fn encoded_len(&self) -> usize {
        INPUT_BATCH_FIXED_LEN + INPUT_RECORD_LEN * self.count.min(MAX_INPUT_RECORDS as u16) as usize
    }
}
