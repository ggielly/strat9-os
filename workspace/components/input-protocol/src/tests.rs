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

//! Host tests for the normalized input protocol.

use crate::*;
use std::vec;
use std::vec::Vec;

fn event(event_type: u16, code: u16, value: i32, flags: u32) -> NormalizedEvent {
    NormalizedEvent {
        timestamp_ns: 0x0123_4567_89ab_cdef,
        sequence: 0xfedc_ba98_7654_3210,
        device_id: 0xdead_beef,
        event_type,
        code,
        value,
        flags,
    }
}

fn text_record(text: &[u8]) -> InputRecord {
    let mut record = InputRecord::default();
    record.event = event(INPUT_EVENT_TEXT, 0, text.len() as i32, 0);
    record.text[..text.len()].copy_from_slice(text);
    record
}

fn key_record(index: u16) -> InputRecord {
    let mut record = InputRecord::default();
    record.event = event(INPUT_EVENT_KEY, index, (index % 2) as i32, 0);
    record
}

fn event_bytes(e: &NormalizedEvent) -> Vec<u8> {
    let mut buf = [0u8; NORMALIZED_EVENT_LEN];
    e.encode(&mut buf).unwrap();
    buf.to_vec()
}

fn record_bytes(r: &InputRecord) -> Vec<u8> {
    let mut buf = [0u8; INPUT_RECORD_LEN];
    r.encode(&mut buf).unwrap();
    buf.to_vec()
}

fn assert_well_formed(error: InputError) {
    match error {
        InputError::Truncated
        | InputError::SizeMismatch
        | InputError::BadValue
        | InputError::BadFlags
        | InputError::Overflow
        | InputError::UnknownEvent
        | InputError::NotUtf8
        | InputError::TooManyRecords
        | InputError::PathTooLong => {}
    }
}

/// Every event type at its documented bounds round-trips.
#[test]
fn event_roundtrip_min_max() {
    let cases = [
        event(INPUT_EVENT_POINTER_ENTER, 0, i32::MIN, 0),
        event(INPUT_EVENT_POINTER_ENTER, u16::MAX, i32::MAX, 0),
        event(INPUT_EVENT_POINTER_LEAVE, 0, i32::MIN, 0),
        event(INPUT_EVENT_POINTER_LEAVE, u16::MAX, i32::MAX, 0),
        event(INPUT_EVENT_POINTER_MOTION, 0, i16::MIN as i32, 0),
        event(INPUT_EVENT_POINTER_MOTION, u16::MAX, i16::MAX as i32, 0),
        event(
            INPUT_EVENT_POINTER_MOTION,
            u16::MAX,
            i16::MIN as i32,
            INPUT_FLAG_ABSOLUTE,
        ),
        event(INPUT_EVENT_POINTER_BUTTON, 0, 0, 0),
        event(INPUT_EVENT_POINTER_BUTTON, u16::MAX, 1, 0),
        event(INPUT_EVENT_POINTER_AXIS, 0, i32::MIN, 0),
        event(INPUT_EVENT_POINTER_AXIS, 1, i32::MAX, 0),
        event(INPUT_EVENT_KEY, 0, 0, 0),
        event(INPUT_EVENT_KEY, u16::MAX, 1, 0),
        event(INPUT_EVENT_TEXT, 0, 1, 0),
        event(INPUT_EVENT_TEXT, 0, 16, 0),
        event(INPUT_EVENT_FOCUS_GAINED, 0, 0, 0),
        event(INPUT_EVENT_FOCUS_LOST, 0, 0, 0),
    ];

    for original in cases {
        let bytes = event_bytes(&original);
        assert_eq!(bytes.len(), NORMALIZED_EVENT_LEN);
        assert_eq!(NormalizedEvent::decode(&bytes).unwrap(), original);
    }
}

#[test]
fn record_roundtrip_all_types() {
    let records = [
        text_record(b"A"),
        text_record(b"abcdefghijklmnop"),
        key_record(0x1234),
        {
            let mut r = key_record(7);
            r.event = event(INPUT_EVENT_POINTER_MOTION, u16::MAX, i16::MIN as i32, 0);
            r
        },
        {
            let mut r = key_record(7);
            r.event = event(
                INPUT_EVENT_POINTER_MOTION,
                1,
                i16::MAX as i32,
                INPUT_FLAG_ABSOLUTE,
            );
            r
        },
        {
            let mut r = key_record(7);
            r.event = event(INPUT_EVENT_POINTER_AXIS, 1, i32::MAX, 0);
            r
        },
        {
            let mut r = key_record(7);
            r.event = event(INPUT_EVENT_FOCUS_LOST, 0, 0, 0);
            r
        },
    ];

    for original in records {
        let bytes = record_bytes(&original);
        assert_eq!(bytes.len(), INPUT_RECORD_LEN);
        let decoded = InputRecord::decode(&bytes).unwrap();
        assert_eq!(decoded, original);
        // A decoded record re-encodes identically.
        assert_eq!(record_bytes(&decoded), bytes);
    }
}

#[test]
fn batch_roundtrip_zero_and_sixteen() {
    for count in [0u16, 16] {
        let mut batch = InputBatch {
            count,
            reserved: 0,
            focus_epoch: 0xdead_beef,
            records: [InputRecord::default(); MAX_INPUT_RECORDS],
        };
        for (index, record) in batch.records.iter_mut().enumerate() {
            *record = key_record(index as u16);
        }

        let mut buf = vec![0u8; INPUT_BATCH_FIXED_LEN + INPUT_RECORD_LEN * count as usize];
        let written = batch.encode(&mut buf).unwrap();
        assert_eq!(written, buf.len());
        assert_eq!(batch.encoded_len(), buf.len());

        let decoded = InputBatch::decode(&buf).unwrap();
        assert_eq!(decoded.count, batch.count);
        assert_eq!(decoded.reserved, batch.reserved);
        assert_eq!(decoded.focus_epoch, batch.focus_epoch);
        assert_eq!(decoded.records(), batch.records());
        assert_eq!(decoded.records().len(), count as usize);

        let mut again = vec![0u8; written];
        assert_eq!(decoded.encode(&mut again).unwrap(), written);
        assert_eq!(again, buf);
    }
}

#[test]
fn event_exact_length_and_truncation() {
    let bytes = event_bytes(&event(INPUT_EVENT_KEY, 1, 1, 0));
    for prefix in 0..NORMALIZED_EVENT_LEN {
        assert_eq!(
            NormalizedEvent::decode(&bytes[..prefix]).unwrap_err(),
            InputError::Truncated,
            "prefix {prefix}"
        );
    }
    assert_eq!(
        NormalizedEvent::decode(&[bytes.as_slice(), &[0u8]].concat()).unwrap_err(),
        InputError::SizeMismatch
    );

    let short = [0u8; NORMALIZED_EVENT_LEN - 1];
    let mut out = short;
    assert_eq!(
        event(INPUT_EVENT_KEY, 1, 1, 0).encode(&mut out).unwrap_err(),
        InputError::Truncated
    );
}

#[test]
fn record_exact_length_and_truncation() {
    let bytes = record_bytes(&text_record(b"hello"));
    for prefix in 0..INPUT_RECORD_LEN {
        assert_eq!(
            InputRecord::decode(&bytes[..prefix]).unwrap_err(),
            InputError::Truncated,
            "prefix {prefix}"
        );
    }
    assert_eq!(
        InputRecord::decode(&[bytes.as_slice(), &[0u8]].concat()).unwrap_err(),
        InputError::SizeMismatch
    );

    let mut out = [0u8; INPUT_RECORD_LEN - 1];
    assert_eq!(
        text_record(b"hello").encode(&mut out).unwrap_err(),
        InputError::Truncated
    );
}

#[test]
fn batch_exact_length_and_truncation() {
    for count in [0usize, 1, 3, 16] {
        let mut batch = InputBatch {
            count: count as u16,
            reserved: 0,
            focus_epoch: 1,
            records: [InputRecord::default(); MAX_INPUT_RECORDS],
        };
        for (index, record) in batch.records.iter_mut().enumerate() {
            *record = key_record(index as u16);
        }
        let mut bytes = vec![0u8; batch.encoded_len()];
        batch.encode(&mut bytes).unwrap();

        for prefix in 0..bytes.len() {
            assert_eq!(
                InputBatch::decode(&bytes[..prefix]).unwrap_err(),
                InputError::Truncated,
                "count {count} prefix {prefix}"
            );
        }
        assert_eq!(
            InputBatch::decode(&[bytes.as_slice(), &[0u8]].concat()).unwrap_err(),
            InputError::SizeMismatch
        );

        let mut out = vec![0u8; bytes.len() - 1];
        assert_eq!(batch.encode(&mut out).unwrap_err(), InputError::Truncated);
    }
}

#[test]
fn subscribe_roundtrip_and_exact_length() {
    for path in [&b"a"[..], &[7u8; MAX_SUBSCRIBE_PATH][..]] {
        let subscribe = Subscribe {
            focus_epoch: 42,
            path,
        };
        let mut bytes = vec![0u8; SUBSCRIBE_FIXED_LEN + path.len()];
        subscribe.encode(&mut bytes).unwrap();
        assert_eq!(&bytes[4..6], &(path.len() as u16).to_le_bytes()[..]);

        let decoded = Subscribe::decode(&bytes).unwrap();
        assert_eq!(decoded, subscribe);

        for prefix in 0..bytes.len() {
            assert_eq!(
                Subscribe::decode(&bytes[..prefix]).unwrap_err(),
                InputError::Truncated,
                "path len {} prefix {prefix}",
                path.len()
            );
        }
        assert_eq!(
            Subscribe::decode(&[bytes.as_slice(), &[0u8]].concat()).unwrap_err(),
            InputError::SizeMismatch
        );

        let mut out = vec![0u8; bytes.len() - 1];
        assert_eq!(subscribe.encode(&mut out).unwrap_err(), InputError::Truncated);
    }
}

#[test]
fn subscribe_ack_and_reset_roundtrip_and_exact_length() {
    for status in [
        SUBSCRIBE_STATUS_ACCEPTED,
        SUBSCRIBE_STATUS_TABLE_FULL,
        SUBSCRIBE_STATUS_BAD_PATH,
        SUBSCRIBE_STATUS_INTERNAL,
    ] {
        let ack = SubscribeAck { status };
        let mut bytes = [0u8; SUBSCRIBE_ACK_LEN];
        ack.encode(&mut bytes).unwrap();
        assert_eq!(SubscribeAck::decode(&bytes).unwrap(), ack);
        for prefix in 0..SUBSCRIBE_ACK_LEN {
            assert_eq!(
                SubscribeAck::decode(&bytes[..prefix]).unwrap_err(),
                InputError::Truncated
            );
        }
        assert_eq!(
            SubscribeAck::decode(&[&bytes[..], &[0u8]].concat()).unwrap_err(),
            InputError::SizeMismatch
        );
        let mut short = [0u8; SUBSCRIBE_ACK_LEN - 1];
        assert_eq!(ack.encode(&mut short).unwrap_err(), InputError::Truncated);
    }

    for reason in [RESET_REASON_RESYNC, RESET_REASON_SERVICE_CHANGED] {
        let reset = Reset {
            focus_epoch: 0x1234_5678,
            reason,
        };
        let mut bytes = [0u8; RESET_LEN];
        reset.encode(&mut bytes).unwrap();
        assert_eq!(Reset::decode(&bytes).unwrap(), reset);
        for prefix in 0..RESET_LEN {
            assert_eq!(
                Reset::decode(&bytes[..prefix]).unwrap_err(),
                InputError::Truncated
            );
        }
        assert_eq!(
            Reset::decode(&[&bytes[..], &[0u8]].concat()).unwrap_err(),
            InputError::SizeMismatch
        );
        let mut short = [0u8; RESET_LEN - 1];
        assert_eq!(reset.encode(&mut short).unwrap_err(), InputError::Truncated);
    }
}

#[test]
fn text_valid_utf8_lengths() {
    for text in [&b"x"[..], &b"0123456789abcdef"[..]] {
        let record = text_record(text);
        assert!(record.check().is_ok());
        let bytes = record_bytes(&record);
        let decoded = InputRecord::decode(&bytes).unwrap();
        assert_eq!(&decoded.text[..text.len()], text);
        assert_eq!(decoded.event.value as usize, text.len());
        assert_eq!(record_bytes(&decoded), bytes);
    }
}

#[test]
fn text_invalid_utf8_rejected() {
    let record = text_record(&[0xff]);
    assert_eq!(record.check().unwrap_err(), InputError::NotUtf8);
    assert_eq!(record_bytes_result(&record).unwrap_err(), InputError::NotUtf8);

    // Same through the decoder.
    let mut bytes = record_bytes(&text_record(b"a"));
    bytes[NORMALIZED_EVENT_LEN] = 0xff;
    assert_eq!(
        InputRecord::decode(&bytes).unwrap_err(),
        InputError::NotUtf8
    );

    let mut record = text_record(&[0xc3]);
    record.event.value = 1;
    assert_eq!(record.check().unwrap_err(), InputError::NotUtf8);
}

fn record_bytes_result(record: &InputRecord) -> Result<Vec<u8>, InputError> {
    let mut buf = [0u8; INPUT_RECORD_LEN];
    record.encode(&mut buf)?;
    Ok(buf.to_vec())
}

#[test]
fn text_bad_lengths_rejected() {
    for value in [0i32, -1, 17] {
        let mut record = text_record(b"x");
        record.event.value = value;
        assert_eq!(record.check().unwrap_err(), InputError::BadValue);
        assert_eq!(record_bytes_result(&record).unwrap_err(), InputError::BadValue);
    }
}

#[test]
fn text_nonzero_padding_rejected() {
    let mut record = text_record(b"AB");
    record.text[2] = 1;
    assert_eq!(record.check().unwrap_err(), InputError::BadValue);

    let mut bytes = record_bytes(&text_record(b"AB"));
    bytes[NORMALIZED_EVENT_LEN + 2] = 1;
    assert_eq!(
        InputRecord::decode(&bytes).unwrap_err(),
        InputError::BadValue
    );
}

#[test]
fn non_text_text_area_rejected() {
    let mut record = key_record(3);
    record.text[0] = 1;
    assert_eq!(record.check().unwrap_err(), InputError::BadValue);
    assert_eq!(record_bytes_result(&record).unwrap_err(), InputError::BadValue);

    let mut bytes = record_bytes(&key_record(3));
    bytes[NORMALIZED_EVENT_LEN] = 1;
    assert_eq!(
        InputRecord::decode(&bytes).unwrap_err(),
        InputError::BadValue
    );
}

#[test]
fn absolute_flag_only_on_motion() {
    for invalid in [
        event(INPUT_EVENT_KEY, 0, 0, INPUT_FLAG_ABSOLUTE),
        event(INPUT_EVENT_POINTER_ENTER, 0, 0, INPUT_FLAG_ABSOLUTE),
        event(INPUT_EVENT_TEXT, 0, 1, INPUT_FLAG_ABSOLUTE),
        event(INPUT_EVENT_POINTER_MOTION, 0, 0, 2),
        event(INPUT_EVENT_POINTER_MOTION, 0, 0, 3),
    ] {
        assert_eq!(invalid.check().unwrap_err(), InputError::BadFlags);
    }

    // Records reject the same flag misuse.
    let mut record = key_record(1);
    record.event.flags = INPUT_FLAG_ABSOLUTE;
    assert_eq!(record.check().unwrap_err(), InputError::BadFlags);
}

#[test]
fn motion_value_outside_i16_rejected() {
    for value in [i16::MAX as i32 + 1, i16::MIN as i32 - 1] {
        let motion = event(INPUT_EVENT_POINTER_MOTION, 0, value, 0);
        assert_eq!(motion.check().unwrap_err(), InputError::Overflow);
        let mut buf = [0u8; NORMALIZED_EVENT_LEN];
        assert_eq!(motion.encode(&mut buf).unwrap_err(), InputError::Overflow);
    }
}

#[test]
fn unknown_event_type_rejected() {
    for event_type in [0u16, 10, u16::MAX] {
        assert_eq!(
            event(event_type, 0, 0, 0).check().unwrap_err(),
            InputError::UnknownEvent
        );
    }
}

#[test]
fn batch_rejects_too_many_and_bad_reserved() {
    let mut body = vec![0u8; INPUT_BATCH_FIXED_LEN + INPUT_RECORD_LEN * 17];
    body[0..2].copy_from_slice(&17u16.to_le_bytes());
    assert_eq!(
        InputBatch::decode(&body).unwrap_err(),
        InputError::TooManyRecords
    );

    let mut batch = InputBatch::default();
    batch.count = 17;
    let mut out = vec![0u8; INPUT_BATCH_FIXED_LEN + INPUT_RECORD_LEN * 17];
    assert_eq!(
        batch.encode(&mut out).unwrap_err(),
        InputError::TooManyRecords
    );

    let mut body = vec![0u8; INPUT_BATCH_FIXED_LEN];
    body[2] = 1;
    assert_eq!(
        InputBatch::decode(&body).unwrap_err(),
        InputError::BadValue
    );
}

#[test]
fn subscribe_bad_path_rejected() {
    let empty = Subscribe {
        focus_epoch: 0,
        path: &[],
    };
    assert_eq!(empty.encode(&mut [0u8; 8]).unwrap_err(), InputError::BadValue);

    let too_long = Subscribe {
        focus_epoch: 0,
        path: &[0u8; MAX_SUBSCRIBE_PATH + 1],
    };
    let mut out = [0u8; SUBSCRIBE_FIXED_LEN + MAX_SUBSCRIBE_PATH + 1];
    assert_eq!(too_long.encode(&mut out).unwrap_err(), InputError::PathTooLong);

    // Decoder: path_len 0 and 65, with no bytes after the header.
    let mut header = [0u8; SUBSCRIBE_FIXED_LEN];
    assert_eq!(
        Subscribe::decode(&header).unwrap_err(),
        InputError::BadValue
    );
    header[4..6].copy_from_slice(&65u16.to_le_bytes());
    assert_eq!(
        Subscribe::decode(&header).unwrap_err(),
        InputError::PathTooLong
    );

    // A non-zero reserved word is rejected.
    let mut header = [0u8; SUBSCRIBE_FIXED_LEN];
    header[4..6].copy_from_slice(&1u16.to_le_bytes());
    header[6] = 1;
    assert_eq!(
        Subscribe::decode(&header).unwrap_err(),
        InputError::BadValue
    );
}

#[test]
fn invalid_ack_and_reset_values_rejected() {
    let ack = SubscribeAck { status: 4 };
    assert_eq!(ack.encode(&mut [0u8; 4]).unwrap_err(), InputError::BadValue);
    assert_eq!(
        SubscribeAck::decode(&4u32.to_le_bytes()).unwrap_err(),
        InputError::BadValue
    );

    for reason in [0u32, 3] {
        let reset = Reset {
            focus_epoch: 0,
            reason,
        };
        assert_eq!(
            reset.encode(&mut [0u8; RESET_LEN]).unwrap_err(),
            InputError::BadValue
        );
        let mut bytes = [0u8; RESET_LEN];
        bytes[4..8].copy_from_slice(&reason.to_le_bytes());
        assert_eq!(
            Reset::decode(&bytes).unwrap_err(),
            InputError::BadValue
        );
    }
}

#[test]
fn focus_roundtrip_and_exact_length() {
    for path in [&b"a"[..], &[7u8; MAX_FOCUS_PATH][..]] {
        let focus = Focus {
            focus_epoch: 42,
            path,
        };
        let mut bytes = vec![0u8; FOCUS_FIXED_LEN + path.len()];
        focus.encode(&mut bytes).unwrap();
        assert_eq!(&bytes[4..6], &(path.len() as u16).to_le_bytes()[..]);
        assert_eq!(&bytes[6..8], &[0u8, 0u8]);

        let decoded = Focus::decode(&bytes).unwrap();
        assert_eq!(decoded, focus);

        for prefix in 0..bytes.len() {
            assert_eq!(
                Focus::decode(&bytes[..prefix]).unwrap_err(),
                InputError::Truncated,
                "path len {} prefix {prefix}",
                path.len()
            );
        }
        assert_eq!(
            Focus::decode(&[bytes.as_slice(), &[0u8]].concat()).unwrap_err(),
            InputError::SizeMismatch
        );

        let mut out = vec![0u8; bytes.len() - 1];
        assert_eq!(focus.encode(&mut out).unwrap_err(), InputError::Truncated);
    }
}

#[test]
fn focus_bad_path_rejected() {
    let empty = Focus {
        focus_epoch: 0,
        path: &[],
    };
    assert_eq!(empty.encode(&mut [0u8; 8]).unwrap_err(), InputError::BadValue);

    let too_long = Focus {
        focus_epoch: 0,
        path: &[0u8; MAX_FOCUS_PATH + 1],
    };
    let mut out = [0u8; FOCUS_FIXED_LEN + MAX_FOCUS_PATH + 1];
    assert_eq!(too_long.encode(&mut out).unwrap_err(), InputError::PathTooLong);

    // Decoder: path_len 0 and 65, with no bytes after the header.
    let mut header = [0u8; FOCUS_FIXED_LEN];
    assert_eq!(Focus::decode(&header).unwrap_err(), InputError::BadValue);
    header[4..6].copy_from_slice(&65u16.to_le_bytes());
    assert_eq!(Focus::decode(&header).unwrap_err(), InputError::PathTooLong);

    // A non-zero reserved word is rejected.
    let mut header = [0u8; FOCUS_FIXED_LEN];
    header[4..6].copy_from_slice(&1u16.to_le_bytes());
    header[6] = 1;
    assert_eq!(Focus::decode(&header).unwrap_err(), InputError::BadValue);
}

/// Deterministic LCG: `0..=800` byte buffers for every decoder.
#[test]
fn fuzz_decoders_never_panic() {
    let mut state = 0x1234_5678u32;
    let mut next = || {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        state
    };

    for len in 0..=800usize {
        let mut bytes = vec![0u8; len];
        for byte in bytes.iter_mut() {
            *byte = next() as u8;
        }

        if let Ok(decoded) = NormalizedEvent::decode(&bytes) {
            let mut out = [0u8; NORMALIZED_EVENT_LEN];
            decoded.encode(&mut out).unwrap();
            assert_eq!(&out[..], &bytes[..]);
        } else {
            assert_well_formed(NormalizedEvent::decode(&bytes).unwrap_err());
        }

        if let Ok(decoded) = InputRecord::decode(&bytes) {
            let mut out = [0u8; INPUT_RECORD_LEN];
            decoded.encode(&mut out).unwrap();
            assert_eq!(&out[..], &bytes[..]);
        } else {
            assert_well_formed(InputRecord::decode(&bytes).unwrap_err());
        }

        if let Ok(decoded) = InputBatch::decode(&bytes) {
            let mut out = vec![0u8; bytes.len()];
            assert_eq!(decoded.encode(&mut out).unwrap(), bytes.len());
            assert_eq!(out, bytes);
        } else {
            assert_well_formed(InputBatch::decode(&bytes).unwrap_err());
        }

        if let Ok(decoded) = Subscribe::decode(&bytes) {
            let mut out = vec![0u8; bytes.len()];
            decoded.encode(&mut out).unwrap();
            assert_eq!(out, bytes);
        } else {
            assert_well_formed(Subscribe::decode(&bytes).unwrap_err());
        }

        if let Ok(decoded) = SubscribeAck::decode(&bytes) {
            let mut out = [0u8; SUBSCRIBE_ACK_LEN];
            decoded.encode(&mut out).unwrap();
            assert_eq!(&out[..], &bytes[..]);
        } else {
            assert_well_formed(SubscribeAck::decode(&bytes).unwrap_err());
        }

        if let Ok(decoded) = Reset::decode(&bytes) {
            let mut out = [0u8; RESET_LEN];
            decoded.encode(&mut out).unwrap();
            assert_eq!(&out[..], &bytes[..]);
        } else {
            assert_well_formed(Reset::decode(&bytes).unwrap_err());
        }

        if let Ok(decoded) = Focus::decode(&bytes) {
            let mut out = vec![0u8; bytes.len()];
            decoded.encode(&mut out).unwrap();
            assert_eq!(out, bytes);
        } else {
            assert_well_formed(Focus::decode(&bytes).unwrap_err());
        }
    }
}

#[test]
fn debug_redaction_never_prints_text() {
    let record = text_record(b"SUPERSECRETTEXT!");
    let rendered = std::format!("{record:?}");
    assert!(!rendered.contains("SUPER"));
    assert!(!rendered.contains("SECRET"));
    assert!(rendered.contains("text_len: 16"));

    let mut batch = InputBatch {
        count: 1,
        reserved: 0,
        focus_epoch: 9,
        records: [InputRecord::default(); MAX_INPUT_RECORDS],
    };
    batch.records[0] = record;
    let rendered = std::format!("{batch:?}");
    assert!(!rendered.contains("SUPER"));
    assert!(!rendered.contains("SECRET"));
    assert!(rendered.contains("count: 1"));

    let rendered = std::format!("{:?}", record.event);
    assert!(!rendered.contains("SUPER"));
    // Keycode, value, timestamp and sequence must not be printed either.
    let mut secret = record.event;
    secret.code = 0xDEAD;
    secret.value = 0x1234_5678;
    secret.timestamp_ns = 0xAAAA_BBBB_CCCC_DDDD;
    secret.sequence = 0x1111_2222_3333_4444;
    let rendered = std::format!("{secret:?}");
    assert!(!rendered.contains("dead"));
    assert!(!rendered.contains("12345678"));
    assert!(!rendered.contains("aaaa"));
    assert!(!rendered.contains("1111"));
}
