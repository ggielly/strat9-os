//! Attribute Protocol (ATT) server: opcode dispatch over a caller supplied
//! output buffer.  No dynamic allocation.

pub const ATT_ERROR_RSP: u8 = 0x01;
pub const ATT_EXCHANGE_MTU_REQ: u8 = 0x02;
pub const ATT_EXCHANGE_MTU_RSP: u8 = 0x03;
pub const ATT_FIND_INFORMATION_REQ: u8 = 0x04;
pub const ATT_FIND_INFORMATION_RSP: u8 = 0x05;
pub const ATT_READ_BY_TYPE_REQ: u8 = 0x08;
pub const ATT_READ_BY_TYPE_RSP: u8 = 0x09;
pub const ATT_READ_REQ: u8 = 0x0A;
pub const ATT_READ_RSP: u8 = 0x0B;
pub const ATT_READ_BLOB_REQ: u8 = 0x0C;
pub const ATT_READ_BLOB_RSP: u8 = 0x0D;
pub const ATT_READ_BY_GROUP_TYPE_REQ: u8 = 0x10;
pub const ATT_READ_BY_GROUP_TYPE_RSP: u8 = 0x11;
pub const ATT_WRITE_REQ: u8 = 0x12;
pub const ATT_WRITE_RSP: u8 = 0x13;
pub const ATT_HANDLE_VALUE_NTF: u8 = 0x1B;
pub const ATT_HANDLE_VALUE_IND: u8 = 0x1D;
pub const ATT_WRITE_CMD: u8 = 0x52;

pub const ERR_INVALID_HANDLE: u8 = 0x01;
pub const ERR_READ_NOT_PERMITTED: u8 = 0x02;
pub const ERR_WRITE_NOT_PERMITTED: u8 = 0x03;
pub const ERR_INVALID_PDU: u8 = 0x04;
pub const ERR_INSUFFICIENT_AUTH: u8 = 0x05;
pub const ERR_REQUEST_NOT_SUPPORTED: u8 = 0x06;
pub const ERR_INVALID_OFFSET: u8 = 0x07;
pub const ERR_ATTRIBUTE_NOT_FOUND: u8 = 0x0A;
pub const ERR_INSUFFICIENT_RESOURCES: u8 = 0x11;

/// A GATT attribute table used by `handle_request`.
///
/// `read_by_type` and `read_group` write a consecutive list of entries with a
/// uniform length and return `(entry_len, bytes_written)`.  Each entry starts
/// with the little-endian attribute handle.
pub trait AttServer {
    fn read(&self, handle: u16, offset: usize, out: &mut [u8]) -> Option<usize>;

    fn read_by_type(
        &self,
        start: u16,
        end: u16,
        uuid: &[u8],
        out: &mut [u8],
    ) -> Option<(usize, usize)>;

    fn read_group(
        &self,
        start: u16,
        end: u16,
        uuid: &[u8],
        out: &mut [u8],
    ) -> Option<(usize, usize)>;

    fn write(&mut self, handle: u16, data: &[u8]) -> Result<(), u8>;

    fn notify_handle(&self) -> u16;

    fn cccd_enabled(&self) -> bool;

    fn mtu(&self) -> u16 {
        23
    }

    fn set_mtu(&mut self, _mtu: u16) {}

    fn handle_exists(&self, _handle: u16) -> bool {
        true
    }

    fn find_info(&self, _start: u16, _end: u16, _out: &mut [u8]) -> Option<usize> {
        None
    }
}

fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn error_response(
    out: &mut [u8],
    request_opcode: u8,
    handle: u16,
    code: u8,
) -> Option<usize> {
    if out.len() < 5 {
        return None;
    }
    out[0] = ATT_ERROR_RSP;
    out[1] = request_opcode;
    out[2..4].copy_from_slice(&handle.to_le_bytes());
    out[4] = code;
    Some(5)
}

/// Build a Handle Value Notification in `out`.
pub fn build_notification(handle: u16, value: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = 3 + value.len();
    if out.len() < n {
        return None;
    }
    out[0] = ATT_HANDLE_VALUE_NTF;
    out[1..3].copy_from_slice(&handle.to_le_bytes());
    out[3..n].copy_from_slice(value);
    Some(n)
}

impl<S: AttServer + ?Sized> AttServerDispatch for S {}

/// Dispatch extension trait so `handle_request` can be implemented for any
/// `AttServer` without adding it to the trait itself.
pub trait AttServerDispatch: AttServer {
    fn handle_request(&mut self, req: &[u8], out: &mut [u8]) -> Option<usize> {
        if req.is_empty() {
            return None;
        }
        let opcode = req[0];
        match opcode {
            ATT_EXCHANGE_MTU_REQ => {
                if req.len() != 3 {
                    return error_response(out, opcode, 0, ERR_INVALID_PDU);
                }
                let client = le16(req, 1).max(23);
                self.set_mtu(client);
                if out.len() < 3 {
                    return None;
                }
                out[0] = ATT_EXCHANGE_MTU_RSP;
                out[1..3].copy_from_slice(&self.mtu().to_le_bytes());
                Some(3)
            }
            ATT_FIND_INFORMATION_REQ => {
                if req.len() != 5 {
                    return error_response(out, opcode, 0, ERR_INVALID_PDU);
                }
                let start = le16(req, 1);
                let end = le16(req, 3);
                if out.len() < 2 {
                    return None;
                }
                match self.find_info(start, end, &mut out[2..]) {
                    Some(n) => {
                        out[0] = ATT_FIND_INFORMATION_RSP;
                        out[1] = 0x01; // format: 16-bit UUIDs
                        Some(2 + n)
                    }
                    None => error_response(out, opcode, start, ERR_ATTRIBUTE_NOT_FOUND),
                }
            }
            ATT_READ_BY_TYPE_REQ => {
                if req.len() < 7 {
                    return error_response(out, opcode, 0, ERR_INVALID_PDU);
                }
                let start = le16(req, 1);
                let end = le16(req, 3);
                let uuid = &req[5..];
                if uuid.len() != 2 && uuid.len() != 16 {
                    return error_response(out, opcode, start, ERR_REQUEST_NOT_SUPPORTED);
                }
                if out.len() < 2 {
                    return None;
                }
                match self.read_by_type(start, end, uuid, &mut out[2..]) {
                    Some((entry_len, total)) => {
                        if entry_len == 0 || entry_len > u8::MAX as usize {
                            return error_response(
                                out,
                                opcode,
                                start,
                                ERR_INSUFFICIENT_RESOURCES,
                            );
                        }
                        out[0] = ATT_READ_BY_TYPE_RSP;
                        out[1] = entry_len as u8;
                        Some(2 + total)
                    }
                    None => error_response(out, opcode, start, ERR_ATTRIBUTE_NOT_FOUND),
                }
            }
            ATT_READ_REQ => {
                if req.len() != 3 {
                    return error_response(out, opcode, 0, ERR_INVALID_PDU);
                }
                let handle = le16(req, 1);
                if !self.handle_exists(handle) {
                    return error_response(out, opcode, handle, ERR_INVALID_HANDLE);
                }
                if out.len() < 1 {
                    return None;
                }
                match self.read(handle, 0, &mut out[1..]) {
                    Some(n) => {
                        out[0] = ATT_READ_RSP;
                        Some(1 + n)
                    }
                    None => error_response(out, opcode, handle, ERR_READ_NOT_PERMITTED),
                }
            }
            ATT_READ_BLOB_REQ => {
                if req.len() != 5 {
                    return error_response(out, opcode, 0, ERR_INVALID_PDU);
                }
                let handle = le16(req, 1);
                let offset = le16(req, 3) as usize;
                if !self.handle_exists(handle) {
                    return error_response(out, opcode, handle, ERR_INVALID_HANDLE);
                }
                if out.len() < 1 {
                    return None;
                }
                match self.read(handle, offset, &mut out[1..]) {
                    Some(n) => {
                        out[0] = ATT_READ_BLOB_RSP;
                        Some(1 + n)
                    }
                    None => error_response(out, opcode, handle, ERR_INVALID_OFFSET),
                }
            }
            ATT_READ_BY_GROUP_TYPE_REQ => {
                if req.len() < 7 {
                    return error_response(out, opcode, 0, ERR_INVALID_PDU);
                }
                let start = le16(req, 1);
                let end = le16(req, 3);
                let uuid = &req[5..];
                if uuid.len() != 2 && uuid.len() != 16 {
                    return error_response(out, opcode, start, ERR_REQUEST_NOT_SUPPORTED);
                }
                if out.len() < 2 {
                    return None;
                }
                match self.read_group(start, end, uuid, &mut out[2..]) {
                    Some((entry_len, total)) => {
                        if entry_len == 0 || entry_len > u8::MAX as usize {
                            return error_response(
                                out,
                                opcode,
                                start,
                                ERR_INSUFFICIENT_RESOURCES,
                            );
                        }
                        out[0] = ATT_READ_BY_GROUP_TYPE_RSP;
                        out[1] = entry_len as u8;
                        Some(2 + total)
                    }
                    None => error_response(out, opcode, start, ERR_ATTRIBUTE_NOT_FOUND),
                }
            }
            ATT_WRITE_REQ => {
                if req.len() < 3 {
                    return error_response(out, opcode, 0, ERR_INVALID_PDU);
                }
                let handle = le16(req, 1);
                match self.write(handle, &req[3..]) {
                    Ok(()) => {
                        if out.len() < 1 {
                            return None;
                        }
                        out[0] = ATT_WRITE_RSP;
                        Some(1)
                    }
                    Err(code) => error_response(out, opcode, handle, code),
                }
            }
            ATT_WRITE_CMD => {
                if req.len() >= 3 {
                    let handle = le16(req, 1);
                    // A command never generates a response, even on error.
                    let _ = self.write(handle, &req[3..]);
                }
                None
            }
            _ => error_response(out, opcode, 0, ERR_REQUEST_NOT_SUPPORTED),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gatt::{self, NUS_RX_UUID, NUS_SERVICE_UUID, NUS_TX_UUID};

    #[test]
    fn windows_discovery_flow() {
        let mut s = gatt::GattServer::new();
        let mut out = [0u8; 128];

        // 1. Exchange MTU: client asks 247, server answers 247.
        let n = s.handle_request(&[0x02, 0xF7, 0x00], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x03, 0xF7, 0x00]);
        assert_eq!(s.mtu(), 247);

        // 2. Discover primary services.
        let n = s
            .handle_request(&[0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28], &mut out)
            .unwrap();
        assert_eq!(
            &out[..n],
            &[0x11, 0x06, 0x01, 0x00, 0x05, 0x00, 0x00, 0x18]
        );

        let n = s
            .handle_request(&[0x10, 0x06, 0x00, 0xFF, 0xFF, 0x00, 0x28], &mut out)
            .unwrap();
        let mut expect = [0u8; 22];
        expect[0] = 0x11;
        expect[1] = 0x14;
        expect[2..4].copy_from_slice(&6u16.to_le_bytes());
        expect[4..6].copy_from_slice(&11u16.to_le_bytes());
        expect[6..22].copy_from_slice(&NUS_SERVICE_UUID);
        assert_eq!(&out[..n], &expect);

        // 3. Read all characteristic declarations in the NUS range.
        let n = s
            .handle_request(&[0x08, 0x07, 0x00, 0x0B, 0x00, 0x03, 0x28], &mut out)
            .unwrap();
        assert_eq!(out[0], 0x09);
        assert_eq!(out[1], 21);
        assert_eq!(&out[2..4], &7u16.to_le_bytes());
        assert_eq!(&out[4..6], &[0x10, 0x08]);
        assert_eq!(&out[6], &0x00);
        assert_eq!(&out[7..23], &NUS_TX_UUID);
        assert_eq!(&out[23..25], &10u16.to_le_bytes());
        assert_eq!(&out[25..27], &[0x0C, 0x0B]);
        assert_eq!(&out[27], &0x00);
        assert_eq!(&out[28..44], &NUS_RX_UUID);
        assert_eq!(n, 2 + 21 * 2);

        // 4. Read Device Name by type.
        let n = s
            .handle_request(&[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x2A], &mut out)
            .unwrap();
        assert_eq!(&out[..n], &[0x09, 0x09, 0x03, 0x00, b'S', b'9', b'-', b'D', b'U', b'M', b'P']);

        // 5. Enable notifications through the TX CCCD.
        let n = s.handle_request(&[0x12, 0x09, 0x00, 0x01, 0x00], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x13]);
        assert!(s.cccd_enabled());
        assert_eq!(s.notify_handle(), 8);
    }

    #[test]
    fn find_information_and_reads() {
        let mut s = gatt::GattServer::new();
        let mut out = [0u8; 128];

        let n = s
            .handle_request(&[0x04, 0x01, 0x00, 0x03, 0x00], &mut out)
            .unwrap();
        assert_eq!(out[0], 0x05);
        assert_eq!(out[1], 0x01);
        assert_eq!(&out[2..6], &[0x01, 0x00, 0x00, 0x28]);
        assert_eq!(&out[6..10], &[0x02, 0x00, 0x03, 0x28]);
        assert_eq!(&out[10..14], &[0x03, 0x00, 0x00, 0x2A]);
        assert_eq!(n, 2 + 4 * 3);

        let n = s.handle_request(&[0x0A, 0x03, 0x00], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x0B, b'S', b'9', b'-', b'D', b'U', b'M', b'P']);

        // Read Blob with an offset into the device name.
        let n = s.handle_request(&[0x0C, 0x03, 0x00, 0x03, 0x00], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x0D, b'D', b'U', b'M', b'P']);

        // Offset past the end -> Invalid Offset.
        let n = s.handle_request(&[0x0C, 0x03, 0x00, 0x40, 0x00], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x01, 0x0C, 0x03, 0x00, ERR_INVALID_OFFSET]);

        let n = s.handle_request(&[0x0A, 0xFE, 0x00], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x01, 0x0A, 0xFE, 0x00, ERR_INVALID_HANDLE]);
    }

    #[test]
    fn write_reads_back_and_commands_are_silent() {
        let mut s = gatt::GattServer::new();
        let mut out = [0u8; 64];

        let n = s.handle_request(&[0x12, 0x0B, 0x00, b'h', b'i'], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x13]);

        let n = s.handle_request(&[0x0A, 0x0B, 0x00], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x0B, b'h', b'i']);

        assert_eq!(
            s.handle_request(&[0x52, 0x0B, 0x00, b'x'], &mut out),
            None
        );
        let n = s.handle_request(&[0x0A, 0x0B, 0x00], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x0B, b'x']);
    }

    #[test]
    fn error_responses() {
        let mut s = gatt::GattServer::new();
        let mut out = [0u8; 64];

        let n = s.handle_request(&[0x12, 0x08, 0x00, 0x01], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x01, 0x12, 0x08, 0x00, ERR_WRITE_NOT_PERMITTED]);

        let n = s.handle_request(&[0x12, 0xFF, 0x00, 0x01], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x01, 0x12, 0xFF, 0x00, ERR_INVALID_HANDLE]);

        let n = s.handle_request(&[0x99], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x01, 0x99, 0x00, 0x00, ERR_REQUEST_NOT_SUPPORTED]);

        // Unknown UUID in a type read.
        let n = s
            .handle_request(&[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x34, 0x12], &mut out)
            .unwrap();
        assert_eq!(
            &out[..n],
            &[0x01, 0x08, 0x01, 0x00, ERR_ATTRIBUTE_NOT_FOUND]
        );
    }

    #[test]
    fn notification_builder() {
        let mut out = [0u8; 32];
        let n = build_notification(0x0008, &[0xD2, 1, 0, 0, 0], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x1B, 0x08, 0x00, 0xD2, 1, 0, 0, 0]);
        assert!(build_notification(1, &[0u8; 40], &mut out[..10]).is_none());
    }
}
