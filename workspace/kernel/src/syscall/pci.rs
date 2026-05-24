//! PCI syscall handlers.
//!
//! Provides userspace PCI enumeration and configuration space access.

use super::error::SyscallError;
use crate::{
    arch::x86_64::pci,
    memory::{UserSliceRead, UserSliceWrite},
};

/// PCI match flags for probe criteria.
const PCI_MATCH_VENDOR_ID: u32 = 1 << 0;
const PCI_MATCH_DEVICE_ID: u32 = 1 << 1;
const PCI_MATCH_CLASS_CODE: u32 = 1 << 2;
const PCI_MATCH_SUBCLASS: u32 = 1 << 3;
const PCI_MATCH_PROG_IF: u32 = 1 << 4;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct PciAddressAbi {
    bus: u8,
    device: u8,
    function: u8,
    _reserved: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct PciDeviceInfoAbi {
    address: PciAddressAbi,
    vendor_id: u16,
    device_id: u16,
    class_code: u8,
    subclass: u8,
    prog_if: u8,
    revision: u8,
    header_type: u8,
    interrupt_line: u8,
    interrupt_pin: u8,
    _reserved: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct PciProbeCriteriaAbi {
    match_flags: u32,
    vendor_id: u16,
    device_id: u16,
    class_code: u8,
    subclass: u8,
    prog_if: u8,
    _reserved: [u8; 5],
}

fn read_pci_address(addr_ptr: u64) -> Result<pci::PciAddress, SyscallError> {
    if addr_ptr == 0 {
        return Err(SyscallError::Fault);
    }
    let user = UserSliceRead::new(addr_ptr, core::mem::size_of::<PciAddressAbi>())?;
    let mut raw = [0u8; core::mem::size_of::<PciAddressAbi>()];
    user.copy_to(&mut raw);
    let abi = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const PciAddressAbi) };
    if abi.device > 31 || abi.function > 7 {
        return Err(SyscallError::InvalidArgument);
    }
    Ok(pci::PciAddress::new(abi.bus, abi.device, abi.function))
}

/// SYS_PCI_ENUM: enumerate PCI devices matching a probe criteria.
pub fn sys_pci_enum(
    criteria_ptr: u64,
    out_ptr: u64,
    max_entries: u64,
) -> Result<u64, SyscallError> {
    if criteria_ptr == 0 || out_ptr == 0 {
        return Err(SyscallError::Fault);
    }
    if max_entries == 0 {
        return Ok(0);
    }
    let max_entries = core::cmp::min(max_entries as usize, 4096);
    let user_criteria =
        UserSliceRead::new(criteria_ptr, core::mem::size_of::<PciProbeCriteriaAbi>())?;
    let mut criteria_bytes = [0u8; core::mem::size_of::<PciProbeCriteriaAbi>()];
    user_criteria.copy_to(&mut criteria_bytes);
    let criteria_abi =
        unsafe { core::ptr::read_unaligned(criteria_bytes.as_ptr() as *const PciProbeCriteriaAbi) };

    let criteria = pci::ProbeCriteria {
        vendor_id: if (criteria_abi.match_flags & PCI_MATCH_VENDOR_ID) != 0 {
            Some(criteria_abi.vendor_id)
        } else {
            None
        },
        device_id: if (criteria_abi.match_flags & PCI_MATCH_DEVICE_ID) != 0 {
            Some(criteria_abi.device_id)
        } else {
            None
        },
        class_code: if (criteria_abi.match_flags & PCI_MATCH_CLASS_CODE) != 0 {
            Some(criteria_abi.class_code)
        } else {
            None
        },
        subclass: if (criteria_abi.match_flags & PCI_MATCH_SUBCLASS) != 0 {
            Some(criteria_abi.subclass)
        } else {
            None
        },
        prog_if: if (criteria_abi.match_flags & PCI_MATCH_PROG_IF) != 0 {
            Some(criteria_abi.prog_if)
        } else {
            None
        },
    };

    let devices = pci::probe_all(criteria);
    let count = core::cmp::min(devices.len(), max_entries);
    let mut out = alloc::vec::Vec::<PciDeviceInfoAbi>::with_capacity(count);
    for dev in devices.into_iter().take(count) {
        out.push(PciDeviceInfoAbi {
            address: PciAddressAbi {
                bus: dev.address.bus,
                device: dev.address.device,
                function: dev.address.function,
                _reserved: 0,
            },
            vendor_id: dev.vendor_id,
            device_id: dev.device_id,
            class_code: dev.class_code,
            subclass: dev.subclass,
            prog_if: dev.prog_if,
            revision: dev.revision,
            header_type: dev.header_type,
            interrupt_line: dev.interrupt_line,
            interrupt_pin: dev.interrupt_pin,
            _reserved: 0,
        });
    }
    let out_bytes_len = out
        .len()
        .checked_mul(core::mem::size_of::<PciDeviceInfoAbi>())
        .ok_or(SyscallError::InvalidArgument)?;
    let user_out = UserSliceWrite::new(out_ptr, out_bytes_len)?;
    let out_bytes =
        unsafe { core::slice::from_raw_parts(out.as_ptr() as *const u8, out_bytes_len) };
    user_out.copy_from(out_bytes);
    Ok(out.len() as u64)
}

/// SYS_PCI_CFG_READ: read from PCI configuration space.
pub fn sys_pci_cfg_read(addr_ptr: u64, offset: u64, width: u64) -> Result<u64, SyscallError> {
    let dev_addr = read_pci_address(addr_ptr)?;
    let off = u8::try_from(offset).map_err(|_| SyscallError::InvalidArgument)?;
    let w = u8::try_from(width).map_err(|_| SyscallError::InvalidArgument)?;
    if !matches!(w, 1 | 2 | 4) {
        return Err(SyscallError::InvalidArgument);
    }
    if off > 0xFC || (off as u16 + w as u16) > 0x100 {
        return Err(SyscallError::InvalidArgument);
    }
    if (w == 2 && (off & 1) != 0) || (w == 4 && (off & 3) != 0) {
        return Err(SyscallError::InvalidArgument);
    }
    let dev = pci::all_devices()
        .into_iter()
        .find(|d| d.address == dev_addr)
        .ok_or(SyscallError::NotFound)?;
    let value = match w {
        1 => dev.read_config_u8(off) as u32,
        2 => dev.read_config_u16(off) as u32,
        _ => dev.read_config_u32(off),
    };
    Ok(value as u64)
}

/// SYS_PCI_CFG_WRITE: write to PCI configuration space.
pub fn sys_pci_cfg_write(
    addr_ptr: u64,
    offset: u64,
    width: u64,
    value: u64,
) -> Result<u64, SyscallError> {
    let dev_addr = read_pci_address(addr_ptr)?;
    let off = u8::try_from(offset).map_err(|_| SyscallError::InvalidArgument)?;
    let w = u8::try_from(width).map_err(|_| SyscallError::InvalidArgument)?;
    if !matches!(w, 1 | 2 | 4) {
        return Err(SyscallError::InvalidArgument);
    }
    if off > 0xFC || (off as u16 + w as u16) > 0x100 {
        return Err(SyscallError::InvalidArgument);
    }
    if (w == 2 && (off & 1) != 0) || (w == 4 && (off & 3) != 0) {
        return Err(SyscallError::InvalidArgument);
    }
    let dev = pci::all_devices()
        .into_iter()
        .find(|d| d.address == dev_addr)
        .ok_or(SyscallError::NotFound)?;
    match w {
        1 => dev.write_config_u8(off, value as u8),
        2 => dev.write_config_u16(off, value as u16),
        _ => dev.write_config_u32(off, value as u32),
    }
    Ok(0)
}
