use core::{mem, ptr};
use fs_abstraction::{BlockDevice, FsError};

use super::{DISK_ADDRESS_PACKET_ADDR, DISK_BIOS_ADDR, ThunkData};

const SECTOR_SIZE: u64 = 512;
const BLOCK_SIZE: u64 = 4096; // Standard block size (4KB)
const BLOCKS_PER_SECTOR: u64 = BLOCK_SIZE / SECTOR_SIZE;
// 128 sectors is the amount allocated for DISK_BIOS_ADDR
// 127 sectors is the maximum for many BIOSes
const MAX_SECTORS: u64 = 127;
const MAX_BLOCKS: u64 = MAX_SECTORS * SECTOR_SIZE / BLOCK_SIZE;

#[allow(dead_code)]
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct DiskAddressPacket {
    size: u8,
    reserved: u8,
    sectors: u16,
    buffer: u16,
    segment: u16,
    address: u64,
}

impl DiskAddressPacket {
    pub fn from_block(block: u64, count: u64) -> DiskAddressPacket {
        let address = block * BLOCKS_PER_SECTOR;
        let sectors = count * BLOCKS_PER_SECTOR;
        assert!(sectors <= MAX_SECTORS);
        DiskAddressPacket {
            size: mem::size_of::<DiskAddressPacket>() as u8,
            reserved: 0,
            sectors: sectors as u16,
            buffer: (DISK_BIOS_ADDR & 0xF) as u16,
            segment: (DISK_BIOS_ADDR >> 4) as u16,
            address,
        }
    }
}

pub struct DiskBios {
    boot_disk: u8,
    thunk13: extern "C" fn(),
    chs_opt: Option<(u32, u32, u32)>,
}

impl DiskBios {
    pub fn new(boot_disk: u8, thunk13: extern "C" fn()) -> Self {
        let chs_opt = unsafe {
            let mut data = ThunkData::new();
            data.eax = 0x4100;
            data.ebx = 0x55AA;
            data.edx = boot_disk as u32;

            data.with(thunk13);

            if (data.ebx & 0xFFFF) == 0xAA55 {
                // Extensions are installed, do not use CHS
                None
            } else {
                // Extensions are not installed, get CHS geometry
                data = ThunkData::new();
                data.eax = 0x0800;
                data.edx = boot_disk as u32;
                data.edi = 0;

                data.with(thunk13);

                //TODO: return result on error
                let ah = ({ data.eax } >> 8) & 0xFF;
                assert_eq!(ah, 0);

                let c = (data.ecx >> 8) & 0xFF | ((data.ecx >> 6) & 0x3) << 8;
                let h = ((data.edx >> 8) & 0xFF) + 1;
                let s = data.ecx & 0x3F;

                Some((c, h, s))
            }
        };

        Self {
            boot_disk,
            thunk13,
            chs_opt,
        }
    }
}

impl BlockDevice for DiskBios {
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize, FsError> {
        // Convert byte offset to block number
        let block = offset / BLOCK_SIZE;
        unsafe {

            for (i, chunk) in buffer
                .chunks_mut((MAX_BLOCKS * BLOCK_SIZE) as usize)
                .enumerate()
            {
                let dap = DiskAddressPacket::from_block(
                    block + i as u64 * MAX_BLOCKS,
                    chunk.len() as u64 / BLOCK_SIZE,
                );

                if let Some((_, h_max, s_max)) = self.chs_opt {
                    let s = (dap.address % s_max as u64) + 1;
                    assert!(s <= 63, "invalid sector {s}");

                    let tmp = dap.address / s_max as u64;
                    let h = tmp % h_max as u64;
                    assert!(h <= 255, "invalid head {h}");

                    let c = tmp / h_max as u64;
                    assert!(c <= 1023, "invalid cylinder {c}");

                    let mut data = ThunkData::new();
                    data.eax = 0x0200 | (dap.sectors as u32);
                    data.ebx = dap.buffer as u32;
                    data.ecx =
                        (s as u32) | (((c as u32) & 0xFF) << 8) | ((((c as u32) >> 8) & 0x3) << 6);
                    data.edx = (self.boot_disk as u32) | ((h as u32) << 8);
                    data.es = dap.segment;

                    data.with(self.thunk13);

                    //TODO: return result on error
                    let ah = ({ data.eax } >> 8) & 0xFF;
                    assert_eq!(ah, 0);
                } else {
                    ptr::write(DISK_ADDRESS_PACKET_ADDR as *mut DiskAddressPacket, dap);

                    let mut data = ThunkData::new();
                    data.eax = 0x4200;
                    data.edx = self.boot_disk as u32;
                    data.esi = DISK_ADDRESS_PACKET_ADDR as u32;

                    data.with(self.thunk13);

                    //TODO: return result on error
                    let ah = ({ data.eax } >> 8) & 0xFF;
                    assert_eq!(ah, 0);

                    //TODO: check blocks transferred
                    // dap = ptr::read(DISK_ADDRESS_PACKET_ADDR as *mut DiskAddressPacket);
                }

                ptr::copy(DISK_BIOS_ADDR as *const u8, chunk.as_mut_ptr(), chunk.len());
            }

            Ok(buffer.len())
        }
    }

    fn write_at(&mut self, offset: u64, buffer: &[u8]) -> Result<usize, FsError> {
        log::error!(
            "DiskBios::write_at(0x{:X}, 0x{:X}:0x{:X}) not allowed",
            offset,
            buffer.as_ptr() as usize,
            buffer.len()
        );
        Err(FsError::ReadOnly)
    }

    fn size(&mut self) -> Result<u64, FsError> {
        // Return a large size for now
        // TODO: Get actual disk size from BIOS
        Ok(u64::MAX)
    }

    fn sector_size(&self) -> usize {
        SECTOR_SIZE as usize
    }
}
