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

//! L2: contract between the bare-metal guest virtio drivers and the kernel
//! device models.
//!
//! The guest drivers are generic over `virtio::Transport`; this binary
//! implements that trait on top of the kernel device models and runs **the
//! exact driver code the guest executes on hardware**. A mismatch between the
//! guest handshake/queue programming/descriptor chain and the engine model is
//! therefore caught on the host, without a VT-x machine: the hardware path
//! really is `guest driver -> replayed MMIO -> same model`.
//!
//! The guest drivers keep their queue tables in `static mut` buffers, so all
//! the checks run from a single test function (no parallel access).

extern crate alloc;

mod kernel {
    #[path = "../../../kernel/src/s9vm/virtio.rs"]
    pub mod virtio;
    #[path = "../../../kernel/src/s9vm/virtio_blk.rs"]
    pub mod virtio_blk;
    #[path = "../../../kernel/src/s9vm/virtio_console.rs"]
    pub mod virtio_console;
    #[path = "../../../kernel/src/s9vm/virtio_net.rs"]
    pub mod virtio_net;
}

#[path = "../../guest/s9vm-guest/src/virtio.rs"]
mod virtio;
#[path = "../../guest/s9vm-guest/src/virtio_blk.rs"]
mod virtio_blk;
#[path = "../../guest/s9vm-guest/src/virtio_console.rs"]
mod virtio_console;
#[path = "../../guest/s9vm-guest/src/virtio_net.rs"]
mod virtio_net;

use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;

use kernel::virtio::QueueMemory;
use virtio::Transport;

/// Guest address space as seen by the device model.
///
/// The guest drivers publish the addresses of their own `.bss` buffers as
/// guest-physical addresses. In this host binary those are ordinary process
/// addresses and there is no translation, so the model can read and write them
/// directly.
struct GuestMemory;

impl QueueMemory for GuestMemory {
    fn read_gpa(&mut self, gpa: u64, out: &mut [u8]) -> bool {
        // SAFETY: the address was published by the guest driver for a buffer
        // it owns; the destination is a live slice of `out.len()` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(gpa as *const u8, out.as_mut_ptr(), out.len());
        }
        true
    }

    fn write_gpa(&mut self, gpa: u64, bytes: &[u8]) -> bool {
        // SAFETY: same contract as `read_gpa`.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), gpa as *mut u8, bytes.len());
        }
        true
    }
}

/// Transport over the kernel virtio-console model.
struct ConsoleTransport {
    device: Rc<RefCell<kernel::virtio_console::VirtioConsole>>,
}

impl Transport for ConsoleTransport {
    fn read(&self, offset: u64) -> u32 {
        self.device.borrow().read(offset as u32)
    }

    fn write(&self, offset: u64, value: u32) {
        self.device
            .borrow_mut()
            .write(offset as u32, value, &mut GuestMemory);
    }
}

/// Transport over the kernel virtio-block model.
struct BlockTransport {
    device: Rc<RefCell<kernel::virtio_blk::VirtioBlk>>,
}

impl Transport for BlockTransport {
    fn read(&self, offset: u64) -> u32 {
        self.device.borrow().read(offset as u32)
    }

    fn write(&self, offset: u64, value: u32) {
        self.device
            .borrow_mut()
            .write(offset as u32, value, &mut GuestMemory);
    }
}

/// Transport over the kernel virtio-net model.
struct NetworkTransport {
    device: Rc<RefCell<kernel::virtio_net::VirtioNet>>,
}

impl Transport for NetworkTransport {
    fn read(&self, offset: u64) -> u32 {
        self.device.borrow().read(offset as u32)
    }

    fn write(&self, offset: u64, value: u32) {
        self.device
            .borrow_mut()
            .write(offset as u32, value, &mut GuestMemory);
    }
}

/// One labelled sector, the way the policy provisions the boot disk.
fn disk_sector() -> [u8; 512] {
    let mut sector = [0u8; 512];
    sector[..8].copy_from_slice(b"S9VMDISK");
    sector
}

#[test]
fn guest_drivers_speak_the_engine_device_protocol() {
    // --- virtio-console: two messages through one transmit queue ----------
    let console_device = Rc::new(RefCell::new(kernel::virtio_console::VirtioConsole::new()));
    let console = ConsoleTransport {
        device: Rc::clone(&console_device),
    };
    let mut driver = virtio_console::Console::init_with(console)
        .expect("console handshake must complete against the engine model");
    let greeting = b"s9vm-guest: virtio-console online\n";
    let summary = b"acpi: XSDT 2 tables madt=1 facp=1\n";
    driver
        .send(greeting)
        .expect("first console message must be consumed");
    driver
        .send(summary)
        .expect("second console message must be consumed");
    let mut expected = Vec::new();
    expected.extend_from_slice(greeting);
    expected.extend_from_slice(summary);
    assert_eq!(
        console_device.borrow_mut().drain_output(),
        expected,
        "the engine model must receive exactly the bytes the guest sent"
    );

    // --- virtio-block: read sector 0 and match the label ------------------
    let mut block = kernel::virtio_blk::VirtioBlk::new(4096);
    assert!(block.write_sector(0, &disk_sector()));
    let block_device = Rc::new(RefCell::new(block));
    let block = BlockTransport {
        device: Rc::clone(&block_device),
    };
    assert_eq!(
        virtio_blk::read_disk_label_with(block),
        Ok(()),
        "the guest block driver must complete its request against the model"
    );

    // A device that is not a block device is named by the diagnostic code.
    let console_for_block = ConsoleTransport {
        device: Rc::new(RefCell::new(kernel::virtio_console::VirtioConsole::new())),
    };
    assert_eq!(
        virtio_blk::read_disk_label_with(console_for_block),
        Err(virtio_blk::failure::DEVICE_ID),
        "the guest driver must reject a non-block device by identity"
    );

    // A device whose sector 0 carries no label: the request completes but the
    // data does not match, which is the `d` code 7 path.
    let unlabelled = BlockTransport {
        device: Rc::new(RefCell::new(kernel::virtio_blk::VirtioBlk::new(4096))),
    };
    assert_eq!(
        virtio_blk::read_disk_label_with(unlabelled),
        Err(virtio_blk::failure::LABEL),
        "an unlabelled sector must be reported as a label mismatch"
    );

    // --- virtio-net: one frame through the transmit queue -----------------
    let net_device = Rc::new(RefCell::new(kernel::virtio_net::VirtioNet::new()));
    let net = NetworkTransport {
        device: Rc::clone(&net_device),
    };
    assert_eq!(
        virtio_net::transmit_with(net),
        Ok(()),
        "the guest network driver must complete its frame against the model"
    );
    assert_eq!(
        net_device.borrow().frames_sent(),
        1,
        "the model must record exactly one transmitted frame"
    );
}
