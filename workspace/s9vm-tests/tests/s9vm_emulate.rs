//! L2: in-kernel emulation layer (page walks, device replay).
//!
//! The module under test is pure: physical memory is a byte vector, the
//! vCPU is replaced by an explicit register block. This exercises the exact
//! code the exit handler runs on the target machine.

extern crate alloc;

#[path = "../../kernel/src/s9vm/apic.rs"]
mod apic;
#[path = "../../kernel/src/s9vm/decode.rs"]
mod decode;
#[path = "../../kernel/src/s9vm/emulate.rs"]
mod emulate;
#[path = "../../kernel/src/s9vm/exit.rs"]
mod exit;
#[path = "../../kernel/src/s9vm/ioapic.rs"]
mod ioapic;
#[path = "../../kernel/src/s9vm/pic.rs"]
mod pic;

use emulate::{
    handle_exit, walk_guest, walk_second_level, DevicePage, Devices, GuestContext, MemoryView,
    PhysMemory, IOAPIC_BASE,
};
use exit::ExitClass;

// Physical layout of the synthetic machine (all identity mapped in EPT).
const EPT_PML4: u64 = 0x0000;
const EPT_PDPT: u64 = 0x1000;
const EPT_PD: u64 = 0x2000;
const GUEST_PML4: u64 = 0x4000;
const GUEST_PDPT: u64 = 0x5000;
const GUEST_PD: u64 = 0x6000;
const GUEST_PT: u64 = 0x7000;
const CODE_PAGE: u64 = 0x8000;
const DATA_PAGE: u64 = 0x9000;
const MEMORY_SIZE: usize = 0x20_0000;

const APIC_TPR: u64 = 0xFEE0_0080;
const IOAPIC_SELECT: u64 = 0xFEC0_0000;

/// Physical memory backed by a byte vector.
struct TestMemory {
    bytes: alloc::vec::Vec<u8>,
}

impl TestMemory {
    fn new() -> Self {
        Self {
            bytes: alloc::vec![0u8; MEMORY_SIZE],
        }
    }

    fn write_u64(&mut self, address: u64, value: u64) {
        let offset = address as usize;
        self.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn write_bytes(&mut self, address: u64, bytes: &[u8]) {
        let offset = address as usize;
        self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
}

impl PhysMemory for TestMemory {
    fn read_bytes(&mut self, phys: u64, out: &mut [u8]) -> bool {
        let start = phys as usize;
        let Some(slice) = self.bytes.get(start..start + out.len()) else {
            return false;
        };
        out.copy_from_slice(slice);
        true
    }

    fn write_bytes(&mut self, phys: u64, bytes: &[u8]) -> bool {
        let start = phys as usize;
        let Some(slice) = self.bytes.get_mut(start..start + bytes.len()) else {
            return false;
        };
        slice.copy_from_slice(bytes);
        true
    }
}

/// Explicit guest register block (x86 encoding order).
struct TestGuest {
    regs: [u64; 16],
    rip: u64,
    cr3: u64,
    paging: bool,
}

impl TestGuest {
    fn new(rip: u64) -> Self {
        Self {
            regs: [0; 16],
            rip,
            cr3: GUEST_PML4,
            paging: true,
        }
    }
}

impl GuestContext for TestGuest {
    fn gpr(&self, register: u8) -> u64 {
        self.regs[register as usize]
    }

    fn set_gpr(&mut self, register: u8, value: u64) {
        self.regs[register as usize] = value;
    }

    fn rip(&self) -> u64 {
        self.rip
    }

    fn set_rip(&mut self, rip: u64) {
        self.rip = rip;
    }

    fn cr3(&self) -> u64 {
        self.cr3
    }

    fn paging(&self) -> bool {
        self.paging
    }
}

/// Builds the synthetic machine: 2 MiB EPT page, identity guest page tables.
fn machine() -> TestMemory {
    let mut memory = TestMemory::new();

    // EPT: PML4[0] -> PDPT, PDPT[0] -> PD, PD[0] = 2 MiB page at HPA 0.
    // Bits: read | write | execute | large page.
    memory.write_u64(EPT_PML4, EPT_PDPT | 0x7);
    memory.write_u64(EPT_PDPT, EPT_PD | 0x7);
    memory.write_u64(EPT_PD, 0x0 | 0x7 | 0x80);

    // Guest: identity map the low 64 KiB with 4 KiB pages.
    memory.write_u64(GUEST_PML4, GUEST_PDPT | 0x3);
    memory.write_u64(GUEST_PDPT, GUEST_PD | 0x3);
    memory.write_u64(GUEST_PD, GUEST_PT | 0x3);
    for page in 0..16u64 {
        memory.write_u64(GUEST_PT + page * 8, page * 0x1000 | 0x3);
    }
    memory
}

/// Loads `code` at the start of the code page.
fn load_code(memory: &mut TestMemory, code: &[u8]) -> u64 {
    memory.write_bytes(CODE_PAGE, code);
    CODE_PAGE
}

/// Builds a view on the synthetic machine.
fn view<'a>(memory: &'a mut TestMemory, guest: &TestGuest) -> MemoryView<'a> {
    MemoryView::new(memory, EPT_PML4, guest.cr3, guest.paging)
}

#[test]
fn second_level_walk_translates_through_a_large_page() {
    let mut memory = machine();
    let (hpa, page_size) = walk_second_level(&mut memory, EPT_PML4, 0x1234).expect("mapped");
    assert_eq!(hpa, 0x1234);
    assert_eq!(page_size, 1 << 21);
}

#[test]
fn second_level_walk_rejects_unmapped_address() {
    let mut memory = machine();
    assert!(walk_second_level(&mut memory, EPT_PML4, 0x40_0000).is_none());
}

#[test]
fn second_level_walk_rejects_non_readable_entry() {
    let mut memory = machine();
    // Clear the read bit of the leaf: an EPT walk must refuse the access.
    memory.write_u64(EPT_PD, 0x0 | 0x2 | 0x80);
    assert!(walk_second_level(&mut memory, EPT_PML4, 0x10).is_none());
}

#[test]
fn guest_walk_follows_four_levels() {
    let mut memory = machine();
    assert_eq!(
        walk_guest(&mut memory, EPT_PML4, GUEST_PML4, 0x1234),
        Some(0x1234)
    );
}

#[test]
fn guest_walk_reports_absent_page() {
    let mut memory = machine();
    // Clear the present bit of the last page-table entry.
    memory.write_u64(GUEST_PT + 8 * 4, 0);
    assert!(walk_guest(&mut memory, EPT_PML4, GUEST_PML4, 0x4000).is_none());
}

#[test]
fn guest_walk_accepts_two_megabyte_mapping() {
    let mut memory = machine();
    // Replace the guest PD entry with a 2 MiB page covering 0..2 MiB.
    memory.write_u64(GUEST_PD, 0x0 | 0x3 | 0x80);
    assert_eq!(
        walk_guest(&mut memory, EPT_PML4, GUEST_PML4, 0x1_2345),
        Some(0x1_2345)
    );
}

#[test]
fn memory_view_reads_across_a_page_boundary() {
    let mut memory = machine();
    // Last two bytes of the code page, first two bytes of the data page.
    memory.write_bytes(CODE_PAGE - 2, &[0xAA, 0xBB]);
    memory.write_bytes(CODE_PAGE, &[0x01, 0x02]);
    let guest = TestGuest::new(CODE_PAGE);
    let mut view = view(&mut memory, &guest);
    let mut bytes = [0u8; 4];
    assert!(view.read(CODE_PAGE - 2, &mut bytes));
    assert_eq!(bytes, [0xAA, 0xBB, 0x01, 0x02]);
}

#[test]
fn out_to_pic_data_port_is_emulated() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0xE6, 0x21]);
    let mut guest = TestGuest::new(rip);
    guest.regs[0] = 0xFF;
    let mut devices = Devices::new();
    // OUT: size-1 = 0, direction bit 3 = 0, port in bits 31:16.
    let qualification = u64::from(0x21u16) << 16;
    let mut view = view(&mut memory, &guest);
    let handled = handle_exit(
        &mut devices,
        &mut apic::LocalApic::new(0),
        &mut view,
        &mut guest,
        ExitClass::IoPort,
        qualification,
        0,
    )
    .expect("emulated");
    assert!(handled);
    assert_eq!(devices.pic.master().mask(), 0xFF);
    assert_eq!(guest.rip, rip + 2);
}

#[test]
fn in_from_pic_data_port_returns_the_programmed_mask() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0xE4, 0x21]);
    let mut guest = TestGuest::new(rip);
    guest.regs[0] = 0xFFFF_FFFF_FFFF_0000;
    let mut devices = Devices::new();
    devices.pic.write(pic::port::MASTER_DATA, 0x42);
    // IN: direction bit 3 = 1.
    let qualification = (u64::from(0x21u16) << 16) | 0x8;
    let mut view = view(&mut memory, &guest);
    let handled = handle_exit(
        &mut devices,
        &mut apic::LocalApic::new(0),
        &mut view,
        &mut guest,
        ExitClass::IoPort,
        qualification,
        0,
    )
    .expect("emulated");
    assert!(handled);
    // Only AL is written: the upper bits of RAX are preserved.
    assert_eq!(guest.regs[0], 0xFFFF_FFFF_FFFF_0042);
    assert_eq!(guest.rip, rip + 2);
}

#[test]
fn unmodeled_port_is_left_to_policy() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0xE6, 0xE9]);
    let mut guest = TestGuest::new(rip);
    let mut devices = Devices::new();
    let qualification = u64::from(0xE9u16) << 16;
    let mut view = view(&mut memory, &guest);
    let handled = handle_exit(
        &mut devices,
        &mut apic::LocalApic::new(0),
        &mut view,
        &mut guest,
        ExitClass::IoPort,
        qualification,
        0,
    )
    .expect("no error");
    assert!(!handled);
    assert_eq!(guest.rip, rip);
}

#[test]
fn post_port_discards_writes_and_advances() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0xE6, 0x80]);
    let mut guest = TestGuest::new(rip);
    guest.regs[0] = 0x10;
    let mut devices = Devices::new();
    let qualification = u64::from(0x80u16) << 16;
    let mut view = view(&mut memory, &guest);
    let handled = handle_exit(
        &mut devices,
        &mut apic::LocalApic::new(0),
        &mut view,
        &mut guest,
        ExitClass::IoPort,
        qualification,
        0,
    )
    .expect("emulated");
    assert!(handled);
    assert_eq!(guest.rip, rip + 2);
    assert_eq!(devices.pic.master().mask(), 0xFF);
}

#[test]
fn apic_page_write_is_emulated() {
    let mut memory = machine();
    // mov [rax], ecx
    let rip = load_code(&mut memory, &[0x89, 0x08]);
    let mut guest = TestGuest::new(rip);
    guest.regs[0] = APIC_TPR;
    guest.regs[1] = 0x30;
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    // Data access, write: bit 1 set, bit 3 (instruction fetch) clear.
    let mut view = view(&mut memory, &guest);
    let handled = handle_exit(
        &mut devices,
        &mut apic,
        &mut view,
        &mut guest,
        ExitClass::EptViolation,
        0b010,
        APIC_TPR,
    )
    .expect("emulated");
    assert!(handled);
    assert_eq!(apic.tpr(), 0x30);
    assert_eq!(guest.rip, rip + 2);
}

#[test]
fn apic_page_read_returns_the_register_value() {
    let mut memory = machine();
    // mov ecx, [rax]
    let rip = load_code(&mut memory, &[0x8B, 0x08]);
    let mut guest = TestGuest::new(rip);
    guest.regs[0] = APIC_TPR;
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    apic.mmio_write(0x80, 0x70);
    let mut view = view(&mut memory, &guest);
    let handled = handle_exit(
        &mut devices,
        &mut apic,
        &mut view,
        &mut guest,
        ExitClass::EptViolation,
        0b001,
        APIC_TPR,
    )
    .expect("emulated");
    assert!(handled);
    assert_eq!(guest.regs[1], 0x70);
    assert_eq!(guest.rip, rip + 2);
}

#[test]
fn apic_page_read_does_not_clobber_unrelated_registers() {
    let mut memory = machine();
    // mov ecx, [rax]
    let rip = load_code(&mut memory, &[0x8B, 0x08]);
    let mut guest = TestGuest::new(rip);
    guest.regs[0] = APIC_TPR;
    guest.regs[1] = 0xDEAD_BEEF_DEAD_BEEF;
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    apic.mmio_write(0x80, 0x10);
    let mut view = view(&mut memory, &guest);
    let handled = handle_exit(
        &mut devices,
        &mut apic,
        &mut view,
        &mut guest,
        ExitClass::EptViolation,
        0b001,
        APIC_TPR,
    )
    .expect("emulated");
    assert!(handled);
    // A 32-bit read only replaces ECX: the upper half of RCX is preserved.
    assert_eq!(guest.regs[1], 0xDEAD_BEEF_0000_0010);
}

#[test]
fn ioapic_page_access_uses_the_indirect_window() {
    let mut memory = machine();
    // mov [rax], ecx then mov ecx, [rax + 0x10]
    let rip = load_code(&mut memory, &[0x89, 0x08, 0x8B, 0x48, 0x10]);
    let mut guest = TestGuest::new(rip);
    guest.regs[0] = IOAPIC_SELECT;
    guest.regs[1] = 0x01; // select the version register
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    let mut view = view(&mut memory, &guest);
    let handled = handle_exit(
        &mut devices,
        &mut apic,
        &mut view,
        &mut guest,
        ExitClass::EptViolation,
        0b010,
        IOAPIC_SELECT,
    )
    .expect("emulated");
    assert!(handled);
    assert_eq!(devices.ioapic.selected(), 0x01);
    let handled = handle_exit(
        &mut devices,
        &mut apic,
        &mut view,
        &mut guest,
        ExitClass::EptViolation,
        0b001,
        IOAPIC_SELECT + 0x10,
    )
    .expect("emulated");
    assert!(handled);
    assert_eq!(guest.regs[1], u64::from(ioapic::VERSION));
    assert_eq!(guest.rip, rip + 5);
}

#[test]
fn instruction_fetch_violation_is_left_to_policy() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0x8B, 0x08]);
    let mut guest = TestGuest::new(rip);
    guest.regs[0] = APIC_TPR;
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    let mut view = view(&mut memory, &guest);
    let handled = handle_exit(
        &mut devices,
        &mut apic,
        &mut view,
        &mut guest,
        ExitClass::EptViolation,
        0b1000,
        APIC_TPR,
    )
    .expect("no error");
    assert!(!handled);
    assert_eq!(guest.rip, rip);
}

#[test]
fn device_page_identifies_the_modeled_pages() {
    assert_eq!(emulate::device_page(0xFEE0_0F00), Some(DevicePage::Apic));
    assert_eq!(
        emulate::device_page(IOAPIC_BASE + 4),
        Some(DevicePage::IoApic)
    );
    assert_eq!(emulate::device_page(0x1000), None);
}

#[test]
fn modeled_ports_are_advertised() {
    assert!(Devices::handles_port(0x20));
    assert!(Devices::handles_port(0x21));
    assert!(Devices::handles_port(0xA0));
    assert!(Devices::handles_port(0xA1));
    assert!(Devices::handles_port(0x80));
    assert!(!Devices::handles_port(0xE9));
    assert!(!Devices::handles_port(0x3F8));
}

#[test]
fn wrmsr_programs_the_x2apic_tpr() {
    let mut memory = machine();
    // wrmsr: ECX = MSR number, EDX:EAX = value.
    let rip = load_code(&mut memory, &[0x0F, 0x30]);
    let mut guest = TestGuest::new(rip);
    guest.regs[1] = 0x808; // IA32_X2APIC_TPR
    guest.regs[2] = 0;
    guest.regs[0] = 0x30;
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    let mut view = view(&mut memory, &guest);
    let handled = handle_exit(
        &mut devices,
        &mut apic,
        &mut view,
        &mut guest,
        ExitClass::Msr,
        0,
        0,
    )
    .expect("emulated");
    assert!(handled);
    assert_eq!(apic.tpr(), 0x30);
    assert_eq!(guest.rip, rip + 2);
}

#[test]
fn rdmsr_reads_the_x2apic_tpr_into_edx_eax() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0x0F, 0x32]);
    let mut guest = TestGuest::new(rip);
    guest.regs[1] = 0x808;
    guest.regs[0] = 0xFFFF_FFFF_FFFF_0000;
    guest.regs[2] = 0xFFFF_FFFF_FFFF_0000;
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    apic.mmio_write(0x80, 0x50);
    let mut view = view(&mut memory, &guest);
    let handled = handle_exit(
        &mut devices,
        &mut apic,
        &mut view,
        &mut guest,
        ExitClass::Msr,
        0,
        0,
    )
    .expect("emulated");
    assert!(handled);
    // Only EAX and EDX are replaced; the upper halves are preserved.
    assert_eq!(guest.regs[0], 0xFFFF_FFFF_0000_0050);
    assert_eq!(guest.regs[2], 0xFFFF_FFFF_0000_0000);
    assert_eq!(guest.rip, rip + 2);
}

#[test]
fn msr_outside_the_x2apic_window_is_left_to_policy() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0x0F, 0x32]);
    let mut guest = TestGuest::new(rip);
    guest.regs[1] = 0x10; // IA32_TSC
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    let mut view = view(&mut memory, &guest);
    let handled = handle_exit(
        &mut devices,
        &mut apic,
        &mut view,
        &mut guest,
        ExitClass::Msr,
        0,
        0,
    )
    .expect("no error");
    assert!(!handled);
    assert_eq!(guest.rip, rip);
}

#[test]
fn unmodeled_x2apic_msr_is_left_to_policy() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0x0F, 0x32]);
    let mut guest = TestGuest::new(rip);
    guest.regs[1] = 0x8FF; // last MSR of the window, not modeled
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    let mut view = view(&mut memory, &guest);
    let handled = handle_exit(
        &mut devices,
        &mut apic,
        &mut view,
        &mut guest,
        ExitClass::Msr,
        0,
        0,
    )
    .expect("no error");
    assert!(!handled);
    assert_eq!(guest.rip, rip);
}
