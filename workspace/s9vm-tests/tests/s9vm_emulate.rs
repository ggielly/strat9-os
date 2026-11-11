//! L2: in-kernel emulation layer (page walks, device replay).
//!
//! The module under test is pure: physical memory is a byte vector, the
//! vCPU is replaced by an explicit register block. This exercises the exact
//! code the exit handler runs on the target machine.

extern crate alloc;

#[path = "../../kernel/src/s9vm/acpi.rs"]
mod acpi;
#[path = "../../kernel/src/s9vm/apic.rs"]
mod apic;
#[path = "../../kernel/src/s9vm/decode.rs"]
mod decode;
#[path = "../../kernel/src/s9vm/emulate.rs"]
mod emulate;
#[path = "../../kernel/src/s9vm/exit.rs"]
mod exit;
#[path = "../../kernel/src/s9vm/hpet.rs"]
mod hpet;
#[path = "../../kernel/src/s9vm/ioapic.rs"]
mod ioapic;
#[path = "../../kernel/src/s9vm/msr.rs"]
mod msr;
#[path = "../../kernel/src/s9vm/pci.rs"]
mod pci;
#[path = "../../kernel/src/s9vm/pic.rs"]
mod pic;
#[path = "../../kernel/src/s9vm/pit.rs"]
mod pit;
#[path = "../../kernel/src/rtc_math.rs"]
mod rtc_math;
#[path = "../../kernel/src/s9vm/rtc.rs"]
mod rtc;
#[path = "../../kernel/src/s9vm/uart.rs"]
mod uart;
#[path = "../../kernel/src/s9vm/virtio.rs"]
mod virtio;
#[path = "../../kernel/src/s9vm/virtio_blk.rs"]
mod virtio_blk;
#[path = "../../kernel/src/s9vm/virtio_console.rs"]
mod virtio_console;
#[path = "../../kernel/src/s9vm/virtio_net.rs"]
mod virtio_net;

use emulate::{
    handle_exit, interrupt_action, interrupt_deliverable, walk_guest, walk_second_level,
    DevicePage, Devices, GuestContext, InterruptAction, MemoryView, PhysMemory, CONSOLE_BASE,
    CONSOLE_IRQ_LINE, CONSOLE_IRQ_VECTOR, INTERRUPTIBILITY_MOV_SS_BLOCKING,
    INTERRUPTIBILITY_STI_BLOCKING, IOAPIC_BASE,
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

    fn slice(&self, address: u64, len: usize) -> &[u8] {
        &self.bytes[address as usize..address as usize + len]
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
    // Legacy platform devices are modeled in-kernel: COM1, the 8254 and the
    // CMOS RTC are replayed instead of being reported to policy.
    assert!(Devices::handles_port(0x3F8));
    assert!(Devices::handles_port(0x43));
    assert!(Devices::handles_port(0x70));
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

#[test]
fn interrupt_action_injects_when_the_guest_is_interruptible() {
    assert_eq!(interrupt_action(true, true, false), InterruptAction::Inject);
    // A window that is still armed is disarmed after the injection.
    assert_eq!(interrupt_action(true, true, true), InterruptAction::Inject);
}

#[test]
fn interrupt_action_arms_the_window_when_interrupts_are_disabled() {
    assert_eq!(
        interrupt_action(true, false, false),
        InterruptAction::ArmWindow
    );
    // Already armed: the action is idempotent.
    assert_eq!(
        interrupt_action(true, false, true),
        InterruptAction::ArmWindow
    );
}

#[test]
fn interrupt_action_disarms_the_window_when_nothing_is_pending() {
    assert_eq!(
        interrupt_action(false, false, true),
        InterruptAction::DisarmWindow
    );
    assert_eq!(
        interrupt_action(false, true, true),
        InterruptAction::DisarmWindow
    );
    assert_eq!(interrupt_action(false, true, false), InterruptAction::None);
    assert_eq!(interrupt_action(false, false, false), InterruptAction::None);
}

#[test]
fn interrupt_deliverable_rejects_the_sti_and_mov_ss_shadows() {
    // IF = 0: nothing can be delivered whatever the shadow bits say.
    assert!(!interrupt_deliverable(false, 0));
    assert!(!interrupt_deliverable(false, 0b01));

    // IF = 1 and no shadow: deliverable.
    assert!(interrupt_deliverable(true, 0));
    // Only the low two bits matter; the upper bits are reserved / unrelated.
    assert!(interrupt_deliverable(true, 0b1100));

    // Blocking by STI: the vector must wait for the shadow to clear, otherwise
    // VM-entry interruption delivery silently discards it after the APIC
    // already moved it to the in-service register.
    assert!(!interrupt_deliverable(true, INTERRUPTIBILITY_STI_BLOCKING));
    // Blocking by MOV SS, same rule.
    assert!(!interrupt_deliverable(
        true,
        INTERRUPTIBILITY_MOV_SS_BLOCKING
    ));
    // Both set is rejected too.
    assert!(!interrupt_deliverable(
        true,
        INTERRUPTIBILITY_STI_BLOCKING | INTERRUPTIBILITY_MOV_SS_BLOCKING
    ));
}

// ---------------------------------------------------------------------------
// virtio console transport page
// ---------------------------------------------------------------------------

const CONSOLE_DESC: u64 = 0x9000;
const CONSOLE_AVAIL: u64 = 0xA000;
const CONSOLE_USED: u64 = 0xB000;
const CONSOLE_BUFFER: u64 = 0xC000;

/// Writes one MMIO register of a device page through a replayed instruction.
fn mmio_write(
    devices: &mut Devices,
    apic: &mut apic::LocalApic,
    memory: &mut TestMemory,
    guest: &mut TestGuest,
    base: u64,
    offset: u64,
    value: u32,
) -> bool {
    let rip = load_code(memory, &[0x89, 0x08]); // mov [rax], ecx
    guest.rip = rip;
    guest.regs[0] = base + offset;
    guest.regs[1] = u64::from(value);
    let mut view = MemoryView::new(memory, EPT_PML4, guest.cr3, guest.paging);
    handle_exit(
        devices,
        apic,
        &mut view,
        guest,
        ExitClass::EptViolation,
        0b010,
        base + offset,
    )
    .expect("no error")
}

/// Reads one MMIO register of a device page through a replayed instruction.
fn mmio_read(
    devices: &mut Devices,
    apic: &mut apic::LocalApic,
    memory: &mut TestMemory,
    guest: &mut TestGuest,
    base: u64,
    offset: u64,
) -> u32 {
    let rip = load_code(memory, &[0x8B, 0x08]); // mov ecx, [rax]
    guest.rip = rip;
    guest.regs[0] = base + offset;
    let mut view = MemoryView::new(memory, EPT_PML4, guest.cr3, guest.paging);
    handle_exit(
        devices,
        apic,
        &mut view,
        guest,
        ExitClass::EptViolation,
        0b001,
        base + offset,
    )
    .expect("no error");
    guest.regs[1] as u32
}

/// Writes one console transport register.
fn console_write(
    devices: &mut Devices,
    apic: &mut apic::LocalApic,
    memory: &mut TestMemory,
    guest: &mut TestGuest,
    offset: u64,
    value: u32,
) -> bool {
    mmio_write(devices, apic, memory, guest, CONSOLE_BASE, offset, value)
}

/// Reads one console transport register.
fn console_read(
    devices: &mut Devices,
    apic: &mut apic::LocalApic,
    memory: &mut TestMemory,
    guest: &mut TestGuest,
    offset: u64,
) -> u32 {
    mmio_read(devices, apic, memory, guest, CONSOLE_BASE, offset)
}

/// Programs a console queue through the transport registers.
fn console_program_queue(
    devices: &mut Devices,
    apic: &mut apic::LocalApic,
    memory: &mut TestMemory,
    guest: &mut TestGuest,
    queue: u32,
) {
    console_write(
        devices,
        apic,
        memory,
        guest,
        u64::from(virtio_console::reg::QUEUE_SEL),
        queue,
    );
    console_write(
        devices,
        apic,
        memory,
        guest,
        u64::from(virtio_console::reg::QUEUE_NUM),
        8,
    );
    console_write(
        devices,
        apic,
        memory,
        guest,
        u64::from(virtio_console::reg::QUEUE_DESC_LOW),
        CONSOLE_DESC as u32,
    );
    console_write(
        devices,
        apic,
        memory,
        guest,
        u64::from(virtio_console::reg::QUEUE_AVAIL_LOW),
        CONSOLE_AVAIL as u32,
    );
    console_write(
        devices,
        apic,
        memory,
        guest,
        u64::from(virtio_console::reg::QUEUE_USED_LOW),
        CONSOLE_USED as u32,
    );
    console_write(
        devices,
        apic,
        memory,
        guest,
        u64::from(virtio_console::reg::QUEUE_READY),
        1,
    );
}

#[test]
fn console_page_is_identified() {
    assert_eq!(
        emulate::device_page(CONSOLE_BASE + 0x50),
        Some(DevicePage::Console)
    );
}

#[test]
fn console_registers_are_reachable_through_the_transport_page() {
    let mut memory = machine();
    let mut guest = TestGuest::new(CODE_PAGE);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    assert_eq!(
        console_read(
            &mut devices,
            &mut apic,
            &mut memory,
            &mut guest,
            u64::from(virtio_console::reg::MAGIC)
        ),
        virtio_console::MAGIC
    );
    assert_eq!(
        console_read(
            &mut devices,
            &mut apic,
            &mut memory,
            &mut guest,
            u64::from(virtio_console::reg::DEVICE_ID)
        ),
        virtio_console::DEVICE_ID
    );
}

#[test]
fn console_transmit_queue_is_serviced_by_the_kernel() {
    let mut memory = machine();
    let mut guest = TestGuest::new(CODE_PAGE);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);

    // Driver status: acknowledged, driver, features ok, DRIVER_OK.
    console_write(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        u64::from(virtio_console::reg::STATUS),
        virtio_console::status::ACKNOWLEDGE
            | virtio_console::status::DRIVER
            | virtio_console::status::FEATURES_OK
            | virtio_console::status::DRIVER_OK,
    );
    console_program_queue(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        virtio_console::QUEUE_TX,
    );

    // Guest descriptor: buffer with "ok".
    let descriptor = virtio::Descriptor {
        addr: CONSOLE_BUFFER,
        len: 2,
        flags: 0,
        next: 0,
    };
    memory.write_bytes(CONSOLE_DESC, &descriptor.encode());
    memory.write_bytes(CONSOLE_BUFFER, b"ok");
    memory.write_u64(CONSOLE_AVAIL, 0);
    memory.write_bytes(CONSOLE_AVAIL + 4, &0u16.to_le_bytes());
    memory.write_bytes(CONSOLE_AVAIL + 2, &1u16.to_le_bytes());

    assert!(console_write(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        u64::from(virtio_console::reg::QUEUE_NOTIFY),
        virtio_console::QUEUE_TX,
    ));
    assert_eq!(devices.console.output(), b"ok");
    assert_eq!(devices.console.drain_output(), b"ok");
}

#[test]
fn console_receive_queue_reaches_the_guest_buffers() {
    let mut memory = machine();
    let mut guest = TestGuest::new(CODE_PAGE);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);

    console_write(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        u64::from(virtio_console::reg::STATUS),
        virtio_console::status::ACKNOWLEDGE
            | virtio_console::status::DRIVER
            | virtio_console::status::FEATURES_OK
            | virtio_console::status::DRIVER_OK,
    );
    console_program_queue(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        virtio_console::QUEUE_RX,
    );

    let descriptor = virtio::Descriptor {
        addr: CONSOLE_BUFFER,
        len: 8,
        flags: virtio::DESC_F_WRITE,
        next: 0,
    };
    memory.write_bytes(CONSOLE_DESC, &descriptor.encode());
    memory.write_bytes(CONSOLE_AVAIL + 2, &1u16.to_le_bytes());
    memory.write_bytes(CONSOLE_AVAIL + 4, &0u16.to_le_bytes());

    devices.console.push_input(b"input");
    assert!(console_write(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        u64::from(virtio_console::reg::QUEUE_NOTIFY),
        virtio_console::QUEUE_RX,
    ));
    assert_eq!(memory.slice(CONSOLE_BUFFER, 5), b"input");
}

#[test]
fn console_queue_register_writes_are_visible_to_the_guest() {
    let mut memory = machine();
    let mut guest = TestGuest::new(CODE_PAGE);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    console_program_queue(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        virtio_console::QUEUE_TX,
    );
    assert_eq!(
        console_read(
            &mut devices,
            &mut apic,
            &mut memory,
            &mut guest,
            u64::from(virtio_console::reg::QUEUE_READY)
        ),
        1
    );
    assert_eq!(
        console_read(
            &mut devices,
            &mut apic,
            &mut memory,
            &mut guest,
            u64::from(virtio_console::reg::QUEUE_NUM)
        ),
        8
    );
}

#[test]
fn console_output_raises_the_console_vector() {
    let mut memory = machine();
    let mut guest = TestGuest::new(CODE_PAGE);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);

    console_write(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        u64::from(virtio_console::reg::STATUS),
        virtio_console::status::ACKNOWLEDGE
            | virtio_console::status::DRIVER
            | virtio_console::status::FEATURES_OK
            | virtio_console::status::DRIVER_OK,
    );
    console_program_queue(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        virtio_console::QUEUE_TX,
    );

    let descriptor = virtio::Descriptor {
        addr: CONSOLE_BUFFER,
        len: 2,
        flags: 0,
        next: 0,
    };
    memory.write_bytes(CONSOLE_DESC, &descriptor.encode());
    memory.write_bytes(CONSOLE_BUFFER, b"hi");
    memory.write_bytes(CONSOLE_AVAIL + 2, &1u16.to_le_bytes());
    memory.write_bytes(CONSOLE_AVAIL + 4, &0u16.to_le_bytes());

    console_write(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        u64::from(virtio_console::reg::QUEUE_NOTIFY),
        virtio_console::QUEUE_TX,
    );
    assert_eq!(devices.console.output(), b"hi");
    assert_eq!(apic.pending_vector(), Some(CONSOLE_IRQ_VECTOR));
}

#[test]
fn console_interrupt_is_only_raised_while_reported() {
    let mut memory = machine();
    let mut guest = TestGuest::new(CODE_PAGE);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    // A plain register write must not raise the vector.
    console_write(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        u64::from(virtio_console::reg::QUEUE_SEL),
        0,
    );
    assert_eq!(apic.pending_vector(), None);
}

// ---------------------------------------------------------------------------
// virtio block transport page
// ---------------------------------------------------------------------------

const BLK_DESC: u64 = 0x9000;
const BLK_AVAIL: u64 = 0xA000;
const BLK_USED: u64 = 0xB000;
const BLK_HEADER: u64 = 0xC000;
const BLK_DATA: u64 = 0xD000;
const BLK_STATUS: u64 = 0xE000;

/// Programs the block request queue through the transport registers.
fn blk_program_queue(
    devices: &mut Devices,
    apic: &mut apic::LocalApic,
    memory: &mut TestMemory,
    guest: &mut TestGuest,
) {
    for (offset, value) in [
        (virtio_blk::reg::QUEUE_SEL, 0),
        (virtio_blk::reg::QUEUE_NUM, 8),
        (virtio_blk::reg::QUEUE_DESC_LOW, BLK_DESC as u32),
        (virtio_blk::reg::QUEUE_AVAIL_LOW, BLK_AVAIL as u32),
        (virtio_blk::reg::QUEUE_USED_LOW, BLK_USED as u32),
        (virtio_blk::reg::QUEUE_READY, 1),
    ] {
        mmio_write(
            devices,
            apic,
            memory,
            guest,
            emulate::BLK_BASE,
            u64::from(offset),
            value,
        );
    }
}

#[test]
fn block_page_is_identified() {
    assert_eq!(
        emulate::device_page(emulate::BLK_BASE + 0x50),
        Some(DevicePage::Blk)
    );
}

#[test]
fn block_read_request_is_served_through_the_transport_page() {
    let mut memory = machine();
    let mut guest = TestGuest::new(CODE_PAGE);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);

    mmio_write(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        emulate::BLK_BASE,
        u64::from(virtio_blk::reg::STATUS),
        virtio_blk::status::ACKNOWLEDGE
            | virtio_blk::status::DRIVER
            | virtio_blk::status::FEATURES_OK
            | virtio_blk::status::DRIVER_OK,
    );
    blk_program_queue(&mut devices, &mut apic, &mut memory, &mut guest);

    // Disk: sector 0 starts with 'D'.
    let mut sector = [0u8; 512];
    sector[0] = b'D';
    devices.blk.write_sector(0, &sector);

    // Request: header (IN, sector 0), data buffer, status byte.
    memory.write_u64(BLK_HEADER, u64::from(virtio_blk::request::IN));
    memory.write_u64(BLK_HEADER + 8, 0);
    let chain = [
        virtio::Descriptor {
            addr: BLK_HEADER,
            len: 16,
            flags: virtio::DESC_F_NEXT,
            next: 1,
        },
        virtio::Descriptor {
            addr: BLK_DATA,
            len: 512,
            flags: virtio::DESC_F_NEXT | virtio::DESC_F_WRITE,
            next: 2,
        },
        virtio::Descriptor {
            addr: BLK_STATUS,
            len: 1,
            flags: virtio::DESC_F_WRITE,
            next: 0,
        },
    ];
    for (index, descriptor) in chain.iter().enumerate() {
        memory.write_bytes(
            BLK_DESC + index as u64 * virtio::DESCRIPTOR_SIZE,
            &descriptor.encode(),
        );
    }
    memory.write_bytes(BLK_AVAIL + 2, &1u16.to_le_bytes());
    memory.write_bytes(BLK_AVAIL + 4, &0u16.to_le_bytes());

    mmio_write(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        emulate::BLK_BASE,
        u64::from(virtio_blk::reg::QUEUE_NOTIFY),
        0,
    );
    assert_eq!(memory.slice(BLK_DATA, 1), b"D");
    assert_eq!(
        memory.slice(BLK_STATUS, 1)[0],
        virtio_blk::request_status::OK
    );
    assert_eq!(devices.blk.completed(), 1);
    assert_eq!(apic.pending_vector(), Some(emulate::BLK_IRQ_VECTOR));
}

// ---------------------------------------------------------------------------
// virtio network transport page
// ---------------------------------------------------------------------------

#[test]
fn network_page_is_identified() {
    assert_eq!(
        emulate::device_page(emulate::NET_BASE + 0x50),
        Some(DevicePage::Net)
    );
}

#[test]
fn network_frame_is_captured_through_the_transport_page() {
    let mut memory = machine();
    let mut guest = TestGuest::new(CODE_PAGE);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);

    mmio_write(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        emulate::NET_BASE,
        u64::from(virtio_net::reg::STATUS),
        virtio_net::status::ACKNOWLEDGE
            | virtio_net::status::DRIVER
            | virtio_net::status::FEATURES_OK
            | virtio_net::status::DRIVER_OK,
    );
    // Transmit queue (1).
    for (offset, value) in [
        (virtio_net::reg::QUEUE_SEL, 1),
        (virtio_net::reg::QUEUE_NUM, 8),
        (virtio_net::reg::QUEUE_DESC_LOW, CONSOLE_DESC as u32),
        (virtio_net::reg::QUEUE_AVAIL_LOW, CONSOLE_AVAIL as u32),
        (virtio_net::reg::QUEUE_USED_LOW, CONSOLE_USED as u32),
        (virtio_net::reg::QUEUE_READY, 1),
    ] {
        mmio_write(
            &mut devices,
            &mut apic,
            &mut memory,
            &mut guest,
            emulate::NET_BASE,
            u64::from(offset),
            value,
        );
    }

    // Packet: zeroed network header + payload, one readable descriptor.
    let mut packet = alloc::vec![0u8; virtio_net::NET_HDR_SIZE];
    packet.extend_from_slice(b"frame");
    memory.write_bytes(CONSOLE_BUFFER, &packet);
    let descriptor = virtio::Descriptor {
        addr: CONSOLE_BUFFER,
        len: packet.len() as u32,
        flags: 0,
        next: 0,
    };
    memory.write_bytes(CONSOLE_DESC, &descriptor.encode());
    memory.write_bytes(CONSOLE_AVAIL + 2, &1u16.to_le_bytes());
    memory.write_bytes(CONSOLE_AVAIL + 4, &0u16.to_le_bytes());

    mmio_write(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        emulate::NET_BASE,
        u64::from(virtio_net::reg::QUEUE_NOTIFY),
        1,
    );
    assert_eq!(devices.net.output(), b"frame");
    assert_eq!(devices.net.frames_sent(), 1);
    assert_eq!(apic.pending_vector(), Some(emulate::NET_IRQ_VECTOR));
}

// ---------------------------------------------------------------------------
// I/O APIC routing of device lines
// ---------------------------------------------------------------------------

/// Programs one I/O APIC redirection entry through the MMIO page.
fn program_ioapic_entry(
    devices: &mut Devices,
    apic: &mut apic::LocalApic,
    memory: &mut TestMemory,
    guest: &mut TestGuest,
    pin: u32,
    low_word: u32,
) {
    mmio_write(
        devices,
        apic,
        memory,
        guest,
        IOAPIC_BASE,
        ioapic::REG_SELECT as u64,
        ioapic::REDIRECTION_BASE + pin * 2,
    );
    mmio_write(
        devices,
        apic,
        memory,
        guest,
        IOAPIC_BASE,
        ioapic::REG_WINDOW as u64,
        low_word,
    );
}

/// Notifies the console transmit queue with one small buffer.
fn console_send(
    memory: &mut TestMemory,
    devices: &mut Devices,
    apic: &mut apic::LocalApic,
    guest: &mut TestGuest,
) {
    console_write(
        devices,
        apic,
        memory,
        guest,
        u64::from(virtio_console::reg::STATUS),
        virtio_console::status::ACKNOWLEDGE
            | virtio_console::status::DRIVER
            | virtio_console::status::FEATURES_OK
            | virtio_console::status::DRIVER_OK,
    );
    console_program_queue(devices, apic, memory, guest, virtio_console::QUEUE_TX);
    let descriptor = virtio::Descriptor {
        addr: CONSOLE_BUFFER,
        len: 1,
        flags: 0,
        next: 0,
    };
    memory.write_bytes(CONSOLE_DESC, &descriptor.encode());
    memory.write_bytes(CONSOLE_BUFFER, b"x");
    memory.write_bytes(CONSOLE_AVAIL + 2, &1u16.to_le_bytes());
    memory.write_bytes(CONSOLE_AVAIL + 4, &0u16.to_le_bytes());
    console_write(
        devices,
        apic,
        memory,
        guest,
        u64::from(virtio_console::reg::QUEUE_NOTIFY),
        virtio_console::QUEUE_TX,
    );
}

#[test]
fn device_line_defaults_to_the_console_vector() {
    let mut memory = machine();
    let mut guest = TestGuest::new(CODE_PAGE);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    console_send(&mut memory, &mut devices, &mut apic, &mut guest);
    assert_eq!(apic.pending_vector(), Some(CONSOLE_IRQ_VECTOR));
}

#[test]
fn guest_can_remap_the_device_line() {
    let mut memory = machine();
    let mut guest = TestGuest::new(CODE_PAGE);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    // Remap console line 16 to vector 0x40, unmasked.
    program_ioapic_entry(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        CONSOLE_IRQ_LINE as u32,
        0x40,
    );
    console_send(&mut memory, &mut devices, &mut apic, &mut guest);
    assert_eq!(apic.pending_vector(), Some(0x40));
}

#[test]
fn masked_device_line_delivers_nothing() {
    let mut memory = machine();
    let mut guest = TestGuest::new(CODE_PAGE);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    // Mask the console line: low word with bit 16 set.
    program_ioapic_entry(
        &mut devices,
        &mut apic,
        &mut memory,
        &mut guest,
        CONSOLE_IRQ_LINE as u32,
        (1 << 16) | 0x21,
    );
    console_send(&mut memory, &mut devices, &mut apic, &mut guest);
    assert_eq!(apic.pending_vector(), None);
}

// MSI delivery model

#[test]
fn msi_decodes_vector_and_destination() {
    let address = emulate::MSI_ADDRESS_BASE | (2 << 12);
    assert_eq!(emulate::msi_write(address, 0x40), Some((0x40, 2)));
    assert_eq!(emulate::msi_write(address, 0xFF), Some((0xFF, 2)));
}

#[test]
fn msi_rejects_malformed_address_and_data() {
    // Wrong base, non-zero low bits, high 32 bits, reserved data bits.
    assert_eq!(emulate::msi_write(0xFEE0_0004, 0x40), None);
    assert_eq!(emulate::msi_write(0xFEC0_0000, 0x40), None);
    assert_eq!(emulate::msi_write(0x1_FEE0_0000, 0x40), None);
    assert_eq!(
        emulate::msi_write(emulate::MSI_ADDRESS_BASE, 0x1_0040),
        None
    );
    assert_eq!(emulate::msi_write(emulate::MSI_ADDRESS_BASE, 0x0F), None);
}

#[test]
fn msi_delivers_directly_to_the_local_apic() {
    let mut apic = apic::LocalApic::new(0);
    assert!(emulate::deliver_msi(
        &mut apic,
        emulate::MSI_ADDRESS_BASE | (3 << 12),
        0x45
    ));
    assert_eq!(apic.pending_vector(), Some(0x45));
    assert!(!emulate::deliver_msi(&mut apic, 0, 0x45));
    assert_eq!(apic.pending_vector(), Some(0x45));
}

#[test]
fn msi_adversarial_values_do_not_panic() {
    let mut apic = apic::LocalApic::new(0);
    for address in [0, 1, u64::MAX, 0xFEE0_0FFF, 0xFEEF_F000] {
        for data in [0, 1, 0xFFFF_FFFF, 0x0000_00FF, 0x0000_0F00] {
            let _ = emulate::msi_write(address, data);
            let _ = emulate::deliver_msi(&mut apic, address, data);
        }
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Legacy platform devices (8254 timer, 16550 COM1, CMOS RTC) on the port path.
// ---------------------------------------------------------------------------

/// Replays one port access on the synthetic machine.
fn replay_port(
    memory: &mut TestMemory,
    guest: &mut TestGuest,
    devices: &mut Devices,
    apic: &mut apic::LocalApic,
    port: u16,
    is_in: bool,
) -> bool {
    let qualification = (u64::from(port) << 16) | if is_in { 0x8 } else { 0 };
    let mut view = view(memory, guest);
    handle_exit(
        devices,
        apic,
        &mut view,
        guest,
        ExitClass::IoPort,
        qualification,
        0,
    )
    .expect("emulated port access")
}

#[test]
fn legacy_device_ports_are_claimed() {
    // COM1 is above 0xFF: the guest reaches it through DX (`out dx, al`).
    assert!(Devices::handles_port(uart::BASE_PORT));
    assert!(Devices::handles_port(uart::BASE_PORT + 7));
    assert!(Devices::handles_port(pit::BASE_PORT));
    assert!(Devices::handles_port(pit::BASE_PORT + 3));
    assert!(Devices::handles_port(rtc::INDEX_PORT));
    assert!(Devices::handles_port(rtc::DATA_PORT));
    assert!(!Devices::handles_port(0xE9));
    assert!(!Devices::handles_port(uart::BASE_PORT + 8));
}

#[test]
fn uart_write_reaches_the_model_and_advances_rip() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0xEE]); // out dx, al
    let mut guest = TestGuest::new(rip);
    guest.regs[0] = u64::from(b'A');
    guest.regs[2] = u64::from(uart::BASE_PORT); // DX
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    assert!(replay_port(
        &mut memory,
        &mut guest,
        &mut devices,
        &mut apic,
        uart::BASE_PORT,
        false
    ));
    assert_eq!(devices.uart.drain_output(), b"A");
    assert_eq!(guest.rip, rip + 1);
}

#[test]
fn uart_status_read_reports_a_ready_transmitter() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0xEC]); // in al, dx
    let mut guest = TestGuest::new(rip);
    guest.regs[0] = 0xFFFF_FFFF_FFFF_0000;
    guest.regs[2] = u64::from(uart::BASE_PORT + 5); // DX = LSR
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    assert!(replay_port(
        &mut memory,
        &mut guest,
        &mut devices,
        &mut apic,
        uart::BASE_PORT + 5,
        true
    ));
    // THR empty and transmitter empty; only AL changes.
    assert_eq!(guest.regs[0] & 0xFF, 0x60);
    assert_eq!(guest.regs[0] & !0xFF, 0xFFFF_FFFF_FFFF_0000);
    assert_eq!(guest.rip, rip + 1);
}

#[test]
fn pit_programming_reaches_the_model() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0xE6, 0x43, 0xE6, 0x40, 0xE6, 0x40]);
    let mut guest = TestGuest::new(rip);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    // Mode/command register: channel 0, lo/hi access, mode 3, binary.
    for (offset, value) in [(0u16, 0x36u64), (1, 0x00), (2, 0x10)] {
        guest.regs[0] = value;
        let port = if offset == 0 { 0x43 } else { 0x40 };
        assert!(replay_port(
            &mut memory,
            &mut guest,
            &mut devices,
            &mut apic,
            port,
            false
        ));
    }
    // Count 0x1000: the periodic output pulses once per period.
    assert!(!devices.pit.advance(1));
    assert!(devices.pit.advance(0x1000));
    assert_eq!(guest.rip, rip + 6);
}

#[test]
fn rtc_index_and_data_reads_return_the_calendar() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0xE6, 0x70, 0xE4, 0x71]);
    let mut guest = TestGuest::new(rip);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    devices.rtc.set_unix_time(1);
    // Select register 0 (seconds) through the index port.
    guest.regs[0] = 0;
    assert!(replay_port(
        &mut memory,
        &mut guest,
        &mut devices,
        &mut apic,
        0x70,
        false
    ));
    // Read it through the data port: BCD seconds of epoch + 1 s.
    guest.regs[0] = 0xFFFF_FFFF_FFFF_0000;
    assert!(replay_port(
        &mut memory,
        &mut guest,
        &mut devices,
        &mut apic,
        0x71,
        true
    ));
    assert_eq!(guest.regs[0] & 0xFF, 0x01);
    assert_eq!(guest.rip, rip + 4);
}

#[test]
fn uart_interrupt_line_is_level_triggered_on_the_ioapic() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0xEE, 0xEE]); // out dx, al twice (IER)
    let mut guest = TestGuest::new(rip);
    guest.regs[2] = u64::from(uart::BASE_PORT + 1);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    // Receive-data interrupt enabled, then input arrives: the model asserts
    // its line and the dispatch injects the pre-programmed COM1 vector.
    guest.regs[0] = 0x01;
    assert!(replay_port(
        &mut memory,
        &mut guest,
        &mut devices,
        &mut apic,
        uart::BASE_PORT + 1,
        false
    ));
    assert!(!devices.uart.irq_asserted());
    devices.uart.push_input(b"x");
    assert!(replay_port(
        &mut memory,
        &mut guest,
        &mut devices,
        &mut apic,
        uart::BASE_PORT + 1,
        false
    ));
    assert!(devices.uart.irq_asserted());
    assert_eq!(
        apic.pending_vector(),
        Some(emulate::UART_IRQ_VECTOR),
        "the dispatch must inject the pre-programmed COM1 vector"
    );
}


// ---------------------------------------------------------------------------
// Legacy interrupt delivery through the 8259 pair (PIC mode).
// ---------------------------------------------------------------------------

/// Programs the 8259 pair like an operating system does: master vector base
/// 0x20, slave 0x28, cascade on IRQ2, every line unmasked. The reset vector
/// base (0x08) is below the processor's reserved vector range, so a delivered
/// vector would never be accepted by the local APIC.
fn init_legacy_pic(devices: &mut Devices) {
    devices.pic.write(pic::port::MASTER_COMMAND, 0x11);
    devices.pic.write(pic::port::MASTER_DATA, 0x20);
    devices.pic.write(pic::port::MASTER_DATA, 0x04);
    devices.pic.write(pic::port::MASTER_DATA, 0x01);
    devices.pic.write(pic::port::SLAVE_COMMAND, 0x11);
    devices.pic.write(pic::port::SLAVE_DATA, 0x28);
    devices.pic.write(pic::port::SLAVE_DATA, 0x02);
    devices.pic.write(pic::port::SLAVE_DATA, 0x01);
    devices.pic.write(pic::port::MASTER_DATA, 0x00);
    devices.pic.write(pic::port::SLAVE_DATA, 0x00);
}

#[test]
fn gsi_to_isa_line_reverses_the_madt_overrides() {
    // IRQ0 is wired to GSI2 (8254 cascade), IRQ9 to GSI9; the rest is the
    // identity. GSIs above the ISA range have no 8259 line.
    assert_eq!(emulate::gsi_isa_irq(emulate::isa_gsi(0)), Some(0));
    assert_eq!(emulate::gsi_isa_irq(emulate::isa_gsi(9)), Some(9));
    // IRQ2 is the 8259 cascade: it has no device and its identity GSI2 is the
    // same pin the MADT override gives to IRQ0, so it cannot round-trip. Every
    // line that a device can actually raise does.
    for irq in [1u8, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15] {
        assert_eq!(
            emulate::gsi_isa_irq(emulate::isa_gsi(irq)),
            Some(irq),
            "IRQ{irq} must round-trip through its GSI"
        );
    }
    assert_eq!(emulate::gsi_isa_irq(16), None);
    assert_eq!(emulate::gsi_isa_irq(64), None);
}

#[test]
fn a_timer_expiry_reaches_the_8259_pair_in_pic_mode() {
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    init_legacy_pic(&mut devices);
    mask_ioapic_pins(&mut devices);
    // The 8254 channel-0 line is GSI2 on a PC: the pair must acknowledge IRQ0
    // and the vector must reach the local APIC.
    emulate::pulse_device_line(&mut devices, &mut apic, emulate::isa_gsi(pit::IRQ_LINE));
    assert_eq!(devices.pic.master().isr(), 0x01);
    assert_eq!(devices.pic.master().irr(), 0x00);
    assert_eq!(apic.pending_vector(), Some(0x20));
}

#[test]
fn the_guest_end_of_interrupt_releases_the_8259_in_service_register() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0xE6, 0x20]); // out 0x20, al (non-specific EOI)
    let mut guest = TestGuest::new(rip);
    guest.regs[0] = 0x20;
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    init_legacy_pic(&mut devices);
    mask_ioapic_pins(&mut devices);
    emulate::pulse_device_line(&mut devices, &mut apic, emulate::isa_gsi(pit::IRQ_LINE));
    assert_eq!(devices.pic.master().isr(), 0x01);
    assert!(replay_port(
        &mut memory,
        &mut guest,
        &mut devices,
        &mut apic,
        pic::port::MASTER_COMMAND,
        false
    ));
    assert_eq!(devices.pic.master().isr(), 0x00);
}

#[test]
fn a_masked_8259_line_is_latched_and_delivered_on_unmask() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0xE6, 0x21]); // out 0x21, al (mask write)
    let mut guest = TestGuest::new(rip);
    guest.regs[0] = 0x00; // unmask every master line
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    init_legacy_pic(&mut devices);
    mask_ioapic_pins(&mut devices);
    devices.pic.write(pic::port::MASTER_DATA, 0xFF); // mask everything
    emulate::pulse_device_line(&mut devices, &mut apic, emulate::isa_gsi(pit::IRQ_LINE));
    assert_eq!(apic.pending_vector(), None, "a masked line must not deliver");
    assert_eq!(devices.pic.master().isr(), 0x00);
    // Unmasking through the port path makes the pending request deliverable.
    assert!(replay_port(
        &mut memory,
        &mut guest,
        &mut devices,
        &mut apic,
        pic::port::MASTER_DATA,
        false
    ));
    assert_eq!(apic.pending_vector(), Some(0x20));
    assert_eq!(devices.pic.master().isr(), 0x01);
}

#[test]
fn a_level_line_is_not_acknowledged_twice_while_in_service() {
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    init_legacy_pic(&mut devices);
    mask_ioapic_pins(&mut devices);
    let line = emulate::isa_gsi(uart::IRQ_LINE);
    emulate::set_device_line(&mut devices, &mut apic, line, true);
    assert_eq!(devices.pic.master().isr(), 1 << uart::IRQ_LINE);
    assert_eq!(devices.pic.master().irr(), 0x00);
    assert_eq!(apic.pending_vector(), Some(0x24));
    // The line stays high: a second evaluation must not create a second
    // in-service request, because the guest has not acknowledged the first.
    emulate::set_device_line(&mut devices, &mut apic, line, true);
    assert_eq!(devices.pic.master().isr(), 1 << uart::IRQ_LINE);
    assert_eq!(apic.pending_vector(), Some(0x24));
    // The pair is edge-triggered by default: deasserting the line leaves both
    // the in-service bit and the latched edge to the guest, exactly like the
    // real ladder (the edge is acknowledged, not the level).
    emulate::set_device_line(&mut devices, &mut apic, line, false);
    assert_eq!(devices.pic.master().isr(), 1 << uart::IRQ_LINE);
    assert_eq!(devices.pic.master().irr(), 1 << uart::IRQ_LINE);
}

#[test]
fn a_slave_line_is_delivered_through_the_cascade_in_pic_mode() {
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    init_legacy_pic(&mut devices);
    mask_ioapic_pins(&mut devices);
    // The CMOS clock is ISA IRQ8, on the slave chip.
    emulate::pulse_device_line(&mut devices, &mut apic, emulate::isa_gsi(rtc::IRQ_LINE));
    assert_eq!(devices.pic.master().isr(), 1 << pic::CASCADE_IRQ);
    assert_eq!(devices.pic.slave().isr(), 0x01);
    assert_eq!(apic.pending_vector(), Some(0x28));
}
/// Masks every I/O APIC pin, as firmware does before an operating system picks
/// its interrupt mode. The model pre-programs the device pins unmasked so a
/// guest that follows the MADT works without a routing policy; a guest that
/// keeps the legacy pair must see the 8259 path alone.
fn mask_ioapic_pins(devices: &mut Devices) {
    for pin in 0..ioapic::PIN_COUNT {
        let vector = devices
            .ioapic
            .vector_for_pin(pin)
            .unwrap_or(emulate::PIT_IRQ_VECTOR);
        devices.ioapic.set_pin(pin, vector, true);
    }
}
// ---------------------------------------------------------------------------
// PCI configuration mechanism #1 (host bridge + virtio functions).
// ---------------------------------------------------------------------------

/// Replays one port access of an explicit width (the generic helper above is
/// byte-wide, which is what the legacy devices use).
fn replay_port_sized(
    memory: &mut TestMemory,
    guest: &mut TestGuest,
    devices: &mut Devices,
    apic: &mut apic::LocalApic,
    port: u16,
    is_in: bool,
    size: u8,
) -> bool {
    let qualification = (u64::from(port) << 16)
        | if is_in { 0x8 } else { 0 }
        | u64::from(size.saturating_sub(1));
    let mut view = view(memory, guest);
    handle_exit(
        devices,
        apic,
        &mut view,
        guest,
        ExitClass::IoPort,
        qualification,
        0,
    )
    .expect("emulated port access")
}

/// Writes the 32-bit CAM register (port 0xCF8) from EAX.
fn pci_write_cam(
    memory: &mut TestMemory,
    guest: &mut TestGuest,
    devices: &mut Devices,
    apic: &mut apic::LocalApic,
    value: u32,
) {
    let rip = load_code(memory, &[0xEF]); // out dx, eax
    guest.rip = rip;
    guest.regs[0] = u64::from(value);
    guest.regs[2] = u64::from(pci::CONFIG_ADDRESS);
    assert!(replay_port_sized(
        memory,
        guest,
        devices,
        apic,
        pci::CONFIG_ADDRESS,
        false,
        4
    ));
}

/// Reads one configuration dword (port 0xCFC) into EAX.
fn pci_read_data(
    memory: &mut TestMemory,
    guest: &mut TestGuest,
    devices: &mut Devices,
    apic: &mut apic::LocalApic,
) -> u32 {
    let rip = load_code(memory, &[0xED]); // in eax, dx
    guest.rip = rip;
    guest.regs[2] = u64::from(pci::CONFIG_DATA);
    assert!(replay_port_sized(
        memory,
        guest,
        devices,
        apic,
        pci::CONFIG_DATA,
        true,
        4
    ));
    guest.regs[0] as u32
}

#[test]
fn pci_configuration_ports_are_claimed() {
    assert!(emulate::handles_pci_port(pci::CONFIG_ADDRESS));
    assert!(emulate::handles_pci_port(pci::CONFIG_DATA + 3));
    assert!(!emulate::handles_pci_port(pci::CONFIG_ADDRESS - 1));
    assert!(!emulate::handles_pci_port(pci::CONFIG_DATA + 4));
    assert!(Devices::handles_port(pci::CONFIG_ADDRESS));
    assert!(Devices::handles_port(pci::CONFIG_DATA));
}

#[test]
fn pci_host_bridge_answers_its_identity() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0xED]);
    let mut guest = TestGuest::new(rip);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    // Enable, bus 0, device 0, function 0, register 0.
    pci_write_cam(&mut memory, &mut guest, &mut devices, &mut apic, 0x8000_0000);
    let identity = pci_read_data(&mut memory, &mut guest, &mut devices, &mut apic);
    assert_eq!(identity & 0xFFFF, pci::HOST_BRIDGE_VENDOR_ID as u32);
    assert_eq!(identity >> 16, pci::HOST_BRIDGE_DEVICE_ID as u32);
}

#[test]
fn pci_virtio_functions_are_visible_on_bus_zero() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0xED]);
    let mut guest = TestGuest::new(rip);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    for (slot, device_type) in [
        (emulate::PCI_CONSOLE_SLOT, pci::virtio_device_type::CONSOLE),
        (emulate::PCI_BLK_SLOT, pci::virtio_device_type::BLOCK),
        (emulate::PCI_NET_SLOT, pci::virtio_device_type::NET),
    ] {
        let cam = 0x8000_0000u32 | (u32::from(slot) << 11);
        pci_write_cam(&mut memory, &mut guest, &mut devices, &mut apic, cam);
        let identity = pci_read_data(&mut memory, &mut guest, &mut devices, &mut apic);
        assert_eq!(
            identity & 0xFFFF,
            pci::VIRTIO_VENDOR_ID as u32,
            "slot {slot} must expose the virtio vendor id"
        );
        assert_eq!(
            identity >> 16,
            u32::from(pci::VIRTIO_MODERN_DEVICE_ID_BASE + u16::from(device_type)),
            "slot {slot} must expose the modern virtio device id"
        );
    }
}

#[test]
fn pci_disabled_cam_reads_all_ones() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0xED]);
    let mut guest = TestGuest::new(rip);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    // Without the enable bit the bridge answers as if the bus floated.
    pci_write_cam(&mut memory, &mut guest, &mut devices, &mut apic, 0);
    assert_eq!(
        pci_read_data(&mut memory, &mut guest, &mut devices, &mut apic),
        0xFFFF_FFFF
    );
}

#[test]
fn pci_virtio_bar_can_be_sized_and_placed_by_the_guest() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0xEF, 0xED]);
    let mut guest = TestGuest::new(rip);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    // Console function BAR0 (offset 0x10).
    let cam = 0x8000_0000u32 | (u32::from(emulate::PCI_CONSOLE_SLOT) << 11) | 0x10;
    pci_write_cam(&mut memory, &mut guest, &mut devices, &mut apic, cam);
    // Program a 64-bit memory BAR at 0xFE00_0000.
    let rip = load_code(&mut memory, &[0xEF]);
    guest.rip = rip;
    guest.regs[0] = 0xFE00_0000;
    guest.regs[2] = u64::from(pci::CONFIG_DATA);
    assert!(replay_port_sized(
        &mut memory,
        &mut guest,
        &mut devices,
        &mut apic,
        pci::CONFIG_DATA,
        false,
        4
    ));
    let placed = devices.pci.memory_map().windows().len();
    assert!(placed >= 1, "the programmed BAR must appear in the map");
    assert_eq!(
        devices.pci.memory_map().find(0xFE00_0000).map(|w| w.size),
        Some(pci::VIRTIO_BAR_SIZE)
    );
}
// ---------------------------------------------------------------------------
// High-precision event timer (MMIO page at 0xFED0_0000).
// ---------------------------------------------------------------------------

#[test]
fn the_hpet_page_is_a_modeled_device_page() {
    assert_eq!(
        emulate::device_page(hpet::BASE_GPA),
        Some(emulate::DevicePage::Hpet)
    );
    assert_eq!(
        emulate::device_page(hpet::BASE_GPA + hpet::MMIO_SIZE as u64 - 4),
        Some(emulate::DevicePage::Hpet)
    );
    assert_eq!(
        emulate::device_page(hpet::BASE_GPA + 0x1000),
        None
    );
}

#[test]
fn hpet_capability_register_is_readable_through_the_device_page() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0x48, 0x8B, 0x08]); // mov rcx, [rax]
    let mut guest = TestGuest::new(rip);
    guest.regs[0] = hpet::BASE_GPA + u64::from(hpet::CAPS_ID);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    let mut view = view(&mut memory, &guest);
    let handled = handle_exit(
        &mut devices,
        &mut apic,
        &mut view,
        &mut guest,
        ExitClass::EptViolation,
        0b011,
        hpet::BASE_GPA + u64::from(hpet::CAPS_ID),
    )
    .expect("emulated");
    assert!(handled);
    assert_eq!(guest.regs[1], devices.hpet.caps().encode());
}

#[test]
fn hpet_configuration_and_counter_are_visible_to_the_guest() {
    let mut memory = machine();
    let rip = load_code(&mut memory, &[0x89, 0x08]); // mov [rax], ecx
    let mut guest = TestGuest::new(rip);
    guest.regs[0] = hpet::BASE_GPA + u64::from(hpet::CONFIG);
    guest.regs[1] = u64::from(hpet::CONFIG_ENABLE);
    let mut devices = Devices::new();
    let mut apic = apic::LocalApic::new(0);
    let mut config_view = view(&mut memory, &guest);
    assert!(handle_exit(
        &mut devices,
        &mut apic,
        &mut config_view,
        &mut guest,
        ExitClass::EptViolation,
        0b001,
        hpet::BASE_GPA + u64::from(hpet::CONFIG),
    )
    .expect("emulated"));
    assert!(devices.hpet.enabled());
    // The counter advances with the device time base and reads back 64-bit.
    devices.hpet.advance_ticks(1000);
    assert_eq!(devices.hpet.counter(), 1000);
    let rip = load_code(&mut memory, &[0x48, 0x8B, 0x08]); // mov rcx, [rax]
    guest.rip = rip;
    guest.regs[0] = hpet::BASE_GPA + u64::from(hpet::COUNTER);
    let mut counter_view = view(&mut memory, &guest);
    assert!(handle_exit(
        &mut devices,
        &mut apic,
        &mut counter_view,
        &mut guest,
        ExitClass::EptViolation,
        0b011,
        hpet::BASE_GPA + u64::from(hpet::COUNTER),
    )
    .expect("emulated"));
    assert_eq!(guest.regs[1], 1000);
}