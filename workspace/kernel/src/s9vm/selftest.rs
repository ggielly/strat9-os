//! s9vm — hardware smoke test of the engine.
//!
//! Goal: run a minimal guest (64-bit long mode, EPT enabled, two
//! mapped pages) that writes a byte to an I/O port and then executes `hlt`, and
//! check that the full path works:
//!
//! 1. building the guest tables and the second-level tables;
//! 2. loading the control block;
//! 3. guest entry (`vmlaunch`), exit on I/O, resume, exit on `hlt`;
//! 4. clean shutdown.
//!
//! The test is only started if the kernel is enabled on VT-x and if the boot
//! option `s9vm.selftest=1` is present. It never panics: a failure is
//! logged and boot continues.

use crate::memory::frame::{FrameAllocOptions, FramePurpose, PhysFrame};
use crate::s9vm::caps::HwCaps;
use crate::s9vm::exit::{ExitClass, ExitReason};
use crate::s9vm::guest::GuestState;
use crate::s9vm::vcpu::{SecondLevelMemory, Vcpu, VcpuError};

/// Size of the test guest area: 6 pages (tables + code + stack).
const GUEST_PAGES: u64 = 6;
const GPA_PML4: u64 = 0x0000;
const GPA_PDPT: u64 = 0x1000;
const GPA_PD: u64 = 0x2000;
const GPA_CODE: u64 = 0x3000;
const GPA_STACK: u64 = 0x4000;
const GPA_PT: u64 = 0x5000;
const ENTRY_POINT: u64 = GPA_CODE;
const STACK_TOP: u64 = GPA_STACK + 0x800;

/// Byte written by the guest to the test port (0xE9).
const TEST_BYTE: u8 = 0x41;
/// I/O port used by the test (standard debug port of emulators).
const TEST_PORT: u16 = 0xE9;

/// Errors of the smoke test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelftestError {
    OutOfMemory,
    Mmu,
    Vcpu(VcpuError),
    BadExit(&'static str),
    VmFail(u32),
}

impl From<VcpuError> for SelftestError {
    fn from(value: VcpuError) -> Self {
        Self::Vcpu(value)
    }
}

/// Detailed result, logged by the caller.
pub struct SelftestReport {
    pub io_exits: u32,
    pub halt_exits: u32,
    pub total_exits: u32,
    pub observed_byte: Option<u8>,
}

/// Allocates a zeroed frame for the guest.
fn alloc_frame() -> Result<PhysFrame, SelftestError> {
    crate::sync::with_irqs_disabled(|token| {
        FrameAllocOptions::new()
            .purpose(FramePurpose::KernelData)
            .allocate(token)
    })
    .map_err(|_| SelftestError::OutOfMemory)
}

/// Writes a 64-bit value into a frame through the HHDM.
fn write_u64(frame: &PhysFrame, offset: usize, value: u64) {
    let base = crate::memory::phys_to_virt(frame.start_address.as_u64()) as *mut u8;
    // SAFETY: the frame is 4 KiB and `offset` is a valid offset.
    unsafe {
        core::ptr::write_volatile(base.add(offset) as *mut u64, value);
    }
}

/// Writes bytes into a frame through the HHDM.
fn write_bytes(frame: &PhysFrame, bytes: &[u8]) {
    let base = crate::memory::phys_to_virt(frame.start_address.as_u64()) as *mut u8;
    // SAFETY: the frame is 4 KiB and `bytes` fits in one page.
    unsafe {
        for (index, byte) in bytes.iter().enumerate() {
            core::ptr::write_volatile(base.add(index), *byte);
        }
    }
}

/// Runs the smoke test. Returns a report or an error.
pub fn run(caps: &HwCaps) -> Result<SelftestReport, SelftestError> {
    if !caps.can_run() {
        return Err(SelftestError::BadExit("platform cannot run"));
    }

    // Guest pages: PML4, PDPT, PD, code, stack, PT.
    let pml4 = alloc_frame()?;
    let pdpt = alloc_frame()?;
    let pd = alloc_frame()?;
    let code = alloc_frame()?;
    let stack = alloc_frame()?;
    let pt = alloc_frame()?;

    // Guest paging tables: GVA = GPA identity over 6 pages.
    write_u64(&pml4, 0, pdpt.start_address.as_u64() | 0x3);
    write_u64(&pdpt, 0, pd.start_address.as_u64() | 0x3);
    write_u64(&pd, 0, pt.start_address.as_u64() | 0x3);
    for page in 0..GUEST_PAGES {
        let gpa = page * crate::s9vm::mmu::PAGE_SIZE;
        write_u64(&pt, page as usize * 8, gpa | 0x3);
    }

    // Guest code: mov al, imm8 ; out 0xE9, al ; hlt.
    write_bytes(&code, &[0xB0, TEST_BYTE, 0xE6, TEST_PORT as u8, 0xF4]);

    // Second-level translation: GPA → HPA for the 6 pages.
    let mut second_level = SecondLevelMemory::new().map_err(|_| SelftestError::Mmu)?;
    let pages = [
        (GPA_PML4, &pml4),
        (GPA_PDPT, &pdpt),
        (GPA_PD, &pd),
        (GPA_CODE, &code),
        (GPA_STACK, &stack),
        (GPA_PT, &pt),
    ];
    for (gpa, frame) in pages {
        second_level
            .map_4k(
                gpa,
                frame.start_address.as_u64(),
                crate::s9vm::mmu::Perms::read_write_execute(),
            )
            .map_err(|_| SelftestError::Mmu)?;
    }
    let pointer = second_level.pointer(caps);

    let mut vcpu = Vcpu::new(caps, pointer)?;
    let guest = GuestState::long_mode_64(ENTRY_POINT, STACK_TOP, GPA_PML4);

    // Local validation before entry: a state refused here would produce a
    // "VM entry with invalid guest state" that is difficult to diagnose.
    let fixed = crate::s9vm::guest::FixedBits {
        cr0_fixed0: caps.cr0_fixed0,
        cr0_fixed1: caps.cr0_fixed1,
        cr4_fixed0: caps.cr4_fixed0,
        cr4_fixed1: caps.cr4_fixed1,
    };
    if let Err(error) = guest.validate(&fixed, caps.unrestricted_guest) {
        log::warn!("[s9vm] état invité refusé par validate(): {:?}", error);
    }

    // SAFETY: VT-x is active on this CPU (checked by the caller), interrupts
    // are disabled at the bootstrap stage, and the control
    // block has just been created for this vCPU.
    unsafe {
        vcpu.load()?;
        vcpu.configure_host()?;
        vcpu.configure(caps, &guest)?;
    }

    let mut report = SelftestReport {
        io_exits: 0,
        halt_exits: 0,
        total_exits: 0,
        observed_byte: None,
    };

    let mut outcome: Result<(), SelftestError> = Ok(());
    for _ in 0..16 {
        // SAFETY: `run` contract (block loaded, IRQs disabled).
        let exit = match unsafe { vcpu.run() } {
            Ok(exit) => exit,
            Err(error) => {
                // SAFETY: the control block is still loaded; useful
                // diagnostic for `VmFail(8/9)` failures.
                unsafe {
                    log::warn!("[s9vm] {}", vcpu.host_diagnostics());
                }
                outcome = Err(SelftestError::from(error));
                break;
            }
        };
        report.total_exits += 1;
        let class = ExitReason::decode(exit.raw_reason).class();
        match class {
            ExitClass::IoPort => {
                report.io_exits += 1;
                // I/O qualification: port in bits 16..31.
                let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                if port == TEST_PORT {
                    report.observed_byte = Some((vcpu.guest().rax & 0xFF) as u8);
                }
                // For an exit on an I/O instruction, the processor has already
                // set `GUEST_RIP` to the next instruction: do not
                // advance it again, otherwise the resume would skip the `hlt`.
                log::info!(
                    "[s9vm] sortie E/S port={:#x} octet={:?} rip={:#x} len={}",
                    port,
                    report.observed_byte,
                    vcpu.guest().rip,
                    exit.instruction_length
                );
            }
            ExitClass::Halt => {
                report.halt_exits += 1;
                break;
            }
            ExitClass::ExternalInterrupt | ExitClass::InterruptWindow => {
                // At boot, host interrupts are masked: we simply
                // resume the guest.
            }
            ExitClass::EntryFailure => {
                // SAFETY: the control block is still loaded; diagnostic
                // of the guest field refused by the processor.
                unsafe {
                    log::warn!("[s9vm] {}", vcpu.guest_diagnostics());
                }
                outcome = Err(SelftestError::BadExit("entry failure"));
                break;
            }
            _ => {
                outcome = Err(SelftestError::BadExit("unexpected exit"));
                break;
            }
        }
    }

    // SAFETY: the vCPU is no longer active; we unload its control block.
    unsafe {
        let _ = vcpu.clear();
    }

    match outcome {
        Ok(()) if report.io_exits >= 1 && report.halt_exits >= 1 => Ok(report),
        Ok(()) => Err(SelftestError::BadExit("guest did not reach hlt")),
        Err(error) => Err(error),
    }
}

/// Starts the test if the boot option `s9vm.selftest=1` is present.
///
/// Does nothing if VT-x is not active. Never panics.
pub fn maybe_run_from_boot_env(caps: &HwCaps) {
    let enabled = crate::boot_args()
        .and_then(|args| args.env_get("s9vm.selftest"))
        .map(|value| value == "1" || value == "true")
        .unwrap_or(false);
    if !enabled {
        return;
    }
    log::info!("[s9vm] test de fumée matériel demandé");
    match run(caps) {
        Ok(report) => log::info!(
            "[s9vm] selftest PASS: exits={} io={} hlt={} byte={:?}",
            report.total_exits,
            report.io_exits,
            report.halt_exits,
            report.observed_byte
        ),
        Err(error) => log::warn!("[s9vm] selftest FAIL: {:?}", error),
    }
}
