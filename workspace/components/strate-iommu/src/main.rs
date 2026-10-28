//! `strate-iommu` : IOMMU policy and diagnostic server.
//!
//! P1 scope: this server is deliberately **outside the data path**.  Drivers
//! keep direct access to their `IommuDomain` capabilities; this strate binds
//! `/srv/iommu` and exposes a small textual control endpoint for init and
//! administrators:
//!
//! ```text
//! msg_type 0x10 : platform summary   (IommuInfo)
//! msg_type 0x11 : global counters    (IommuStats)
//! msg_type 0x12 : drain fault queue  (IommuFault, text lines)
//! msg_type 0x13 : reserved regions   (RMRR/IVMD)
//! msg_type 0x14 : coarse IOMMU groups
//! msg_type 0x15 : attempt activation (returns 1/0/errno)
//! ```
//!
//! Replies are `IpcMessage::REPLY_MSG_TYPE` with UTF-8 text in `payload`.
//!
//! The server is safe to restart: domains are kernel objects owned by their
//! capabilities, so a new instance simply re-reads the state through the
//! `SYS_IOMMU_*` syscalls.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::{alloc::Layout, fmt::Write, panic::PanicInfo};
use strat9_abi::iommu::{
    IommuDomainInfo, IommuFault, IommuGroupInfo, IommuInfo, IommuReservedRegion, IommuStats,
};
use strat9_syscall::{
    call,
    data::{IpcMessage, TimeSpec},
    error, number, syscall2,
};

alloc_freelist::define_freelist_brk_allocator!(
    pub struct BumpAllocator;
    brk = strat9_syscall::call::brk;
    heap_max = 4 * 1024 * 1024;
);

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    log("[strate-iommu] OOM\n");
    call::exit(12);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("strate-iommu", info)
}

const OP_INFO: u32 = 0x10;
const OP_STATS: u32 = 0x11;
const OP_FAULTS: u32 = 0x12;
const OP_RESERVED: u32 = 0x13;
const OP_GROUPS: u32 = 0x14;
const OP_ACTIVATE: u32 = 0x15;

fn log(message: &str) {
    let _ = call::debug_log(message.as_bytes());
}

fn log_errno(prefix: &str, err: error::Error) {
    let mut buffer = [0u8; 96];
    let len = {
        let mut writer = PayloadWriter::new(&mut buffer);
        let _ = write!(writer, "{}{}", prefix, err.to_errno());
        writer.position()
    };
    if let Ok(message) = core::str::from_utf8(&buffer[..len]) {
        log(message);
    }
}

struct PayloadWriter<'a> {
    buffer: &'a mut [u8],
    position: usize,
}

impl<'a> PayloadWriter<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }

    fn position(&self) -> usize {
        self.position
    }
}

impl Write for PayloadWriter<'_> {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let available = self.buffer.len().saturating_sub(self.position);
        let length = text.len().min(available);
        self.buffer[self.position..self.position + length]
            .copy_from_slice(&text.as_bytes()[..length]);
        self.position += length;
        Ok(())
    }
}

fn render_info(writer: &mut PayloadWriter<'_>) {
    let mut info = IommuInfo::default();
    match call::iommu_info(&mut info) {
        Ok(_) => {
            let _ = writeln!(
                writer,
                "present={} enabled={} ready={} units={} domains={} width={} ir={} x2apic_opt_out={}",
                info.present,
                info.enabled,
                info.ready,
                info.units,
                info.domains,
                info.host_address_width,
                info.intr_remap,
                info.x2apic_opt_out
            );
        }
        Err(err) => {
            let _ = writeln!(writer, "error={}", err.to_errno());
        }
    }
}

fn render_stats(writer: &mut PayloadWriter<'_>) {
    let mut stats = IommuStats::default();
    match call::iommu_stats(&mut stats) {
        Ok(_) => {
            let _ = writeln!(
                writer,
                "domains created={} destroyed={} live={}",
                stats.domains_created, stats.domains_destroyed, stats.domains_live
            );
            let _ = writeln!(
                writer,
                "maps={} unmaps={} faults={} dropped={} activations={}",
                stats.maps,
                stats.unmaps,
                stats.faults,
                stats.dropped_faults,
                stats.activations
            );
        }
        Err(err) => {
            let _ = writeln!(writer, "error={}", err.to_errno());
        }
    }
}

fn render_faults(writer: &mut PayloadWriter<'_>) {
    let mut count = 0;
    loop {
        let mut fault = IommuFault::default();
        match call::iommu_fault_next(&mut fault) {
            Ok(0) => break,
            Ok(_) => {
                count += 1;
                let _ = writeln!(
                    writer,
                    "seq={} t={} domain={} sbdf={:04x}:{:02x}:{:02x}.{:x} iova={:#x} reason={} action={} owner={:#x}",
                    fault.seq,
                    fault.timestamp_ns,
                    fault.domain_id,
                    fault.segment,
                    fault.bus,
                    fault.device,
                    fault.function,
                    fault.iova,
                    fault.reason,
                    fault.action,
                    fault.owner
                );
            }
            Err(err) => {
                let _ = writeln!(writer, "error={}", err.to_errno());
                break;
            }
        }
        if count >= 32 {
            let _ = writeln!(writer, "... (truncated)");
            break;
        }
    }
    if count == 0 {
        let _ = writeln!(writer, "no faults");
    }
}

fn render_reserved(writer: &mut PayloadWriter<'_>) {
    let mut regions = [IommuReservedRegion::default(); 16];
    match call::iommu_reserved(&mut regions) {
        Ok(count) => {
            for region in &regions[..count] {
                let _ = writeln!(
                    writer,
                    "seg={} {:#x}..{:#x} devices={} all_buses={}",
                    region.segment,
                    region.base,
                    region.limit,
                    region.device_count,
                    region.all_buses
                );
            }
            if count == 0 {
                let _ = writeln!(writer, "no reserved regions");
            }
        }
        Err(err) => {
            let _ = writeln!(writer, "error={}", err.to_errno());
        }
    }
}

fn render_groups(writer: &mut PayloadWriter<'_>) {
    let mut groups = [IommuGroupInfo::default(); 16];
    match call::iommu_groups(&mut groups) {
        Ok(count) => {
            for group in &groups[..count] {
                let _ = writeln!(
                    writer,
                    "group={} seg={} bus={:02x} devices={}",
                    group.id, group.segment, group.bus, group.device_count
                );
            }
            if count == 0 {
                let _ = writeln!(writer, "no IOMMU groups");
            }
        }
        Err(err) => {
            let _ = writeln!(writer, "error={}", err.to_errno());
        }
    }
}

fn handle(msg: &IpcMessage) {
    let mut reply = IpcMessage::new(IpcMessage::REPLY_MSG_TYPE);
    reply.sender = msg.sender;

    let mut writer = PayloadWriter::new(&mut reply.payload);
    match msg.msg_type {
        OP_INFO => render_info(&mut writer),
        OP_STATS => render_stats(&mut writer),
        OP_FAULTS => render_faults(&mut writer),
        OP_RESERVED => render_reserved(&mut writer),
        OP_GROUPS => render_groups(&mut writer),
        OP_ACTIVATE => match call::iommu_activate() {
            Ok(active) => {
                let _ = writeln!(writer, "activated={}", active);
            }
            Err(err) => {
                let _ = writeln!(writer, "error={}", err.to_errno());
            }
        },
        _ => {
            let _ = writeln!(writer, "unknown command {:#x}", msg.msg_type);
        }
    }

    if let Err(err) = call::ipc_reply(&reply) {
        log_errno("[strate-iommu] reply failed: ", err);
    }
}

fn sleep_micros(micros: u64) {
    let nanos = micros.saturating_mul(1000);
    let request = TimeSpec {
        tv_sec: (nanos / 1_000_000_000) as i64,
        tv_nsec: (nanos % 1_000_000_000) as i64,
    };
    // SAFETY: raw syscall with a valid stack `TimeSpec`.
    let _ = unsafe {
        syscall2(
            number::SYS_NANOSLEEP,
            &request as *const TimeSpec as usize,
            0,
        )
    };
}

fn report_startup() {
    let mut info = IommuInfo::default();
    if call::iommu_info(&mut info).is_ok() {
        let mut buffer = [0u8; 160];
        let len = {
            let mut writer = PayloadWriter::new(&mut buffer);
            let _ = writeln!(
                writer,
                "[strate-iommu] present={} ready={} units={} domains={}",
                info.present, info.ready, info.units, info.domains
            );
            writer.position()
        };
        if let Ok(message) = core::str::from_utf8(&buffer[..len]) {
            log(message);
        }
    }

    let mut regions = [IommuReservedRegion::default(); 8];
    if let Ok(count) = call::iommu_reserved(&mut regions) {
        let mut buffer = [0u8; 96];
        let len = {
            let mut writer = PayloadWriter::new(&mut buffer);
            let _ = writeln!(writer, "[strate-iommu] reserved_regions={}", count);
            writer.position()
        };
        if let Ok(message) = core::str::from_utf8(&buffer[..len]) {
            log(message);
        }
    }
}

/// Optional helper for a future `ctl` file: copy a domain info snapshot.
pub fn domain_snapshot(handle: usize) -> Option<IommuDomainInfo> {
    let mut info = IommuDomainInfo::default();
    call::iommu_domain_info(handle, &mut info).ok()?;
    Some(info)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    log("[strate-iommu] starting\n");

    let port = match call::ipc_create_port(0) {
        Ok(port) => port as u64,
        Err(err) => {
            log_errno("[strate-iommu] create port: ", err);
            call::exit(1);
        }
    };

    if let Err(err) = call::ipc_bind_port(port as usize, b"/srv/iommu") {
        log_errno("[strate-iommu] bind /srv/iommu: ", err);
        // Do not exit: a supervisor restart loop would only repeat the same
        // failure.  Keep the port alive for diagnostics.
        log("[strate-iommu] running without /srv/iommu binding\n");
    } else {
        log("[strate-iommu] bound /srv/iommu\n");
    }

    report_startup();

    let mut message = IpcMessage::new(0);
    loop {
        match call::ipc_try_recv(port as usize, &mut message) {
            Ok(_) => handle(&message),
            Err(_) => sleep_micros(2_000),
        }
    }
}
