//! Intel VT-d backend (x86_64).
//!
//! P1/P2 status:
//! * the DMAR is parsed at boot and every DRHD register block is probed for
//!   `CAP`/`ECAP`;
//! * a **shadow** root table, per-bus context tables and four-level
//!   second-level page tables are built in kernel memory from the same
//!   `hardware::iommu` domain model used by the DMA allocator;
//! * 4 KiB, 2 MiB and 1 GiB leaves are supported;
//! * hardware activation (RTADDR + GCMD.TE + invalidations) is implemented but
//!   gated by [`HARDWARE_ACTIVATION_ENABLED`], which stays `false` until the
//!   path has been validated under QEMU `intel-iommu`.  Until then
//!   `is_ready()` is false and `activate()` returns `NotReady`.
//!
//! This gives the rest of the kernel a coherent, inspectable translation
//! model without risking the boot on unproven MMIO programming.

use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use super::super::iommu::{Backend, Discovery, IommuError};
use crate::{
    hardware::iommu::{DmaProt, DomainId, MappingKind, Sbdf},
    memory,
    sync::SpinLock,
};

/// Flip only after QEMU/hardware validation of the activation path.
pub const HARDWARE_ACTIVATION_ENABLED: bool = false;

// Register offsets from the DRHD register base.
const VTD_CAP: usize = 0x08;
const VTD_ECAP: usize = 0x10;
const VTD_GCMD: usize = 0x18;
const VTD_GSTS: usize = 0x1c;
const VTD_RTADDR: usize = 0x20;
const VTD_CCMD: usize = 0x28;

const GCMD_SRTP: u32 = 1 << 30;
const GCMD_TE: u32 = 1 << 31;
const GSTS_RTPS: u32 = 1 << 30;
const GSTS_TES: u32 = 1 << 31;

const ECAP_IR: u64 = 1 << 3;

const CAP_CM: u64 = 1 << 7;

/// Page-table entry flags for second-level tables.
const SL_PRESENT: u64 = 1 << 0;
const SL_WRITE: u64 = 1 << 1;
const SL_SUPERPAGE: u64 = 1 << 7;
const SL_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

struct Unit {
    segment: u16,
    #[allow(dead_code)]
    register_base: u64,
    /// HHDM mapping of `register_base`.
    virt: u64,
    cap: u64,
    ecap: u64,
}

struct DomainShadow {
    /// Second-level PML4 physical address.
    slpt: u64,
}

struct VtdState {
    root: u64,
    /// bus -> context table physical address.
    context_tables: BTreeMap<u8, u64>,
    domains: BTreeMap<DomainId, DomainShadow>,
    units: Vec<Unit>,
}

static STATE: SpinLock<Option<VtdState>> = SpinLock::new(None);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static DISCOVERY: SpinLock<Option<Discovery>> = SpinLock::new(None);

struct VtdBackend;

static VTD: VtdBackend = VtdBackend;

impl Backend for VtdBackend {
    fn name(&self) -> &'static str {
        "vt-d"
    }

    fn is_ready(&self) -> bool {
        HARDWARE_ACTIVATION_ENABLED && STATE.lock().is_some()
    }

    fn activate(&self) -> Result<(), IommuError> {
        if ACTIVE.load(Ordering::Acquire) {
            return Ok(());
        }
        if !HARDWARE_ACTIVATION_ENABLED {
            return Err(IommuError::NotReady);
        }

        let mut guard = STATE.lock();
        let state = guard.as_mut().ok_or(IommuError::NotPresent)?;
        if state.units.is_empty() {
            return Err(IommuError::NotPresent);
        }
        for unit in &state.units {
            if unit.cap & CAP_CM != 0 {
                // Register-based invalidation is unavailable with CM=1.  A
                // queued-invalidation implementation is the next milestone.
                log::warn!(
                    "[IOMMU] unit seg={} has CM=1 (queued invalidation required)",
                    unit.segment
                );
                return Err(IommuError::Unsupported);
            }
        }

        for unit in &state.units {
            mmio_write64(unit.virt, VTD_RTADDR, state.root);
            let gcmd = mmio_read32(unit.virt, VTD_GCMD) | GCMD_SRTP | GCMD_TE;
            mmio_write32(unit.virt, VTD_GCMD, gcmd);
            if !wait_bits(unit.virt, VTD_GSTS, GSTS_RTPS | GSTS_TES) {
                log::error!(
                    "[IOMMU] unit seg={} refused translation enable (GSTS timeout)",
                    unit.segment
                );
                return Err(IommuError::Hardware);
            }
            invalidate_unit(unit);
        }

        ACTIVE.store(true, Ordering::Release);
        log::info!("[IOMMU] VT-d translation enabled on {} unit(s)", state.units.len());
        Ok(())
    }

    fn invalidate_domain(&self, domain: DomainId) {
        if !ACTIVE.load(Ordering::Acquire) {
            return;
        }
        if let Some(state) = STATE.lock().as_ref() {
            if state.domains.contains_key(&domain) {
                for unit in &state.units {
                    invalidate_unit(unit);
                }
            }
        }
    }

    fn map(
        &self,
        domain: DomainId,
        sbdf: Sbdf,
        iova: u64,
        phys: u64,
        len: u64,
        prot: DmaProt,
        kind: MappingKind,
    ) -> Result<(), IommuError> {
        let mut guard = STATE.lock();
        let state = guard.as_mut().ok_or(IommuError::NotPresent)?;

        // Context table for the device's bus.
        let context = match state.context_tables.get(&sbdf.bus) {
            Some(context) => *context,
            None => {
                let context = alloc_zeroed_table()?;
                state.context_tables.insert(sbdf.bus, context);
                install_root_entry(state.root, sbdf.segment, sbdf.bus, context)?;
                context
            }
        };

        // One second-level tree per domain.
        let slpt = match state.domains.get(&domain) {
            Some(shadow) => shadow.slpt,
            None => {
                let slpt = alloc_zeroed_table()?;
                state.domains.insert(domain, DomainShadow { slpt });
                slpt
            }
        };

        install_context_entry(context, sbdf, slpt)?;

        let mut offset = 0u64;
        while offset < len {
            if let Err(err) = install_leaf(slpt, iova + offset, phys + offset, kind, prot) {
                // Roll back the leaves already installed by this call so the
                // shadow never advertises a partial mapping.
                let mut done = 0u64;
                while done < offset {
                    let _ = clear_leaf(slpt, iova + done, kind);
                    done += kind.size();
                }
                return Err(err);
            }
            offset += kind.size();
        }

        if ACTIVE.load(Ordering::Acquire) {
            flush_context();
            for unit in &state.units {
                invalidate_unit(unit);
            }
        }
        Ok(())
    }

    fn unmap(
        &self,
        domain: DomainId,
        _sbdf: Sbdf,
        iova: u64,
        len: u64,
        kind: MappingKind,
    ) -> Result<(), IommuError> {
        let guard = STATE.lock();
        let state = guard.as_ref().ok_or(IommuError::NotPresent)?;
        let shadow = state.domains.get(&domain).ok_or(IommuError::InvalidDomain)?;

        let mut offset = 0u64;
        while offset < len {
            clear_leaf(shadow.slpt, iova + offset, kind)?;
            offset += kind.size();
        }

        drop(guard);
        if ACTIVE.load(Ordering::Acquire) {
            if let Some(state) = STATE.lock().as_ref() {
                for unit in &state.units {
                    invalidate_unit(unit);
                }
            }
        }
        Ok(())
    }

    fn interrupt_remapping(&self) -> bool {
        STATE
            .lock()
            .as_ref()
            .map(|state| state.units.iter().any(|unit| unit.ecap & ECAP_IR != 0))
            .unwrap_or(false)
    }

    fn interrupt_remapping_active(&self) -> bool {
        // IRTAs are not programmed yet: MSI must keep using physical
        // destinations, and the guard in `msi.rs` enforces the 8-bit limit.
        false
    }
}

/// Parse the DMAR, probe the units and build the shadow root table.
pub fn init() -> Discovery {
    let Some(dmar) = crate::acpi::get_dmar() else {
        *DISCOVERY.lock() = Some(Discovery::absent());
        return Discovery::absent();
    };

    let units = match dmar.drhds() {
        Ok(units) => units,
        Err(err) => {
            log::warn!("[IOMMU] DMAR DRHD parse error: {:?}", err);
            Vec::new()
        }
    };

    let mut probed = Vec::new();
    for unit in &units {
        let virt = match map_mmio(unit.register_base) {
            Some(virt) => virt,
            None => continue,
        };
        let cap = mmio_read64(virt, VTD_CAP);
        let ecap = mmio_read64(virt, VTD_ECAP);
        log::info!(
            "[IOMMU] DRHD seg={} base={:#x} include_all={} scopes={} cap={:#x} ecap={:#x}",
            unit.segment,
            unit.register_base,
            unit.include_pci_all(),
            unit.scopes.len(),
            cap,
            ecap
        );
        probed.push(Unit {
            segment: unit.segment,
            register_base: unit.register_base,
            virt,
            cap,
            ecap,
        });
    }

    let mut ready = false;
    match alloc_zeroed_table() {
        Ok(root) => {
            let state = VtdState {
                root,
                context_tables: BTreeMap::new(),
                domains: BTreeMap::new(),
                units: probed,
            };
            ready = !state.units.is_empty();
            *STATE.lock() = Some(state);
            log::info!(
                "[IOMMU] VT-d shadow root at {:#x} ({} unit(s), activation {})",
                root,
                ready as u8,
                if HARDWARE_ACTIVATION_ENABLED {
                    "enabled"
                } else {
                    "locked"
                }
            );
        }
        Err(err) => {
            log::warn!("[IOMMU] cannot allocate VT-d root table: {:?}", err);
            *STATE.lock() = None;
        }
    }

    let discovery = Discovery {
        present: true,
        // Shadow tables alone do not enable translation.
        ready: ready && HARDWARE_ACTIVATION_ENABLED,
        backend: "vt-d",
        units: units.len() as u32,
        rmrrs: dmar.rmrrs().map(|v| v.len()).unwrap_or(0) as u32,
        atsrs: dmar.atsrs().map(|v| v.len()).unwrap_or(0) as u32,
        host_address_width: dmar.host_address_width(),
        intr_remap: dmar.intr_remap_supported(),
        x2apic_opt_out: dmar.x2apic_opt_out(),
    };
    *DISCOVERY.lock() = Some(discovery);
    discovery
}

/// Summary recorded by [`init`].
pub fn discovery() -> Discovery {
    DISCOVERY
        .lock()
        .as_ref()
        .copied()
        .unwrap_or_else(Discovery::absent)
}

/// Backend handle, available only when a DMAR was found.
pub fn backend() -> Option<&'static dyn Backend> {
    let present = DISCOVERY
        .lock()
        .as_ref()
        .map(|discovery| discovery.present)
        .unwrap_or(false);
    if present {
        Some(&VTD)
    } else {
        None
    }
}

// =============================================================================
// Table helpers
// =============================================================================

fn alloc_zeroed_table() -> Result<u64, IommuError> {
    let frame =
        crate::sync::with_irqs_disabled(|token| memory::allocate_phys_contiguous(token, 0))
            .map_err(|_| IommuError::Hardware)?;
    let phys = frame.start_address.as_u64();
    let virt = memory::phys_to_virt(phys) as *mut u8;
    // SAFETY: the buddy allocator returned a full 4 KiB frame that is now
    // owned by the IOMMU backend; the HHDM pointer is valid for 4 KiB.
    unsafe {
        core::ptr::write_bytes(virt, 0, 4096);
    }
    Ok(phys)
}

fn map_mmio(base: u64) -> Option<u64> {
    if base == 0 {
        return None;
    }
    memory::paging::ensure_identity_map_range(base, 0x1000);
    Some(memory::phys_to_virt(base))
}

fn mmio_read32(virt: u64, offset: usize) -> u32 {
    // SAFETY: `virt` maps a full 4 KiB register page.
    unsafe { core::ptr::read_volatile((virt as usize + offset) as *const u32) }
}

fn mmio_read64(virt: u64, offset: usize) -> u64 {
    // SAFETY: as above.
    unsafe { core::ptr::read_volatile((virt as usize + offset) as *const u64) }
}

fn mmio_write32(virt: u64, offset: usize, value: u32) {
    // SAFETY: as above.
    unsafe { core::ptr::write_volatile((virt as usize + offset) as *mut u32, value) }
}

fn mmio_write64(virt: u64, offset: usize, value: u64) {
    // SAFETY: as above.
    unsafe { core::ptr::write_volatile((virt as usize + offset) as *mut u64, value) }
}

fn wait_bits(virt: u64, offset: usize, mask: u32) -> bool {
    for _ in 0..1_000_000 {
        if mmio_read32(virt, offset) & mask == mask {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn invalidate_unit(unit: &Unit) {
    // Context-cache global invalidation: ICC=1, CIRG=01.
    mmio_write64(unit.virt, VTD_CCMD, (1u64 << 63) | (1u64 << 61));
    // IOTLB global invalidation: IIRG=001 in GCMD[63:61].
    let gcmd = mmio_read64(unit.virt, VTD_GCMD);
    mmio_write64(unit.virt, VTD_GCMD, gcmd | (1u64 << 61));
}

fn flush_context() {
    // Per-unit context invalidation is issued in `invalidate_unit`.
}

unsafe fn table_read(phys: u64, index: usize) -> u64 {
    let ptr = memory::phys_to_virt(phys) as *const u64;
    // SAFETY: `phys` is a 4 KiB table owned by the backend.
    unsafe { core::ptr::read_volatile(ptr.add(index)) }
}

unsafe fn table_write(phys: u64, index: usize, value: u64) {
    let ptr = memory::phys_to_virt(phys) as *mut u64;
    // SAFETY: as above.
    unsafe { core::ptr::write_volatile(ptr.add(index), value) }
}

fn install_root_entry(root: u64, _segment: u16, bus: u8, context: u64) -> Result<(), IommuError> {
    let entry = SL_PRESENT | (context & SL_ADDR_MASK);
    // SAFETY: `root` is a 4 KiB root table; the bus selects a 16-byte entry.
    unsafe {
        table_write(root, (bus as usize) * 2, entry);
        table_write(root, (bus as usize) * 2 + 1, 0);
    }
    Ok(())
}

fn install_context_entry(
    context: u64,
    sbdf: Sbdf,
    slpt: u64,
) -> Result<(), IommuError> {
    // Translation type 01 (translated), AGAW 010 (48-bit).
    let flags = SL_PRESENT | (0b01 << 2) | (0b010 << 4);
    let entry = flags | (slpt & SL_ADDR_MASK);
    let index = ((sbdf.device as usize) << 3) | sbdf.function as usize;
    // SAFETY: `context` is a 4 KiB table, index < 256.
    unsafe {
        table_write(context, index * 2, entry);
        table_write(context, index * 2 + 1, 0);
    }
    Ok(())
}

fn next_table(table: u64, index: usize) -> Result<u64, IommuError> {
    // SAFETY: `table` is a 4 KiB table and `index` < 512.
    let entry = unsafe { table_read(table, index) };
    if entry & SL_PRESENT != 0 {
        return Ok(entry & SL_ADDR_MASK);
    }
    let fresh = alloc_zeroed_table()?;
    // SAFETY: same as above.
    unsafe {
        table_write(table, index, SL_PRESENT | SL_WRITE | (fresh & SL_ADDR_MASK));
    }
    Ok(fresh)
}

fn install_leaf(
    slpt: u64,
    iova: u64,
    phys: u64,
    kind: MappingKind,
    prot: DmaProt,
) -> Result<(), IommuError> {
    let mut flags = SL_PRESENT;
    if prot.writable() {
        flags |= SL_WRITE;
    }
    let pml4 = ((iova >> 39) & 0x1ff) as usize;
    let pdpt = ((iova >> 30) & 0x1ff) as usize;
    let pd = ((iova >> 21) & 0x1ff) as usize;
    let pt = ((iova >> 12) & 0x1ff) as usize;

    let pdpt_table = next_table(slpt, pml4)?;
    match kind {
        MappingKind::Page1G => {
            // SAFETY: `pdpt_table` is a 4 KiB table.
            unsafe {
                table_write(
                    pdpt_table,
                    pdpt,
                    flags | SL_SUPERPAGE | (phys & SL_ADDR_MASK & !((1u64 << 30) - 1)),
                );
            }
            return Ok(());
        }
        _ => {}
    }

    let pd_table = next_table(pdpt_table, pdpt)?;
    if kind == MappingKind::Page2M {
        // SAFETY: `pd_table` is a 4 KiB table.
        unsafe {
            table_write(
                pd_table,
                pd,
                flags | SL_SUPERPAGE | (phys & SL_ADDR_MASK & !((1u64 << 21) - 1)),
            );
        }
        return Ok(());
    }

    let pt_table = next_table(pd_table, pd)?;
    // SAFETY: `pt_table` is a 4 KiB table.
    unsafe {
        table_write(pt_table, pt, flags | (phys & SL_ADDR_MASK));
    }
    Ok(())
}

fn clear_leaf(slpt: u64, iova: u64, kind: MappingKind) -> Result<(), IommuError> {
    let pml4 = ((iova >> 39) & 0x1ff) as usize;
    let pdpt = ((iova >> 30) & 0x1ff) as usize;
    let pd = ((iova >> 21) & 0x1ff) as usize;
    let pt = ((iova >> 12) & 0x1ff) as usize;

    // SAFETY: all tables are 4 KiB and indices are masked to 9 bits.
    unsafe {
        let pdpt_entry = table_read(slpt, pml4);
        if pdpt_entry & SL_PRESENT == 0 {
            return Ok(());
        }
        let pdpt_table = pdpt_entry & SL_ADDR_MASK;
        if kind == MappingKind::Page1G {
            table_write(pdpt_table, pdpt, 0);
            return Ok(());
        }
        let pd_entry = table_read(pdpt_table, pdpt);
        if pd_entry & SL_PRESENT == 0 {
            return Ok(());
        }
        let pd_table = pd_entry & SL_ADDR_MASK;
        if kind == MappingKind::Page2M {
            table_write(pd_table, pd, 0);
            return Ok(());
        }
        let pt_entry = table_read(pd_table, pt);
        if pt_entry & SL_PRESENT == 0 {
            return Ok(());
        }
        let pt_table = pt_entry & SL_ADDR_MASK;
        table_write(pt_table, pt, 0);
    }
    Ok(())
}
