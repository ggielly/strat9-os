//! Intel VT-d backend (x86_64).
//!
//! Implements the legacy (non-scalable) translation path:
//! * DMAR/DRHD discovery and CAP/ECAP probing;
//! * shadow root/context/second-level tables (4 KiB, 2 MiB, 1 GiB leaves);
//! * queued invalidation (QI) with WAIT completion;
//! * interrupt-remapping table (IRTA/IRTE) and MSI doorbell allocation.
//!
//! Context entries follow the legacy format observed in ESXi
//! (`IOMMU-ANALYSE.md` §3.4): `TT = 00` (second-level translation), AGAW in
//! bits 6:4, domain id in the high qword bits 23:8.  QI descriptor types and
//! the IR doorbell formula follow §3.6/§3.7 of the same document.
//!
//! Activation remains gated by [`HARDWARE_ACTIVATION_ENABLED`]: the code is
//! complete but must be validated under QEMU `intel-iommu` before a boot path
//! may enable it.  Until then `is_ready()` is false, `SYS_IOMMU_ACTIVATE`
//! returns 0 and MSI stays on the physical path.

use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use super::super::iommu::{Backend, Discovery, IommuError, MsiAllocation};
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
const VTD_IQH: usize = 0x80;
const VTD_IQT: usize = 0x88;
const VTD_IQA: usize = 0x90;
const VTD_IRTA: usize = 0xb8;

const GCMD_SIRTP: u32 = 1 << 24;
const GCMD_IRE: u32 = 1 << 25;
const GCMD_QI: u32 = 1 << 26;
const GCMD_SRTP: u32 = 1 << 30;
const GCMD_TE: u32 = 1 << 31;

const GSTS_SIRTPS: u32 = 1 << 24;
const GSTS_IRES: u32 = 1 << 25;
const GSTS_QIES: u32 = 1 << 26;
const GSTS_RTPS: u32 = 1 << 30;
const GSTS_TES: u32 = 1 << 31;

const ECAP_QI: u64 = 1 << 1;
const ECAP_IR: u64 = 1 << 3;

const CAP_CM: u64 = 1 << 7;

/// Second-level page-table flags.
const SL_PRESENT: u64 = 1 << 0;
const SL_WRITE: u64 = 1 << 1;
const SL_SUPERPAGE: u64 = 1 << 7;
const SL_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

/// QI descriptor types (ESXi `IOMMU-ANALYSE.md` §3.6).
const QI_CONTEXT: u64 = 1;
const QI_IOTLB: u64 = 2;
const QI_IRTE: u64 = 4;
const QI_WAIT: u64 = 5;

const QI_ENTRIES: usize = 256;
const QI_SIZE_BYTES: usize = QI_ENTRIES * 16;

/// Number of 128-bit IRTEs (one 4 KiB page).
const IRTE_COUNT: usize = 256;

struct Qi {
    /// Physical address of the 4 KiB descriptor ring.
    queue: u64,
    /// Physical address of the WAIT status word.
    status: u64,
    /// MMIO base of the owning unit.
    register_base: u64,
    index: AtomicU16,
}

impl Qi {
    fn submit(&self, qw0: u64, qw1: u64) {
        let index = self.index.load(Ordering::Acquire) as usize;
        // SAFETY: the ring is a 4 KiB page owned by this unit and `index`
        // is always < QI_ENTRIES.
        unsafe {
            let base = memory::phys_to_virt(self.queue) as *mut u64;
            core::ptr::write_volatile(base.add(index * 2), qw0);
            core::ptr::write_volatile(base.add(index * 2 + 1), qw1);
        }
        core::sync::atomic::fence(Ordering::Release);
        let next = (index + 1) % QI_ENTRIES;
        self.index.store(next as u16, Ordering::Release);
        // Tail is a byte offset; it wraps to 0 after the last descriptor.
        let tail = ((next * 16) & (QI_SIZE_BYTES - 1)) as u64;
        // SAFETY: MMIO write to this unit's IQT register.
        unsafe {
            core::ptr::write_volatile(
                (self.register_base as usize + VTD_IQT) as *mut u64,
                tail,
            );
        }
    }

    fn wait(&self) {
        // Status word: set to ~0, ask the unit to write 0 on completion.
        // SAFETY: `status` is a 4 KiB page owned by this unit.
        unsafe {
            core::ptr::write_volatile(
                memory::phys_to_virt(self.status) as *mut u32,
                u32::MAX,
            );
        }
        core::sync::atomic::fence(Ordering::SeqCst);
        // WAIT descriptor: type 5, SW=1, status data 0, status address.
        self.submit(QI_WAIT | (1 << 4), self.status);
        for _ in 0..20_000_000 {
            // SAFETY: as above.
            let value = unsafe {
                core::ptr::read_volatile(memory::phys_to_virt(self.status) as *const u32)
            };
            if value == 0 {
                return;
            }
            core::hint::spin_loop();
        }
        log::warn!("[IOMMU] QI WAIT timeout");
    }
}

struct Unit {
    segment: u16,
    #[allow(dead_code)]
    register_base: u64,
    virt: u64,
    cap: u64,
    ecap: u64,
    qi: Option<Qi>,
}

struct DomainShadow {
    slpt: u64,
}

struct IrTable {
    phys: u64,
    used: [u64; 4],
}

impl IrTable {
    fn alloc(&mut self) -> Option<usize> {
        for word in 0..self.used.len() {
            let free = !self.used[word];
            if free != 0 {
                let bit = free.trailing_zeros() as usize;
                self.used[word] |= 1u64 << bit;
                return Some(word * 64 + bit);
            }
        }
        None
    }

    fn free(&mut self, index: usize) {
        if index < IRTE_COUNT {
            self.used[index / 64] &= !(1u64 << (index % 64));
        }
    }
}

struct VtdState {
    root: u64,
    context_tables: BTreeMap<u8, u64>,
    domains: BTreeMap<DomainId, DomainShadow>,
    units: Vec<Unit>,
    ir: Option<IrTable>,
}

static STATE: SpinLock<Option<VtdState>> = SpinLock::new(None);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static IR_ACTIVE: AtomicBool = AtomicBool::new(false);
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

        // Clear residual state (ESXi `VTDIommuPrecheckAndCleanup`).
        for unit in &mut state.units {
            mmio_write32(unit.virt, VTD_GCMD, 0);
            if !wait_gsts_clear(unit.virt) {
                return Err(IommuError::Hardware);
            }
            // Queued invalidation is mandatory when CM=1.
            if unit.ecap & ECAP_QI != 0 {
                qi_setup(unit)?;
            } else if unit.cap & CAP_CM != 0 {
                log::warn!(
                    "[IOMMU] unit seg={} requires QI (CM=1) but ECAP.QI is absent",
                    unit.segment
                );
                return Err(IommuError::Unsupported);
            }
        }

        // Root table, then context-entry translation.
        for unit in &mut state.units {
            mmio_write64(unit.virt, VTD_RTADDR, state.root);
            mmio_write32(unit.virt, VTD_GCMD, mmio_read32(unit.virt, VTD_GCMD) | GCMD_SRTP);
            if !wait_bits(unit.virt, VTD_GSTS, GSTS_RTPS) {
                return Err(IommuError::Hardware);
            }
        }

        // Optional interrupt remapping.
        if state.units.iter().any(|unit| unit.ecap & ECAP_IR != 0) {
            match ir_enable(state) {
                Ok(()) => IR_ACTIVE.store(true, Ordering::Release),
                Err(err) => log::warn!("[IOMMU] interrupt remapping unavailable: {:?}", err),
            }
        }

        // Finally enable DMA translation.
        for unit in &mut state.units {
            mmio_write32(unit.virt, VTD_GCMD, mmio_read32(unit.virt, VTD_GCMD) | GCMD_TE);
            if !wait_bits(unit.virt, VTD_GSTS, GSTS_TES) {
                log::error!("[IOMMU] unit seg={} refused TE", unit.segment);
                return Err(IommuError::Hardware);
            }
            flush_unit(unit, true, true);
        }

        ACTIVE.store(true, Ordering::Release);
        log::info!(
            "[IOMMU] VT-d translation enabled on {} unit(s), IR={}",
            state.units.len(),
            IR_ACTIVE.load(Ordering::Acquire)
        );
        Ok(())
    }

    fn invalidate_domain(&self, domain: DomainId) {
        if !ACTIVE.load(Ordering::Acquire) {
            return;
        }
        if let Some(state) = STATE.lock().as_ref() {
            if state.domains.contains_key(&domain) {
                for unit in &state.units {
                    flush_unit(unit, false, true);
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

        let context = match state.context_tables.get(&sbdf.bus) {
            Some(context) => *context,
            None => {
                let context = alloc_zeroed_table()?;
                state.context_tables.insert(sbdf.bus, context);
                install_root_entry(state.root, sbdf.bus, context)?;
                context
            }
        };

        let slpt = match state.domains.get(&domain) {
            Some(shadow) => shadow.slpt,
            None => {
                let slpt = alloc_zeroed_table()?;
                state.domains.insert(domain, DomainShadow { slpt });
                slpt
            }
        };

        install_context_entry(context, sbdf, domain, slpt)?;

        let mut offset = 0u64;
        while offset < len {
            if let Err(err) = install_leaf(slpt, iova + offset, phys + offset, kind, prot) {
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
            for unit in &state.units {
                flush_unit(unit, true, true);
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
                    flush_unit(unit, false, true);
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
        IR_ACTIVE.load(Ordering::Acquire)
    }

    fn allocate_msi(
        &self,
        sbdf: Sbdf,
        vector: u8,
    ) -> Result<MsiAllocation, IommuError> {
        if !IR_ACTIVE.load(Ordering::Acquire) {
            return Err(IommuError::NotReady);
        }
        let mut guard = STATE.lock();
        let state = guard.as_mut().ok_or(IommuError::NotPresent)?;
        let ir = state.ir.as_mut().ok_or(IommuError::NotReady)?;
        let index = ir.alloc().ok_or(IommuError::Hardware)?;
        let lapic = crate::arch::x86_64::apic::lapic_id();
        write_irte(ir, index, sbdf, vector, lapic);
        for unit in &state.units {
            if unit.ecap & ECAP_IR != 0 {
                flush_unit(unit, false, false);
                qi_flush_ir(unit);
            }
        }
        // ESXi doorbell: 0xFEE00018 | ((index * 32) & 0xFFFE0), data = 0.
        let address = 0xFEE0_0018u64 | (((index as u64) * 32) & 0xFFFE0);
        Ok(MsiAllocation {
            cookie: index as u32 + 1,
            address,
            data: 0,
        })
    }

    fn free_msi(&self, cookie: u32) -> Result<(), IommuError> {
        if cookie == 0 {
            return Err(IommuError::InvalidDomain);
        }
        let index = (cookie - 1) as usize;
        let mut guard = STATE.lock();
        let state = guard.as_mut().ok_or(IommuError::NotPresent)?;
        let phys = state.ir.as_ref().ok_or(IommuError::NotReady)?.phys;
        if index >= IRTE_COUNT {
            return Err(IommuError::InvalidDomain);
        }
        // Clear the IRTE first, then flush the IR caches.
        // SAFETY: the IR table is a 4 KiB page and index < IRTE_COUNT.
        unsafe {
            let base = memory::phys_to_virt(phys) as *mut u64;
            core::ptr::write_volatile(base.add(index * 2), 0);
            core::ptr::write_volatile(base.add(index * 2 + 1), 0);
        }
        for unit in &state.units {
            if unit.ecap & ECAP_IR != 0 {
                qi_flush_ir(unit);
            }
        }
        if let Some(ir) = state.ir.as_mut() {
            ir.free(index);
        }
        Ok(())
    }
}

// =============================================================================
// Discovery
// =============================================================================

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
            qi: None,
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
                ir: None,
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
// QI
// =============================================================================

fn qi_setup(unit: &mut Unit) -> Result<(), IommuError> {
    let queue = alloc_zeroed_table()?;
    let status = alloc_zeroed_table()?;
    let qi = Qi {
        queue,
        status,
        register_base: unit.virt,
        index: AtomicU16::new(0),
    };
    mmio_write64(unit.virt, VTD_IQA, queue);
    mmio_write64(unit.virt, VTD_IQT, 0);
    if mmio_read64(unit.virt, VTD_IQH) != 0 {
        return Err(IommuError::Hardware);
    }
    unit.qi = Some(qi);
    mmio_write32(unit.virt, VTD_GCMD, mmio_read32(unit.virt, VTD_GCMD) | GCMD_QI);
    if !wait_bits(unit.virt, VTD_GSTS, GSTS_QIES) {
        return Err(IommuError::Hardware);
    }
    Ok(())
}

fn wait_gsts_clear(virt: u64) -> bool {
    for _ in 0..1_000_000 {
        let gsts = mmio_read32(virt, VTD_GSTS);
        if gsts & (GSTS_TES | GSTS_RTPS | GSTS_IRES | GSTS_QIES | GSTS_SIRTPS) == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn qi_flush_ir(unit: &Unit) {
    if let Some(qi) = &unit.qi {
        qi.submit(QI_IRTE, 0);
        qi.wait();
    }
}

fn flush_unit(unit: &Unit, context: bool, iotlb: bool) {
    if let Some(qi) = &unit.qi {
        if context {
            qi.submit(QI_CONTEXT, 0);
        }
        if iotlb {
            qi.submit(QI_IOTLB, 0);
        }
        if context || iotlb {
            qi.wait();
        }
        return;
    }
    // Register-based fallback (only valid when CAP.CM=0).
    if context {
        mmio_write64(unit.virt, 0x28, (1u64 << 63) | (1u64 << 61));
    }
    if iotlb {
        let gcmd = mmio_read64(unit.virt, VTD_GCMD);
        mmio_write64(unit.virt, VTD_GCMD, gcmd | (1u64 << 61));
    }
}

// =============================================================================
// IR
// =============================================================================

fn ir_enable(state: &mut VtdState) -> Result<(), IommuError> {
    let phys = alloc_zeroed_table()?;
    let x2apic = crate::arch::x86_64::apic::lapic_id() > 0xff;
    state.ir = Some(IrTable {
        phys,
        used: [0; 4],
    });

    for unit in &mut state.units {
        if unit.ecap & ECAP_IR == 0 {
            continue;
        }
        // One page = 256 IRTEs, so the size field is 0.
        let irta = phys | if x2apic { 0x800 } else { 0 };
        mmio_write64(unit.virt, VTD_IRTA, irta);
        mmio_write32(unit.virt, VTD_GCMD, mmio_read32(unit.virt, VTD_GCMD) | GCMD_SIRTP);
        if !wait_bits(unit.virt, VTD_GSTS, GSTS_SIRTPS) {
            return Err(IommuError::Hardware);
        }
        qi_flush_ir(unit);
        mmio_write32(unit.virt, VTD_GCMD, mmio_read32(unit.virt, VTD_GCMD) | GCMD_IRE);
        if !wait_bits(unit.virt, VTD_GSTS, GSTS_IRES) {
            return Err(IommuError::Hardware);
        }
    }
    Ok(())
}

fn write_irte(ir: &IrTable, index: usize, sbdf: Sbdf, vector: u8, lapic: u32) {
    let sid = ((sbdf.bus as u64) << 8)
        | ((sbdf.device as u64) << 3)
        | (sbdf.function as u64 & 0x7);
    let destination = lapic as u64;
    // Extended IRTE: P | SID | SQ | SVT=01 | vector | destination low.
    let qw0 = SL_PRESENT
        | (sid << 16)
        | (1u64 << 32)
        | (1u64 << 33)
        | ((vector as u64) << 40)
        | ((destination & 0xffff) << 48);
    let qw1 = (destination >> 16) & 0xffff_ffff;
    // SAFETY: the IR table is a zeroed 4 KiB page, index < 256.
    unsafe {
        let base = memory::phys_to_virt(ir.phys) as *mut u64;
        core::ptr::write_volatile(base.add(index * 2), qw0);
        core::ptr::write_volatile(base.add(index * 2 + 1), qw1);
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
    // SAFETY: the buddy allocator returned a full 4 KiB frame owned by us.
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

fn install_root_entry(root: u64, bus: u8, context: u64) -> Result<(), IommuError> {
    let entry = SL_PRESENT | (context & SL_ADDR_MASK);
    // SAFETY: `root` is a 4 KiB root table; the bus selects a 16-byte entry.
    unsafe {
        table_write(root, (bus as usize) * 2, entry);
        table_write(root, (bus as usize) * 2 + 1, 0);
    }
    Ok(())
}

/// Legacy context entry (ESXi `IOMMU-ANALYSE.md` §3.4).
///
/// `TT = 00` selects second-level translation; AGAW is encoded in bits 6:4
/// and repeated in the low bits of the second qword; the domain id occupies
/// bits 23:8 of the second qword.
fn install_context_entry(
    context: u64,
    sbdf: Sbdf,
    domain: DomainId,
    slpt: u64,
) -> Result<(), IommuError> {
    // AGAW 010 = 48-bit guest address width.
    const AGAW: u64 = 0b010;
    let low = SL_PRESENT | (AGAW << 4) | (slpt & SL_ADDR_MASK);
    let high = (((domain.raw() as u64) << 8) & 0x00ff_ff00) | AGAW;
    let index = ((sbdf.device as usize) << 3) | sbdf.function as usize;
    // SAFETY: `context` is a 4 KiB table, index < 256.
    unsafe {
        table_write(context, index * 2, low);
        table_write(context, index * 2 + 1, high);
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
    if kind == MappingKind::Page1G {
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
