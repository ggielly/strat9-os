//! s9vm — handlers des syscalls `SYS_VMM_*` (bloc ABI 560–569).
//!
//! Périmètre P0 : gestion du registre des mondes (`CREATE`, `DESTROY`,
//! `INFO`). Les appels qui dépendent de l'exécution invitée (`MAP_MEM`,
//! `SET_REGS`, `RUN`, `INJECT_IRQ`, `EXIT_HANDLER`, `IRQ_WAIT`) renvoient
//! `ENOSYS` : leur implémentation viendra avec la couche vCPU exposée à
//! l'utilisateur. Le but de cette étape est de figer l'ABI et le routage sans
//! exposer de surface incomplète.
//!
//! Contrôle d'accès : toute opération exige la capability d'administration de
//! silo (`silo::require_silo_admin`). Quand les capabilities `Vmm`/`Vcpu`
//! seront émises, elles remplaceront ce contrôle global.

use super::error::SyscallError;
use crate::memory::{UserSliceRead, UserSliceWrite};
use crate::s9vm::memmap::MapError;
use crate::s9vm::vm::{self, VmError};
use crate::s9vm;
use crate::silo;
use alloc::vec;
use strat9_abi::vmm::{state, VmmInfo, VmmRegs};

/// Taille maximale d'une structure lue depuis l'espace utilisateur.
const MAX_STRUCT: usize = 192;

fn require_control() -> Result<(), SyscallError> {
    silo::require_silo_admin()
}

fn read_struct<T: Copy>(ptr: u64) -> Result<T, SyscallError> {
    if ptr == 0 {
        return Err(SyscallError::Fault);
    }
    let size = core::mem::size_of::<T>();
    let mut raw = [0u8; MAX_STRUCT];
    if size == 0 || size > raw.len() {
        return Err(SyscallError::InvalidArgument);
    }
    let slice = UserSliceRead::new(ptr, size)?;
    if slice.copy_to(&mut raw[..size]) != size {
        return Err(SyscallError::Fault);
    }
    // SAFETY: `raw[..size]` est entièrement initialisé et `T: Copy`.
    Ok(unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const T) })
}

fn write_struct<T: Copy>(ptr: u64, value: &T) -> Result<(), SyscallError> {
    if ptr == 0 {
        return Err(SyscallError::Fault);
    }
    let size = core::mem::size_of::<T>();
    let slice = UserSliceWrite::new(ptr, size)?;
    // SAFETY: lecture de `size` octets depuis une référence valide.
    let bytes = unsafe { core::slice::from_raw_parts(value as *const T as *const u8, size) };
    slice.copy_from(bytes);
    Ok(())
}

/// SYS_VMM_CREATE (560) : crée un monde virtuel.
pub fn sys_vmm_create(name_ptr: u64, name_len: u64, silo_id: u64) -> Result<u64, SyscallError> {
    require_control()?;
    if !s9vm::detected() {
        return Err(SyscallError::NotSupported);
    }
    if name_len == 0 || name_len > vm::NAME_MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    if silo_id > u32::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let mut name = [0u8; vm::NAME_MAX];
    let slice = UserSliceRead::new(name_ptr, name_len as usize)?;
    if slice.copy_to(&mut name[..name_len as usize]) != name_len as usize {
        return Err(SyscallError::Fault);
    }
    let record = vm::create(&name[..name_len as usize], silo_id as u32)
        .ok_or(SyscallError::OutOfMemory)?;
    Ok(record.id)
}

/// SYS_VMM_DESTROY (561) : détruit un monde.
pub fn sys_vmm_destroy(vmm_id: u64) -> Result<u64, SyscallError> {
    require_control()?;
    if vmm_id == 0 {
        return Err(SyscallError::InvalidArgument);
    }
    vm::destroy(vmm_id).ok_or(SyscallError::NotFound)?;
    Ok(0)
}

/// SYS_VMM_MAP_MEM (562) : mappe de la RAM invitée dans un monde.
///
/// `perms` : bits 1 = lecture, 2 = écriture, 4 = exécution (0 = lecture).
/// `memtype` : 0 = write-back (seul type supporté pour l'instant).
pub fn sys_vmm_map_mem(
    vmm_id: u64,
    gpa: u64,
    len: u64,
    perms: u64,
    memtype: u64,
) -> Result<u64, SyscallError> {
    require_control()?;
    let caps = s9vm::detect().ok_or(SyscallError::NotSupported)?;
    if vmm_id == 0 || perms > 0b111 || memtype > 6 {
        return Err(SyscallError::InvalidArgument);
    }
    if memtype != 0 && memtype != 6 {
        return Err(SyscallError::NotSupported);
    }
    vm::map_memory(vmm_id, &caps, gpa, len, perms as u32, memtype as u8)
        .map_err(map_vm_error)
}

/// SYS_VMM_SET_REGS (563) : écrit le bloc de registres d'un vCPU.
pub fn sys_vmm_set_regs(vcpu_id: u64, regs_ptr: u64) -> Result<u64, SyscallError> {
    require_control()?;
    let regs: VmmRegs = read_struct(regs_ptr)?;
    vm::set_vcpu_regs(vcpu_id, &regs).map_err(map_vcpu_error)?;
    Ok(0)
}

/// SYS_VMM_GET_REGS (564) : lit le bloc de registres d'un vCPU.
pub fn sys_vmm_get_regs(vcpu_id: u64, regs_ptr: u64) -> Result<u64, SyscallError> {
    require_control()?;
    let regs = vm::get_vcpu_regs(vcpu_id).ok_or(SyscallError::NotFound)?;
    write_struct(regs_ptr, &regs)?;
    Ok(0)
}

/// SYS_VMM_CREATE_VCPU (570) : crée un vCPU logique dans un monde.
pub fn sys_vmm_create_vcpu(vmm_id: u64, apic_id: u64) -> Result<u64, SyscallError> {
    require_control()?;
    if vmm_id == 0 || apic_id > u32::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    vm::create_vcpu(vmm_id, apic_id as u32).map_err(map_vcpu_error)
}

/// SYS_VMM_DESTROY_VCPU (571) : détruit un vCPU logique.
pub fn sys_vmm_destroy_vcpu(vcpu_id: u64) -> Result<u64, SyscallError> {
    require_control()?;
    if vcpu_id == 0 {
        return Err(SyscallError::InvalidArgument);
    }
    if vm::destroy_vcpu(vcpu_id) {
        Ok(0)
    } else {
        Err(SyscallError::NotFound)
    }
}

/// SYS_VMM_RUN (565) : exécute un vCPU jusqu'à la prochaine sortie « de
/// politique » et empile l'événement dans la file du monde.
pub fn sys_vmm_run(vcpu_id: u64) -> Result<u64, SyscallError> {
    require_control()?;
    let caps = s9vm::detect().ok_or(SyscallError::NotSupported)?;
    vm::run_vcpu(vcpu_id, &caps).map_err(map_run_error)?;
    Ok(0)
}

/// SYS_VMM_INJECT_IRQ (566) : à implémenter avec l'API vCPU.
pub fn sys_vmm_inject_irq(_vcpu_id: u64, _vector: u64) -> Result<u64, SyscallError> {
    require_control()?;
    Err(SyscallError::NotImplemented)
}

/// SYS_VMM_EXIT_HANDLER (567) : dépile un événement de sortie.
///
/// Retourne 1 si un événement a été écrit, 0 si la file est vide.
pub fn sys_vmm_exit_handler(vmm_id: u64, event_ptr: u64) -> Result<u64, SyscallError> {
    require_control()?;
    let event = match vm::pop_exit(vmm_id) {
        Ok(event) => event,
        Err(()) => return Ok(0),
    };
    write_struct(event_ptr, &event)?;
    Ok(1)
}

/// SYS_VMM_IRQ_WAIT (568) : à implémenter avec le réveil des vCPU.
pub fn sys_vmm_irq_wait(_vcpu_id: u64, _timeout_ns: u64) -> Result<u64, SyscallError> {
    require_control()?;
    Err(SyscallError::NotImplemented)
}

/// SYS_VMM_INFO (569) : snapshot d'un monde, ou résumé global si `vmm_id = 0`.
pub fn sys_vmm_info(vmm_id: u64, out_ptr: u64) -> Result<u64, SyscallError> {
    require_control()?;
    let mut info = VmmInfo {
        abi_version: strat9_abi::vmm::VMM_ABI_VERSION,
        ..VmmInfo::default()
    };
    if vmm_id == 0 {
        // Résumé global du moteur.
        info.state = if s9vm::detected() {
            state::RUNNING
        } else {
            state::STOPPED
        };
        info.vmm_id = 0;
        info.vcpu_count = vm::count() as u32;
        let name = b"s9vm";
        info.name[..name.len()].copy_from_slice(name);
    } else {
        let record = vm::get(vmm_id).ok_or(SyscallError::NotFound)?;
        info.state = record.state;
        info.vmm_id = record.id;
        info.silo_id = record.silo_id;
        info.vcpu_count = record.vcpu_count;
        info.mapped_pages = record.mapped_pages;
        let length = record.name_slice().len();
        info.name[..length].copy_from_slice(record.name_slice());
    }
    write_struct(out_ptr, &info)?;
    Ok(0)
}

/// Construit un vecteur de mondes pour la commande shell (diagnostic).
pub fn list_worlds() -> alloc::vec::Vec<vm::WorldRecord> {
    vm::list()
}

/// Construit un `VmmInfo` pour un monde (diagnostic, sans copie utilisateur).
pub fn world_info(vmm_id: u64) -> Option<VmmInfo> {
    let record = vm::get(vmm_id)?;
    let mut info = VmmInfo {
        abi_version: strat9_abi::vmm::VMM_ABI_VERSION,
        state: record.state,
        vmm_id: record.id,
        silo_id: record.silo_id,
        vcpu_count: record.vcpu_count,
        mapped_pages: record.mapped_pages,
        ..VmmInfo::default()
    };
    let length = record.name_slice().len();
    info.name[..length].copy_from_slice(record.name_slice());
    Some(info)
}

/// Marque un monde comme en cours d'exécution (utilisé par le selftest et le
/// shell). Retourne `false` si le monde est inconnu.
pub fn mark_running(vmm_id: u64) -> bool {
    vm::set_state(vmm_id, state::RUNNING)
}

/// Marque un monde comme arrêté.
pub fn mark_stopped(vmm_id: u64) -> bool {
    vm::set_state(vmm_id, state::STOPPED)
}
fn map_vm_error(error: VmError) -> SyscallError {
    match error {
        VmError::Unknown => SyscallError::NotFound,
        VmError::Map(MapError::InvalidRange) => SyscallError::InvalidArgument,
        VmError::Map(MapError::Overlap) => SyscallError::InvalidArgument,
        VmError::Map(MapError::QuotaExceeded) => SyscallError::OutOfMemory,
        VmError::Map(MapError::TooManyRegions) => SyscallError::OutOfMemory,
        VmError::Map(MapError::NotMapped) => SyscallError::NotFound,
        VmError::OutOfMemory => SyscallError::OutOfMemory,
        VmError::Translation(_) => SyscallError::NotSupported,
    }
}
fn map_vcpu_error(error: vm::VcpuRegistryError) -> SyscallError {
    match error {
        vm::VcpuRegistryError::WorldUnknown => SyscallError::NotFound,
        vm::VcpuRegistryError::Unknown => SyscallError::NotFound,
        vm::VcpuRegistryError::Limit => SyscallError::OutOfMemory,
        vm::VcpuRegistryError::BadAbiVersion => SyscallError::InvalidArgument,
    }
}
fn map_run_error(error: vm::RunError) -> SyscallError {
    match error {
        vm::RunError::UnknownVcpu => SyscallError::NotFound,
        vm::RunError::NoMemory => SyscallError::Again,
        vm::RunError::InvalidGuestState => SyscallError::InvalidArgument,
        vm::RunError::HardwareNotReady => SyscallError::NotSupported,
        vm::RunError::Hardware(_) => SyscallError::IoError,
        vm::RunError::ExitStorm => SyscallError::Again,
    }
}