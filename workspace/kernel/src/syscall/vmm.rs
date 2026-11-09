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
use crate::s9vm::{self, vm};
use crate::silo;
use alloc::vec;
use strat9_abi::vmm::{state, VmmInfo};

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

/// SYS_VMM_MAP_MEM (562) : à implémenter avec la mémoire invitée.
pub fn sys_vmm_map_mem(
    _vmm_id: u64,
    _gpa: u64,
    _len: u64,
    _perms: u64,
    _memtype: u64,
) -> Result<u64, SyscallError> {
    require_control()?;
    Err(SyscallError::NotImplemented)
}

/// SYS_VMM_SET_REGS (563) : à implémenter avec l'API vCPU.
pub fn sys_vmm_set_regs(_vcpu_id: u64, _regs_ptr: u64) -> Result<u64, SyscallError> {
    require_control()?;
    Err(SyscallError::NotImplemented)
}

/// SYS_VMM_GET_REGS (564) : à implémenter avec l'API vCPU.
pub fn sys_vmm_get_regs(_vcpu_id: u64, _regs_ptr: u64) -> Result<u64, SyscallError> {
    require_control()?;
    Err(SyscallError::NotImplemented)
}

/// SYS_VMM_RUN (565) : à implémenter avec l'ordonnancement des vCPU.
pub fn sys_vmm_run(_vcpu_id: u64) -> Result<u64, SyscallError> {
    require_control()?;
    Err(SyscallError::NotImplemented)
}

/// SYS_VMM_INJECT_IRQ (566) : à implémenter avec l'API vCPU.
pub fn sys_vmm_inject_irq(_vcpu_id: u64, _vector: u64) -> Result<u64, SyscallError> {
    require_control()?;
    Err(SyscallError::NotImplemented)
}

/// SYS_VMM_EXIT_HANDLER (567) : à implémenter avec la file d'exits.
pub fn sys_vmm_exit_handler(_vmm_id: u64, _event_ptr: u64) -> Result<u64, SyscallError> {
    require_control()?;
    Err(SyscallError::NotImplemented)
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

/// Alloue un tampon utilitaire (évite un import inutilisé dans certains
/// profils de compilation).
#[allow(dead_code)]
fn _scratch() -> alloc::vec::Vec<u8> {
    vec![0u8; 0]
}
