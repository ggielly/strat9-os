//! s9vm — handlers des syscalls `SYS_VMM_*` (bloc ABI 560–569).
//!
//! Périmètre P0 : gestion du registre des mondes (`CREATE`, `DESTROY`,
//! `INFO`). Les appels qui dépendent de l'exécution invitée (`MAP_MEM`,
//! `SET_REGS`, `RUN`, `INJECT_IRQ`, `EXIT_HANDLER`, `IRQ_WAIT`) renvoyaient
//! `ENOSYS` : leur implémentation viendra avec la couche vCPU exposée à
//! l'utilisateur. Le but de cette étape est de figer l'ABI et le routage sans
//! exposer de surface incomplète.
//!
//! Contrôle d'accès : `CREATE` exige l'administration de silo ; les autres
//! appels prennent une **poignée de capability** rendue par `CREATE`
//! (`ResourceType::Vmm`) ou `CREATE_VCPU` (`ResourceType::Vcpu`). La poignée
//! est opaque pour l'espace utilisateur ; les identifiants internes ne sont
//! jamais acceptés directement.

use super::error::SyscallError;
use crate::capability::{
    get_capability_manager, CapId, CapPermissions, ResourceType,
};
use crate::memory::{UserSliceRead, UserSliceWrite};
use crate::process::current_task_clone;
use crate::s9vm::memmap::MapError;
use crate::s9vm::vm::{self, VmError};
use crate::s9vm;
use crate::silo;
use alloc::vec;
use strat9_abi::vmm::{state, VmmInfo, VmmRegs};

/// Taille maximale d'une structure lue depuis l'espace utilisateur.
const MAX_STRUCT: usize = 192;

/// Droits du créateur d'un monde : lecture, écriture, révocation.
const VMM_OWNER: CapPermissions = CapPermissions {
    read: true,
    write: true,
    execute: false,
    grant: false,
    revoke: true,
};

/// Droits d'un vCPU : lecture, écriture, exécution (`RUN`).
const VCPU_OWNER: CapPermissions = CapPermissions {
    read: true,
    write: true,
    execute: true,
    grant: false,
    revoke: true,
};

/// `CREATE` reste une opération d'administration de silo : créer un monde
/// n'est pas couvert par une capability existante.
fn require_control() -> Result<(), SyscallError> {
    silo::require_silo_admin()
}

/// Installe une capability dans la tâche courante et retourne sa poignée.
fn install_handle(
    resource_type: ResourceType,
    resource: u64,
    permissions: CapPermissions,
) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let capability = get_capability_manager().create_capability(
        resource_type,
        resource as usize,
        permissions,
    );
    // SAFETY: la table de capabilities de la tâche est protégée par l'API
    // `CapabilityTable` ; le motif est identique aux autres créations de
    // poignées du noyau.
    let id = unsafe { (&mut *task.process.capabilities.get()).insert(capability) };
    Ok(id.as_u64())
}

/// Résout une poignée de capability en identifiant de ressource interne.
fn resolve_handle(
    handle: u64,
    expected: ResourceType,
    required: CapPermissions,
) -> Result<u64, SyscallError> {
    if handle == 0 {
        return Err(SyscallError::InvalidArgument);
    }
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: lecture sous la protection de `CapabilityTable`.
    let capabilities = unsafe { &*task.process.capabilities.get() };
    let capability = capabilities
        .get_with_permissions(CapId::from_raw(handle), required)
        .ok_or(SyscallError::PermissionDenied)?;
    if capability.resource_type != expected {
        return Err(SyscallError::BadHandle);
    }
    Ok(capability.resource as u64)
}

/// Révoque une poignée (retire la capability de la tâche et du registre
/// global).
fn revoke_handle(handle: u64) {
    let Some(task) = current_task_clone() else {
        return;
    };
    // SAFETY: mutation sous la protection de `CapabilityTable`.
    let mut capabilities = unsafe { &mut *task.process.capabilities.get() };
    let _ = capabilities.remove(CapId::from_raw(handle));
}

/// Résout une poignée de monde (`ResourceType::Vmm`).
fn vmm_world(handle: u64, required: CapPermissions) -> Result<u64, SyscallError> {
    resolve_handle(handle, ResourceType::Vmm, required)
}

/// Résout une poignée de vCPU (`ResourceType::Vcpu`).
fn vcpu_target(handle: u64, required: CapPermissions) -> Result<u64, SyscallError> {
    resolve_handle(handle, ResourceType::Vcpu, required)
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
    match install_handle(ResourceType::Vmm, record.id, VMM_OWNER) {
        Ok(handle) => Ok(handle),
        Err(error) => {
            let _ = vm::destroy(record.id);
            Err(error)
        }
    }
}

/// SYS_VMM_DESTROY (561) : détruit un monde.
pub fn sys_vmm_destroy(vmm_handle: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        revoke: true,
        ..VMM_OWNER
    };
    let world = vmm_world(vmm_handle, required)?;
    vm::destroy(world).ok_or(SyscallError::NotFound)?;
    revoke_handle(vmm_handle);
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
    let required = CapPermissions {
        write: true,
        ..CapPermissions::none()
    };
    let world = vmm_world(vmm_id, required)?;
    let caps = s9vm::detect().ok_or(SyscallError::NotSupported)?;
    if perms > 0b111 || memtype > 6 {
        return Err(SyscallError::InvalidArgument);
    }
    if memtype != 0 && memtype != 6 {
        return Err(SyscallError::NotSupported);
    }
    vm::map_memory(world, &caps, gpa, len, perms as u32, memtype as u8)
        .map_err(map_vm_error)
}

/// SYS_VMM_SET_REGS (563) : écrit le bloc de registres d'un vCPU.
pub fn sys_vmm_set_regs(vcpu_handle: u64, regs_ptr: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        write: true,
        ..CapPermissions::none()
    };
    let vcpu = vcpu_target(vcpu_handle, required)?;
    let regs: VmmRegs = read_struct(regs_ptr)?;
    vm::set_vcpu_regs(vcpu, &regs).map_err(map_vcpu_error)?;
    Ok(0)
}

/// SYS_VMM_GET_REGS (564) : lit le bloc de registres d'un vCPU.
pub fn sys_vmm_get_regs(vcpu_handle: u64, regs_ptr: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        read: true,
        ..CapPermissions::none()
    };
    let vcpu = vcpu_target(vcpu_handle, required)?;
    let regs = vm::get_vcpu_regs(vcpu).ok_or(SyscallError::NotFound)?;
    write_struct(regs_ptr, &regs)?;
    Ok(0)
}

/// SYS_VMM_CREATE_VCPU (570) : crée un vCPU logique dans un monde.
pub fn sys_vmm_create_vcpu(vmm_handle: u64, apic_id: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        write: true,
        ..CapPermissions::none()
    };
    let world = vmm_world(vmm_handle, required)?;
    if apic_id > u32::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let vcpu = vm::create_vcpu(world, apic_id as u32).map_err(map_vcpu_error)?;
    match install_handle(ResourceType::Vcpu, vcpu, VCPU_OWNER) {
        Ok(handle) => Ok(handle),
        Err(error) => {
            let _ = vm::destroy_vcpu(vcpu);
            Err(error)
        }
    }
}

/// SYS_VMM_DESTROY_VCPU (571) : détruit un vCPU logique.
pub fn sys_vmm_destroy_vcpu(vcpu_handle: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        revoke: true,
        ..VCPU_OWNER
    };
    let vcpu = vcpu_target(vcpu_handle, required)?;
    if !vm::destroy_vcpu(vcpu) {
        return Err(SyscallError::NotFound);
    }
    revoke_handle(vcpu_handle);
    Ok(0)
}

/// SYS_VMM_RUN (565) : exécute un vCPU jusqu'à la prochaine sortie « de
/// politique » et empile l'événement dans la file du monde.
pub fn sys_vmm_run(vcpu_handle: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        execute: true,
        write: true,
        ..CapPermissions::none()
    };
    let vcpu = vcpu_target(vcpu_handle, required)?;
    // `RUN` est bloquant : la tâche noyau du vCPU exécute l'invité jusqu'à la
    // prochaine sortie de politique, puis l'appelant reprend.
    vm::request_run(vcpu).map_err(map_run_error)?;
    Ok(0)
}

/// SYS_VMM_INJECT_IRQ (566) : programme l'injection d'une interruption
/// externe dans un vCPU ; elle sera délivrée à la prochaine entrée invitée.
///
/// `vector` doit être un vecteur valide (0..=255). L'injection est différée :
/// le vecteur est mémorisé dans le vCPU et écrit dans le bloc de contrôle au
/// prochain `RUN`.
pub fn sys_vmm_inject_irq(vcpu_handle: u64, vector: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        write: true,
        ..CapPermissions::none()
    };
    let vcpu = vcpu_target(vcpu_handle, required)?;
    if vector > u8::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    vm::inject_irq(vcpu, vector as u8).map_err(map_vcpu_error)?;
    Ok(0)
}

/// SYS_VMM_EXIT_HANDLER (567) : dépile un événement de sortie.
///
/// Retourne 1 si un événement a été écrit, 0 si la file est vide.
pub fn sys_vmm_exit_handler(vmm_handle: u64, event_ptr: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        read: true,
        ..CapPermissions::none()
    };
    let world = vmm_world(vmm_handle, required)?;
    let event = match vm::pop_exit(world) {
        Ok(event) => event,
        Err(()) => return Ok(0),
    };
    write_struct(event_ptr, &event)?;
    Ok(1)
}

/// SYS_VMM_IRQ_WAIT (568) : attend un événement de sortie du vCPU.
///
/// Retourne 1 si un événement est disponible, 0 si `timeout_ns` expire avant
/// (`timeout_ns = 0` teste immédiatement).
pub fn sys_vmm_irq_wait(vcpu_handle: u64, timeout_ns: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        read: true,
        ..CapPermissions::none()
    };
    let vcpu = vcpu_target(vcpu_handle, required)?;
    let ready = vm::wait_exit(vcpu, timeout_ns).map_err(map_vcpu_error)?;
    Ok(u64::from(ready))
}

/// SYS_VMM_INFO (569) : snapshot d'un monde, ou résumé global si `vmm_id = 0`.
pub fn sys_vmm_info(vmm_handle: u64, out_ptr: u64) -> Result<u64, SyscallError> {
    let mut info = VmmInfo {
        abi_version: strat9_abi::vmm::VMM_ABI_VERSION,
        ..VmmInfo::default()
    };
    let vmm_id = if vmm_handle == 0 {
        require_control()?;
        0
    } else {
        let required = CapPermissions {
            read: true,
            ..CapPermissions::none()
        };
        vmm_world(vmm_handle, required)?
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
        vm::VcpuRegistryError::Thread => SyscallError::OutOfMemory,
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
        vm::RunError::Busy => SyscallError::Again,
    }
}
