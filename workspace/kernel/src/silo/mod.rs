//! Silo manager (kernel-side, minimal mechanisms only)
//!
//! This module provides the core kernel structures and syscalls
//! to create and manage silos. Policy lives in userspace (Silo Admin).

use crate::{
    capability::{get_capability_manager, CapId, CapPermissions, ResourceType},
    hardware::storage::{ahci, virtio_block},
    ipc::port::{self, PortId},
    memory::{UserSliceRead, UserSliceWrite},
    process::{current_task_clone, task::Task, TaskId},
    sync::SpinLock,
    syscall::error::SyscallError,
};
use alloc::{
    collections::{BTreeMap, VecDeque},
    string::{String, ToString},
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Public ABI structs (repr(C) for syscall boundary)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum SiloTier {
    Critical = 0,
    System   = 1,
    User     = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SiloId {
    pub sid: u32,
    pub tier: SiloTier,
}

impl SiloId {
    pub const fn new(sid: u32) -> Self {
        let tier = match sid {
            1..=9     => SiloTier::Critical,
            10..=999  => SiloTier::System,
            _         => SiloTier::User,
        };
        Self { sid, tier }
    }

    pub fn as_u64(&self) -> u64 {
        self.sid as u64
    }
}

use bitflags::bitflags;

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ControlMode: u8 {
        const LIST  = 0b100;
        const STOP  = 0b010;
        const SPAWN = 0b001;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct HardwareMode: u8 {
        const INTERRUPT = 0b100;
        const IO        = 0b010;
        const DMA       = 0b001;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RegistryMode: u8 {
        const LOOKUP = 0b100;
        const BIND   = 0b010;
        const PROXY  = 0b001;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OctalMode {
    pub control:  ControlMode,
    pub hardware: HardwareMode,
    pub registry: RegistryMode,
}

impl OctalMode {
    pub const fn from_octal(val: u16) -> Self {
        Self {
            control:  ControlMode::from_bits_truncate(((val >> 6) & 0o7) as u8),
            hardware: HardwareMode::from_bits_truncate(((val >> 3) & 0o7) as u8),
            registry: RegistryMode::from_bits_truncate((val & 0o7) as u8),
        }
    }

    pub const fn is_subset_of(&self, other: &OctalMode) -> bool {
        (self.control.bits()  & !other.control.bits()  == 0)
        && (self.hardware.bits() & !other.hardware.bits() == 0)
        && (self.registry.bits() & !other.registry.bits() == 0)
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrateFamily {
    SYS  = 0,
    DRV  = 1,
    FS   = 2,
    NET  = 3,
    WASM = 4,
    USR  = 5,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SiloConfig {
    pub mem_min: u64,
    pub mem_max: u64,
    pub cpu_shares: u32,
    pub cpu_quota_us: u64,
    pub cpu_period_us: u64,
    pub cpu_affinity_mask: u64,
    pub max_tasks: u32,
    pub io_bw_read: u64,
    pub io_bw_write: u64,
    pub caps_ptr: u64,
    pub caps_len: u64,
    pub flags: u64,
    // Security Model Extensions
    pub sid: u32,
    pub mode: u16,      // Octal mode packed
    pub family: u8,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Strat9ModuleHeader {
    pub magic: [u8; 4], // "CMOD"
    pub version: u16,
    pub cpu_arch: u8, // 0 = x86_64
    pub flags: u32,
    pub code_offset: u64,
    pub code_size: u64,
    pub data_offset: u64,
    pub data_size: u64,
    pub bss_size: u64,
    pub entry_point: u64,
    pub export_table_offset: u64,
    pub import_table_offset: u64,
    pub relocation_table_offset: u64,
    pub key_id: [u8; 8],
    pub signature: [u8; 64],
    pub reserved: [u8; 56],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ModuleInfo {
    pub id: u64,
    pub format: u32, // 0 = raw/ELF, 1 = CMOD
    pub flags: u32,
    pub version: u16,
    pub cpu_arch: u8,
    pub reserved: u8,
    pub code_size: u64,
    pub data_size: u64,
    pub bss_size: u64,
    pub entry_point: u64,
    pub total_size: u64,
}

impl Default for SiloConfig {
    fn default() -> Self {
        SiloConfig {
            mem_min: 0,
            mem_max: 0,
            cpu_shares: 0,
            cpu_quota_us: 0,
            cpu_period_us: 0,
            cpu_affinity_mask: 0,
            max_tasks: 0,
            io_bw_read: 0,
            io_bw_write: 0,
            caps_ptr: 0,
            caps_len: 0,
            flags: 0,
        }
    }
}

impl SiloConfig {
    fn validate(&self) -> Result<(), SyscallError> {
        if self.mem_min > self.mem_max {
            return Err(SyscallError::InvalidArgument);
        }
        if self.cpu_quota_us > 0 && self.cpu_period_us == 0 {
            return Err(SyscallError::InvalidArgument);
        }
        if self.caps_len > MAX_SILO_CAPS as u64 {
            return Err(SyscallError::InvalidArgument);
        }
        if self.caps_len > 0 && self.caps_ptr == 0 {
            return Err(SyscallError::InvalidArgument);
        }
        Ok(())
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiloEventKind {
    Started = 1,
    Stopped = 2,
    Killed = 3,
    Crashed = 4,
    Paused = 5,
    Resumed = 6,
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiloFaultReason {
    PageFault = 1,
    GeneralProtection = 2,
    InvalidOpcode = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SiloEvent {
    pub silo_id: u64,
    pub kind: SiloEventKind,
    pub data0: u64,
    pub data1: u64,
    pub tick: u64,
}

// data0 encoding for Crashed:
// - bits 0..15: fault reason (SiloFaultReason)
// - bits 16..31: fault subcode (arch-specific)
// - bits 32..63: reserved
pub const FAULT_SUBCODE_SHIFT: u64 = 16;

pub fn pack_fault(reason: SiloFaultReason, subcode: u64) -> u64 {
    (reason as u64) | (subcode << FAULT_SUBCODE_SHIFT)
}

// ============================================================================
// Internal kernel structs
// ============================================================================

#[derive(Debug)]
struct Silo {
    id: SiloId,
    name: String,
    strate_label: Option<String>,
    state: SiloState,
    config: SiloConfig,
    mode: OctalMode,
    family: StrateFamily,
    /// Current memory usage accounted to this silo (bytes).
    /// This tracks user-space virtual regions reserved/mapped via AddressSpace APIs.
    mem_usage_bytes: u64,
    flags: u32,
    module_id: Option<u64>,
    tasks: Vec<TaskId>,
    granted_caps: Vec<u64>,
    granted_resources: Vec<GrantedResource>,
    event_seq: u64,
}

#[derive(Debug, Clone)]
pub struct SiloSnapshot {
    pub id: u32,
    pub tier: SiloTier,
    pub name: String,
    pub strate_label: Option<String>,
    pub state: SiloState,
    pub task_count: usize,
    pub mem_usage_bytes: u64,
    pub mem_min_bytes: u64,
    pub mem_max_bytes: u64,
    pub mode: u16,
}

struct SiloManager {
    silos: BTreeMap<u32, Silo>,
    events: VecDeque<SiloEvent>,
    task_to_silo: BTreeMap<TaskId, u32>,
}

impl SiloManager {
    const fn new() -> Self {
        SiloManager {
            silos: BTreeMap::new(),
            events: VecDeque::new(),
            task_to_silo: BTreeMap::new(),
        }
    }

    fn create_silo(&mut self, config: &SiloConfig) -> Result<SiloId, SyscallError> {
        let id = SiloId::new(config.sid);
        if self.silos.contains_key(&id.sid) {
            return Err(SyscallError::AlreadyExists);
        }

        kernel_check_spawn_invariants(&id, &OctalMode::from_octal(config.mode))?;

        let mut name = String::from("silo-");
        name.push_str(&id.sid.to_string());

        let family = match config.family {
            0 => StrateFamily::SYS,
            1 => StrateFamily::DRV,
            2 => StrateFamily::FS,
            3 => StrateFamily::NET,
            4 => StrateFamily::WASM,
            _ => StrateFamily::USR,
        };

        let silo = Silo {
            id,
            name,
            strate_label: None,
            state: SiloState::Created,
            config: *config,
            mode: OctalMode::from_octal(config.mode),
            family,
            mem_usage_bytes: 0,
            flags: config.flags as u32,
            module_id: None,
            tasks: Vec::new(),
            granted_caps: Vec::new(),
            granted_resources: Vec::new(),
            event_seq: 0,
        };

        self.silos.insert(id.sid, silo);
        Ok(id)
    }

    fn get_mut(&mut self, id: u32) -> Result<&mut Silo, SyscallError> {
        self.silos.get_mut(&id).ok_or(SyscallError::BadHandle)
    }

    fn get(&self, id: u32) -> Result<&Silo, SyscallError> {
        self.silos.get(&id).ok_or(SyscallError::BadHandle)
    }

    fn push_event(&mut self, ev: SiloEvent) {
        const MAX_EVENTS: usize = 256;
        if self.events.len() >= MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(ev);
    }

    fn map_task(&mut self, task_id: TaskId, silo_id: u32) {
        self.task_to_silo.insert(task_id, silo_id);
    }

    fn unmap_task(&mut self, task_id: TaskId) {
        self.task_to_silo.remove(&task_id);
    }

    fn silo_for_task(&self, task_id: TaskId) -> Option<u32> {
        self.task_to_silo.get(&task_id).copied()
    }
}

pub fn kernel_check_spawn_invariants(
    id: &SiloId,
    mode: &OctalMode,
) -> Result<(), SyscallError> {
    if id.tier == SiloTier::User && !mode.hardware.is_empty() {
        return Err(SyscallError::PermissionDenied);
    }
    if id.tier == SiloTier::User && !mode.control.is_empty() {
        return Err(SyscallError::PermissionDenied);
    }
    Ok(())
}

static SILO_MANAGER: SpinLock<SiloManager> = SpinLock::new(SiloManager::new());

const SILO_ADMIN_RESOURCE: usize = 0;
const MAX_SILO_CAPS: usize = 64;
const MAX_MODULE_BLOB_LEN: usize = 16 * 1024 * 1024; // 16 MiB (UserSlice limit)
const IPC_STREAM_DATA: u32 = 0xFFFF_FFFE;
const IPC_STREAM_EOF: u32 = 0xFFFF_FFFF;
const MODULE_FLAG_SIGNED: u32 = 1 << 0;
const MODULE_FLAG_KERNEL: u32 = 1 << 1;

fn read_user_config(ptr: u64) -> Result<SiloConfig, SyscallError> {
    if ptr == 0 {
        return Err(SyscallError::Fault);
    }
    const SIZE: usize = core::mem::size_of::<SiloConfig>();
    let user = UserSliceRead::new(ptr, SIZE)?;
    let mut buf = [0u8; SIZE];
    user.copy_to(&mut buf);
    // SAFETY: We copied the exact bytes for SiloConfig from userspace.
    let config = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const SiloConfig) };
    Ok(config)
}

fn read_caps_list(ptr: u64, len: u64) -> Result<Vec<u64>, SyscallError> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if len > MAX_SILO_CAPS as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let byte_len = len as usize * core::mem::size_of::<u64>();
    let user = UserSliceRead::new(ptr, byte_len)?;
    let bytes = user.read_to_vec();
    let mut out = Vec::with_capacity(len as usize);
    for chunk in bytes.chunks_exact(8) {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(chunk);
        out.push(u64::from_ne_bytes(arr));
    }
    Ok(out)
}

fn read_module_stream_from_port(
    port: &alloc::sync::Arc<port::Port>,
) -> Result<Vec<u8>, SyscallError> {
    let mut out = Vec::new();
    loop {
        let msg = port.recv().map_err(|_| SyscallError::BadHandle)?;

        if msg.msg_type == IPC_STREAM_EOF {
            break;
        }
        if msg.msg_type != IPC_STREAM_DATA {
            return Err(SyscallError::InvalidArgument);
        }
        if msg.flags != 0 {
            return Err(SyscallError::InvalidArgument);
        }

        let chunk_len = u16::from_le_bytes([msg.payload[0], msg.payload[1]]) as usize;
        if chunk_len == 0 {
            break;
        }
        if chunk_len > msg.payload.len() - 2 {
            return Err(SyscallError::InvalidArgument);
        }
        if out.len().saturating_add(chunk_len) > MAX_MODULE_BLOB_LEN {
            return Err(SyscallError::InvalidArgument);
        }

        out.extend_from_slice(&msg.payload[2..2 + chunk_len]);
    }
    Ok(out)
}

fn parse_module_header(data: &[u8]) -> Result<Option<Strat9ModuleHeader>, SyscallError> {
    const MAGIC: [u8; 4] = *b"CMOD";
    let header_size = core::mem::size_of::<Strat9ModuleHeader>();

    if data.len() < MAGIC.len() {
        return Ok(None);
    }
    if data[0..4] != MAGIC {
        return Ok(None);
    }
    if data.len() < header_size {
        return Err(SyscallError::InvalidArgument);
    }

    // SAFETY: We checked length, and we read unaligned from a byte slice.
    let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Strat9ModuleHeader) };

    if header.version != 1 {
        return Err(SyscallError::InvalidArgument);
    }
    if header.cpu_arch != 0 {
        return Err(SyscallError::InvalidArgument);
    }

    let data_len = data.len() as u64;
    let code_end = header
        .code_offset
        .checked_add(header.code_size)
        .ok_or(SyscallError::InvalidArgument)?;
    let data_end = header
        .data_offset
        .checked_add(header.data_size)
        .ok_or(SyscallError::InvalidArgument)?;
    if code_end > data_len || data_end > data_len {
        return Err(SyscallError::InvalidArgument);
    }
    if header.entry_point >= header.code_size && header.code_size != 0 {
        return Err(SyscallError::InvalidArgument);
    }
    if header.export_table_offset > data_len
        || header.import_table_offset > data_len
        || header.relocation_table_offset > data_len
    {
        return Err(SyscallError::InvalidArgument);
    }

    // Segmentation rules: code/data must not overlap and must be page-aligned.
    const PAGE_SIZE: u64 = 4096;
    if header.code_size > 0 {
        if header.code_offset % PAGE_SIZE != 0 || header.code_size % PAGE_SIZE != 0 {
            return Err(SyscallError::InvalidArgument);
        }
    }
    if header.data_size > 0 {
        if header.data_offset % PAGE_SIZE != 0 || header.data_size % PAGE_SIZE != 0 {
            return Err(SyscallError::InvalidArgument);
        }
    }
    let code_range = header.code_offset..code_end;
    let data_range = header.data_offset..data_end;
    if code_range.start < data_range.end && data_range.start < code_range.end {
        return Err(SyscallError::InvalidArgument);
    }

    // Flags/signature checks (verification is TODO).
    if header.flags & MODULE_FLAG_SIGNED != 0 {
        let sig_nonzero = header.signature.iter().any(|b| *b != 0);
        let key_nonzero = header.key_id.iter().any(|b| *b != 0);
        if !sig_nonzero || !key_nonzero {
            return Err(SyscallError::PermissionDenied);
        }
    }
    if header.flags & MODULE_FLAG_KERNEL != 0 {
        // Kernel modules are allowed only when loaded by admin (already enforced).
    }

    Ok(Some(header))
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, SyscallError> {
    if offset + 4 > data.len() {
        return Err(SyscallError::InvalidArgument);
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&data[offset..offset + 4]);
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_le(data: &[u8], offset: usize) -> Result<u64, SyscallError> {
    if offset + 8 > data.len() {
        return Err(SyscallError::InvalidArgument);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[offset..offset + 8]);
    Ok(u64::from_le_bytes(buf))
}

fn resolve_export_offset(module: &ModuleImage, ordinal: u64) -> Result<u64, SyscallError> {
    let header = module.header.ok_or(SyscallError::NotImplemented)?;
    if header.export_table_offset == 0 {
        return Err(SyscallError::NotImplemented);
    }
    let table_off = header.export_table_offset as usize;
    let count = read_u32_le(&module.data, table_off)? as u64;
    if ordinal >= count {
        return Err(SyscallError::InvalidArgument);
    }
    let entries_off = table_off + 8;
    let entry_off = entries_off + (ordinal as usize * 8);
    let rva = read_u64_le(&module.data, entry_off)?;
    Ok(rva)
}

pub fn require_silo_admin() -> Result<(), SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: Current task owns its capability table during syscall execution.
    let caps = unsafe { &*task.process.capabilities.get() };
    let required = CapPermissions {
        read: false,
        write: false,
        execute: false,
        grant: true,
        revoke: false,
    };

    if caps.has_resource_with_permissions(ResourceType::Silo, SILO_ADMIN_RESOURCE, required) {
        Ok(())
    } else {
        Err(SyscallError::PermissionDenied)
    }
}

fn resolve_silo_handle(handle: u64, required: CapPermissions) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let cap_id = CapId::from_raw(handle);
    let cap = caps.get(cap_id).ok_or(SyscallError::BadHandle)?;

    // Ensure this is a Silo capability and permissions are sufficient.
    if cap.resource_type != ResourceType::Silo {
        return Err(SyscallError::BadHandle);
    }

    if (!required.read || cap.permissions.read)
        && (!required.write || cap.permissions.write)
        && (!required.execute || cap.permissions.execute)
        && (!required.grant || cap.permissions.grant)
        && (!required.revoke || cap.permissions.revoke)
    {
        Ok(cap.resource as u64)
    } else {
        Err(SyscallError::PermissionDenied)
    }
}

// ============================================================================
// Module registry (temporary blob store for .cmod/ELF)
// ============================================================================

#[derive(Debug)]
struct ModuleImage {
    id: u64,
    data: Vec<u8>,
    header: Option<Strat9ModuleHeader>,
}

struct ModuleRegistry {
    modules: BTreeMap<u64, ModuleImage>,
}

impl ModuleRegistry {
    const fn new() -> Self {
        ModuleRegistry {
            modules: BTreeMap::new(),
        }
    }

    fn register(&mut self, data: Vec<u8>) -> Result<u64, SyscallError> {
        let header = parse_module_header(&data)?;
        static NEXT_MOD: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_MOD.fetch_add(1, Ordering::SeqCst);
        self.modules.insert(id, ModuleImage { id, data, header });
        Ok(id)
    }

    fn get(&self, id: u64) -> Option<&ModuleImage> {
        self.modules.get(&id)
    }

    fn remove(&mut self, id: u64) -> Option<ModuleImage> {
        self.modules.remove(&id)
    }
}

static MODULE_REGISTRY: SpinLock<ModuleRegistry> = SpinLock::new(ModuleRegistry::new());

fn charge_task_silo_memory(task_id: TaskId, bytes: u64) -> Result<(), SyscallError> {
    if bytes == 0 {
        return Ok(());
    }
    let mut mgr = SILO_MANAGER.lock();
    let Some(silo_id) = mgr.silo_for_task(task_id) else {
        return Ok(());
    };
    let silo = mgr.get_mut(silo_id)?;
    let next = silo
        .mem_usage_bytes
        .checked_add(bytes)
        .ok_or(SyscallError::OutOfMemory)?;
    if silo.config.mem_max != 0 && next > silo.config.mem_max {
        return Err(SyscallError::OutOfMemory);
    }
    silo.mem_usage_bytes = next;
    Ok(())
}

fn release_task_silo_memory(task_id: TaskId, bytes: u64) {
    if bytes == 0 {
        return;
    }
    let mut mgr = SILO_MANAGER.lock();
    let Some(silo_id) = mgr.silo_for_task(task_id) else {
        return;
    };
    if let Ok(silo) = mgr.get_mut(silo_id) {
        silo.mem_usage_bytes = silo.mem_usage_bytes.saturating_sub(bytes);
    }
}

/// Charge memory usage against the current task's silo quota (if any).
///
/// Returns `OutOfMemory` when charging would exceed `SiloConfig.mem_max`.
/// Tasks that are not part of a silo are ignored.
pub fn charge_current_task_memory(bytes: u64) -> Result<(), SyscallError> {
    let Some(task) = crate::process::scheduler::current_task_clone_try() else {
        // Boot-time/kernel contexts may have no current task.
        // Also avoid deadlock when scheduler lock is already held in cleanup paths.
        return Ok(());
    };
    charge_task_silo_memory(task.id, bytes)
}

/// Release memory usage from the current task's silo quota (if any).
///
/// Tasks that are not part of a silo are ignored.
pub fn release_current_task_memory(bytes: u64) {
    if let Some(task) = crate::process::scheduler::current_task_clone_try() {
        release_task_silo_memory(task.id, bytes);
    }
}

fn extract_strate_label(path: &str) -> Option<String> {
    let prefix = "/srv/strate-fs-";
    let rest = path.strip_prefix(prefix)?;
    let mut parts = rest.split('/').filter(|p| !p.is_empty());
    let _strate_type = parts.next()?;
    let label = parts.next()?;
    if label.is_empty() || parts.next().is_some() {
        return None;
    }
    Some(String::from(label))
}

fn sanitize_label(raw: &str) -> String {
    let mut out = String::new();
    for b in raw.bytes().take(31) {
        let ok = (b as char).is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.';
        out.push(if ok { b as char } else { '_' });
    }
    if out.is_empty() {
        String::from("default")
    } else {
        out
    }
}

fn is_valid_label(raw: &str) -> bool {
    if raw.is_empty() || raw.len() > 31 {
        return false;
    }
    raw.bytes()
        .all(|b| (b as char).is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

pub fn set_current_silo_label_from_path(path: &str) -> Result<(), SyscallError> {
    let Some(label) = extract_strate_label(path) else {
        return Ok(());
    };
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let mut mgr = SILO_MANAGER.lock();
    let Some(silo_id) = mgr.silo_for_task(task.id) else {
        return Ok(());
    };
    let silo = mgr.get_mut(silo_id)?;
    // Do not overwrite a label that was already set (e.g. by kernel_spawn_strate).
    // The spawner's requested label takes precedence over the default path-derived one.
    if silo.strate_label.is_none() {
        silo.strate_label = Some(label);
    }
    Ok(())
}

pub fn current_task_silo_label() -> Option<String> {
    let task = current_task_clone()?;
    let mgr = SILO_MANAGER.lock();
    let silo_id = mgr.silo_for_task(task.id)?;
    let silo = mgr.get(silo_id).ok()?;
    silo.strate_label.clone()
}

pub fn list_silos_snapshot() -> Vec<SiloSnapshot> {
    let mgr = SILO_MANAGER.lock();
    mgr.silos
        .values()
        .map(|s| SiloSnapshot {
            id: s.id.sid,
            tier: s.id.tier,
            name: s.name.clone(),
            strate_label: s.strate_label.clone(),
            state: s.state,
            task_count: s.tasks.len(),
            mem_usage_bytes: s.mem_usage_bytes,
            mem_min_bytes: s.config.mem_min,
            mem_max_bytes: s.config.mem_max,
            mode: s.config.mode,
        })
        .collect()
}

/// Return silo identity + memory accounting for a task, if the task belongs to a silo.
///
/// Tuple layout:
/// - silo id (u32)
/// - optional label
/// - current usage bytes
/// - configured minimum bytes
/// - configured maximum bytes (0 = unlimited)
pub fn silo_info_for_task(task_id: TaskId) -> Option<(u32, Option<String>, u64, u64, u64)> {
    let mgr = SILO_MANAGER.lock();
    let silo_id = mgr.silo_for_task(task_id)?;
    let silo = mgr.get(silo_id).ok()?;
    Some((
        silo.id.sid,
        silo.strate_label.clone(),
        silo.mem_usage_bytes,
        silo.config.mem_min,
        silo.config.mem_max,
    ))
}

fn resolve_volume_resource_from_dev_path(dev_path: &str) -> Result<usize, SyscallError> {
    match dev_path {
        "/dev/sda" => ahci::get_device()
            .map(|d| d as *const _ as usize)
            .ok_or(SyscallError::NotFound),
        "/dev/vda" => virtio_block::get_device()
            .map(|d| d as *const _ as usize)
            .ok_or(SyscallError::NotFound),
        _ => Err(SyscallError::NotFound),
    }
}

pub fn kernel_spawn_strate(
    elf_data: &[u8],
    label: Option<&str>,
    dev_path: Option<&str>,
) -> Result<u32, SyscallError> {
    let module_id = {
        let mut registry = MODULE_REGISTRY.lock();
        registry.register(elf_data.to_vec())?
    };

    let silo_id = {
        let mut mgr = SILO_MANAGER.lock();
        // For kernel_spawn_strate (manual command), we auto-assign SID > 1000.
        // In a production system, this would follow the "42" rule from Init.
        let mut sid = 1000u32;
        while mgr.silos.contains_key(&sid) { sid += 1; }

        let id = SiloId::new(sid);
        let requested_label = label
            .map(sanitize_label)
            .unwrap_or_else(|| alloc::format!("inst-{}", id.sid));
        
        if mgr.silos.values().any(|s| s.strate_label.as_deref() == Some(requested_label.as_str())) {
            return Err(SyscallError::AlreadyExists);
        }

        let silo = Silo {
            id,
            name: alloc::format!("silo-{}", id.sid),
            strate_label: Some(requested_label),
            state: SiloState::Ready,
            config: SiloConfig {
                sid: id.sid,
                mode: 0o000, // Minimal mode for manual spawn
                family: StrateFamily::USR as u8,
                ..SiloConfig::default()
            },
            mode: OctalMode::from_octal(0),
            family: StrateFamily::USR,
            mem_usage_bytes: 0,
            flags: 0,
            module_id: Some(module_id),
            tasks: Vec::new(),
            granted_caps: Vec::new(),
            granted_resources: Vec::new(),
            event_seq: 0,
        };

        mgr.silos.insert(id.sid, silo);
        id.sid
    };

    let module_data = {
        let registry = MODULE_REGISTRY.lock();
        let module = registry.get(module_id).ok_or(SyscallError::BadHandle)?;
        module.data.clone()
    };

    let mut seed_caps = Vec::new();
    if let Some(path) = dev_path {
        let resource = resolve_volume_resource_from_dev_path(path)?;
        let cap = get_capability_manager().create_capability(
            ResourceType::Volume,
            resource,
            CapPermissions {
                read: true,
                write: true,
                execute: false,
                grant: true,
                revoke: true,
            },
        );
        seed_caps.push(cap);
    }

    let task = crate::process::elf::load_elf_task_with_caps(&module_data, "silo-admin", &seed_caps)
        .map_err(|_| SyscallError::InvalidArgument)?;
    let task_id = task.id;

    let mut mgr = SILO_MANAGER.lock();
    {
        let silo = mgr.get_mut(silo_id)?;
        silo.tasks.push(task_id);
        silo.state = SiloState::Running;
    }
    mgr.map_task(task_id, silo_id);
    mgr.push_event(SiloEvent {
        silo_id: silo_id as u64,
        kind: SiloEventKind::Started,
        data0: 0,
        data1: 0,
        tick: crate::process::scheduler::ticks(),
    });
    drop(mgr);
    crate::process::add_task(task);
    Ok(silo_id)
}

fn resolve_selector_to_silo_id(selector: &str, mgr: &SiloManager) -> Result<u32, SyscallError> {
    if let Ok(id) = selector.parse::<u32>() {
        if mgr.silos.contains_key(&id) {
            return Ok(id);
        }
        return Err(SyscallError::NotFound);
    }
    let mut found: Option<u32> = None;
    for s in mgr.silos.values() {
        if s.strate_label.as_deref() == Some(selector) {
            if found.is_some() {
                return Err(SyscallError::InvalidArgument);
            }
            found = Some(s.id.sid);
        }
    }
    found.ok_or(SyscallError::NotFound)
}

pub fn kernel_stop_silo(selector: &str, force_kill: bool) -> Result<u32, SyscallError> {
    let (silo_id, tasks) = {
        let mut mgr = SILO_MANAGER.lock();
        let silo_id = resolve_selector_to_silo_id(selector, &mgr)?;
        let mut tasks = Vec::new();
        {
            let silo = mgr.get_mut(silo_id)?;
            match silo.state {
                SiloState::Running | SiloState::Paused => {
                    if !force_kill {
                        silo.state = SiloState::Stopping;
                    }
                    tasks = silo.tasks.clone();
                    silo.tasks.clear();
                    silo.state = SiloState::Stopped;
                }
                SiloState::Stopped | SiloState::Created | SiloState::Ready => {}
                _ => return Err(SyscallError::InvalidArgument),
            }
        }
        for tid in &tasks {
            mgr.unmap_task(*tid);
        }
        mgr.push_event(SiloEvent {
            silo_id: silo_id as u64,
            kind: if force_kill {
                SiloEventKind::Killed
            } else {
                SiloEventKind::Stopped
            },
            data0: 0,
            data1: 0,
            tick: crate::process::scheduler::ticks(),
        });
        (silo_id, tasks)
    };
    for tid in tasks {
        crate::process::kill_task(tid);
    }
    Ok(silo_id)
}

pub fn kernel_destroy_silo(selector: &str) -> Result<u32, SyscallError> {
    let (silo_id, module_id) = {
        let mut mgr = SILO_MANAGER.lock();
        let silo_id = resolve_selector_to_silo_id(selector, &mgr)?;
        let module_id = {
            let silo = mgr.get(silo_id)?;
            if !silo.tasks.is_empty() {
                return Err(SyscallError::InvalidArgument);
            }
            match silo.state {
                SiloState::Stopped | SiloState::Created | SiloState::Ready | SiloState::Crashed => {
                }
                _ => return Err(SyscallError::InvalidArgument),
            }
            silo.module_id
        };
        let _ = mgr.silos.remove(&silo_id);
        (silo_id, module_id)
    };
    if let Some(mid) = module_id {
        let mut reg = MODULE_REGISTRY.lock();
        let _ = reg.remove(mid);
    }
    Ok(silo_id)
}

pub fn kernel_rename_silo_label(selector: &str, new_label: &str) -> Result<u32, SyscallError> {
    if !is_valid_label(new_label) {
        return Err(SyscallError::InvalidArgument);
    }
    let mut mgr = SILO_MANAGER.lock();
    let silo_id = resolve_selector_to_silo_id(selector, &mgr)?;
    if mgr
        .silos
        .values()
        .any(|s| s.id.sid != silo_id && s.strate_label.as_deref() == Some(new_label))
    {
        return Err(SyscallError::AlreadyExists);
    }
    let silo = mgr.get_mut(silo_id)?;
    match silo.state {
        SiloState::Stopped | SiloState::Created | SiloState::Ready | SiloState::Crashed => {
            silo.strate_label = Some(String::from(new_label));
            Ok(silo_id)
        }
        _ => Err(SyscallError::InvalidArgument),
    }
}

pub fn register_boot_strate_task(task_id: TaskId, label: &str) -> Result<u32, SyscallError> {
    let mut mgr = SILO_MANAGER.lock();
    // Default boot tasks get SID 1, 2, ...
    let mut sid = 1u32;
    while mgr.silos.contains_key(&sid) { sid += 1; }

    let id = SiloId::new(sid);
    let sanitized = sanitize_label(label);
    if mgr
        .silos
        .values()
        .any(|s| s.strate_label.as_deref() == Some(sanitized.as_str()))
    {
        return Err(SyscallError::AlreadyExists);
    }
    {
        let silo = Silo {
            id,
            name: alloc::format!("silo-{}", id.sid),
            strate_label: Some(sanitized),
            state: SiloState::Running,
            config: SiloConfig {
                sid: id.sid,
                mode: 0o777, // Boot tasks are fully privileged
                family: StrateFamily::SYS as u8,
                ..SiloConfig::default()
            },
            mode: OctalMode::from_octal(0o777),
            family: StrateFamily::SYS,
            mem_usage_bytes: 0,
            flags: 0,
            module_id: None,
            tasks: alloc::vec![task_id],
            granted_caps: Vec::new(),
            granted_resources: Vec::new(),
            event_seq: 0,
        };
        mgr.silos.insert(id.sid, silo);
    }
    mgr.map_task(task_id, id.sid);
    mgr.push_event(SiloEvent {
        silo_id: id.sid as u64,
        kind: SiloEventKind::Started,
        data0: 0,
        data1: 0,
        tick: crate::process::scheduler::ticks(),
    });
    Ok(id.sid)
}

fn resolve_module_handle(handle: u64, required: CapPermissions) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let cap_id = CapId::from_raw(handle);
    let cap = caps.get(cap_id).ok_or(SyscallError::BadHandle)?;

    if cap.resource_type != ResourceType::Module {
        return Err(SyscallError::BadHandle);
    }

    if (!required.read || cap.permissions.read)
        && (!required.write || cap.permissions.write)
        && (!required.execute || cap.permissions.execute)
        && (!required.grant || cap.permissions.grant)
        && (!required.revoke || cap.permissions.revoke)
    {
        Ok(cap.resource as u64)
    } else {
        Err(SyscallError::PermissionDenied)
    }
}

/// Grant the Silo Admin capability to a task (bootstrapping).
///
/// This should be called only for the initial admin task (e.g. "init").
pub fn grant_silo_admin_to_task(task: &alloc::sync::Arc<Task>) -> CapId {
    let cap = get_capability_manager().create_capability(
        ResourceType::Silo,
        SILO_ADMIN_RESOURCE,
        CapPermissions::all(),
    );
    // SAFETY: Bootstrapping. Caller must ensure exclusive access.
    unsafe { (&mut *task.process.capabilities.get()).insert(cap) }
}

// ============================================================================
// Module syscalls (temporary blob loader)
// ============================================================================

pub fn sys_module_load(fd_or_ptr: u64, len: u64) -> Result<u64, SyscallError> {
    // Module loading is currently restricted to admin.
    require_silo_admin()?;

    // Transitional path: if len != 0, treat arg1 as a userspace blob pointer.
    if len != 0 {
        let len = len as usize;
        if len == 0 || len > MAX_MODULE_BLOB_LEN {
            return Err(SyscallError::InvalidArgument);
        }

        let user = UserSliceRead::new(fd_or_ptr, len)?;
        let data = user.read_to_vec();

        let mut registry = MODULE_REGISTRY.lock();
        let id = registry.register(data)?;
        drop(registry);

        let cap = get_capability_manager().create_capability(
            ResourceType::Module,
            id as usize,
            CapPermissions::all(),
        );

        let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
        let cap_id = unsafe { (&mut *task.process.capabilities.get()).insert(cap) };

        return Ok(cap_id.as_u64());
    }

    // TODO: Load from a file handle (fd) via VFS once the path exists.
    // For now, interpret `fd_or_ptr` as either:
    // - a File handle (read all), or
    // - an IPC port handle that streams the module bytes.
    //
    // Stream protocol:
    // - msg_type = IPC_STREAM_DATA, flags = payload length (0..48)
    // - msg_type = IPC_STREAM_EOF (or DATA with flags=0) ends the stream
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let required = CapPermissions {
        read: true,
        write: false,
        execute: false,
        grant: false,
        revoke: false,
    };
    let cap = caps
        .get_with_permissions(CapId::from_raw(fd_or_ptr), required)
        .ok_or(SyscallError::PermissionDenied)?;
    let data = match cap.resource_type {
        ResourceType::File => {
            let fd = u32::try_from(cap.resource).map_err(|_| SyscallError::BadHandle)?;
            crate::vfs::read_all(fd)?
        }
        ResourceType::IpcPort => {
            let port_id = PortId::from_u64(cap.resource as u64);
            let port = port::get_port(port_id).ok_or(SyscallError::BadHandle)?;
            read_module_stream_from_port(&port)?
        }
        _ => return Err(SyscallError::BadHandle),
    };
    if data.len() > MAX_MODULE_BLOB_LEN {
        return Err(SyscallError::InvalidArgument);
    }

    let mut registry = MODULE_REGISTRY.lock();
    let id = registry.register(data)?;
    drop(registry);

    let cap = get_capability_manager().create_capability(
        ResourceType::Module,
        id as usize,
        CapPermissions::all(),
    );

    let cap_id = unsafe { (&mut *task.process.capabilities.get()).insert(cap) };

    Ok(cap_id.as_u64())
}

pub fn sys_module_unload(handle: u64) -> Result<u64, SyscallError> {
    require_silo_admin()?;
    let required = CapPermissions {
        read: false,
        write: false,
        execute: false,
        grant: false,
        revoke: true,
    };
    let module_id = resolve_module_handle(handle, required)?;
    let mut registry = MODULE_REGISTRY.lock();
    registry.remove(module_id);
    Ok(0)
}

pub fn sys_module_get_symbol(handle: u64, _ordinal: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        read: true,
        write: false,
        execute: false,
        grant: false,
        revoke: false,
    };
    let module_id = resolve_module_handle(handle, required)?;
    let registry = MODULE_REGISTRY.lock();
    let module = registry.get(module_id).ok_or(SyscallError::BadHandle)?;

    // The export table format is a simple array of u64 RVAs indexed by ordinal.
    let rva = resolve_export_offset(module, _ordinal)?;
    if let Some(header) = module.header {
        // Return file-relative offset for now (code base + RVA).
        return Ok(header.code_offset.saturating_add(rva));
    }
    Err(SyscallError::NotImplemented)
}

pub fn sys_module_query(handle: u64, out_ptr: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        read: true,
        write: false,
        execute: false,
        grant: false,
        revoke: false,
    };
    let module_id = resolve_module_handle(handle, required)?;
    if out_ptr == 0 {
        return Err(SyscallError::Fault);
    }

    let registry = MODULE_REGISTRY.lock();
    let module = registry.get(module_id).ok_or(SyscallError::BadHandle)?;

    let (format, flags, version, cpu_arch, code_size, data_size, bss_size, entry_point) =
        if let Some(header) = module.header {
            (
                1u32,
                header.flags,
                header.version,
                header.cpu_arch,
                header.code_size,
                header.data_size,
                header.bss_size,
                header.entry_point,
            )
        } else {
            (0u32, 0u32, 0u16, 0u8, 0u64, 0u64, 0u64, 0u64)
        };

    let info = ModuleInfo {
        id: module.id,
        format,
        flags,
        version,
        cpu_arch,
        reserved: 0,
        code_size,
        data_size,
        bss_size,
        entry_point,
        total_size: module.data.len() as u64,
    };

    const INFO_SIZE: usize = core::mem::size_of::<ModuleInfo>();
    let user = UserSliceWrite::new(out_ptr, INFO_SIZE)?;
    let src =
        unsafe { core::slice::from_raw_parts(&info as *const ModuleInfo as *const u8, INFO_SIZE) };
    user.copy_from(src);
    Ok(0)
}

// ============================================================================
// Syscall handlers (kernel entry points)
// ============================================================================

pub fn sys_silo_create(config_ptr: u64) -> Result<u64, SyscallError> {
    require_silo_admin()?;
    let config = read_user_config(config_ptr)?;
    config.validate()?;

    let mut mgr = SILO_MANAGER.lock();
    let id = mgr.create_silo(&config)?;
    drop(mgr);

    let cap = get_capability_manager().create_capability(
        ResourceType::Silo,
        id.sid as usize,
        CapPermissions::all(),
    );

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cap_id = unsafe { (&mut *task.process.capabilities.get()).insert(cap) };

    Ok(cap_id.as_u64())
}

pub fn sys_silo_config(handle: u64, res_ptr: u64) -> Result<u64, SyscallError> {
    require_silo_admin()?;
    let config = read_user_config(res_ptr)?;
    config.validate()?;

    let mut granted_caps = Vec::new();
    let mut granted_resources = Vec::new();
    if config.caps_len > 0 {
        let caps_list = read_caps_list(config.caps_ptr, config.caps_len)?;
        let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
        let caps = unsafe { &*task.process.capabilities.get() };

        for cap_handle in caps_list {
            let cap = caps
                .get(CapId::from_raw(cap_handle))
                .ok_or(SyscallError::BadHandle)?;
            if !cap.permissions.grant {
                return Err(SyscallError::PermissionDenied);
            }
            if !is_delegated_resource(cap.resource_type) {
                return Err(SyscallError::InvalidArgument);
            }
            if !granted_caps.contains(&cap_handle) {
                granted_caps.push(cap_handle);
            }
            add_or_merge_granted_resource(
                &mut granted_resources,
                GrantedResource {
                    resource_type: cap.resource_type,
                    resource: cap.resource,
                    permissions: cap.permissions,
                },
            );
        }
    }

    let sid = resolve_silo_handle(handle, CapPermissions::read_write())?;
    let mut mgr = SILO_MANAGER.lock();
    let silo = mgr.get_mut(sid as u32)?;
    
    // Validate potential mode change
    kernel_check_spawn_invariants(&silo.id, &OctalMode::from_octal(config.mode))?;

    silo.config = config;
    silo.mode = OctalMode::from_octal(config.mode);
    silo.granted_caps = granted_caps;
    silo.granted_resources = granted_resources;
    Ok(0)
}

pub fn sys_silo_attach_module(handle: u64, module_handle: u64) -> Result<u64, SyscallError> {
    require_silo_admin()?;
    let silo_id = resolve_silo_handle(handle, CapPermissions::read_write())?;

    let required = CapPermissions {
        read: true,
        write: false,
        execute: false,
        grant: false,
        revoke: false,
    };
    let module_id = resolve_module_handle(module_handle, required)?;

    let mut mgr = SILO_MANAGER.lock();
    let silo = mgr.get_mut(silo_id)?;

    match silo.state {
        SiloState::Created | SiloState::Stopped | SiloState::Ready => {
            silo.module_id = Some(module_id);
            silo.state = SiloState::Ready;
            Ok(0)
        }
        _ => Err(SyscallError::InvalidArgument),
    }
}

pub fn sys_silo_start(handle: u64) -> Result<u64, SyscallError> {
    require_silo_admin()?;
    let required = CapPermissions {
        read: false,
        write: false,
        execute: true,
        grant: false,
        revoke: false,
    };
    let silo_id = resolve_silo_handle(handle, required)?;
    let (module_id, granted_caps, silo_flags, can_start, within_task_limit) = {
        let mut mgr = SILO_MANAGER.lock();
        let silo = mgr.get_mut(silo_id)?;
        let can_start = matches!(silo.state, SiloState::Ready | SiloState::Stopped);
        let within_task_limit = match silo.config.max_tasks {
            0 => true, // 0 = unlimited
            max => silo.tasks.len() < max as usize,
        };
        let module_id = silo.module_id;
        let granted_caps = silo.granted_caps.clone();
        let silo_flags = silo.config.flags;
        if can_start && within_task_limit {
            silo.state = SiloState::Loading;
        }
        (
            module_id,
            granted_caps,
            silo_flags,
            can_start,
            within_task_limit,
        )
    };

    if !can_start {
        return Err(SyscallError::InvalidArgument);
    }
    if !within_task_limit {
        return Err(SyscallError::QueueFull);
    }

    let module_id = module_id.ok_or(SyscallError::InvalidArgument)?;

    let seed_caps = {
        let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
        let caps = unsafe { &mut *task.process.capabilities.get() };
        let mut out = Vec::new();
        for handle in granted_caps {
            // Enforce: caller must currently hold the capability.
            if !silo_has_capability(&task, handle) {
                return Err(SyscallError::PermissionDenied);
            }
            if let Some(dup) = caps.duplicate(CapId::from_raw(handle)) {
                out.push(dup);
            } else {
                return Err(SyscallError::PermissionDenied);
            }
        }
        out
    };

    let task_name: &'static str = if silo_flags & SILO_FLAG_ADMIN != 0 {
        "silo-admin"
    } else {
        "silo"
    };

    // Load the module entry without holding the manager lock.
    let load_result = {
        let registry = MODULE_REGISTRY.lock();
        let module = registry.get(module_id).ok_or(SyscallError::BadHandle)?;
        crate::process::elf::load_and_run_elf_with_caps(&module.data, task_name, &seed_caps)
            .map_err(|_| SyscallError::InvalidArgument)
    };

    let task_id = match load_result {
        Ok(id) => id,
        Err(e) => {
            let mut mgr = SILO_MANAGER.lock();
            if let Ok(silo) = mgr.get_mut(silo_id) {
                silo.state = SiloState::Ready;
            }
            return Err(e);
        }
    };

    // Give the silo an EOF stdin so that any read(0, …) returns 0 immediately
    // instead of EBADF (which can cause busy-loops) or blocking on the
    // keyboard (which would steal input from the foreground shell).
    if let Some(task) = crate::process::get_task_by_id(task_id) {
        let bg_stdin = crate::vfs::create_background_stdin();
        let fd_table = unsafe { &mut *task.process.fd_table.get() };
        fd_table.insert_at(crate::vfs::STDIN, bg_stdin);
    }

    let mut mgr = SILO_MANAGER.lock();
    {
        let silo = mgr.get_mut(silo_id)?;
        silo.tasks.push(task_id);
        silo.state = SiloState::Running;
    }
    mgr.map_task(task_id, silo_id);
    mgr.push_event(SiloEvent {
        silo_id,
        kind: SiloEventKind::Started,
        data0: 0,
        data1: 0,
        tick: crate::process::scheduler::ticks(),
    });
    Ok(0)
}

/// Best-effort cleanup hook called by the scheduler when a task terminates.
///
/// Ensures `task_to_silo` mappings are removed even for normal exits and
/// transitions a running/paused silo to `Stopped` when its last task is gone.
pub fn on_task_terminated(task_id: TaskId) {
    let mut mgr = SILO_MANAGER.lock();
    let silo_id = match mgr.silo_for_task(task_id) {
        Some(id) => id,
        None => return,
    };
    mgr.unmap_task(task_id);

    let mut emit_stopped = false;
    if let Ok(silo) = mgr.get_mut(silo_id) {
        if let Some(pos) = silo.tasks.iter().position(|tid| *tid == task_id) {
            silo.tasks.swap_remove(pos);
        }
        if silo.tasks.is_empty() {
            match silo.state {
                SiloState::Running | SiloState::Paused | SiloState::Stopping => {
                    silo.state = SiloState::Stopped;
                    silo.event_seq = silo.event_seq.wrapping_add(1);
                    emit_stopped = true;
                }
                _ => {}
            }
        }
    }

    if emit_stopped {
        mgr.push_event(SiloEvent {
            silo_id,
            kind: SiloEventKind::Stopped,
            data0: 0,
            data1: 0,
            tick: crate::process::scheduler::ticks(),
        });
    }
}

pub fn sys_silo_stop(handle: u64) -> Result<u64, SyscallError> {
    require_silo_admin()?;
    let required = CapPermissions {
        read: false,
        write: false,
        execute: true,
        grant: false,
        revoke: false,
    };
    let silo_id = resolve_silo_handle(handle, required)?;
    let tasks = {
        let mut mgr = SILO_MANAGER.lock();
        let mut tasks = Vec::new();
        let mut emit = false;
        {
            let silo = mgr.get_mut(silo_id)?;
            match silo.state {
                SiloState::Running | SiloState::Paused => {
                    silo.state = SiloState::Stopping;
                    tasks = silo.tasks.clone();
                    silo.tasks.clear();
                    emit = true;
                }
                _ => return Err(SyscallError::InvalidArgument),
            }
        }
        for tid in &tasks {
            mgr.unmap_task(*tid);
        }
        if emit {
            if let Ok(silo) = mgr.get_mut(silo_id) {
                silo.state = SiloState::Stopped;
            }
            mgr.push_event(SiloEvent {
                silo_id,
                kind: SiloEventKind::Stopped,
                data0: 0,
                data1: 0,
                tick: crate::process::scheduler::ticks(),
            });
        }
        tasks
    };

    for tid in tasks {
        crate::process::kill_task(tid);
    }
    Ok(0)
}

pub fn sys_silo_kill(handle: u64) -> Result<u64, SyscallError> {
    require_silo_admin()?;
    let required = CapPermissions {
        read: false,
        write: false,
        execute: true,
        grant: false,
        revoke: false,
    };
    let silo_id = resolve_silo_handle(handle, required)?;
    let tasks = {
        let mut mgr = SILO_MANAGER.lock();
        let mut tasks = Vec::new();
        {
            let silo = mgr.get_mut(silo_id)?;
            silo.state = SiloState::Stopped;
            tasks = silo.tasks.clone();
            silo.tasks.clear();
        }
        for tid in &tasks {
            mgr.unmap_task(*tid);
        }
        mgr.push_event(SiloEvent {
            silo_id,
            kind: SiloEventKind::Killed,
            data0: 0,
            data1: 0,
            tick: crate::process::scheduler::ticks(),
        });
        tasks
    };

    for tid in tasks {
        crate::process::kill_task(tid);
    }
    Ok(0)
}

fn silo_has_capability(task: &Task, cap_id: u64) -> bool {
    let caps = unsafe { &*task.process.capabilities.get() };
    caps.get(CapId::from_raw(cap_id)).is_some()
}

fn is_delegated_resource(rt: ResourceType) -> bool {
    matches!(
        rt,
        ResourceType::Nic
            | ResourceType::FileSystem
            | ResourceType::Console
            | ResourceType::Keyboard
            | ResourceType::Volume
            | ResourceType::Namespace
            | ResourceType::Device
            | ResourceType::File
            | ResourceType::IpcPort
            | ResourceType::IoPortRange
            | ResourceType::InterruptLine
    )
}

fn is_admin_task(task: &Task) -> bool {
    let caps = unsafe { &*task.process.capabilities.get() };
    let required = CapPermissions {
        read: false,
        write: false,
        execute: false,
        grant: true,
        revoke: false,
    };
    caps.has_resource_with_permissions(ResourceType::Silo, SILO_ADMIN_RESOURCE, required)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GrantedResource {
    resource_type: ResourceType,
    resource: usize,
    permissions: CapPermissions,
}

fn merge_permissions(a: CapPermissions, b: CapPermissions) -> CapPermissions {
    CapPermissions {
        read: a.read || b.read,
        write: a.write || b.write,
        execute: a.execute || b.execute,
        grant: a.grant || b.grant,
        revoke: a.revoke || b.revoke,
    }
}

fn permissions_subset(requested: CapPermissions, allowed: CapPermissions) -> bool {
    (!requested.read || allowed.read)
        && (!requested.write || allowed.write)
        && (!requested.execute || allowed.execute)
        && (!requested.grant || allowed.grant)
        && (!requested.revoke || allowed.revoke)
}

fn add_or_merge_granted_resource(list: &mut Vec<GrantedResource>, grant: GrantedResource) {
    for existing in list.iter_mut() {
        if existing.resource_type == grant.resource_type && existing.resource == grant.resource {
            existing.permissions = merge_permissions(existing.permissions, grant.permissions);
            return;
        }
    }
    list.push(grant);
}

/// Enforce that the current task may use a delegated capability.
pub fn enforce_cap_for_current_task(handle: u64) -> Result<(), SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;

    // Admin tasks bypass delegated-cap enforcement.
    if is_admin_task(&task) {
        return Ok(());
    }

    let caps = unsafe { &*task.process.capabilities.get() };
    let cap = caps
        .get(CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;

    if !is_delegated_resource(cap.resource_type) {
        return Ok(());
    }

    let silo_id = {
        let mgr = SILO_MANAGER.lock();
        mgr.silo_for_task(task.id)
    };

    if let Some(silo_id) = silo_id {
        let mgr = SILO_MANAGER.lock();
        if let Ok(silo) = mgr.get(silo_id) {
            for grant in &silo.granted_resources {
                if grant.resource_type == cap.resource_type && grant.resource == cap.resource {
                    if permissions_subset(cap.permissions, grant.permissions) {
                        return Ok(());
                    }
                    return Err(SyscallError::PermissionDenied);
                }
            }
        }
    }

    Err(SyscallError::PermissionDenied)
}

/// Enforce console access for the current task.
///
/// Only admin tasks or tasks holding a Console capability with write permission
/// can access the kernel console (SYS_WRITE fd=1/2).
pub fn enforce_console_access() -> Result<(), SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    if is_admin_task(&task) {
        return Ok(());
    }
    let caps = unsafe { &*task.process.capabilities.get() };
    let required = CapPermissions {
        read: false,
        write: true,
        execute: false,
        grant: false,
        revoke: false,
    };
    if caps.has_resource_type_with_permissions(ResourceType::Console, required) {
        Ok(())
    } else {
        Err(SyscallError::PermissionDenied)
    }
}

pub fn sys_silo_event_next(_event_ptr: u64) -> Result<u64, SyscallError> {
    require_silo_admin()?;
    if _event_ptr == 0 {
        return Err(SyscallError::Fault);
    }

    let event = {
        let mut mgr = SILO_MANAGER.lock();
        mgr.events.pop_front()
    };

    let event = match event {
        Some(e) => e,
        None => return Err(SyscallError::Again),
    };

    const EVT_SIZE: usize = core::mem::size_of::<SiloEvent>();
    let user = UserSliceWrite::new(_event_ptr, EVT_SIZE)?;
    let src =
        unsafe { core::slice::from_raw_parts(&event as *const SiloEvent as *const u8, EVT_SIZE) };
    user.copy_from(src);
    Ok(0)
}

pub fn sys_silo_suspend(handle: u64) -> Result<u64, SyscallError> {
    require_silo_admin()?;
    let required = CapPermissions {
        read: false,
        write: false,
        execute: true,
        grant: false,
        revoke: false,
    };
    let silo_id = resolve_silo_handle(handle, required)?;

    let tasks = {
        let mut mgr = SILO_MANAGER.lock();
        let silo = mgr.get_mut(silo_id)?;
        match silo.state {
            SiloState::Running => {
                silo.state = SiloState::Paused;
                silo.tasks.clone()
            }
            _ => return Err(SyscallError::InvalidArgument),
        }
    };

    for tid in &tasks {
        crate::process::suspend_task(*tid);
    }

    let mut mgr = SILO_MANAGER.lock();
    mgr.push_event(SiloEvent {
        silo_id,
        kind: SiloEventKind::Paused,
        data0: 0,
        data1: 0,
        tick: crate::process::scheduler::ticks(),
    });

    Ok(0)
}

pub fn sys_silo_resume(handle: u64) -> Result<u64, SyscallError> {
    require_silo_admin()?;
    let required = CapPermissions {
        read: false,
        write: false,
        execute: true,
        grant: false,
        revoke: false,
    };
    let silo_id = resolve_silo_handle(handle, required)?;

    let tasks = {
        let mut mgr = SILO_MANAGER.lock();
        let silo = mgr.get_mut(silo_id)?;
        match silo.state {
            SiloState::Paused => {
                silo.state = SiloState::Running;
                silo.tasks.clone()
            }
            _ => return Err(SyscallError::InvalidArgument),
        }
    };

    for tid in &tasks {
        crate::process::resume_task(*tid);
    }

    let mut mgr = SILO_MANAGER.lock();
    mgr.push_event(SiloEvent {
        silo_id,
        kind: SiloEventKind::Resumed,
        data0: 0,
        data1: 0,
        tick: crate::process::scheduler::ticks(),
    });

    Ok(0)
}

// ============================================================================
// Fault handling (called from exception handlers)
// ============================================================================

fn dump_user_fault(task_id: TaskId, reason: SiloFaultReason, extra: u64, subcode: u64, rip: u64) {
    let task_meta = crate::process::get_task_by_id(task_id).map(|task| {
        let state = unsafe { *task.state.get() };
        let as_ref = unsafe { &*task.process.address_space.get() };
        (
            task.pid,
            task.tid,
            task.name,
            state,
            as_ref.cr3().as_u64(),
            as_ref.is_kernel(),
        )
    });

    if let Some((pid, tid, name, state, as_cr3, as_is_kernel)) = task_meta {
        crate::serial_println!(
            "\x1b[31m[handle_user_fault]\x1b[0m task={} \x1b[36mpid={}\x1b[0m tid={} name='{}' state={:?} reason={:?} \x1b[35mrip={:#x}\x1b[0m \x1b[35mextra={:#x}\x1b[0m subcode={:#x} as_cr3={:#x} as_kernel={}",
            task_id.as_u64(),
            pid,
            tid,
            name,
            state,
            reason,
            rip,
            extra,
            subcode,
            as_cr3,
            as_is_kernel
        );
    } else {
        crate::serial_println!(
            "\x1b[31m[handle_user_fault]\x1b[0m task={} reason={:?} \x1b[35mrip={:#x}\x1b[0m \x1b[35mextra={:#x}\x1b[0m subcode={:#x} (task metadata unavailable)",
            task_id.as_u64(),
            reason,
            rip,
            extra,
            subcode
        );
    }

    if reason == SiloFaultReason::PageFault {
        let present = (subcode & 0x1) != 0;
        let write = (subcode & 0x2) != 0;
        let user = (subcode & 0x4) != 0;
        let reserved = (subcode & 0x8) != 0;
        let instr_fetch = (subcode & 0x10) != 0;
        let pkey = (subcode & 0x20) != 0;
        let shadow_stack = (subcode & 0x40) != 0;
        let sgx = (subcode & 0x8000) != 0;
        crate::serial_println!(
            "\x1b[31m[handle_user_fault]\x1b[0m \x1b[31mpagefault\x1b[0m \x1b[35maddr={:#x}\x1b[0m \x1b[35mrip={:#x}\x1b[0m ec={:#x} present={} write={} user={} reserved={} ifetch={} pkey={} shadow_stack={} sgx={}",
            extra,
            rip,
            subcode,
            present,
            write,
            user,
            reserved,
            instr_fetch,
            pkey,
            shadow_stack,
            sgx
        );
        if user && extra < 0x1000 {
            crate::serial_println!(
                "\x1b[31m[handle_user_fault]\x1b[0m \x1b[33mhint: low user address fault ({:#x}) -> probable NULL/near-NULL dereference\x1b[0m",
                extra
            );
        }
    } else {
        crate::serial_println!(
            "\x1b[31m[handle_user_fault]\x1b[0m \x1b[31mfault detail\x1b[0m \x1b[35mrip={:#x}\x1b[0m code={:#x}",
            rip,
            subcode
        );
    }
}

pub fn handle_user_fault(
    task_id: TaskId,
    reason: SiloFaultReason,
    extra: u64,
    subcode: u64,
    rip: u64,
) {
    dump_user_fault(task_id, reason, extra, subcode, rip);

    // Best-effort: map task to silo, mark crashed, emit event, kill tasks.
    let tasks = {
        let mut mgr = SILO_MANAGER.lock();
        let silo_id = match mgr.silo_for_task(task_id) {
            Some(id) => id,
            None => {
                crate::serial_println!(
                    "[handle_user_fault] Non-silo task {} crashed (reason={:?})! Killing it.",
                    task_id.as_u64(),
                    reason
                );
                drop(mgr);
                crate::process::kill_task(task_id);
                return;
            }
        };
        let mut tasks = Vec::new();
        {
            if let Ok(silo) = mgr.get_mut(silo_id) {
                silo.state = SiloState::Crashed;
                tasks = silo.tasks.clone();
                silo.tasks.clear();
                silo.event_seq = silo.event_seq.wrapping_add(1);
            }
        }
        for tid in &tasks {
            mgr.unmap_task(*tid);
        }
        mgr.push_event(SiloEvent {
            silo_id,
            kind: SiloEventKind::Crashed,
            data0: pack_fault(reason, subcode),
            data1: extra,
            tick: crate::process::scheduler::ticks(),
        });
        tasks
    };

    // Kill all tasks in the silo (including current).
    for tid in tasks {
        crate::process::kill_task(tid);
    }
    // If task_id wasn't in the task list (stale mapping), kill it anyway.
    crate::process::kill_task(task_id);
}
