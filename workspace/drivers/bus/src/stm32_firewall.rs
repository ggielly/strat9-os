use alloc::{string::String, vec::Vec};
use crate::BusError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallType {
    Peripheral,
    Memory,
    NoType,
}

pub struct FirewallEntry {
    pub firewall_id: u32,
    pub extra_args: [u32; 4],
    pub extra_args_count: usize,
}

pub trait FirewallController: Send + Sync {
    /// Performs the name operation.
    fn name(&self) -> &str;
    /// Performs the firewall type operation.
    fn firewall_type(&self) -> FirewallType;
    /// Performs the max entries operation.
    fn max_entries(&self) -> u32;
    /// Performs the grant access operation.
    fn grant_access(&self, firewall_id: u32) -> Result<(), BusError>;
    /// Performs the release access operation.
    fn release_access(&self, firewall_id: u32) -> Result<(), BusError>;
    /// Performs the grant memory range operation.
    fn grant_memory_range(&self, _start: u64, _size: u64) -> Result<(), BusError> {
        Err(BusError::NotSupported)
    }
}
