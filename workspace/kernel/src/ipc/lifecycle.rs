use crate::process::TaskId;

use super::{
    channel::{self, ChanId},
    port::{self, PortId},
    semaphore::{self, SemId},
    shared_ring::{self, RingId},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiHandleDestroyError {
    NotFound,
}

/// Shared finalization path for IPC resources that remain live until their
/// last handle disappears from the global capability set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiHandleResource {
    Channel(ChanId),
    Semaphore(SemId),
    SharedRing(RingId),
    IpcPort { id: PortId, owner: Option<TaskId> },
}

impl MultiHandleResource {
    /// Destroy the underlying resource once the last handle is gone.
    pub fn destroy(self) -> Result<(), MultiHandleDestroyError> {
        match self {
            Self::Channel(id) => channel::destroy_channel(id)
                .map_err(|_| MultiHandleDestroyError::NotFound),
            Self::Semaphore(id) => semaphore::destroy_semaphore(id)
                .map_err(|_| MultiHandleDestroyError::NotFound),
            Self::SharedRing(id) => {
                shared_ring::destroy_ring(id).map_err(|_| MultiHandleDestroyError::NotFound)
            }
            Self::IpcPort { id, owner } => {
                let owner = owner.or_else(|| port::get_port(id).map(|port| port.owner));
                let task_id = owner.ok_or(MultiHandleDestroyError::NotFound)?;
                port::destroy_port(id, task_id).map_err(|_| MultiHandleDestroyError::NotFound)
            }
        }
    }
}