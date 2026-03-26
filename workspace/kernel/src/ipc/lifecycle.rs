use crate::process::TaskId;

use super::{
    channel::{self, ChanId},
    port::{self, PortId},
    semaphore::{self, SemId},
    shared_ring::{self, RingId},
};

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
    pub fn destroy(self) {
        match self {
            Self::Channel(id) => {
                let _ = channel::destroy_channel(id);
            }
            Self::Semaphore(id) => {
                let _ = semaphore::destroy_semaphore(id);
            }
            Self::SharedRing(id) => {
                let _ = shared_ring::destroy_ring(id);
            }
            Self::IpcPort { id, owner } => {
                let owner = owner.or_else(|| port::get_port(id).map(|port| port.owner));
                if let Some(task_id) = owner {
                    let _ = port::destroy_port(id, task_id);
                }
            }
        }
    }
}