/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

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
    // TODO(migration): This API currently serves both "last handle dropped"
    // and admin-side destroy paths such as ipcfs::unlink. Decide whether those
    // semantics should stay identical. If admin unlink is meant to force
    // teardown even while capabilities still exist, split this into explicit
    // final-release vs force-destroy entry points and make the caller choose
    // intentionally instead of sharing one ambiguous destroy() path.
    pub fn destroy(self) -> Result<(), MultiHandleDestroyError> {
        match self {
            Self::Channel(id) => {
                channel::destroy_channel(id).map_err(|_| MultiHandleDestroyError::NotFound)
            }
            Self::Semaphore(id) => {
                semaphore::destroy_semaphore(id).map_err(|_| MultiHandleDestroyError::NotFound)
            }
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
