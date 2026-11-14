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

//! Per-process generation-tagged handle table (IPC ABI v2, §3.1).

use super::{
    endpoint,
    endpoint::{CallSlot, Endpoint},
    notif::Notification,
};
use alloc::{sync::Arc, vec::Vec};
use strat9_abi::ipc_v2::{Handle, EP_RECV, GENERIC_RIGHTS_MASK, RIGHTS_SAME, RIGHT_DUPLICATE};

/// Hard limit on live entries in one process handle table.
pub const MAX_HANDLES: usize = 256;

/// The object a handle resolves to.
#[derive(Clone)]
pub enum ObjRef {
    /// Endpoint object.
    Endpoint(Arc<Endpoint>),
    /// Single-use reply target for an in-flight call.
    Reply(Arc<CallSlot>),
    /// Notification object.
    Notif(Arc<Notification>),
    /// Memory object.
    Mem(Arc<super::memobj::MemObject>),
}

impl ObjRef {
    /// `ObjType` written into a received `CapXfer::mode` (§4.2).
    pub fn obj_type(&self) -> u32 {
        use strat9_abi::ipc_v2::{OBJ_ENDPOINT, OBJ_MEMOBJ, OBJ_NOTIFICATION, OBJ_REPLY};
        match self {
            ObjRef::Endpoint(_) => OBJ_ENDPOINT,
            ObjRef::Reply(_) => OBJ_REPLY,
            ObjRef::Notif(_) => OBJ_NOTIFICATION,
            ObjRef::Mem(_) => OBJ_MEMOBJ,
        }
    }
}

/// One table entry: rights, object and immutable badge.
#[derive(Clone)]
pub struct Entry {
    /// Rights bitmask (§3.2).
    pub rights: u32,
    /// Referenced object.
    pub obj: ObjRef,
    /// Endpoint sender badge / notification bit mask / Reply generation.
    pub badge: u64,
}

#[derive(Clone)]
struct Slot {
    gen: u32,
    entry: Option<Entry>,
}

/// The process handle table.
///
/// Index 0 is permanently reserved and never handed out: this makes handle
/// value `0` (structure `(index=0, gen=0)/2`) impossible without needing a
/// non-zero starting generation. A new slot starts at generation 1 and every
/// reuse increments the generation before the entry becomes visible.
pub struct HandleTable {
    slots: Vec<Slot>,
    free: Vec<u32>,
    len: usize,
    /// Slots promised to an in-progress receive (§4.5 step 3). Counted against
    /// [`HandleTable::free_slots`] but not yet occupied; [`HandleTable::insert`]
    /// consumes one unit per successful insert.
    reserved: usize,
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

impl HandleTable {
    /// Create an empty table with the reserved index-0 slot.
    pub fn new() -> Self {
        HandleTable {
            slots: alloc::vec![Slot {
                gen: 0,
                entry: None,
            }],
            free: Vec::new(),
            len: 0,
            reserved: 0,
        }
    }

    /// Number of live entries.
    pub fn table_len(&self) -> usize {
        self.len
    }

    /// Number of slots currently promised by [`HandleTable::reserve`].
    pub fn reserved(&self) -> usize {
        self.reserved
    }

    /// Slots that may still be handed out, honouring outstanding reservations.
    pub fn free_slots(&self) -> usize {
        MAX_HANDLES.saturating_sub(self.len + self.reserved)
    }

    /// Reserve `n` slots for an in-progress receive (§4.5 step 3).
    ///
    /// Invariant: after a successful `reserve(n)` the next `n` successful
    /// [`HandleTable::insert`] calls cannot fail for capacity reasons; each one
    /// consumes one reserved unit. The caller must release any unused units
    /// with [`HandleTable::release_reservation`].
    pub fn reserve(&mut self, n: usize) -> Result<(), crate::syscall::error::SyscallError> {
        if n > self.free_slots() {
            return Err(crate::syscall::error::SyscallError::NoSpace);
        }
        self.reserved += n;
        Ok(())
    }

    /// Return `n` unused reserved slots (saturating).
    pub fn release_reservation(&mut self, n: usize) {
        self.reserved = self.reserved.saturating_sub(n);
    }

    /// Insert an entry, reusing a free slot if possible.
    ///
    /// Returns `None` when the table already holds [`MAX_HANDLES`] entries and
    /// no reservation covers this insert. A successful insert consumes one
    /// unit of an outstanding reservation, guaranteeing it cannot fail.
    pub fn insert(&mut self, rights: u32, obj: ObjRef, badge: u64) -> Option<Handle> {
        if self.reserved > 0 {
            self.reserved -= 1;
        } else if self.len >= MAX_HANDLES {
            return None;
        }
        let entry = Entry { rights, obj, badge };
        if let Some(index) = self.free.pop() {
            let slot = &mut self.slots[index as usize];
            // A reused slot must never resolve the previous generation.
            slot.gen = slot.gen.wrapping_add(1).max(1);
            slot.entry = Some(entry);
            self.len += 1;
            Some(Handle::new(index, slot.gen))
        } else {
            let index = self.slots.len() as u32;
            self.slots.push(Slot {
                gen: 1,
                entry: Some(entry),
            });
            self.len += 1;
            Some(Handle::new(index, 1))
        }
    }

    /// Resolve a handle and check that `required` rights are present.
    pub fn resolve(
        &self,
        h: Handle,
        required: u32,
    ) -> Result<Entry, crate::syscall::error::SyscallError> {
        let entry = self.validate(h)?;
        if entry.rights & required != required {
            return Err(crate::syscall::error::SyscallError::PermissionDenied);
        }
        Ok(entry)
    }

    /// Take an entry out of the table and **apply its object side effects**
    /// (endpoint reference release, Reply-handle cancellation).
    pub fn remove(&mut self, h: Handle) -> Result<Entry, crate::syscall::error::SyscallError> {
        let entry = self.remove_raw(h)?;
        endpoint::release_handle(&entry);
        Ok(entry)
    }

    /// Take an entry out of the table without object side effects.
    ///
    /// For consumption paths that take over the object's obligations, e.g.
    /// `sys_ep_reply`, which delivers the reply immediately afterwards and must
    /// not cancel the call it is completing.
    pub fn remove_raw(&mut self, h: Handle) -> Result<Entry, crate::syscall::error::SyscallError> {
        let entry = self.validate(h)?;
        let slot = &mut self.slots[h.index() as usize];
        slot.entry = None;
        self.free.push(h.index());
        self.len -= 1;
        Ok(entry)
    }

    /// Drain every entry, applying the object-side effects of dropping each
    /// handle (in particular closing the last `EP_RECV` endpoint reference).
    pub fn remove_all(&mut self) {
        for slot in self.slots.iter_mut() {
            if let Some(entry) = slot.entry.take() {
                endpoint::release_handle(&entry);
            }
        }
        self.slots.truncate(1);
        self.free.clear();
        self.len = 0;
        self.reserved = 0;
    }

    /// Duplicate a handle with an equal or smaller rights mask.
    pub fn duplicate(
        &mut self,
        h: Handle,
        requested_rights: u32,
    ) -> Result<Handle, crate::syscall::error::SyscallError> {
        let entry = self.validate(h)?;
        if entry.rights & RIGHT_DUPLICATE == 0 {
            return Err(crate::syscall::error::SyscallError::PermissionDenied);
        }
        let rights = if requested_rights == RIGHTS_SAME {
            entry.rights
        } else {
            requested_rights & entry.rights
        };
        let new = self
            .insert(rights, entry.obj.clone(), entry.badge)
            .ok_or(crate::syscall::error::SyscallError::NoSpace)?;
        if rights & EP_RECV != 0 {
            endpoint::retain_handle(&entry);
        }
        Ok(new)
    }

    /// Clone this table for `fork`: same objects, rights and generations.
    /// Every copied `EP_RECV` endpoint entry takes an extra reference.
    pub fn fork_clone(&self) -> Self {
        let out = HandleTable {
            slots: self.slots.clone(),
            free: self.free.clone(),
            len: self.len,
            reserved: 0,
        };
        for slot in out.slots.iter() {
            if let Some(entry) = slot.entry.as_ref() {
                if entry.rights & EP_RECV != 0 {
                    endpoint::retain_handle(entry);
                }
            }
        }
        out
    }

    /// Mask of rights that may be requested through `ipc_mint`/`duplicate`.
    pub const fn generic_rights() -> u32 {
        GENERIC_RIGHTS_MASK
    }

    fn validate(&self, h: Handle) -> Result<Entry, crate::syscall::error::SyscallError> {
        use crate::syscall::error::SyscallError;
        if !h.is_valid() {
            return Err(SyscallError::BadHandle);
        }
        let slot = self
            .slots
            .get(h.index() as usize)
            .ok_or(SyscallError::BadHandle)?;
        if slot.gen != h.generation() {
            return Err(SyscallError::BadHandle);
        }
        slot.entry.clone().ok_or(SyscallError::BadHandle)
    }
}
