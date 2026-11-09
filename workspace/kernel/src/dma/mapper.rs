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

//! Per-device DMA address translation.
//!
//! Drivers keep working with physical addresses for CPU access, but program
//! `DmaMapper::translate()` results into hardware.  When IOMMU translation is
//! inactive the mapper is an identity function, so the same code path is
//! used at boot and after activation.

use alloc::sync::Arc;

use crate::hardware::iommu::{self, DmaProt, Domain, FaultPolicy, Sbdf};

/// Physical <-> device address translator bound to one PCI function.
pub struct DmaMapper {
    domain: Option<Arc<Domain>>,
}

impl DmaMapper {
    /// Build a translator for `sbdf`; creates a domain only when IOMMU
    /// translation is active.
    pub fn for_sbdf(sbdf: Sbdf) -> Self {
        if iommu::enabled() {
            Self {
                domain: iommu::find_domain(sbdf)
                    .or_else(|| iommu::domain_for_owned(sbdf, None, FaultPolicy::Log).ok()),
            }
        } else {
            Self { domain: None }
        }
    }

    /// Map `[phys, phys + len)` and return the device address.
    pub fn translate(&self, phys: u64, len: usize, prot: DmaProt) -> u64 {
        if let Some(domain) = &self.domain {
            if let Ok(iova) = domain.map_auto(phys, len as u64, prot) {
                return iova;
            }
        }
        phys
    }

    /// Release a mapping previously returned by [`DmaMapper::translate`].
    pub fn release(&self, address: u64, len: usize) {
        if let Some(domain) = &self.domain {
            if domain.translate(address).is_some() {
                let _ = domain.unmap(address, len as u64);
            }
        }
    }

    /// True when translation is active.
    pub fn is_translating(&self) -> bool {
        self.domain.is_some() && iommu::enabled()
    }
}
