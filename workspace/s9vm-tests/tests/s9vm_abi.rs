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

//! L2: s9vm ABI (constants, structure, version).

use strat9_abi::syscall::*;
use strat9_abi::vmm as abi;

#[test]
fn p0_syscall_numbers_are_distinct_and_in_range() {
    let p0 = [
        SYS_VMM_CREATE,
        SYS_VMM_DESTROY,
        SYS_VMM_MAP_MEM,
        SYS_VMM_SET_REGS,
        SYS_VMM_GET_REGS,
        SYS_VMM_RUN,
        SYS_VMM_INJECT_IRQ,
        SYS_VMM_EXIT_HANDLER,
        SYS_VMM_IRQ_WAIT,
        SYS_VMM_INFO,
    ];
    for (index, number) in p0.iter().enumerate() {
        assert_eq!(
            *number,
            560 + index,
            "P0 numbering is not contiguous at index {}",
            index
        );
    }
    let mut sorted = p0.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), p0.len());
}

#[test]
fn reserved_syscall_numbers_are_distinct_and_out_of_p0() {
    let reserved = [
        SYS_VMM_CREATE_VCPU,
        SYS_VMM_DESTROY_VCPU,
        SYS_VMM_MAP_IOMMU,
        SYS_VMM_SET_CPUID_POLICY,
        SYS_VMM_GET_EXIT_STATS,
        SYS_VMM_PAUSE,
        SYS_VMM_RESUME,
        SYS_VMM_SET_AFFINITY,
        SYS_VMM_INJECT_NMI,
        SYS_VMM_DEBUG_DUMP,
    ];
    for (index, number) in reserved.iter().enumerate() {
        assert_eq!(*number, 570 + index);
    }
    let mut sorted = reserved.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), reserved.len());
}

#[test]
fn p0_block_does_not_collide_with_iommu_block() {
    // IOMMU syscalls occupy 520..=536; the VMM block starts at 560.
    assert!(SYS_VMM_CREATE > 536);
    assert!(SYS_VMM_CREATE < 600);
}

#[test]
fn abi_version_is_one() {
    assert_eq!(abi::VMM_ABI_VERSION, 1);
}

#[test]
fn regs_structure_layout() {
    use core::mem::{align_of, size_of};
    assert_eq!(size_of::<abi::VmmRegs>(), 184);
    assert_eq!(align_of::<abi::VmmRegs>(), 8);
}

#[test]
fn info_structure_layout() {
    use core::mem::{align_of, size_of};
    assert_eq!(size_of::<abi::VmmInfo>(), 96);
    assert_eq!(align_of::<abi::VmmInfo>(), 8);
}

#[test]
fn exit_event_structure_layout() {
    use core::mem::{align_of, size_of};
    assert_eq!(size_of::<abi::VmmExitEvent>(), 48);
    assert_eq!(align_of::<abi::VmmExitEvent>(), 8);
}

#[test]
fn state_and_exit_kind_values_are_stable() {
    assert_eq!(abi::state::CREATED, 0);
    assert_eq!(abi::state::RUNNING, 1);
    assert_eq!(abi::state::PAUSED, 2);
    assert_eq!(abi::state::STOPPED, 3);
    assert_eq!(abi::state::FAILED, 4);

    let kinds = [
        abi::exit_kind::MMIO_READ,
        abi::exit_kind::MMIO_WRITE,
        abi::exit_kind::IO_PORT,
        abi::exit_kind::HALT,
        abi::exit_kind::TRANSLATION,
        abi::exit_kind::EXCEPTION,
        abi::exit_kind::OTHER,
    ];
    let mut sorted = kinds.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), kinds.len());
    assert!(kinds.iter().all(|kind| *kind != 0));
}

#[test]
fn name_limit_matches_info_storage() {
    assert_eq!(abi::VMM_NAME_MAX, abi::VmmInfo::default().name.len());
}
