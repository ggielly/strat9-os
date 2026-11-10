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
fn abi_version_is_current() {
    assert_eq!(abi::VMM_ABI_VERSION, 3);
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
fn image_info_structure_layout() {
    use core::mem::{align_of, offset_of, size_of};
    assert_eq!(size_of::<abi::VmmImageInfo>(), 40);
    assert_eq!(align_of::<abi::VmmImageInfo>(), 8);
    assert_eq!(offset_of!(abi::VmmImageInfo, abi_version), 0);
    assert_eq!(offset_of!(abi::VmmImageInfo, entry), 8);
    let info = abi::VmmImageInfo::default();
    assert_eq!(info.entry, 0);
    assert_eq!(info.span_max, 0);
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

#[test]
fn exit_complete_syscall_number_is_stable() {
    // Completes an exit emulated by the policy (value + RIP advance).
    assert_eq!(SYS_VMM_EXIT_COMPLETE, 580);
}

#[test]
fn world_list_syscall_numbers_are_stable() {
    assert_eq!(SYS_VMM_LIST, 584);
    assert_eq!(SYS_VMM_STATS, 585);
    assert_eq!(SYS_VMM_LIST, SYS_VMM_BOOT_INFO + 1);
    assert_eq!(SYS_VMM_STATS, SYS_VMM_BOOT_INFO + 2);
    // Still inside the s9vm block, before the storage block (600).
    assert!(SYS_VMM_STATS > SYS_VMM_BOOT_INFO);
    assert!(SYS_VMM_STATS < 600);
}

#[test]
fn world_entry_layout() {
    use core::mem::{align_of, offset_of, size_of};

    assert_eq!(size_of::<abi::VmmWorldEntry>(), 72);
    assert_eq!(align_of::<abi::VmmWorldEntry>(), 8);

    assert_eq!(offset_of!(abi::VmmWorldEntry, abi_version), 0);
    assert_eq!(offset_of!(abi::VmmWorldEntry, state), 4);
    assert_eq!(offset_of!(abi::VmmWorldEntry, vmm_id), 8);
    assert_eq!(offset_of!(abi::VmmWorldEntry, silo_id), 16);
    assert_eq!(offset_of!(abi::VmmWorldEntry, vcpu_count), 20);
    assert_eq!(offset_of!(abi::VmmWorldEntry, mapped_pages), 24);
    assert_eq!(offset_of!(abi::VmmWorldEntry, name), 32);
    assert_eq!(offset_of!(abi::VmmWorldEntry, name_len), 64);
    assert_eq!(offset_of!(abi::VmmWorldEntry, reserved), 68);

    // No implicit padding: the last fixed field ends exactly at `size`.
    assert_eq!(
        offset_of!(abi::VmmWorldEntry, reserved) + 4,
        size_of::<abi::VmmWorldEntry>()
    );
}

#[test]
fn world_entry_zeroed_defaults() {
    let entry = abi::VmmWorldEntry::default();
    assert_eq!(entry.abi_version, 0);
    assert_eq!(entry.state, 0);
    assert_eq!(entry.vmm_id, 0);
    assert_eq!(entry.silo_id, 0);
    assert_eq!(entry.vcpu_count, 0);
    assert_eq!(entry.mapped_pages, 0);
    assert_eq!(entry.name_len, 0);
    assert_eq!(entry.reserved, 0);
    assert!(entry.name.iter().all(|byte| *byte == 0));
    assert!(entry.name_slice().is_empty());
}

#[test]
fn world_entry_name_truncation_invariants() {
    let mut entry = abi::VmmWorldEntry {
        name_len: abi::VMM_NAME_MAX as u32,
        ..abi::VmmWorldEntry::default()
    };
    entry.name = [0xAB; abi::VMM_NAME_MAX];
    assert_eq!(entry.name_slice().len(), abi::VMM_NAME_MAX);
    assert!(entry.name_slice().iter().all(|byte| *byte == 0xAB));

    // A forged over-long `name_len` must never index past the buffer.
    entry.name_len = u32::MAX;
    assert_eq!(entry.name_slice().len(), abi::VMM_NAME_MAX);

    // A shorter name never exposes the zero padding.
    entry.name_len = 5;
    assert_eq!(entry.name_slice(), &[0xAB; 5]);
    assert_eq!(entry.name.len(), abi::VMM_NAME_MAX);
}

#[test]
fn world_stats_layout() {
    use core::mem::{align_of, offset_of, size_of};

    assert_eq!(size_of::<abi::VmmWorldStats>(), 96);
    assert_eq!(align_of::<abi::VmmWorldStats>(), 8);

    assert_eq!(offset_of!(abi::VmmWorldStats, abi_version), 0);
    assert_eq!(offset_of!(abi::VmmWorldStats, paused), 4);
    assert_eq!(offset_of!(abi::VmmWorldStats, vmm_id), 8);
    assert_eq!(offset_of!(abi::VmmWorldStats, runs), 16);
    assert_eq!(offset_of!(abi::VmmWorldStats, policy_exits), 24);
    assert_eq!(offset_of!(abi::VmmWorldStats, emulated_exits), 32);
    assert_eq!(offset_of!(abi::VmmWorldStats, emulated_io), 40);
    assert_eq!(offset_of!(abi::VmmWorldStats, emulated_mmio), 48);
    assert_eq!(offset_of!(abi::VmmWorldStats, emulated_msr), 56);
    assert_eq!(offset_of!(abi::VmmWorldStats, injected_interrupts), 64);
    assert_eq!(offset_of!(abi::VmmWorldStats, windows_armed), 72);
    assert_eq!(offset_of!(abi::VmmWorldStats, timer_exits), 80);
    assert_eq!(offset_of!(abi::VmmWorldStats, exits_pending), 88);
    assert_eq!(
        offset_of!(abi::VmmWorldStats, exits_pending) + 8,
        size_of::<abi::VmmWorldStats>()
    );
}

#[test]
fn world_stats_zeroed_defaults() {
    let stats = abi::VmmWorldStats::default();
    assert_eq!(stats, abi::VmmWorldStats::default());
    assert_eq!(stats.abi_version, 0);
    assert_eq!(stats.paused, 0);
    assert_eq!(stats.vmm_id, 0);
    assert_eq!(stats.runs, 0);
    assert_eq!(stats.policy_exits, 0);
    assert_eq!(stats.emulated_exits, 0);
    assert_eq!(stats.emulated_io, 0);
    assert_eq!(stats.emulated_mmio, 0);
    assert_eq!(stats.emulated_msr, 0);
    assert_eq!(stats.injected_interrupts, 0);
    assert_eq!(stats.windows_armed, 0);
    assert_eq!(stats.timer_exits, 0);
    assert_eq!(stats.exits_pending, 0);
}

#[test]
fn list_bound_matches_world_name_storage() {
    assert_eq!(abi::VMM_LIST_MAX, 64);
    assert_eq!(
        abi::VMM_NAME_MAX,
        abi::VmmWorldEntry::default().name.len()
    );
}
