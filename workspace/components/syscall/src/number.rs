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

pub use strat9_abi::syscall::*;

// s9vm virtualization syscalls (numbers 560..=590, defined in `strat9-abi`).
// The glob above already exports them; this explicit re-export documents the
// userspace contract used by the s9vm console front-end and keeps the range
// visible when grepping this module.
pub use strat9_abi::syscall::{
    SYS_VMM_ACPI, SYS_VMM_BOOT_INFO, SYS_VMM_BOOT_PARAMS, SYS_VMM_CONSOLE_INPUT,
    SYS_VMM_CONSOLE_OUTPUT, SYS_VMM_CREATE, SYS_VMM_CREATE_VCPU, SYS_VMM_DEBUG_DUMP,
    SYS_VMM_DESTROY, SYS_VMM_DESTROY_VCPU, SYS_VMM_EXIT_COMPLETE, SYS_VMM_EXIT_HANDLER,
    SYS_VMM_GET_EXIT_STATS, SYS_VMM_GET_REGS, SYS_VMM_INFO, SYS_VMM_INJECT_IRQ,
    SYS_VMM_INJECT_NMI, SYS_VMM_IRQ_WAIT, SYS_VMM_LIST, SYS_VMM_LOAD_IMAGE, SYS_VMM_MAP_IOMMU,
    SYS_VMM_MAP_MEM, SYS_VMM_PAUSE, SYS_VMM_RESUME, SYS_VMM_RUN, SYS_VMM_SET_AFFINITY,
    SYS_VMM_SET_CPUID_POLICY, SYS_VMM_SET_REGS, SYS_VMM_STATS, SYS_VMM_VCPU_LIST,
    SYS_VMM_VCPU_REGS,
};
