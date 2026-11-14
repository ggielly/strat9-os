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

use core::{
    ptr,
    sync::atomic::{AtomicU64, Ordering},
};

extern "C" {
    static riscv_kernel_stack_top: u8;
}

pub const MAX_CPUS: usize = 32;

#[repr(C, align(64))]
struct PerCpu {
    cpu_index: AtomicU64,
    kernel_rsp: AtomicU64,
    trap_stack_top: AtomicU64,
    tlb_ready: AtomicU64,
    signal_pending: AtomicU64,
}

impl PerCpu {
    const fn new() -> Self {
        Self {
            cpu_index: AtomicU64::new(0),
            kernel_rsp: AtomicU64::new(0),
            trap_stack_top: AtomicU64::new(0),
            tlb_ready: AtomicU64::new(0),
            signal_pending: AtomicU64::new(0),
        }
    }
}

static PERCPU: [PerCpu; MAX_CPUS] = [const { PerCpu::new() }; MAX_CPUS];

pub fn init_boot_cpu(hart_id: u32) -> usize {
    let stack_top =
        unsafe { ptr::read_volatile(ptr::addr_of!(riscv_kernel_stack_top) as *const u64) };
    init_boot_cpu_with_stack(hart_id, stack_top)
}

pub fn init_boot_cpu_with_stack(hart_id: u32, stack_top: u64) -> usize {
    let index = activate_cpu(hart_id as usize);
    PERCPU[index]
        .trap_stack_top
        .store(stack_top, Ordering::Release);
    index
}

pub fn init_gs_base(cpu_index: usize) {
    activate_cpu(cpu_index);
}

pub fn current_cpu_index() -> usize {
    let pointer = read_scratch();
    if pointer == 0 {
        return 0;
    }
    let cpu_index = unsafe {
        (*(pointer as *const PerCpu))
            .cpu_index
            .load(Ordering::Acquire) as usize
    };
    if cpu_index < MAX_CPUS {
        cpu_index
    } else {
        0
    }
}

pub fn current_cpu_index_fast() -> usize {
    current_cpu_index()
}

pub fn cpu_count() -> usize {
    1
}

pub fn get_cpu_count() -> usize {
    1
}

pub fn set_kernel_rsp_current(rsp: u64) {
    let index = current_cpu_index();
    PERCPU[index].kernel_rsp.store(rsp, Ordering::Release);
}

pub fn kernel_rsp_current() -> Option<u64> {
    let index = current_cpu_index();
    let rsp = PERCPU[index].kernel_rsp.load(Ordering::Acquire);
    (rsp != 0).then_some(rsp)
}

pub fn set_kernel_rsp_for_cpu(cpu_index: usize, rsp: u64) {
    if let Some(slot) = PERCPU.get(cpu_index) {
        slot.kernel_rsp.store(rsp, Ordering::Release);
    }
}

pub fn kernel_rsp_for_cpu(cpu_index: usize) -> Option<u64> {
    let rsp = PERCPU.get(cpu_index)?.kernel_rsp.load(Ordering::Acquire);
    (rsp != 0).then_some(rsp)
}

pub fn mark_tlb_ready_current() {
    let index = current_cpu_index();
    PERCPU[index].tlb_ready.store(1, Ordering::Release);
}

pub fn tlb_ready(index: usize) -> bool {
    PERCPU
        .get(index)
        .map_or(false, |slot| slot.tlb_ready.load(Ordering::Acquire) != 0)
}

/// Returns `true` iff CPU `index` is online (single-CPU RISC-V: index 0).
pub fn is_online(index: usize) -> bool {
    index == 0
}

/// Number of currently online CPUs (single-CPU RISC-V).
pub fn online_count() -> usize {
    1
}

/// Fill `out` with online CPU indices; returns the count (single-CPU RISC-V).
pub fn online_cpu_indices(out: &mut [usize]) -> usize {
    if out.is_empty() {
        0
    } else {
        out[0] = 0;
        1
    }
}

#[inline]
const fn encode_signal_hint(task_id: u64) -> u64 {
    (task_id << 1) | 1
}

#[inline]
const fn decode_signal_hint(word: u64) -> Option<u64> {
    if word & 1 != 0 {
        Some(word >> 1)
    } else {
        None
    }
}

/// Set the tagged `signal_pending` hint for an explicit CPU (bounds-checked).
pub fn set_signal_pending_for_cpu(cpu: usize, task_id: u64) {
    if let Some(slot) = PERCPU.get(cpu) {
        slot.signal_pending
            .store(encode_signal_hint(task_id), Ordering::Release);
    }
}

/// Set the tagged `signal_pending` hint for the current CPU.
pub fn set_signal_pending_current_for_task(task_id: u64) {
    let index = current_cpu_index();
    PERCPU[index]
        .signal_pending
        .store(encode_signal_hint(task_id), Ordering::Release);
}

/// Take and clear the tagged hint for the current CPU.
pub fn take_signal_hint_current() -> Option<u64> {
    let index = current_cpu_index();
    decode_signal_hint(PERCPU[index].signal_pending.swap(0, Ordering::AcqRel))
}

/// Restore a taken hint, only if the slot is still empty.
pub fn restore_signal_hint_current(task_id: u64) {
    let index = current_cpu_index();
    let _ = PERCPU[index].signal_pending.compare_exchange(
        0,
        encode_signal_hint(task_id),
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

/// Clear any signal hint referring to `task_id` on every CPU.
pub fn clear_signal_hint_for_task(task_id: u64) {
    let packed = encode_signal_hint(task_id);
    for slot in PERCPU.iter() {
        let _ = slot.signal_pending.compare_exchange(
            packed,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

fn activate_cpu(cpu_index: usize) -> usize {
    assert!(cpu_index < MAX_CPUS, "RISC-V hart index out of range");
    PERCPU[cpu_index]
        .cpu_index
        .store(cpu_index as u64, Ordering::Release);
    let pointer = &PERCPU[cpu_index] as *const PerCpu as usize;
    unsafe {
        core::arch::asm!("csrw sscratch, {0}", in(reg) pointer, options(nostack));
    }
    cpu_index
}

fn read_scratch() -> usize {
    let mut value = 0usize;
    unsafe {
        core::arch::asm!("csrr {0}, sscratch", out(reg) value, options(nostack, nomem));
    }
    value
}
