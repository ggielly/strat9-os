//! Strat9-OS Syscall Interface
//!
//! Implements the kernel-side syscall dispatcher and handlers for the
//! Strat9-OS native ABI.
//!
//! Syscall numbers are organized in blocks of 100:
//!
//! - 000-099 : Capabilities (handle management)
//! - 100-199: memory
//! - 200-299: IPC
//! - 300-399: process/thread
//! - 400-499: filesystem/VFS
//! - 500-599: time/alarms
//! - 600-699: debug/profiling

pub mod dispatcher;
pub mod error;
pub mod fork;
pub mod futex;
pub mod mmap;
pub mod numbers;
pub mod signal;
pub mod time;

pub use dispatcher::dispatch;
pub use time::{sys_clock_gettime, sys_nanosleep};
pub use fork::sys_fork;

/// Stack frame passed to the Rust syscall dispatcher.
///
/// This matches the push order in `syscall_entry` (arch/x86_64/syscall.rs).
/// The struct is laid out in memory from low to high address (RSP grows down,
/// so first push = highest address, last push = lowest = RSP).
#[repr(C)]
pub struct SyscallFrame {
    // Pushed last → at lowest address (RSP points here)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64, // user RFLAGS
    pub r10: u64, // arg 4
    pub r9: u64,  // arg 6
    pub r8: u64,  // arg 5
    pub rsi: u64, // arg 2
    pub rdi: u64, // arg 1
    pub rdx: u64, // arg 3
    pub rcx: u64, // user RIP
    pub rax: u64, // syscall number / return value

    // IRET frame follows (pushed first → highest address)
    pub iret_rip: u64,
    pub iret_cs: u64,
    pub iret_rflags: u64,
    pub iret_rsp: u64,
    pub iret_ss: u64,
}
