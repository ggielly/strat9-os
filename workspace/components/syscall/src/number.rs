//! Strat9-OS syscall numbers

// Block 0-99: capabilities / handles
pub const SYS_NULL: usize = 0;
pub const SYS_HANDLE_DUPLICATE: usize = 1;
pub const SYS_HANDLE_CLOSE: usize = 2;
pub const SYS_HANDLE_WAIT: usize = 3;

// Block 100-199: memory
pub const SYS_MMAP: usize = 100;
pub const SYS_MUNMAP: usize = 101;
pub const SYS_FMAP: usize = 100;
pub const SYS_FUNMAP: usize = 101;
pub const SYS_BRK: usize = 102;
pub const SYS_MREMAP: usize = 103;
pub const SYS_MPROTECT: usize = 104;

// Block 200-299: IPC
pub const SYS_IPC_CREATE_PORT: usize = 200;
pub const SYS_IPC_SEND: usize = 201;
pub const SYS_IPC_RECV: usize = 202;
pub const SYS_IPC_CALL: usize = 203;
pub const SYS_IPC_REPLY: usize = 204;
pub const SYS_IPC_BIND_PORT: usize = 205;
pub const SYS_IPC_UNBIND_PORT: usize = 206;

// Block 300-399: process
pub const SYS_PROC_EXIT: usize = 300;
pub const SYS_YIELD: usize = 301;
pub const SYS_PROC_YIELD: usize = 301;
pub const SYS_PROC_FORK: usize = 302;
pub const SYS_PROC_GETPID: usize = 308;
pub const SYS_PROC_GETPPID: usize = 309;
pub const SYS_PROC_WAITPID: usize = 310;
pub const SYS_PROC_WAIT: usize = 311;
pub const SYS_FUTEX: usize = 303;

// Signal block (from kernel)
pub const SYS_KILL: usize = 320;
pub const SYS_SIGPROCMASK: usize = 321;
pub const SYS_SIGACTION: usize = 322;
pub const SYS_SIGALTSTACK: usize = 323;
pub const SYS_SIGPENDING: usize = 324;
pub const SYS_SIGSUSPEND: usize = 325;
pub const SYS_SIGTIMEDWAIT: usize = 326;
pub const SYS_SIGQUEUE: usize = 327;
pub const SYS_KILLPG: usize = 328;
pub const SYS_GETITIMER: usize = 329;
pub const SYS_SETITIMER: usize = 330;

// Block 400-499: VFS
pub const SYS_OPEN: usize = 403;
pub const SYS_WRITE: usize = 404;
pub const SYS_READ: usize = 405;
pub const SYS_CLOSE: usize = 406;
pub const SYS_FCHMOD: usize = 407;
pub const SYS_FCHOWN: usize = 408;
pub const SYS_FCNTL: usize = 409;
pub const SYS_FPATH: usize = 6; // Old / temporary
pub const SYS_FSTAT: usize = 7; // Old / temporary
pub const SYS_LSEEK: usize = 8; // Old / temporary
pub const SYS_FTRUNCATE: usize = 9; // Old / temporary
pub const SYS_FSYNC: usize = 12; // Old / temporary
pub const SYS_FSTATVFS: usize = 20;
pub const SYS_FUTIMENS: usize = 21;
pub const SYS_DUP: usize = 22;
pub const SYS_DUP2: usize = 23;
pub const SYS_FLINK: usize = 24;
pub const SYS_FRENAME: usize = 25;
pub const SYS_OPENAT: usize = 26;
pub const SYS_UNLINKAT: usize = 27;
pub const SYS_MKNS: usize = 28;
pub const SYS_CALL: usize = 29;
pub const SYS_SENDFD: usize = 30;
pub const SYS_OPENAT_WITH_FILTER: usize = 31;
pub const SYS_UNLINKAT_WITH_FILTER: usize = 32;

// Block 500-599: Time
pub const SYS_CLOCK_GETTIME: usize = 500;
pub const SYS_NANOSLEEP: usize = 501;

// Block 600-699: Debug
pub const SYS_DEBUG_LOG: usize = 600;
