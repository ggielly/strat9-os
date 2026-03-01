//! Strat9-OS syscall numbers

// Block 0-99: capabilities / handle management
pub const SYS_NULL: usize = 0;
pub const SYS_HANDLE_DUPLICATE: usize = 1;
pub const SYS_HANDLE_CLOSE: usize = 2;
pub const SYS_HANDLE_WAIT: usize = 3;
pub const SYS_HANDLE_GRANT: usize = 4;
pub const SYS_HANDLE_REVOKE: usize = 5;
pub const SYS_HANDLE_INFO: usize = 6;

// Block 100-199: memory management
pub const SYS_MMAP: usize = 100;
pub const SYS_MUNMAP: usize = 101;
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
pub const SYS_IPC_TRY_RECV: usize = 207;
pub const SYS_IPC_CONNECT: usize = 208;
pub const SYS_IPC_RING_CREATE: usize = 210;
pub const SYS_IPC_RING_MAP: usize = 211;
pub const SYS_CHAN_CREATE: usize = 220;
pub const SYS_CHAN_SEND: usize = 221;
pub const SYS_CHAN_RECV: usize = 222;
pub const SYS_CHAN_TRY_RECV: usize = 223;
pub const SYS_CHAN_CLOSE: usize = 224;
pub const SYS_SEM_CREATE: usize = 230;
pub const SYS_SEM_WAIT: usize = 231;
pub const SYS_SEM_TRYWAIT: usize = 232;
pub const SYS_SEM_POST: usize = 233;
pub const SYS_SEM_CLOSE: usize = 234;

// Block 300-399: process / thread
pub const SYS_PROC_EXIT: usize = 300;
pub const SYS_PROC_YIELD: usize = 301;
pub const SYS_PROC_FORK: usize = 302;
pub const SYS_FUTEX_WAIT: usize = 303;
pub const SYS_FUTEX_WAKE: usize = 304;
pub const SYS_FUTEX_REQUEUE: usize = 305;
pub const SYS_FUTEX_CMP_REQUEUE: usize = 306;
pub const SYS_FUTEX_WAKE_OP: usize = 307;
pub const SYS_PROC_GETPID: usize = 308;
pub const SYS_PROC_GETPPID: usize = 309;
pub const SYS_PROC_WAITPID: usize = 310;
pub const SYS_GETPID: usize = 311;
pub const SYS_GETTID: usize = 312;
pub const SYS_GETPPID: usize = 313;
pub const SYS_PROC_WAIT: usize = 314;
pub const SYS_PROC_EXECVE: usize = 315;
pub const SYS_FCNTL: usize = 316;
pub const SYS_SETPGID: usize = 317;
pub const SYS_GETPGID: usize = 318;
pub const SYS_SETSID: usize = 319;

// Block 320-329: signal handling
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
pub const SYS_GETPGRP: usize = 331;
pub const SYS_GETSID: usize = 332;
pub const SYS_SET_TID_ADDRESS: usize = 333;
pub const SYS_EXIT_GROUP: usize = 334;
pub const SYS_GETUID: usize = 335;
pub const SYS_GETEUID: usize = 336;
pub const SYS_GETGID: usize = 337;
pub const SYS_GETEGID: usize = 338;
pub const SYS_SETUID: usize = 339;
pub const SYS_SETGID: usize = 340;
pub const SYS_THREAD_CREATE: usize = 341;
pub const SYS_THREAD_JOIN: usize = 342;
pub const SYS_THREAD_EXIT: usize = 343;
pub const SYS_ARCH_PRCTL: usize = 350;
pub const SYS_TGKILL: usize = 352;
pub const SYS_RT_SIGRETURN: usize = 353;

// Block 400-499: filesystem / VFS
pub const SYS_OPEN: usize = 403;
pub const SYS_WRITE: usize = 404;
pub const SYS_READ: usize = 405;
pub const SYS_CLOSE: usize = 406;
pub const SYS_LSEEK: usize = 407;
pub const SYS_FSTAT: usize = 408;
pub const SYS_STAT: usize = 409;

// Block 430-449: VFS extended
pub const SYS_GETDENTS: usize = 430;
pub const SYS_PIPE: usize = 431;
pub const SYS_DUP: usize = 432;
pub const SYS_DUP2: usize = 433;

pub const SYS_POLL: usize = 460;
pub const SYS_PPOLL: usize = 461;

// Block 410-419: network
pub const SYS_NET_RECV: usize = 410;
pub const SYS_NET_SEND: usize = 411;
pub const SYS_NET_INFO: usize = 412;

// Block 420-429: volumes / block devices
pub const SYS_VOLUME_READ: usize = 420;
pub const SYS_VOLUME_WRITE: usize = 421;
pub const SYS_VOLUME_INFO: usize = 422;

// Block 500-599: time / alarms
pub const SYS_CLOCK_GETTIME: usize = 500;
pub const SYS_NANOSLEEP: usize = 501;

// Block 600-699: debug / profiling
pub const SYS_DEBUG_LOG: usize = 600;

// Block 700-799: module management (.cmod)
pub const SYS_MODULE_LOAD: usize = 700;
pub const SYS_MODULE_UNLOAD: usize = 701;
pub const SYS_MODULE_GET_SYMBOL: usize = 702;
pub const SYS_MODULE_QUERY: usize = 703;

// Block 800-899: silo manager
pub const SYS_SILO_CREATE: usize = 800;
pub const SYS_SILO_CONFIG: usize = 801;
pub const SYS_SILO_ATTACH_MODULE: usize = 802;
pub const SYS_SILO_START: usize = 803;
pub const SYS_SILO_STOP: usize = 804;
pub const SYS_SILO_KILL: usize = 805;
pub const SYS_SILO_EVENT_NEXT: usize = 806;
pub const SYS_SILO_SUSPEND: usize = 807;
pub const SYS_SILO_RESUME: usize = 808;
pub const SYS_SILO_PLEDGE: usize = 809;
pub const SYS_SILO_UNVEIL: usize = 810;
pub const SYS_SILO_ENTER_SANDBOX: usize = 811;
