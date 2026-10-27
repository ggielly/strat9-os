# Syscall Layer

`workspace/components/syscall` — the `strat9-syscall` crate. It is the userspace entry point to the kernel: syscall numbers, typed wrappers, error mapping, and the shared data structures.

Native Strat9 components link it directly. C components instead go through `workspace/components/musl-compat`, which translates Linux `LNR_*` numbers and POSIX flags into the same Strat9 syscall numbers. See [ABI Support Matrix](./abi-matrix.md) for what that path covers.

## Modules

| Module | Contents |
|--------|----------|
| `arch` | Architecture-specific syscall entry (`syscall` instruction, register marshalling) |
| `call` | High-level wrappers — one Rust function per syscall or per family |
| `number` | Re-exports `strat9_abi::syscall::*`, so the numbers have exactly one definition |
| `error` | Userspace error type and `to_errno()` |
| `data` | Re-exports `strat9_abi::data` wire structs |
| `flag` | **POSIX** `O_*` constants, plus translation into the Strat9 `OpenFlags` bitmask |
| `io` | I/O helpers over the raw syscalls |
| `sigabi` | Signal ABI: `sigaction`, `Sigaction`, altstack structures |
| `schemev2` | Scheme (VFS) protocol types |
| `dirent` | Directory entry structures |

> **`flag` is the POSIX side.** The constants here (`O_RDONLY = 0o000000`, `O_CREAT = 0o000100`, `O_TRUNC = 0o001000`, …) are Linux values, and the crate converts them to the Strat9-native `OpenFlags` bitmask before issuing `SYS_OPEN`. Do not pass a value from `strat9_syscall::flag` straight to the kernel, and do not use `strat9_abi::flag::OpenFlags` values with the POSIX helpers. See [Syscall Reference → Open flags](./syscalls.md#open-flags--openflags-strat9-native-not-posix).

## Error convention

The kernel returns a non-negative value on success and a negative errno in two's complement on failure. Userspace detects an error with `result > 0xFFFF_F000` and recovers the number with `!result + 1`. The convention is pinned by `workspace/abi/tests/errno_abi.rs`, and `strat9_syscall::error` wraps it.

## API reference

- [strat9_syscall::arch](./api/strat9_syscall/arch/index.html)
- [strat9_syscall::call](./api/strat9_syscall/call/index.html)
- [strat9_syscall::number](./api/strat9_syscall/number/index.html)
- [strat9_syscall::error](./api/strat9_syscall/error/index.html)
- [strat9_syscall::data](./api/strat9_syscall/data/index.html)
- [strat9_syscall::flag](./api/strat9_syscall/flag/index.html)
- [strat9_syscall::io](./api/strat9_syscall/io/index.html)
- [strat9_syscall::sigabi](./api/strat9_syscall/sigabi/index.html)
- [strat9_syscall::schemev2](./api/strat9_syscall/schemev2/index.html)
- [strat9_syscall::dirent](./api/strat9_syscall/dirent/index.html)

## See also

- [Syscall Reference](./syscalls.md) — the full table, with the kernel's real argument lists and the known ABI gaps
- [ABI Overview](./abi.md) — where the numbers and structs are defined
