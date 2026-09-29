# ABI Overview

The canonical ABI definitions live in `workspace/abi` — the `strat9-abi` crate. It is `#![no_std]` and is the single source of truth shared by the kernel, the bootloader and every userspace component.

```text
workspace/abi/src/
  lib.rs            ABI_VERSION_MAJOR / MINOR / PACKED
  syscall.rs        syscall numbers (all 800+ lines are one constant per call)
  data.rs           shared wire structs: TimeSpec, Stat, FileStat, IpcMessage, DirentHeader, SiloConfig...
  flag.rs           OpenFlags, MapFlags, CallFlags, UnlinkFlags + POSIX translation
  errno.rs          error numbers
  boot.rs           boot handoff: KernelArgs, MemoryRegion, MemoryKind, ModuleTable
  ip.rs             IP address parsing and formatting
  ipc.rs            IPC handshake: IpcHandshake, IpcHandshakeReply, protocol version
  ipc_codec.rs      wire codec for IPC messages
  ipc_payload.rs    typed IPC payload variants
```

Nine modules, 4163 lines, plus nine integration test files under `workspace/abi/tests/`.

## Versioning

| Constant | Value |
|----------|-------|
| `ABI_VERSION_MAJOR` | `0` |
| `ABI_VERSION_MINOR` | `1` |
| `ABI_VERSION_PACKED` | `0x0000_0001` |

`SYS_ABI_VERSION` (900) returns `(major << 16) | minor`, so the packed form is a single `u32`. Policy: major bumps for incompatible layout or numbering changes, minor for backward-compatible additions, and **no silent renumbering** of existing syscall IDs. Exported structs must be `repr(C)` with explicit size assertions.

The **boot handoff ABI is versioned separately**: `STRAT9_BOOT_ABI_VERSION = 4` with magic `STRAT9_BOOT_MAGIC = 0x5354_3942` (`"ST9B"`) and a `KernelArgs` pinned at exactly 132 bytes.

## API reference

- [strat9_abi::syscall](./api/strat9_abi/syscall/index.html)
- [strat9_abi::data](./api/strat9_abi/data/index.html)
- [strat9_abi::flag](./api/strat9_abi/flag/index.html)
- [strat9_abi::errno](./api/strat9_abi/errno/index.html)
- [strat9_abi::boot](./api/strat9_abi/boot/index.html)
- [strat9_abi::ip](./api/strat9_abi/ip/index.html)
- [strat9_abi::ipc](./api/strat9_abi/ipc/index.html)
- [strat9_abi::ipc_codec](./api/strat9_abi/ipc_codec/index.html)
- [strat9_abi::ipc_payload](./api/strat9_abi/ipc_payload/index.html)
- [crate root constants](./api/strat9_abi/index.html)

## Test suite

`workspace/abi/tests/` is the anti-regression net for the ABI contract:

| File | Covers |
|------|--------|
| `abi_stability.rs` | Struct sizes, field offsets, alignment |
| `errno_abi.rs` | Every errno value, the `> 0xFFFF_F000` detection window, kernel→user→kernel roundtrips |
| `wire_format.rs` | `repr(C)` layout and byte order of every wire struct |
| `data_types.rs` | Data struct semantics |
| `flags_translation.rs` | `posix_oflags_to_strat9` and the flag bit layouts |
| `ip_parsing.rs` | Address parsing and formatting |
| `ipc_codec_roundtrip.rs` | Encode/decode symmetry |
| `ipc_payload_wire.rs` | Typed payload encoding |
| `ipc_handshake.rs` | Handshake and version negotiation |

## See also

- [Syscall Reference](./syscalls.md) — numbers, kernel argument lists, and the ABI-versus-kernel gap list
- [ABI Support Matrix](./abi-matrix.md) — POSIX API coverage through `musl-compat`
- [ABI Changelog](./abi-changelog.md) — version history
- [Boot Sequence](./boot-sequence.md) — the `KernelArgs` handoff
