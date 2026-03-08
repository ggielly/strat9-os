# ABI Changelog

This page tracks ABI evolution for `strat9-abi`.

## Versioning policy

- **Major** (`ABI_VERSION_MAJOR`) changes only for incompatible wire/layout changes.
- **Minor** (`ABI_VERSION_MINOR`) changes for backward-compatible additions.
- **No silent renumbering** of existing syscall IDs.
- **`repr(C)` and explicit size checks** are mandatory for exported ABI structs.

<!-- AUTO-ABI-CHANGELOG:START -->

## Current version

- `ABI_VERSION_MAJOR = 0`
- `ABI_VERSION_MINOR = 1`
- Packed: `0.1`

See:

- [crate root constants](./api/strat9_abi/index.html)
- [syscall numbers](./api/strat9_abi/syscall/index.html)
- [ABI data structs](./api/strat9_abi/data/index.html)

## Recent ABI updates (auto-generated)

- 2026-03-07 `6191656` cargo fmt
- 2026-03-07 `8cd1410` Refactor memory allocation and deallocation in the kernel : per-CPU frame cach and a CPU-local BuddySet avoids the global lock in the common case.
- 2026-03-04 `04b384e` fix(build): improve stage assembly error handling and warnings
- 2026-03-03 `2eb44c0` feat(task): replace FpuState with ExtendedState, support xsave/xrstor
- 2026-03-03 `ae5480a` feat(silo): add silo attach for live debug output monitoring
- 2026-03-03 `8c0056a` feat: expand and reorganize shell commands with new utilities for hardware, process, and VFS, and update boot ABI structures.
- 2026-03-03 `e9cce98` feat: Implement POSIX-compatible `clock_gettime` syscall and add `call::open` with POSIX `O_*` flag conversion.
- 2026-03-03 `04cbe05` feat: Add comprehensive VFS operation self-tests, refine VFS error handling, and improve IPC port cleanup.
- 2026-03-03 `2642cf8` docs: Add `/// Implements` doc comments to various functions across components for improved clarity.
- 2026-03-03 `ef0f1d7` docs: Add documentation comments to ABI and syscall components and enhance error handling in the documentation build script.
- 2026-03-03 `f314904` feat: Expand `FileStat` with additional POSIX fields and update kernel VFS schemes, and add a `nonce` to `IpcHandshake`.
- 2026-03-03 `769f3eb` feat: Update syscall ABI with struct layout adjustments, error encoding clarification, and versioning.
- 2026-03-03 `c23a68a` feat: Ensure Limine bootloader directories exist, use a real time source for `setitimer`, and add `itimerval` value validation.
- 2026-03-03 `ea80816` fix: Correct `O_NOFOLLOW` flag value and add length bounds checks to `DirentIter` initialization and name length assignment.
- 2026-03-03 `748f98c` feat: Add `pread` and `pwrite` syscalls, enhance WASM `proc_exit` handling, and implement IPC port cleanup on task termination.
- 2026-03-03 `aa38e26` refactor: Change network syscall error for missing device, add user page fault trace budget, and zero demand-paged memory after mapping.
- 2026-03-03 `326613a` feat: Add PCI and handle ABI types, improve user page fault error reporting, ensure identity mapping for demand-paged frames, and update the build target triplet.
- 2026-03-03 `52f3586` Enhance error handling by adding new error variants to the Error enum
- 2026-03-03 `6cf254d` Refactor IPC message handling and update memory management logging
- 2026-03-03 `50d7f2f` Enhance ABI structures and improve syscall error handling
- 2026-03-03 `607abac` Enhance ABI introspection and improve syscall handling
- 2026-03-03 `deabb18` Enhance Strat9 ABI integration and update OpenFlags implementation
- 2026-03-03 `92ba1c6` Add strat9-abi as a workspace dependency and refactor bootloader integration
- 2026-03-03 `eb5de02` Refactor variable names in BuddyAllocator and sys_sigtimedwait for clarity
- 2026-03-03 `259bb9d` Enhance PCI support and update related components
- 2026-03-02 `c57b44d` Add `strate-bus` component and related build tasks.
- 2026-03-01 `8c7a98d` Enhance QEMU GUI support and update related scripts
- 2026-03-01 `84fdb29` Update zerocopy dependency and refactor related code
- 2026-03-01 `34a1f24` Update dependencies and add web-admin component
- 2026-03-01 `51c2a03` Update scheduler functionality and enhance shell command integration

<!-- AUTO-ABI-CHANGELOG:END -->

## Changelog entries

### 0.1

- Introduced canonical `strat9-abi` crate as single source of truth.
- Unified syscall numbers in `strat9_abi::syscall`.
- Unified shared structs (`TimeSpec`, `IpcMessage`, `FileStat`, PCI types).
- Added boot handoff ABI (`KernelArgs`, `MemoryRegion`, `MemoryKind`) with magic/version checks.
- Added ABI introspection syscall `SYS_ABI_VERSION`.

## Entry template

Use this template for future ABI entries:

```text
### X.Y
- Added:
  - <new syscalls/types/flags>
- Changed (compatible):
  - <field additions, new constants, optional semantics>
- Changed (breaking):
  - <layout/numbering/semantic breaks>
- Migration notes:
  - <what userspace/kernel must update>
```
