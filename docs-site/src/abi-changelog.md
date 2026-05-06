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

- 2026-05-06 `117863e` Enhance network and silo management functionality
- 2026-04-12 `6963e28` fix: reduce scheduler contention and harden early boot memory init
- 2026-04-12 `f3647c1` feat(memory): production-grade allocator architecture (#49)
- 2026-04-06 `a941264` feat: capability-based CWD, *at syscalls, and O_RESOLVE_BENEATH sandboxing
- 2026-04-06 `309a9c1` refactor: runtime allocation, scheduler lock decoupling, FixedQueue, and VGA improvements
- 2026-03-26 `a9a6cd6` Implement block-oriented memory management and ownership tracking
- 2026-03-23 `ec8ee9f` refactor(memory): update reference counting logic for COW frames
- 2026-03-23 `aaa89e0` Refactor: Decouple per-CPU scheduler state and logic from the global scheduler instance by moving `SchedulerCpu` to local CPU storage.
- 2026-03-21 `c3f93c6` feat: Implement TSC-based boot timing and milestones, along with an analysis...
- 2026-03-17 `eb7818d` feat: Implement static module loading from initfs paths and increase module blob size limit.
- 2026-03-17 `acfdbbd` feat: Refine E9 debug output, add TSS inspection, and log syscall and kernel stack changes.
- 2026-03-13 `29c6f3d` Refactor scheduler task management and introduce interrupt frame handling
- 2026-03-11 `7e66e69` refactor: enhance interrupt handling and logging mechanisms across the kernel
- 2026-03-09 `ff0a36b` Refactor memory management to use IRQ-disabled tokens
- 2026-03-07 `c3e8969` Fix race condition and lock
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
