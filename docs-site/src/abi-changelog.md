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

- 2026-05-14 `77540e9` refactor(signal): implement fast signal-pending mechanism for improved syscall efficiency
- 2026-05-11 `2a12166` refactor(elf): update ELF loading to use capabilities and fix random seed generation
- 2026-05-11 `3a351bd` refactor(vfs): add path resolution and validation for current task
- 2026-05-10 `0c603e4` refactor(init): integrate SiloMode into FamilyProfile and update security policy validation
- 2026-05-10 `c89a14e` refactor(init): clean up SiloConfig usage and improve code organization
- 2026-05-10 `74cb3a5` refactor(init): move SiloConfig struct to a separate module for better organization and clarity
- 2026-05-08 `f070d41` Add kernel entropy pool with interrupt-driven collection
- 2026-05-08 `9dedb9f` Implement robust list support (set_robust_list/get_robust_list)
- 2026-05-08 `d2e90a2` Bridge clone() thread creation via SYS_THREAD_CREATE, add faccessat routing
- 2026-05-08 `dabcad2` Add sys_access(), sys_faccessat(), and SYS_GETRANDOM() in syscall dispatcher
- 2026-05-08 `946f200` Add missing call for clock_nanosleep and update the calling manager
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
