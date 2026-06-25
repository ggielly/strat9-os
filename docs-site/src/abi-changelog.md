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

- 2026-06-25 [`d1e838f`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/d1e838fbcbc964f67208246303930315f5565331) feat: implement IPC transport layer with 3-level architecture
- 2026-06-25 [`411f5aa`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/411f5aaf1ae30d6b53f71cb08784be42b0cea99a) feat: add IPC transport layer support and enhance ICMP handling
- 2026-06-25 [`5a3d69c`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/5a3d69c4e10c4cfc67976a837751ce50292f9032) feat: migrate input system to userspace
- 2026-06-24 [`3fea3f3`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/3fea3f3776edefa7bdc7c3a8d930c8d17b0939a6) SMP hardware debug, NVMe fixes, VGA refactor, telnetd hardening, docs
- 2026-06-16 [`e4ab1a9`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/e4ab1a96c3579117defffe0f5b32cf7cac853129) Enhance network stack, NIC drivers, USB/NVMe subsystems, and thermal management
- 2026-06-03 [`0c40058`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/0c40058547bd9b7ef07a837b1153577879510994) Refactor the network stack and add dual-stack userspace tooling
- 2026-05-24 [`aeade5e`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/aeade5ef5fcfdddef2caa43da6af361a5102c7cd) Code cleanup
- 2026-05-24 [`b2bbcc0`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/b2bbcc0bdd8c836ad396a1f32afd590b0c7236a8) Improve and fix IPC
- 2026-05-23 [`db23b53`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/db23b5365e1ee201e8928c2a87ac2d449e876552) Fix major memory leak and remove sshd silo
- 2026-05-19 [`93c8927`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/93c8927544e95bb8847495f1044913f9f9ff05b0) async: implement and optimize async I/O completion handling
- 2026-05-18 [`7c5efb4`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/7c5efb4d549c9b259c9fe4d7d5d13b050750c1bb) async: io_uring-like async I/O — ring, dispatch, AHCI bridge (Phases 1-4)
- 2026-05-14 [`cc4944a`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/cc4944a2c78236c41fce4b8f1054e119fc2bcd8e) Refactor and clean up code in various modules
- 2026-05-14 [`ecc416d`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/ecc416df41e29c26f6839ee15cffbc7a7dd41f05) refactor: strate-init refactoring, ELF/VFS/signal hardening, TSC calibration fix
- 2026-05-08 [`f070d41`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/f070d41c31fb505fef36603ee7cbc0c6648944b3) Add kernel entropy pool with interrupt-driven collection
- 2026-05-08 [`9dedb9f`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/9dedb9f19215cd1ad7f4d65d88fe84e4832bfc7c) Implement robust list support (set_robust_list/get_robust_list)
- 2026-05-08 [`d2e90a2`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/d2e90a2ffc1886bc3e72b6d2d10e4dd99c156d5a) Bridge clone() thread creation via SYS_THREAD_CREATE, add faccessat routing
- 2026-05-08 [`dabcad2`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/dabcad2d5250a317a12ec3b41048a9dfe3d6019c) Add sys_access(), sys_faccessat(), and SYS_GETRANDOM() in syscall dispatcher
- 2026-05-08 [`946f200`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/946f200860b2db8971b15b0829b987cb5282fd78) Add missing call for clock_nanosleep and update the calling manager
- 2026-05-06 [`117863e`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/117863ea4c6cb1ab65bf240da800c838e4ad8572) Enhance network and silo management functionality
- 2026-04-12 [`6963e28`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/6963e28b120c8f86bd08c0c6c6c722058693d945) fix: reduce scheduler contention and harden early boot memory init
- 2026-04-12 [`f3647c1`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/f3647c11469c7c728746e3947aecc5d5b067b2fb) feat(memory): production-grade allocator architecture (#49)
- 2026-04-06 [`a941264`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/a941264b051e54b64e96a4f72375cd2b6d533b56) feat: capability-based CWD, *at syscalls, and O_RESOLVE_BENEATH sandboxing
- 2026-04-06 [`309a9c1`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/309a9c1bb5e9938b0b6b5826d27f8977414ca63e) refactor: runtime allocation, scheduler lock decoupling, FixedQueue, and VGA improvements
- 2026-03-26 [`a9a6cd6`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/a9a6cd68b3dbce1e3ecacea313dd598b92312002) Implement block-oriented memory management and ownership tracking
- 2026-03-23 [`ec8ee9f`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/ec8ee9f88ec5a4cade0c7e5f8433c56605ce888a) refactor(memory): update reference counting logic for COW frames
- 2026-03-23 [`aaa89e0`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/aaa89e0ee568eb24908817c20ec50bf4fd3cd282) Refactor: Decouple per-CPU scheduler state and logic from the global scheduler instance by moving `SchedulerCpu` to local CPU storage.
- 2026-03-21 [`c3f93c6`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/c3f93c628fd8be78fd9cc29fbf21692aaacbf494) feat: Implement TSC-based boot timing and milestones, along with an analysis...
- 2026-03-17 [`eb7818d`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/eb7818d13ba67b1b3f718d6161f71eee0d123595) feat: Implement static module loading from initfs paths and increase module blob size limit.
- 2026-03-17 [`acfdbbd`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/acfdbbd126584bcd47355873c93c5584c67877c2) feat: Refine E9 debug output, add TSS inspection, and log syscall and kernel stack changes.
- 2026-03-13 [`29c6f3d`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/29c6f3d75165b41acd72a28d1e1b4e76bd51947c) Refactor scheduler task management and introduce interrupt frame handling

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
