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

- 2026-08-25 [`dc616fa`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/dc616fa7be6e693a96330d3cff49dbaac0880ef8) refactor(arch): unify x86_64 crate access via x86_crate_shim, complete riscv stubs
- 2026-08-25 [`f926367`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/f926367f65dd2ae622412ec1ccc71b4dee486a2a) refactor(arch): route shared code through arch::xshim, gate limine/x86 deps
- 2026-08-25 [`9e75f89`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/9e75f89596da79618fcd1133953aba556b3c4392) refactor(arch): migrate process/ and syscall/ call-sites to arch facade
- 2026-07-18 [`abb7dd7`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/abb7dd7e60991de111632e72ae8658adccdf8697) feat(buddy): harden, optimize, and add kernel.toml configuration
- 2026-07-17 [`fe68f9a`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/fe68f9aacb1b70b8601cbdde1423be75628255d1) fix(vfs,console,scheduler): VFS improvements, console perf, panic backtrace
- 2026-07-14 [`3a5eb69`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/3a5eb69d9b3041f89c205e184b4afe15c07ee44d) feat(silo): replace Vec with heapless::Vec for bounded fields
- 2026-07-09 [`ab22b0d`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/ab22b0d9b010dd704cf6044580b4f310c5748524) feat: 3-level IPC transport, N3 MMU thread migration, graphical silo, NIC/E1000 fixes
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
