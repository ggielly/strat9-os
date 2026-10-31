# ABI Changelog

This page tracks ABI evolution for `strat9-abi`.

## Versioning policy

- **Major** (`ABI_VERSION_MAJOR`) changes only for incompatible wire/layout changes.
- **Minor** (`ABI_VERSION_MINOR`) changes for backward-compatible additions.
- **No silent renumbering** of existing syscall IDs.
- **`repr(C)` and explicit size checks** are mandatory for exported ABI structs.

## Boot handoff ABI (`strat9_abi::boot`)

The bootloader/kernel handoff has its own version, `STRAT9_BOOT_ABI_VERSION`,
independent from the syscall `ABI_VERSION_*` above. The kernel refuses to
boot when it does not match exactly.

| Version | Change |
|---|---|
| 2 | First documented handoff (`KernelArgs`, framebuffer, modules) |
| 3 | Framebuffer channel masks |
| 4 | BSS virtual range fields |
| 5 | `MemoryKind::Bad` (4) and `MemoryKind::AcpiNvs` (5); layout unchanged (132 bytes) |

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

- 2026-10-31 [`a08f12a`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/a08f12ae3e800e623bbe208051a771a0f672e657) tools: improve GPL header script for Rust files and update website links kernel: enhance idle task handling with explicit yield to prevent deadlocks syscall: refine network receive logic to handle multiple queues effectively
- 2026-10-31 [`f2b7eb0`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/f2b7eb032c624c5bcfe699d0729bc27d05939e72) Refactor TUI and syscall handling
- 2026-10-30 [`627a5b7`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/627a5b757a4aa70e3c0c723d810347c3fd26e148) abi/net: allow documented unsafe ring primitives under the workspace lint
- 2026-10-30 [`f41d977`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/f41d977c5d3e8374400f94435f181d6a2dc8117d) Fix build after Code-refactor integration
- 2026-10-29 [`a7baa3a`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/a7baa3ae3ae1a615b87a26350c5d8b7985611315) Refactor silo memory management and enhance syscall functionality
- 2026-10-29 [`97cb28a`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/97cb28adf1aa53af61b1133db3181e1d2c9f9a9c) Implement framebuffer write-combining support and FPU state preservation
- 2026-10-28 [`62e40ef`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/62e40efb60b484b5e5bafb04f0d531a7ec68b6bc) feat(iommu): finish P1/P2 with QI, IR/MSI, IVMD, bounce buffers and strate-iommu boot wiring
- 2026-10-28 [`5ccb269`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/5ccb26910068ceb1ab43ec656ec463a7976b7c70) feat(iommu): P1 policy/robustness and P2 shadow tables, superpages and batch DMA
- 2026-10-28 [`db8ae4d`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/db8ae4db6bd95a93910e6de14d3ecb517ee2c870) feat(iommu): P0 domain/IOVA management, DMAR parser and DMA isolation ABI
- 2026-10-28 [`2f07be9`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/2f07be9bd8cb0f93b67600492aa446ced8311763) test(abi): align ipc_payload_wire with the real 24-byte OpenReply
- 2026-10-28 [`861ee54`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/861ee546838667511ad42236df8b1ca8522f9069) fix: unblock kernel build after 1 KiB IPC and net queue changes
- 2026-10-28 [`9ef21eb`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/9ef21ebf385bd205cbee8de8f713c59d181527a9) Fix compilation
- 2026-10-28 [`e109204`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/e10920414ea12581538af9c161e8ad7723327b44) net: bulk VFS rings, multi-queue RSS, PCI hotplug polling and RX checksum offload
- 2026-10-28 [`9d15fed`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/9d15fed44964c5c5a441dedf59fd1f76fa79eeee) net(P2-P4): offload negotiation, hotplug, IOMMU bookkeeping, vSwitch/QoS, bulk IPC
- 2026-10-28 [`c4d4a13`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/c4d4a13ea4d9ba4c9d2a25d6a803fe589f492c32) net(P1): zero-copy shared queue between kernel and strate-net
- 2026-10-28 [`215eab6`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/215eab6cf813b566c5c49cf8b16cc4e6608bf662) net(P0): capability-gated syscalls, bounded IRQ, shared queue foundation
- 2026-10-27 [`f76ffc3`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/f76ffc3f7522d26eda94447d3a0e5eb5cb3916c0) Merge branch 'feature/console-display-strates' into HEAD
- 2026-10-27 [`af6560c`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/af6560c462050268cf1230edc5861554f5076ac7) Merge boot ABI branch and repair duplicated additions
- 2026-10-27 [`024c393`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/024c39314d4003ae56cab1c43d66aa62ec87e631) Merge remote-tracking branch 'origin/fix/boot-abi-consistency' into integration/merge-all
- 2026-10-27 [`ea7c302`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/ea7c302996f627819d6e6ace15cc161b5162dad6) Merge remote-tracking branch 'origin/Fix-and-enhance-networking' into integration/merge-all
- 2026-10-27 [`c1a9fa4`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/c1a9fa442f2f35052c7f145941592a6ede95a7b3) console: MAP_SHARED frame-backed display surface
- 2026-10-27 [`94ff288`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/94ff2886a51123efdac4bad659c333445b9ec76f) test(abi): repair stale scheme payload wire tests and a lint regression
- 2026-10-27 [`b071184`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/b071184d8fd93a828f2209a7f6395f31151a8e61) fix(dependencies): clean up unused packages and update features in Cargo.toml
- 2026-10-27 [`8c18cdb`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/8c18cdbebd023f2c4b7711572dca0030335a557c) fix(abi): bump boot handoff ABI to v5 and document it
- 2026-09-27 [`f64aff3`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/f64aff3c6072bbb7c6f7ef7e698dadab837df431) Implement console rendering and mouse input handling tasks
- 2026-09-26 [`f7818ad`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/f7818ad4c8936d2fefdc4cf1cce19932ffc0119d) Merge canonical GitLab main with RISC-V integration
- 2026-09-26 [`4e45f2d`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/4e45f2d1c3ae872d0631c8342baf2e00312059cd) Fix merge integration for RISC-V backend
- 2026-09-26 [`bb2df28`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/bb2df28041b624236e15c6fce6bebe9ed12c991d) Merge branch feat/hal-arch-facade into main
- 2026-09-25 [`18818c4`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/18818c4da69438eac459a92551130a21d9c3da2a) chore(riscv): gate remaining x86-only helpers
- 2026-09-25 [`fedacdf`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/fedacdf07474f45d9d6b948c4eb0e9d03c73773e) chore(riscv): scope architecture-specific imports

<!-- AUTO-ABI-CHANGELOG:END -->

## Changelog entries

### 0.1

- Introduced the canonical `strat9-abi` crate as single source of truth.
- Unified syscall numbers in `strat9_abi::syscall`.
- Unified shared structs (`TimeSpec`, `IpcMessage`, `FileStat`, PCI types).
- Added the boot handoff ABI (`KernelArgs`, `MemoryRegion`, `MemoryKind`) with magic and version checks.
- Added the ABI introspection syscall `SYS_ABI_VERSION` (900).

### Boot handoff ABI — tracked separately

The boot struct is versioned on its own counter, not on `ABI_VERSION_*`.

| Version | Struct | Size | Notes |
|---------|--------|------|-------|
| 2 | `KernelArgs` | 132 B | Superseded. Still described in `workspace/bootloader/README.md` |
| 3 | `KernelArgs` | 132 B | Superseded |
| **4** (`STRAT9_BOOT_ABI_VERSION`) | `KernelArgs` | **132 B** | Current. Adds `bss_virt_base` / `bss_virt_size`, drops the `stack_base` / `stack_size` fields in favour of passing the stack in registers to `paging::context_switch` |

`STRAT9_BOOT_MAGIC = 0x5354_3942` (`"ST9B"`). The size is asserted at compile time in two places in `workspace/abi/src/boot.rs`.

### Errno corrections

| Date | Change | Detail |
|------|--------|--------|
| 2026-08-28 | `ENOTSUP` 52 → **95** | Aligned with Linux `EOPNOTSUPP` so musl/relibc map 1:1. Pinned by `workspace/abi/tests/errno_abi.rs:57` |

> **Open inconsistency.** `strat9_abi::errno::ENOTSUP` is 95, but the kernel's `SyscallError::NotSupported` in `workspace/kernel/src/syscall/error.rs` is still `-52`, so the kernel currently emits a value the ABI does not define. `SyscallError` also lacks `ELOOP` (40), `EAFNOSUPPORT` (97), `EADDRINUSE` (98) and `ECONNREFUSED` (111), which the ABI does define. See [Syscall Reference → `ENOTSUP` numbering](./syscalls.md#enotsup-numbering).

### Flag layout

| Date | Change | Detail |
|------|--------|--------|
| initial | `OpenFlags` defined as a bitflag set | Access mode is a 2-bit field (`READ`/`WRITE`), **not** a 0/1/2 enum. `posix_oflags_to_strat9()` performs the POSIX translation |
| initial | `MapFlags` declared with `MAP_NORESERVE`, `MAP_GROWSDOWN`, `MAP_LOCKED`, `MAP_POPULATE` | The kernel's `sys_mmap` rejects these bits with `EINVAL`. See [Syscall Reference → `MapFlags` vs the kernel's `MAP_*`](./syscalls.md#mapflags-vs-the-kernels-map) |

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
