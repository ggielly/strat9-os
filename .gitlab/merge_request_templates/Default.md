## Summary

<!-- What does this MR do? One short paragraph. -->

Closes #<!-- issue number -->

## Changes

<!-- Bullet list of the main changes. Focus on the "why", not just the "what". -->

- 

## Test plan

<!-- How was this tested? Check all that apply. -->

- [ ] `cargo make check` passes
- [ ] `cargo make clippy` passes
- [ ] `cargo make kernel-test` / `run-test` passes
- [ ] Tested in QEMU (`run-gui-smp`)
- [ ] Stress test run (specify which):
- [ ] Not testable — reason:

## Subsystem checklist

<!-- Check subsystems touched by this MR. -->

- [ ] memory (buddy / slab / heap / vmalloc / frame metadata)
- [ ] scheduler / process / IPC
- [ ] syscall / ABI
- [ ] SMP / locking / IRQ
- [ ] driver
- [ ] shell / userspace
- [ ] build / toolchain / CI

## Safety & correctness

- [ ] All new `unsafe` blocks have `// SAFETY:` comments
- [ ] No userspace pointer dereferences without `UserSliceRead`/`UserSliceWrite`
- [ ] No heap allocation in interrupt handlers
- [ ] No new `SpinLock` holding an allocating container on a hot/IRQ path
- [ ] ABI structs have `#[repr(C)]`

## Notes for reviewers

<!-- Anything non-obvious, tricky invariants, known limitations, follow-up tickets. -->
