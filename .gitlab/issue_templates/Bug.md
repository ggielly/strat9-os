---
name: Bug
about: Unexpected behaviour, panic, memory corruption, or regression
labels: bug
---

## Description

<!-- What happened? Be precise. -->

## Expected behaviour

<!-- What should have happened instead. -->

## Steps to reproduce

1. 
2. 
3. 

## Context

- **Branch / commit:** <!-- e.g. main @ a1b2c3d -->
- **QEMU target:** <!-- e.g. run-gui-smp, run-test -->
- **Build mode:** <!-- debug / release -->
- **Toolchain:** <!-- output of: rustup show | head -1 -->

## Logs / output

```
<!-- paste serial log, panic trace, or QEMU output here -->
```

## Subsystem

<!-- Check all that apply -->
- [ ] boot / init
- [ ] memory (buddy / slab / heap / vmalloc)
- [ ] scheduler / process
- [ ] syscall / ABI
- [ ] IPC / sync
- [ ] SMP / per-CPU
- [ ] driver / IRQ
- [ ] shell / userspace
- [ ] other:

## Severity

- [ ] Critical — systematic panic, memory corruption, security issue
- [ ] High — broken feature, regression
- [ ] Medium — incorrect behaviour with a workaround
- [ ] Low — cosmetic, missing log
