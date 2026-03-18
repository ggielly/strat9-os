# TODO

## Buddy Allocator refcount sentinel hardening

### Diagnostic

The buddy allocator does not yet maintain the OSTD-style sentinel invariant for
free-list frames:

- expected hardening target: free-list frame => `refcount == REFCOUNT_UNUSED`
- current behavior: both `mark_block_free()` and `mark_block_allocated()` call
  `reset_refcount()` and write `0`

Relevant files:

- `workspace/kernel/src/memory/buddy.rs`
- `workspace/kernel/src/memory/frame.rs`

### Why it matters

`FrameAllocOptions::allocate()` documents a stronger design where allocation can
use `CAS(REFCOUNT_UNUSED -> 0)` to catch buddy free-list corruption early.
Because the buddy allocator does not currently stamp `REFCOUNT_UNUSED`, that
check is disabled.

Current effect:

- the allocator still relies on its bitmap + free-list invariants and can work
  correctly in the normal case
- but if a frame appears twice in the free list, the system lacks the intended
  fail-fast detection and may corrupt memory silently

### What to modify

1. In `workspace/kernel/src/memory/buddy.rs`, update `mark_block_free()` so the
   metadata refcount is set to `REFCOUNT_UNUSED` instead of `0`.
2. In `workspace/kernel/src/memory/buddy.rs`, update `mark_block_allocated()` so
   it does not destroy the free-list sentinel before the real allocation path
   initializes the frame.
3. In `workspace/kernel/src/memory/frame.rs`, reinstate the CAS-based transition
   in `FrameAllocOptions::allocate()` once the buddy invariant is true.
4. Re-check raw callers of `allocate_frames()` / `buddy::alloc()` and keep their
   semantics explicit: they are raw allocations and should not accidentally rely
   on `FrameAllocOptions` metadata guarantees.

### Priority

Short-term hardening item.

It can wait until the current boot blockers are cleared, but it should be done
before deeper SMP / COW / memory-stress stabilization work, where silent memory
aliasing becomes expensive to diagnose.

## try_lock_no_irqsave diagnostic visibility

### Summary: try_lock_no_irqsave

`SpinLock::<_, IrqDisabled>::try_lock_no_irqsave()` returns `None` for two
different reasons:

- IRQs are enabled, so the precondition is violated
- the lock is already held, which is normal contention

This is acceptable for hot-path best-effort callers, but it hides which case
actually happened when debugging timer / scheduler behaviour.

Relevant file:

- `workspace/kernel/src/sync/spinlock.rs`

### What to keep: try_lock_no_irqsave

Keep the current return type and best-effort behavior.

### What to improve: try_lock_no_irqsave

1. Emit a lightweight diagnostic trace when `IrqDisabledToken::verify()` fails.
2. Keep `None` semantics unchanged so hot-path callers do not need new control
   flow.
3. Preserve the design intent that ordinary contention is not treated as an
   error in timer/scheduler paths.

## IrqDisabledToken encapsulation

### Summary: IrqDisabledToken::new_unchecked

`IrqDisabledToken::new_unchecked()` is `pub(crate)`, which means any code in
the kernel crate can manufacture the proof token directly.

Relevant files:

- `workspace/kernel/src/sync/irq.rs`
- `workspace/kernel/src/sync/guardian.rs`
- `workspace/kernel/src/memory/heap.rs`
- `workspace/kernel/src/memory/paging.rs`

### Why it matters: IrqDisabledToken::new_unchecked

The current API is sound only by convention. The unsafe contract is documented,
but the visibility is broader than necessary and makes it easier to create a
token outside the narrow places that actually own the IRQ-off transition.

### What to improve: IrqDisabledToken::new_unchecked

1. Restrict `new_unchecked()` to the smallest practical visibility.
2. Refactor legitimate external call sites to use a tighter helper API rather
   than open-ended token construction.
3. Keep the rare remaining unchecked construction sites documented with a local
   safety comment that explains why IRQs are already disabled there.

## XSAVE/XRSTOR reactivation

### Summary: XSAVE/XRSTOR

Context switch still forces the legacy `FXSAVE/FXRSTOR` path and ignores
`SwitchTarget.old_xcr0` / `SwitchTarget.new_xcr0`.

Relevant file:

- `workspace/kernel/src/process/task.rs`

### Why it matters: XSAVE/XRSTOR

This is an intentional safety tradeoff, not a security bug. It avoids state-size
or XCR0-transition mismatches while the scheduler and interrupt return paths are
still stabilizing, but it also means vector state support is intentionally
degraded.

### What to improve: XSAVE/XRSTOR

1. Re-enable XSAVE/XRSTOR only after xsave-area sizing and alignment are
   validated for every supported XCR0 mask.
2. Validate save/restore through scheduler switches, syscall exits, and IRQ
   returns.
3. Remove the temporary ignore of `old_xcr0` / `new_xcr0` once those paths are
   proven stable.

## SpinLock multi-Watch debugging

### Summary: SpinLock multi-watch

`debug_set_watch_lock_addr()` currently tracks only one watched lock at a time.

Relevant file:

- `workspace/kernel/src/sync/spinlock.rs`

### Why it matters: SpinLock multi-watch

This is debug ergonomics only. It makes multi-lock deadlock investigations take
multiple runs, but it does not affect correctness.

### What to improve: SpinLock multi-watch

1. Consider allowing a small fixed-size set of watched lock addresses.
2. Keep the implementation allocation-free and safe in very early boot/debug
   contexts.

## Protected module range validation

### Summary: protected module ranges

The buddy allocator relies on boot-allocator protected ranges being excluded
correctly before free regions are handed over.

Relevant files:

- `workspace/kernel/src/memory/boot_alloc.rs`
- `workspace/kernel/src/memory/buddy.rs`

### Why it matters: protected module ranges

If a protected module range is recorded incorrectly, the allocator could expose
pages that should stay reserved for kernel or boot-loaded modules. The current
logic excludes those ranges, but there is little explicit init-time validation.

### What to improve: protected module ranges

1. Add an init-time diagnostic that protected ranges are page-aligned as
   expected after normalization.
2. Verify that protected ranges no longer appear in the boot allocator snapshot
   handed to the buddy allocator.
3. Emit a clear early-boot trace or panic if a supposedly protected interval
   still overlaps a free region after exclusion.
