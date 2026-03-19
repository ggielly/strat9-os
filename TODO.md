# TODO

## Priority scale

- `P1`: important hardening to do soon; likely to save debugging time or prevent silent corruption.
- `P2`: useful correctness/diagnostic improvements; should be done after current blockers.
- `P3`: medium-priority cleanup or API hardening; valuable but not urgent.
- `P4`: low-priority ergonomics, observability, or optional asserts.

## Priority table

| ID | Sujet | Priority | Verdict | Fichiers principaux |
| --- | --- | --- | --- | --- |
| 1 | Buddy allocator `FrameMeta::refcount` sentinel hardening | P1 | Real memory hardening item | `workspace/kernel/src/memory/buddy.rs`, `workspace/kernel/src/memory/frame.rs` |
| 2 | `try_lock_no_irqsave` diagnostic visibility | P2 | Keep best-effort behavior, improve diagnostics | `workspace/kernel/src/sync/spinlock.rs` |
| 3 | `IrqDisabledToken::new_unchecked()` encapsulation | P2 | Real API hardening item | `workspace/kernel/src/sync/irq.rs`, `workspace/kernel/src/memory/heap.rs`, `workspace/kernel/src/memory/paging.rs` |
| 4 | Protected module range validation at init | P2 | Defensive validation worth adding | `workspace/kernel/src/memory/boot_alloc.rs`, `workspace/kernel/src/memory/buddy.rs` |
| 5 | `Arc::strong_count` scheduler diagnostics are heuristic | P3 | Keep as pifometric heuristic, not proof | `workspace/kernel/src/process/scheduler/core_impl.rs`, `workspace/kernel/src/process/scheduler/task_ops.rs`, `workspace/kernel/src/process/scheduler/runtime_ops.rs` |
| 6 | XSAVE/XRSTOR reactivation | P3 | Functional/perf work, not security | `workspace/kernel/src/process/task.rs` |
| 7 | Keyboard buffer full policy visibility | P3 | Drop-oldest policy is intentional but silent | `workspace/kernel/src/arch/x86_64/keyboard.rs` |
| 8 | Shell Ctrl+C cooperative cancellation coverage | P3 | Commands must poll interruption flag | `workspace/kernel/src/shell/mod.rs` |
| 9 | SpinLock multi-watch debugging | P4 | Debug ergonomics only | `workspace/kernel/src/sync/spinlock.rs` |
| 10 | Slab refill IRQ invariant assert | P4 | Optional debug assert; code path already sound | `workspace/kernel/src/memory/heap.rs` |
| 11 | Legacy PIC timer Ring-3 preemption parity | P2 | Audit says path still differs from LAPIC hardening | `workspace/kernel/src/arch/x86_64/idt.rs` |
| 12 | `finish_interrupt_switch()` does not drain `task_to_drop` | P1 | Real lifetime / resource retention bug | `workspace/kernel/src/process/scheduler/runtime_ops.rs` |
| 13 | Large heap allocation page-count overflow | P1 | Real integer overflow bug | `workspace/kernel/src/memory/heap.rs` |
| 14 | `free_to_zone()` silent protected-overlap drop | P2 | Real diagnostic / corruption-masking issue | `workspace/kernel/src/memory/buddy.rs` |
| 15 | `reparent_children()` fallback is nondeterministic without PID 1 | P2 | Real process-lifecycle semantics bug | `workspace/kernel/src/process/scheduler/task_ops.rs` |
| 16 | Dead null-check on Rust reference in scheduler | P3 | Real cleanup item, no runtime effect | `workspace/kernel/src/process/scheduler/core_impl.rs` |
| 17 | Audit guardian choice for `LOCAL_FRAME_CACHES` | P3 | Audit/perf hypothesis, not yet a proven bug | `workspace/kernel/src/memory/buddy.rs`, `workspace/kernel/src/sync/guardian.rs` |

## Audited / closed

### Mars 2026 critical-bug audit

Status snapshot for the latest C1-C5 review:

- `C1` keyboard IRQ deadlock on `spin::Mutex`: not reproduced on current code.
   Task-context buffer access paths already disable IRQs before taking the
   keyboard lock, including `inject_hid_scancode()`.
- `C2` false buddy recursive-deallocation panic on OOM drain path: not
   reproduced on current code. The current wrapper clears `ALLOC_IN_PROGRESS`
   before the public OOM recovery / free path runs.
- `C3` raw userspace write in `clear_child_tid`: fixed. Exit path now writes
   through `UserSliceWrite` instead of dereferencing a raw userspace pointer.
- `C4` unchecked bootstrap-stack context read in
   `seed_kernel_interrupt_frame_from_context()`: fixed. A stack-bounds
   `debug_assert!` now guards the expected saved context window.
- `C5` timer IRQ preemption corruption: already mitigated on the active LAPIC
   timer path, but the legacy PIC timer path still deserves parity review when
   Ring 3 can run before LAPIC timer activation.

## P1

### Buddy allocator `FrameMeta::refcount` sentinel hardening

Diagnostic:

The buddy allocator does not yet maintain the OSTD-style sentinel invariant for
free-list frames:

- expected hardening target: free-list frame => `refcount == REFCOUNT_UNUSED`
- current behavior: both `mark_block_free()` and `mark_block_allocated()` call
  `reset_refcount()` and write `0`

Relevant files:

- `workspace/kernel/src/memory/buddy.rs`
- `workspace/kernel/src/memory/frame.rs`

Why it matters:

`FrameAllocOptions::allocate()` documents a stronger design where allocation can
use `CAS(REFCOUNT_UNUSED -> 0)` to catch buddy free-list corruption early.
Because the buddy allocator does not currently stamp `REFCOUNT_UNUSED`, that
check is disabled.

Current effect:

- the allocator still relies on its bitmap + free-list invariants and can work
  correctly in the normal case
- but if a frame appears twice in the free list, the system lacks the intended
  fail-fast detection and may corrupt memory silently

What to modify:

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

## P2

### `try_lock_no_irqsave` diagnostic visibility

Summary:

`SpinLock::<_, IrqDisabled>::try_lock_no_irqsave()` returns `None` for two
different reasons:

- IRQs are enabled, so the precondition is violated
- the lock is already held, which is normal contention

This is acceptable for hot-path best-effort callers, but it hides which case
actually happened when debugging timer / scheduler behaviour.

Relevant file:

- `workspace/kernel/src/sync/spinlock.rs`

Keep:

Keep the current return type and best-effort behavior.

Improve:

1. Emit a lightweight diagnostic trace when `IrqDisabledToken::verify()` fails.
2. Keep `None` semantics unchanged so hot-path callers do not need new control
   flow.
3. Preserve the design intent that ordinary contention is not treated as an
   error in timer/scheduler paths.

### `IrqDisabledToken::new_unchecked()` encapsulation

Summary:

`IrqDisabledToken::new_unchecked()` is `pub(crate)`, which means any code in
the kernel crate can manufacture the proof token directly.

Relevant files:

- `workspace/kernel/src/sync/irq.rs`
- `workspace/kernel/src/sync/guardian.rs`
- `workspace/kernel/src/memory/heap.rs`
- `workspace/kernel/src/memory/paging.rs`

Why it matters:

The current API is sound only by convention. The unsafe contract is documented,
but the visibility is broader than necessary and makes it easier to create a
token outside the narrow places that actually own the IRQ-off transition.

Improve:

1. Restrict `new_unchecked()` to the smallest practical visibility.
2. Refactor legitimate external call sites to use a tighter helper API rather
   than open-ended token construction.
3. Keep the rare remaining unchecked construction sites documented with a local
   safety comment that explains why IRQs are already disabled there.

### Protected module range validation

Summary:

The buddy allocator relies on boot-allocator protected ranges being excluded
correctly before free regions are handed over.

Relevant files:

- `workspace/kernel/src/memory/boot_alloc.rs`
- `workspace/kernel/src/memory/buddy.rs`

Why it matters:

If a protected module range is recorded incorrectly, the allocator could expose
pages that should stay reserved for kernel or boot-loaded modules. The current
logic excludes those ranges, but there is little explicit init-time validation.

Improve:

1. Add an init-time diagnostic that protected ranges are page-aligned as
   expected after normalization.
2. Verify that protected ranges no longer appear in the boot allocator snapshot
   handed to the buddy allocator.
3. Emit a clear early-boot trace or panic if a supposedly protected interval
   still overlaps a free region after exclusion.

### `free_to_zone()` silent protected-overlap drop

Summary:

`free_to_zone()` returns silently when a freed block overlaps a protected
module/kernel range, while the allocation-side equivalent already treats the
same condition as a hard allocator inconsistency.

Relevant file:

- `workspace/kernel/src/memory/buddy.rs`

Why it matters:

- this asymmetry can mask real corruption, double-free, or broken metadata
- the allocator state becomes harder to reason about during postmortem because
  the free was dropped without a strong signal

Current behavior:

- `alloc_from_zone()` panics if a supposedly free block overlaps protected memory
- `free_to_zone()` only emits a debug-gated trace and returns

Improve:

1. Add an unconditional diagnostic on this path (at minimum `serial_println!`).
2. Re-evaluate whether this should escalate to `panic!` in non-selftest builds,
   matching the allocation-side invariant.
3. Keep the message explicit about zone, range, and order so the offending
   caller can be identified from serial logs alone.

### Legacy PIC timer Ring-3 preemption parity

Summary:

`legacy_timer_handler()` is still an `extern "x86-interrupt"` timer path and
still calls `maybe_preempt()` directly after EOI, unlike the hardened LAPIC
timer path which only posts `request_force_resched_hint(cpu)` for Ring-3-origin
interrupts.

Relevant file:

- `workspace/kernel/src/arch/x86_64/idt.rs`

Why it matters:

The earlier timer corruption bug was specifically about switching away from an
interrupt frame the compiler expects to unwind with `iretq`. The LAPIC handler
was hardened for that reason. If Ring 3 can run while the system is still on
the legacy PIC timer path, the same class of frame-mismatch bug can in theory
reappear there.

Audit verdict:

- active LAPIC timer path: already mitigated
- legacy PIC timer path: still structurally different, so this remains a real
  parity / hardening item

Improve:

1. Mirror the LAPIC policy in `legacy_timer_handler()`: if the interrupted CPL
   is Ring 3, only post a resched hint and return through the interrupt epilogue.
2. Keep direct `maybe_preempt()` only for same-CPL kernel timer interrupts if
   that path is still known-safe.
3. Re-test the early boot window where APIC timer is not yet active but user
   tasks may already be runnable.

### `reparent_children()` fallback is nondeterministic without PID 1

Summary:

When PID 1 is absent, `reparent_children()` falls back to the first key in
`all_tasks`, which depends on task-id / map ordering rather than explicit init
semantics.

Relevant file:

- `workspace/kernel/src/process/scheduler/task_ops.rs`

Why it matters:

- orphan reparenting semantics become unstable
- a short-lived fallback parent can disappear immediately after adoption
- wait/reap behavior for descendants can become difficult to reason about

Current behavior:

- preferred target: task mapped to PID 1
- fallback target: `sched.all_tasks.keys().next()`

Improve:

1. Make the fallback deterministic and policy-driven rather than map-order driven.
2. Prefer a dedicated reaper/init task, or explicitly drop parent links if the
   kernel cannot guarantee a stable adopter.
3. Document the orphan policy so wait/reap semantics stay predictable.

### `finish_interrupt_switch()` does not drain `task_to_drop`

Summary:

The interrupt-driven switch finalization path does not take `cpu.task_to_drop`
out of the scheduler CPU state, unlike the cooperative `finish_switch()` path.

Relevant file:

- `workspace/kernel/src/process/scheduler/runtime_ops.rs`

Why it matters:

- a dead task can remain retained in `cpu.task_to_drop`
- that keeps the `Arc<Task>` alive longer than intended
- kernel-stack reclamation is delayed or potentially stranded if the CPU never
  hits the non-interrupt finalization path again

Current behavior:

- `finish_switch()` calls `drain_post_switch_locked(..., take_drop=true)` and
  then `drop(task_to_drop)`
- `finish_interrupt_switch()` calls `drain_post_switch_locked(..., take_drop=false)`
  and ends with `let _ = task_to_drop;`

Improve:

1. Mirror the `finish_switch()` behavior and drain `task_to_drop` on the
   interrupt finalization path.
2. Keep the drop outside the scheduler lock if that is the intended invariant.
3. Re-check comments and hook contracts so both post-switch paths manage
   ownership symmetrically.

### Large heap allocation page-count overflow

Summary:

The large-allocation buddy path computes page count with `effective + 4095`,
which can overflow for extremely large layouts.

Relevant file:

- `workspace/kernel/src/memory/heap.rs`

Why it matters:

- in release mode, overflow wraps silently
- wrapped page count can under-allocate backing memory
- under-allocation at the global allocator layer is a real memory safety bug

Current behavior:

- `let pages_needed = (effective + 4095) / 4096;`

Improve:

1. Use checked arithmetic when rounding up to page count.
2. Saturate or fail cleanly on impossible layouts before the buddy order is derived.
3. Keep the large-allocation path obviously safe under release-mode overflow semantics.

## P3

### `Arc::strong_count` scheduler diagnostics are heuristic

Summary:

The scheduler keeps some `Arc::strong_count()` checks as pifometric diagnostics.

### Dead null-check on Rust reference in scheduler

Summary:

`select_cpu_for_task()` checks `(self as *const Self).is_null()` even though
`self` is a Rust reference and therefore cannot be null.

Relevant file:

- `workspace/kernel/src/process/scheduler/core_impl.rs`

Why it matters:

- no runtime bug on its own
- but it suggests a false defensive invariant and adds noise to scheduler code

Improve:

1. Remove the null-check.
2. Keep only meaningful early-return conditions based on scheduler state.

### Audit guardian choice for `LOCAL_FRAME_CACHES`

Summary:

`LOCAL_FRAME_CACHES` are per-CPU caches, but they currently use the default
`SpinLock<T>` guardian (`IrqDisabled`) rather than `PreemptDisabled`.

Relevant files:

- `workspace/kernel/src/memory/buddy.rs`
- `workspace/kernel/src/sync/guardian.rs`
- `workspace/kernel/src/sync/spinlock.rs`

Audit verdict:

- this is not yet a proven correctness bug
- it may be a valid optimization / design cleanup
- but the caches are also drained / stolen cross-CPU, and the surrounding buddy
  API is still structured around `IrqDisabledToken`

Improve:

1. Audit all access paths to confirm these caches are never touched from IRQ context.
2. Audit lock ordering around cross-CPU steal/drain paths before changing guardians.
3. Only switch to `PreemptDisabled` if the full call graph supports that contract.
They are intentionally racy and must not be treated as formal corruption proofs.

Relevant files:

- `workspace/kernel/src/process/scheduler/core_impl.rs`
- `workspace/kernel/src/process/scheduler/task_ops.rs`
- `workspace/kernel/src/process/scheduler/runtime_ops.rs`

Keep:

Keep the signal as a debugging heuristic.

Improve:

1. Avoid wording that claims certain corruption from `strong_count()` alone.
2. Keep thresholds clearly documented as heuristic and best-effort.

### XSAVE/XRSTOR reactivation

Summary:

Context switch still forces the legacy `FXSAVE/FXRSTOR` path and ignores
`SwitchTarget.old_xcr0` / `SwitchTarget.new_xcr0`.

Relevant file:

- `workspace/kernel/src/process/task.rs`

Why it matters:

This is an intentional safety tradeoff, not a security bug. It avoids state-size
or XCR0-transition mismatches while the scheduler and interrupt return paths are
still stabilizing, but it also means vector state support is intentionally
degraded.

Improve:

1. Re-enable XSAVE/XRSTOR only after xsave-area sizing and alignment are
   validated for every supported XCR0 mask.
2. Validate save/restore through scheduler switches, syscall exits, and IRQ
   returns.
3. Remove the temporary ignore of `old_xcr0` / `new_xcr0` once those paths are
   proven stable.

### Keyboard buffer full policy visibility

Summary:

The keyboard ring buffer uses a bounded drop-oldest policy when full.

Relevant file:

- `workspace/kernel/src/arch/x86_64/keyboard.rs`

Why it matters:

This is not a buffer overflow. The current behavior is memory-safe, but it can
drop input silently when the producer outruns the consumer.

Improve:

1. Consider a lost-key counter or lightweight trace for debugging.
2. Keep the IRQ handler allocation-free and non-blocking.

### Shell Ctrl+C cooperative cancellation coverage

Summary:

Shell interruption is cooperative through `SHELL_INTERRUPTED`; long-running
commands must poll it explicitly.

Relevant file:

- `workspace/kernel/src/shell/mod.rs`

Why it matters:

The shell is not deadlocked, but cancellation quality depends on command
implementations actually checking the flag.

Improve:

1. Audit long-running shell commands to poll `is_interrupted()` regularly.
2. Document the cooperative cancellation contract for future commands.

## P4

### SpinLock multi-watch debugging

Summary:

`debug_set_watch_lock_addr()` currently tracks only one watched lock at a time.

Relevant file:

- `workspace/kernel/src/sync/spinlock.rs`

Why it matters:

This is debug ergonomics only. It makes multi-lock deadlock investigations take
multiple runs, but it does not affect correctness.

Improve:

1. Consider allowing a small fixed-size set of watched lock addresses.
2. Keep the implementation allocation-free and safe in very early boot/debug
   contexts.

### Slab refill IRQ invariant assert

Summary:

`heap.rs` slab refill currently relies on the enclosing `SpinLock<IrqDisabled>`
contract for IRQ masking.

Relevant file:

- `workspace/kernel/src/memory/heap.rs`

Why it matters:

The current code path already looks sound. A `debug_assert!` would just freeze
the invariant in place for future refactors.

Improve:

1. Optionally add a debug-only assertion documenting that `refill()` runs with
   IRQs disabled.
