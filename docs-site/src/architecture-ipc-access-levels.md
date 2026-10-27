# IPC Access Levels

How Strat9 OS decides *how* two silos may talk to each other, and what each level actually costs.

This page describes the implementation. The original proposal is preserved as a historical design note in `docs/architecture-ipc-access-levels.md` (v0.1.0, 2026-06-23, in French); several of its predictions did not survive contact with the code — see [Divergences from the design note](#divergences-from-the-design-note) at the end.

---

## The three levels

| Label | Enum variant | Implementation | Where |
|-------|--------------|----------------|-------|
| N1 | `TransportLevel::TypeSafe` (= 1) | `IntrusiveMailbox` — lock-free LIFO stack of kernel messages | `kernel/src/ipc/mailbox.rs` |
| N2 | `TransportLevel::LockFree` (= 2) | `LockFreeRing` — bounded MPMC queue on the kernel heap | `kernel/src/ipc/lockfree_ring.rs` |
| N3 | `TransportLevel::Mmu` (= 3) | `N3Transport` — CR3 switch with PCID, unidirectional | `kernel/src/ipc/n3.rs` |

All three run **inside the kernel**. N1 is a kernel-internal mailbox; N2's queue lives on the kernel heap; N3's shared frame and message buffer are mapped kernel-only. Userspace never holds a transport endpoint directly — it goes through `SYS_TRANSPORT_*`.

---

## Selection

### Silo tiers

`SiloTier { Critical = 0, System = 1, User = 2 }`. The tier is not stored; `SiloId::new()` recomputes it from the numeric silo id on every construction:

| Silo id | Tier |
|---------|------|
| `1..=9` | Critical |
| `10..=999` | System |
| everything else, including `0` | User |

### The matrix

`TransportManager` holds a `[[TransportPolicyEntry; 3]; 3]`, indexed `[src.tier][dst.tier]`, where each entry is `(level, ring_capacity)`:

| src \ dst | Critical | System | User |
|-----------|----------|--------|------|
| **Critical** | TypeSafe, 0 | TypeSafe, 0 | LockFree, 256 |
| **System** | TypeSafe, 0 | LockFree, 256 | LockFree, 256 |
| **User** | LockFree, 256 | LockFree, 256 | **Mmu**, 0 |

### Resolution order

`establish(src: SiloId, dst: SiloId, config: TransportConfig)` applies three steps in order:

1. **Cache.** A 128-entry FIFO keyed on `(src.sid, dst.sid)`. A hit is reused only if the cached level is at least `config.min_level`.
2. **Policy override.** `policy_overrides` is consulted next. On a hit it wins outright — both `min_level` and the caller's `ring_capacity` are discarded. Only `TransportManager::set_policy()` populates this map, and it currently has no callers.
3. **Matrix.** Otherwise `level = max(matrix[src][dst], config.min_level)`. The caller's minimum can only *raise* the level, never lower it.

### Why N1 is unreachable from userspace

`sys_transport_create` decodes `config_flags` and defaults the minimum level to `LockFree`:

| Bits | Meaning | Default |
|------|---------|---------|
| `[3:0]` | Minimum level (1 TypeSafe, 2 LockFree, 3 Mmu) | 2 — LockFree |
| `[23:8]` | Ring capacity in slots | 256 |

Because `min_level` is a floor, any caller that does not explicitly pass `1` raises both TypeSafe cells to LockFree. **The N1 mailbox cannot be reached through `SYS_TRANSPORT_CREATE`.** It is used only on the kernel-internal NIC ↔ scheduler path, via `notify_scheduler` and `poll_nic_events` in `kernel/src/ipc/n1.rs`.

The ABI header's claim that "the transport level is selected automatically based on the silo tiers" is therefore only true for callers that pass no `config_flags` at all, and even then only for the User↔User cell.

---

## Level details

### N1 — TypeSafe

`IntrusiveMailbox` is a lock-free LIFO stack built on intrusive tagged pointers.

```rust
let mailbox = IntrusiveMailbox::new();   // preallocates 32 nodes
mailbox.push(b"notification")?;          // LIFO push
let msg = mailbox.pop();                 // last message first
```

- **Genuinely LIFO**, pinned by the unit test `push_pop_lifo_order` and by `kernel-l2-tests/tests/kernel_n1_semaphores.rs`.
- **Not `#[forbid(unsafe_code)]`.** No `forbid`/`deny(unsafe_code)` exists anywhere under `kernel/src/ipc/`, and `mailbox.rs` has raw `unsafe` dereferences at lines 145, 162, 222, 235, 263 and 273. The two `forbid(unsafe_code)` attributes in the tree are in `kernel/src/ostd/`.
- **The preallocation never runs.** `ipc::n1::init()`, which calls `preallocate_nodes(32)` on both mailboxes, has no callers, so the node pool is empty and every `push` falls back to a `Box` heap allocation — defeating the "no heap allocation on the IRQ path" intent.
- Advertised: 256-byte messages, non-blocking, not zero-copy, single direction, `estimated_cost_cycles: 10`.

### N2 — LockFree

`LockFreeRing` wraps `crossbeam_queue::ArrayQueue<Box<[u8]>>` — a **bounded MPMC** queue, not SPSC. Each `write` heap-allocates and copies a boxed buffer.

- `new(slot_count, slot_size)` rounds the capacity up to a power of two
- `write` / `read`, plus `try_write` / `try_read` and `write_vectored`
- `notify_consumer_raw` and `notify_producer_raw` are **empty functions**; `wait_notification()` spins 64 times then loops on `block_current_task()`. There is no futex.
- There is **no shared-memory ring, no DMA and no `RingHeader`**. `dma_buffer()` always returns `None`, and `frame_phys_addrs()` returns a single dummy frame kept for syscall compatibility.
- The SPSC typestate wrapper `TypedLockFreeRing` / `create_spsc_pair` exists in `ipc/transport.rs` but has **zero call sites**, and does not enforce SPSC at runtime.
- Advertised: 2048-byte messages, blocking, not zero-copy, vectored, bidirectional, `estimated_cost_cycles: 400`.

### N3 — MMU

`kernel/src/ipc/n3.rs` is 1552 lines of real implementation: a naked `mov cr3, rax; ret` trampoline, an IDT-registered migration IPI at vector `0xF1`, a PCID allocator, a 4-level page-table walker that validates the target RIP, a shared 320-byte migration frame, a 64-entry frame pool with a bitmap allocator, and a 10 ms TSC watchdog.

- `N3Tier` has only two variants — `PcidPreserving` and `FullIsolation` (named `"n3b"` and `"n3c"`). There is no N3a.
- The module carries a file-level `#![allow(dead_code)]` and has **no `#[cfg(test)]` tests**.
- **Sends currently fail.** `N3Transport::send()` needs `task.trampoline_entry != 0` and then needs that RIP to pass `validate_rip()`, which rejects both `rip >= 0xFFFF_8000_0000_0000` and any page with `U/S = 1` at every level of the walk. Every kernel task constructor sets `trampoline_entry = 0`; the only non-zero assignment is a userspace ELF entry point, which is exactly what the validator rejects. A User↔User transport is therefore *created successfully* and then fails on the first `send` with `EFAULT`. There is no fallback to N2.
- Advertised: 2048-byte messages, blocking, not zero-copy, unidirectional, `estimated_cost_cycles: 800`.

---

## Endpoint shape

For TypeSafe and LockFree, `TransportManager::create()` builds **one** object and `Arc::clone`s it into both `local` and `remote`. The two endpoints are the same underlying mailbox or queue: there is no directional split, and a TypeSafe transport has both ends pushing and popping the same LIFO stack. Only the Mmu branch is directional, and it is unidirectional by construction.

`sys_transport_create` also performs no validation that the destination silo exists.

---

## Syscall surface

| Syscall | # | Args | Notes |
|---------|---|------|-------|
| `SYS_TRANSPORT_CREATE` | 260 | `dst_silo, config_flags` | Returns a capability handle, not a raw id |
| `SYS_TRANSPORT_SEND` | 261 | `handle, buf_ptr, buf_len` | Non-blocking in practice: a full queue returns `EAGAIN` |
| `SYS_TRANSPORT_RECV` | 262 | `handle, buf_ptr, buf_len` | Non-blocking in practice: an empty queue returns `EAGAIN` |
| `SYS_TRANSPORT_CLOSE` | 263 | `handle` | Removes the capability; the manager entry is reclaimed when the last reference drops |
| `SYS_TRANSPORT_INFO` | 264 | `handle, out_ptr` | Writes **8 bytes** — the level discriminant. There is no `TransportInfo` type |

`ResourceType::IpcTransport` is a first-class pollable: readiness comes from `endpoint.has_data()` and `endpoint.has_space()`.

---

## Cost

**No measurement in the repository backs any cycle figure.** There is no IPC benchmark — no `criterion`, `divan` or `iai` harness under `kernel/`, `abi/` or `kernel-l2-tests/`. The only TSC read in the IPC tree is the N3 watchdog timestamp.

The only numbers present in code are three hardcoded `estimated_cost_cycles` literals, and **nothing reads that field anywhere**:

| Level | Literal |
|-------|---------|
| TypeSafe | `10` |
| LockFree | `400` |
| Mmu | `800` |

Treat these as scheduler hints, not measurements.

---

## Divergences from the design note

`docs/architecture-ipc-access-levels.md` proposed a different shape in June 2026. Where the implementation differs:

| Design note | Implementation |
|-------------|----------------|
| N1 as `SfiTransport` selecting by a "100 % safe Rust, `cargo-geiger = 0`" manifest check | N1 is `IntrusiveMailbox`, with no safety audit gate anywhere in the build |
| N2 as an SPSC ring in **shared memory** with a `RingHeader`, a 64-byte header, N slots, and futex notification | N2 is a kernel-heap MPMC `ArrayQueue` of boxed buffers, with no shared memory and no futex |
| N2/N3 as **Ring 3** transports with MMU isolation | Both run entirely in the kernel |
| N3 as `SYSCALL` + thread migration at ~460 cycles | Implemented as a CR3/PCID switch, but unreachable on the current task model |
| A NIC data path where `strate-net` reads the ring with **zero syscalls** | `strate-net` is a userspace silo; it reaches the NIC through syscalls, and the N1 mailbox is the only kernel-internal path |
| Overheads of ~3 / ~200 / ~460 cycles and per-packet CPU percentages | Unmeasured. Only the three literals above exist |

---

## See also

- [IPC Mechanisms](./ipc-mechanisms.md) — the full transport reference, including the legacy port/channel/ring/semaphore mechanisms
- [Silo System](./silo.md) — where silo tiers and pledge/unveil are enforced
- [Syscall Reference → IPC: transport](./syscalls.md#ipc--transport-n1n2n3)
