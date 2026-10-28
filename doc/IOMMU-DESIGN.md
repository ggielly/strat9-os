# IOMMU / DMA isolation design

Status: **P0 + P1 kernel core, P2 shadow/performance core**. Hardware
translation is implemented but intentionally not enabled at boot.

## 1. Layers

```
driver / strate                 SYS_IOMMU_* / DmaBuffer
        │
        ├── hardware::iommu     domains, IOVA, quotas, faults, reservations
        │        │
        │        └── arch::iommu::Backend
        │                 ├── NoIommu        (no firmware / no support)
        │                 └── VT-d (x86_64)  shadow tables + locked activation
        │
        └── acpi::dmar          DRHD / RMRR / ATSR / scopes
```

The kernel owns the objects; `strate-iommu` is **policy only** and sits
outside the data path.

## 2. Domain model

* `Sbdf { segment, bus, device, function }` identifies a PCI function.
* `DomainId` is a 16-bit bitmap id; 0 is reserved.
* `Arc<Domain>` is held by capabilities; `Domain` also carries a logical
  refcount so a delegated domain survives a policy-server restart.
* `BTreeMap<u64, Mapping>` gives O(log n) `map`/`unmap`/`translate`.
* Each mapping records its `MappingKind` (`4 KiB`, `2 MiB`, `1 GiB`).
* `DmaProt` separates device read/write from capability read/write.
* Domains carry `owner: Option<SID>`, a `FaultPolicy`, and counters.

### Reserved regions

DMAR RMRRs become `ReservedRegion`s. When a device domain is created, the
ranges that apply to its SBDF are identity-mapped automatically. A normal
`map` over a reserved range is refused with `EPERM`. Inverted or unusable
RMRRs are logged; `panic_on_invalid_rmrr` is available for strict platforms.

## 3. Faults

* Bounded global queue (`256` records) + per-domain burst budget (`32`).
* `FaultPolicy`: `Log`, `Notify`, `KillOwner`, `Panic`.
* `KillOwner` revokes every domain owned by the faulting SID.
* Records expose seq, timestamp, SBDF, domain, IOVA, reason, access, action
  and owner through `SYS_IOMMU_FAULT_NEXT`.
* The VT-d fault *registers* are not wired to an IRQ yet; the queue is fed by
  the backend and by `inject_fault` for fault-policy tests.

## 4. Quotas

`SiloConfig` gained:

```text
dma_max_domains  dma_max_bytes  dma_iova_base  dma_iova_limit  dma_fault_policy
```

`SYS_IOMMU_DOMAIN_CREATE` enforces the domain count, `SYS_IOMMU_MAP` and
`SYS_IOMMU_MAP_BATCH` enforce the byte budget and IOVA window. `0` means
"unlimited" so existing silos are unaffected.

`pledge` already only narrows the octal mode; a silo that drops `H.DMA`
should destroy its domains and close its capabilities. `unveil` limits access
to `/srv/iommu` through the normal VFS rules.

## 5. Syscall surface (block 440-459)

| Number | Call | Notes |
|---|---|---|
| 440 | `SYS_IOMMU_INFO` | platform summary |
| 441 | `SYS_IOMMU_DOMAIN_CREATE` | returns an `IommuDomain` cap |
| 442 | `SYS_IOMMU_DOMAIN_DESTROY` | revokes all mappings |
| 443 | `SYS_IOMMU_MAP` | checked against RMRR/quotas |
| 444 | `SYS_IOMMU_UNMAP` | exact-granularity |
| 445 | `SYS_IOMMU_TRANSLATE` | software translation |
| 446 | `SYS_IOMMU_ACTIVATE` | 0 unless a validated backend is ready |
| 447 | `SYS_IOMMU_FAULT_NEXT` | drain fault queue |
| 448 | `SYS_IOMMU_DOMAIN_CTL` | quiesce/resume/detach/policy |
| 449 | `SYS_IOMMU_DOMAIN_INFO` | identity + counters |
| 450 | `SYS_IOMMU_MAP_BATCH` | up to 64 descriptors, rollback on error |
| 451 | `SYS_IOMMU_UNMAP_BATCH` | up to 64 descriptors |
| 452 | `SYS_IOMMU_STATS` | global counters |
| 453 | `SYS_IOMMU_GROUPS` | coarse DRHD groups |
| 454 | `SYS_IOMMU_RESERVED` | RMRR/IVMD list |
| 455 | `SYS_PCI_MSI_ALLOC` | IRTE + MSI doorbell (needs active IR) |
| 456 | `SYS_PCI_MSI_FREE` | release an IRTE |

All calls are gated to `SYS`/`DRV` strate families and to the capability
`DmaRights`.

## 6. VT-d backend

The backend builds, in kernel memory:

* a 4 KiB root table (256 entries, 16 bytes each);
* one 4 KiB context table per bus, allocated lazily;
* one four-level second-level page-table tree per domain;
* 4 KiB, 2 MiB and 1 GiB leaf entries (PS bit at level 2/3);
* a 4 KiB queued-invalidation ring (256 descriptors) + WAIT status page;
* a 4 KiB interrupt-remapping table (256 IRTEs).

Context entries use the legacy format: `TT = 00` (second-level
translation), AGAW in bits 6:4 and the domain id in the high qword bits
23:8.  Invalidation uses QI descriptor types 1 (context), 2 (IOTLB), 4
(IRTE) and 5 (WAIT), then polls the WAIT status word.  IR allocation writes
an extended IRTE (`P | SID | SQ | SVT=01 | vector | destination`) and
returns the doorbell address `0xFEE00018 | (index << 5)` with `data = 0`.

Activation (`RTADDR`, `GCMD.QI/SRTP/SIRTP/IRE/TE`, invalidation) is
implemented but gated by `HARDWARE_ACTIVATION_ENABLED = false` until the
path is validated under QEMU `intel-iommu`. Consequences:

* `Backend::is_ready()` is false on real hardware;
* `SYS_IOMMU_ACTIVATE` returns 0;
* `SYS_PCI_MSI_ALLOC/FREE` return `ENOTSUP` until IR is active;
* MSI/MSI-X keep the physical path and refuse APIC IDs > 255;
* the shadow tables still give an exact, inspectable model of what would be
  programmed.

Known P2 limits:

* ATS/PASID/SR-IOV are not implemented;
* scalable mode is not implemented (legacy tables only);
* IOMMU groups are coarse (DRHD + bus), not a full ACS analysis;
* `SYS_PCI_BAR_MAP` is not wired yet: mapping a device BAR into a user
  address space needs the PCI device-capability milestone;
* DMAR fault *interrupts* are not routed to an IRQ; `FaultRecord`s currently
  come from the backend and from `inject_fault`.

## 7. `/srv/iommu`

`workspace/components/strate-iommu` binds `/srv/iommu` and answers textual
requests over IPC:

| `msg_type` | Content |
|---|---|
| `0x10` | platform summary |
| `0x11` | global counters |
| `0x12` | drain fault queue |
| `0x13` | reserved regions |
| `0x14` | IOMMU groups |
| `0x15` | attempt activation |

It is started by `strate-init` from `workspace/assets/boot/silo.toml`
(SYS family, mode `716`) and copied into the initfs image by
`tools/uefi-modules.manifest`.  Domains and buffers survive a restart
because the kernel owns them.

## 8. Hotplug / lifecycle

* `quiesce` stops new mappings; existing DMA continues.
* `detach` quiesces then tears the domain down.
* `revoke_owner(sid)` destroys all domains of a dead silo.
* `Drop for DmaBuffer` unmaps before returning frames to the buddy allocator,
  so a stale translation never points at recycled memory.

## 9. Bounce buffers

`dma::DmaBounce` keeps a staging buffer inside a device's DMA window and
copies across the boundary (`load`/`store`).  It uses
`DmaBuffer::alloc_constrained` (or `alloc_constrained_in` for a domain), so
the staging memory is pinned and IOMMU-mapped like any other DMA buffer.

## 10. Validation

* `cargo check -p strat9-kernel --target x86_64-unknown-none`
* `cargo test -p strat9-abi`
* `cargo check -p strate-iommu --target x86_64-unknown-none`

The kernel unit tests cover DMAR parsing, overlap/alignment, superpage
selection, quiesce, reserved regions and fault policies. They run in the
kernel test configuration (the crate has no host `lib` target).
