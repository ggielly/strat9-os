# Strat9-OS — Design Document: Memory Manager v1.0

**Statut** : Document de référence pour refonte complète
**Date** : 2026-03-25 (rev. 2)
**Audience** : Développeur humain + LLM implémenteur

---

## Errata v1 → v2

| # | Critique v1 | Correction v2 |
|---|---|---|
| C1 | État partagé dupliqué dans `PhysBlock` (refcount, cap_ids) — pas de source unique | L'état mutable vit dans `OwnershipTable` (table centrale). `PhysBlock<S>` est un handle léger sans état partagé. |
| C2 | Pas de reverse mapping capability → mappings — revoke non implémentable | Ajout de `MappingIndex`: `CapId → Vec<(Pid, VirtAddr, PageSize)>` dans le VM manager. |
| C3 | `cap_id` pré-réservé puis ré-assigné dans `create_mem_cap` — divergence | `CapabilityTable` est le seul créateur de `CapId`. Un seul appel, un seul ID. |
| C4 | Buddy stampe `Exclusive` mais retourne `PhysBlock<Free>` — incohérence metadata/typestate | Nouvel état metadata `BuddyReserved`. Le buddy stampe `BuddyReserved`, pas `Exclusive`. `claim()` fait la transition `BuddyReserved → Exclusive`. |
| C5 | `*_by_phys()` bypass le typestate dans COW/fork | Plus de `*_by_phys()`. Le VM retourne `BlockHandle` (base+order), le COW et le fork opèrent via `BlockHandle` + `OwnershipTable`. |

**Choix architecturaux explicites (issues des questions ouvertes) :**

- **La capability EST l'identité canonique du bloc.** Pas d'`owner_cap` dans la metadata physique. La metadata ne contient que l'état physique. Le lien cap→bloc vit dans `CapabilityTable`, le lien bloc→caps vit dans `OwnershipTable`.
- **Typestate = vérification locale de fonction.** Le stockage persistant utilise un enum runtime (`BlockState`) dans `OwnershipTable`. Le typestate garantit qu'une séquence de transitions dans un chemin de code est correcte. La table centrale garantit la cohérence globale.

---

## Table des matières

1. [Principes directeurs](#1-principes-directeurs)
2. [Vue d'ensemble de l'architecture](#2-vue-densemble-de-larchitecture)
3. [Types fondamentaux — Typestate local](#3-types-fondamentaux--typestate-local)
4. [Tables centrales — Source de vérité runtime](#4-tables-centrales--source-de-vérité-runtime)
5. [Metadata physique (BlockMeta)](#5-metadata-physique-blockmeta)
6. [Buddy Allocator](#6-buddy-allocator)
7. [Couche de propriété (Ownership Layer)](#7-couche-de-propriété-ownership-layer)
8. [Capabilities mémoire (seL4-style)](#8-capabilities-mémoire-sel4-style)
9. [VM Manager — Address Space](#9-vm-manager--address-space)
10. [COW (Copy-on-Write)](#10-cow-copy-on-write)
11. [Huge Pages (2 MiB)](#11-huge-pages-2-mib)
12. [Cache local per-CPU](#12-cache-local-per-cpu)
13. [Fork](#13-fork)
14. [Invariants formels](#14-invariants-formels)
15. [Plan de migration](#15-plan-de-migration)
16. [TODO v2.0](#16-todo-v20)

---

## 1. Principes directeurs

### 1.1 Séparation stricte des responsabilités

| Responsabilité | Autorité unique | N'a PAS le droit de |
|---|---|---|
| Libre / alloué | Buddy allocator | Connaître les mappings ou les capabilities |
| Exclusif / partagé / refcount | OwnershipTable | Modifier les page tables ou libérer au buddy |
| Mappé / non mappé | VM manager | Libérer une frame ou modifier le refcount |
| Droits d'accès + identité | CapabilityTable | Allouer de la mémoire ou toucher les PTEs |

Aucune couche ne peut court-circuiter une autre. Toute transition passe par l'API publique de la couche responsable.

### 1.2 Un bloc, pas une frame

L'unité fondamentale est le **bloc physique** identifié par `(base: PhysAddr, order: u8)`.
Un bloc order-9 (2 MiB) n'est jamais traité comme 512 blocs order-0.
Ce couple `(base, order)` est appelé `BlockHandle` — un identifiant léger, copiable, sans état mutable.

### 1.3 Typestate = outil de vérification locale

Le typestate `PhysBlock<S>` garantit qu'une **séquence de transitions dans un chemin de code** est correcte à la compilation. Il ne sert PAS de base de données globale.

L'état global d'un bloc vit dans deux tables centrales :
- `OwnershipTable` : état de propriété + refcount
- `MappingIndex` : reverse mapping cap → address spaces

Les types `PhysBlock<Free>`, `PhysBlock<Exclusive>`, etc. sont des **handles éphémères** créés pour une séquence d'opérations, puis détruits. Ils ne sont jamais stockés de façon persistante dans des tables par tâche.

### 1.4 Capability = identité canonique

La capability est le **seul identifiant** exposé au-dessus du buddy. Un `CapId` est nécessaire pour toute opération (map, unmap, share, free). Il n'y a pas de "block ID" séparé — le `CapId` est l'identité du bloc du point de vue de son propriétaire.

Le lien `CapId → (base, order)` est dans `CapabilityTable`.
Le lien `(base, order) → {CapId...}` est dans `OwnershipTable`.

### 1.5 Simplicité avant optimisation

- COW uniquement sur 4K en v1.0
- Huge pages : eager copy à fork, pas de COW
- Un seul cache local per-CPU, order-0 uniquement
- Pas de partial unmap de huge pages en v1.0

---

## 2. Vue d'ensemble de l'architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Userspace                             │
│  syscall: mem_alloc, mem_map, mem_share, mem_grant, mem_free │
└───────────────────────────┬──────────────────────────────────┘
                            │ CapId
┌───────────────────────────▼──────────────────────────────────┐
│                   CapabilityTable                            │
│  CapId → MemCap { base, order, perms, owner_pid, parent }   │
│  CDT (arbre de dérivation pour révocation)                   │
│  Autorité : identité + droits d'accès                       │
└────────┬────────────────────────────────┬────────────────────┘
         │                                │
┌────────▼──────────────┐   ┌─────────────▼────────────────────┐
│   OwnershipTable      │   │      VM Manager                  │
│                       │   │                                  │
│ (base,order) →        │   │ AddressSpace {                   │
│   OwnerEntry {        │   │   page_table: CR3,               │
│     state: BlockState,│   │   regions: BTreeMap<VMA>,        │
│     refcount: u32,    │   │ }                                │
│     caps: SmallVec    │   │                                  │
│   }                   │   │ MappingIndex (reverse map):      │
│                       │   │   CapId → Vec<MappingRef>        │
│ Autorité :            │   │                                  │
│ exclusif/partagé      │   │ Autorité :                       │
│ + refcount            │   │ mappé/non-mappé + reverse map    │
└────────┬──────────────┘   └──────────────┬───────────────────┘
         │                                 │
┌────────▼─────────────────────────────────▼───────────────────┐
│                    Buddy Allocator                            │
│  Zones: DMA | Normal | HighMem                               │
│  Free lists: order 0..11                                     │
│  Per-CPU cache: order-0 only                                 │
│  Autorité : libre/alloué                                     │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│                Physical Memory + BlockMeta array             │
└──────────────────────────────────────────────────────────────┘
```

### Flux d'allocation complet

```
1. Userspace: sys_mem_alloc(size=4096, perms=RW)
2. CapabilityTable: vérifier quota + créer MemCap → CapId
   (base/order pas encore connus, MemCap en état Pending)
3. Buddy: alloc_block(order=0) → BlockHandle
   (metadata stampée BuddyReserved)
4. OwnershipTable: claim(handle, cap_id) → PhysBlock<Exclusive>
   (CAS refcount UNUSED→1, state→Exclusive, enregistre cap_id)
5. CapabilityTable: finalize(cap_id, handle)
   (MemCap passe de Pending à Active avec base+order)
6. Zéroter le bloc (sécurité)
7. Retour: CapId au userspace
```

### Flux de libération complet

```
1. Userspace: sys_mem_free(cap_id)
2. CapabilityTable: lookup cap → MemCap { base, order, ... }
3. MappingIndex: lookup cap_id → tous les mappings actifs
4. VM: unmap tous les mappings → liste de BlockHandle
5. OwnershipTable: release(handle) → dec refcount
   Si refcount→0: state→Free, retourne PhysBlock<Free>
6. Buddy: free_block(free_block)
7. CapabilityTable: supprimer MemCap + CDT cleanup
```

---

## 3. Types fondamentaux — Typestate local

### 3.1 BlockHandle — identifiant copiable

```rust
/// Identifiant léger d'un bloc physique. Copiable, sans état mutable.
/// C'est un "nom" pour un bloc, pas une possession.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockHandle {
    pub base: PhysAddr,
    pub order: u8,
}

impl BlockHandle {
    pub fn size_bytes(&self) -> u64 {
        PAGE_SIZE << self.order
    }

    pub fn page_count(&self) -> u64 {
        1u64 << self.order
    }

    /// Vérifie l'alignement de base par rapport à l'order.
    pub fn is_valid(&self) -> bool {
        self.base.is_aligned(self.size_bytes())
            && self.order <= MAX_ORDER as u8
    }
}
```

### 3.2 États typestate (tous ZST ou presque)

```rust
/// Bloc sorti du buddy, pas encore possédé par l'ownership layer.
/// Metadata physique = BuddyReserved.
pub struct BuddyReserved;

/// Bloc possédé exclusivement. refcount == 1 dans OwnershipTable.
pub struct Exclusive;

/// Bloc possédé et mappé dans au moins un address space.
/// Le propriétaire est toujours exclusif (refcount == 1).
pub struct MappedExclusive;

/// Bloc partagé et mappé dans au moins deux address spaces.
/// refcount >= 2 dans OwnershipTable.
pub struct MappedShared;

/// Bloc libéré, prêt à être rendu au buddy.
pub struct Released;
```

**Point clé** : aucun état ne porte de `CapId`, `refcount`, ou `SmallVec`. Toute cette information vit dans les tables centrales.

### 3.3 PhysBlock — handle éphémère typé

```rust
/// Handle éphémère typé par état. Consommé par les transitions.
/// NE DOIT JAMAIS être stocké dans une table persistante.
///
/// Invariants:
/// - `handle.base` est aligné sur `PAGE_SIZE << handle.order`
/// - Les transitions consomment `self` (move semantics)
/// - L'état réel du bloc est dans OwnershipTable, pas ici
pub struct PhysBlock<S> {
    handle: BlockHandle,
    _state: PhantomData<S>,
}

impl<S> PhysBlock<S> {
    /// Accès au BlockHandle sous-jacent.
    pub fn handle(&self) -> BlockHandle {
        self.handle
    }

    pub fn base(&self) -> PhysAddr {
        self.handle.base
    }

    pub fn order(&self) -> u8 {
        self.handle.order
    }
}
```

### 3.4 Transitions (compile-time enforced, effets dans les tables)

```rust
// ── BuddyReserved → Exclusive ─────────────────────────────────
// Appelé par OwnershipTable::claim()
impl PhysBlock<BuddyReserved> {
    /// Transition interne. L'OwnershipTable a déjà fait le CAS refcount
    /// et enregistré le cap_id.
    pub(crate) fn into_exclusive(self) -> PhysBlock<Exclusive> {
        PhysBlock {
            handle: self.handle,
            _state: PhantomData,
        }
    }
}

// ── Exclusive → MappedExclusive ───────────────────────────────
// Appelé après que le VM manager a installé le mapping
impl PhysBlock<Exclusive> {
    pub(crate) fn into_mapped(self) -> PhysBlock<MappedExclusive> {
        PhysBlock {
            handle: self.handle,
            _state: PhantomData,
        }
    }

    /// Libération directe sans avoir mappé.
    pub(crate) fn into_released(self) -> PhysBlock<Released> {
        PhysBlock {
            handle: self.handle,
            _state: PhantomData,
        }
    }
}

// ── MappedExclusive → MappedShared ────────────────────────────
// Appelé par OwnershipTable quand un deuxième cap est ajouté
impl PhysBlock<MappedExclusive> {
    pub(crate) fn into_shared(self) -> PhysBlock<MappedShared> {
        PhysBlock {
            handle: self.handle,
            _state: PhantomData,
        }
    }

    /// Unmap complet (plus aucun mapping) → retour en Exclusive.
    pub(crate) fn into_unmapped(self) -> PhysBlock<Exclusive> {
        PhysBlock {
            handle: self.handle,
            _state: PhantomData,
        }
    }
}

// ── MappedShared → MappedExclusive ou MappedShared ────────────
// Retour en exclusif quand refcount retombe à 1
impl PhysBlock<MappedShared> {
    pub(crate) fn into_exclusive_mapped(self) -> PhysBlock<MappedExclusive> {
        PhysBlock {
            handle: self.handle,
            _state: PhantomData,
        }
    }

    // Reste partagé (même type, consommé et re-créé pour forcer
    // le passage par OwnershipTable)
    pub(crate) fn still_shared(self) -> PhysBlock<MappedShared> {
        self
    }
}

// ── Released → prêt pour buddy ────────────────────────────────
impl PhysBlock<Released> {
    /// Consommé par BuddyAllocator::free_block().
    pub(crate) fn into_free(self) -> BlockHandle {
        self.handle
    }
}
```

### 3.5 Diagramme de transitions

```
                  buddy.alloc_block()
                        │
                        ▼
                ┌───────────────┐
                │ BuddyReserved │  metadata: BuddyReserved
                └───────┬───────┘
                        │ ownership.claim(cap_id)
                        ▼
                ┌───────────────┐
           ┌────│   Exclusive   │  table: refcount=1, caps=[cap]
           │    └───────┬───────┘
           │            │ vm.map() + into_mapped()
           │            ▼
           │    ┌──────────────────┐
           │    │ MappedExclusive  │  table: refcount=1, mapped
           │    └──┬───────────┬──┘
           │       │           │ ownership.share(new_cap)
           │       │           ▼
           │       │    ┌──────────────┐
           │       │    │ MappedShared │  table: refcount≥2, caps=[..]
           │       │    └──────┬───────┘
           │       │           │ ownership.remove_ref(cap)
           │       │           │ si refcount→1: into_exclusive_mapped()
           │       │           │
           │       │ vm.unmap()│ vm.unmap()
           │       ▼           ▼
           │    into_unmapped() → Exclusive
           │            │
           │ release()  │ release()
           ▼            ▼
        ┌──────────┐
        │ Released  │  table: refcount=0, state=Free
        └────┬─────┘
             │ buddy.free_block()
             ▼
          (recyclé)
```

---

## 4. Tables centrales — Source de vérité runtime

### 4.1 OwnershipTable

**La source de vérité unique pour l'état de propriété de chaque bloc alloué.**

```rust
/// État d'un bloc dans la table de propriété.
#[derive(Debug)]
pub struct OwnerEntry {
    /// État courant (doit être cohérent avec BlockMeta.block_state).
    pub state: BlockState,

    /// Nombre de références (caps pointant vers ce bloc).
    pub refcount: u32,

    /// Ensemble des CapIds qui référencent ce bloc.
    /// C'est LA source de vérité pour "qui possède quoi".
    pub caps: SmallVec<[CapId; 4]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockState {
    /// Sorti du buddy, pas encore possédé.
    BuddyReserved = 0,
    /// Possédé exclusivement (refcount == 1).
    Exclusive = 1,
    /// Partagé (refcount >= 2).
    Shared = 2,
    /// Libéré, en attente de retour au buddy.
    Free = 3,
}

/// Table globale de propriété.
/// Clé: (base, order) — identifiant physique unique du bloc.
pub struct OwnershipTable {
    /// Protégé par SpinLock. Granularité fine possible en v2.
    entries: SpinLock<BTreeMap<PhysAddr, OwnerEntry>>,
}
```

### 4.2 MappingIndex (reverse map)

**Permet la révocation : `CapId → tous les mappings actifs`.**

```rust
/// Référence à un mapping dans un address space.
#[derive(Debug, Clone)]
pub struct MappingRef {
    pub pid: Pid,
    pub vaddr: VirtAddr,
    pub page_size: PageSize,
}

/// Index inverse: capability → mappings actifs.
/// Vit dans le VM manager (il est l'autorité sur les mappings).
pub struct MappingIndex {
    index: SpinLock<BTreeMap<CapId, SmallVec<[MappingRef; 2]>>>,
}

impl MappingIndex {
    /// Enregistre un nouveau mapping pour une capability.
    pub fn register(&self, cap_id: CapId, mapping: MappingRef);

    /// Retire un mapping spécifique.
    pub fn unregister(&self, cap_id: CapId, pid: Pid, vaddr: VirtAddr);

    /// Retourne tous les mappings pour une capability (pour revoke).
    pub fn lookup(&self, cap_id: CapId) -> SmallVec<[MappingRef; 2]>;

    /// Retire tous les mappings d'une capability (après revoke).
    pub fn remove_all(&self, cap_id: CapId) -> SmallVec<[MappingRef; 2]>;
}
```

### 4.3 Pourquoi pas stocker l'état dans PhysBlock ?

| Approche v1 (état dans PhysBlock) | Approche v2 (état dans tables) |
|---|---|
| Chaque copie du bloc a sa propre vue | Une seule source de vérité |
| `SpinLock<SmallVec>` dupliqué | Un seul `SmallVec` dans la table |
| Pas de reverse mapping possible | `MappingIndex` rend revoke O(caps) |
| Typestate perd sa valeur (runtime déguisé) | Typestate = vérification locale pure |
| Divergence inévitable entre copies | Impossible par construction |

---

## 5. Metadata physique (BlockMeta)

### 5.1 Rôle limité

La metadata physique (dans l'array indexé par PFN) ne contient que ce dont le buddy et les fast-path atomiques ont besoin. **Ce n'est PAS la source de vérité pour l'ownership** — c'est un cache atomique cohérent avec l'OwnershipTable.

### 5.2 Layout — 32 octets par frame

```rust
/// Metadata pour la frame de tête d'un bloc.
#[repr(C, align(32))]
pub struct BlockMeta {
    /// Pointeurs intrusive list pour le buddy (quand Free).
    /// Réutilisés comme padding quand alloué (à la Redox).
    pub(crate) list_next: AtomicU64,        // 8B
    pub(crate) list_prev: AtomicU64,        // 8B

    /// Compteur de références (cache atomique, miroir de OwnershipTable).
    /// REFCOUNT_UNUSED quand libre. Fast-path pour COW fault.
    pub(crate) refcount: AtomicU32,         // 4B

    /// État du bloc (cache atomique de BlockState).
    pub(crate) block_state: AtomicU8,       // 1B

    /// Order du bloc (0..11). Immutable après allocation.
    pub(crate) order: AtomicU8,             // 1B

    /// Flags compacts (DLL, KERNEL, USER, ANONYMOUS).
    /// PAS de flag COW ici — le COW vit dans les PTEs.
    pub(crate) flags: AtomicU16,            // 2B

    pub(crate) _pad: [u8; 8],              // 8B → total 32B
}
```

**Changements vs v1 :**
- **Suppression de `owner_cap`** : le lien cap→bloc est dans `CapabilityTable`, le lien bloc→caps est dans `OwnershipTable`. Pas de duplication.
- **`refcount` est un cache** : lu en fast-path (COW fault), mais la source de vérité est `OwnershipTable.refcount`. Les deux sont mis à jour atomiquement par `OwnershipTable` lors de chaque transition.
- **`block_state` est un cache** : même principe. Permet au buddy de vérifier l'état sans prendre le lock de l'OwnershipTable.

### 5.3 SubFrameMeta (inchangé)

```rust
/// Metadata pour une sub-frame (frame non-tête dans un bloc multi-page).
/// Pointe vers la tête pour remonter au BlockMeta en O(1).
#[repr(C, align(8))]
pub struct SubFrameMeta {
    pub(crate) head_pfn: AtomicU32,         // 4B (suffisant pour 16 TiB)
    pub(crate) sentinel: u16,               // 2B = SUB_FRAME_SENTINEL
    pub(crate) _pad: [u8; 2],              // 2B → total 8B
}

const SUB_FRAME_SENTINEL: u16 = 0xFFFF;
```

### 5.4 Array uniforme

```rust
/// Slot uniforme 32B par frame. Le sentinel distingue tête/sub.
#[repr(C, align(32))]
pub union FrameMetaSlot {
    pub head: ManuallyDrop<BlockMeta>,      // 32B si tête
    pub sub: SubFrameMeta,                  // 8B si sub-frame
    pub raw: [u8; 32],                      // accès brut
}

// Budget: 32B * (RAM / 4096) = 8 MiB par GiB de RAM
// Pour 16 GiB: 128 MiB de metadata (vs 256 MiB avant)
```

### 5.5 Cohérence metadata ↔ OwnershipTable

L'OwnershipTable est la source de vérité. La metadata est un cache.
La cohérence est maintenue par une règle simple :

> **Toute écriture dans `OwnerEntry` écrit aussi les champs atomiques correspondants de `BlockMeta`.**

```rust
impl OwnershipTable {
    /// Helper interne: synchronise le cache metadata après mutation.
    fn sync_meta(handle: BlockHandle, entry: &OwnerEntry) {
        let meta = get_block_meta(handle.base);
        meta.block_state.store(entry.state as u8, Ordering::Release);
        meta.refcount.store(entry.refcount, Ordering::Release);
    }
}
```

En debug builds, un audit périodique vérifie la cohérence.

### 5.6 Accès à la metadata

```rust
/// Récupère la metadata de tête pour un bloc, en remontant si sub-frame.
pub fn get_block_meta(phys: PhysAddr) -> &'static BlockMeta {
    let slot = get_slot(phys);
    if slot.is_sub_frame() {
        let head_pfn = slot.as_sub().head_pfn.load(Ordering::Acquire);
        get_slot(PhysAddr::new(head_pfn as u64 * PAGE_SIZE)).as_head()
    } else {
        slot.as_head()
    }
}

fn get_slot(phys: PhysAddr) -> &'static FrameMetaSlot {
    let pfn = phys.as_u64() / PAGE_SIZE;
    unsafe { &*((META_BASE + pfn as usize * 32) as *const FrameMetaSlot) }
}

/// À partir d'une PhysAddr quelconque dans un bloc, retrouve le BlockHandle.
pub fn resolve_handle(phys: PhysAddr) -> BlockHandle {
    let meta = get_block_meta(phys);
    let order = meta.order.load(Ordering::Acquire);
    // Remonter à la base : si sub-frame, utiliser head_pfn.
    // Si tête, phys est déjà la base.
    let slot = get_slot(phys);
    let base = if slot.is_sub_frame() {
        PhysAddr::new(slot.as_sub().head_pfn.load(Ordering::Acquire) as u64 * PAGE_SIZE)
    } else {
        phys
    };
    BlockHandle { base, order }
}
```

---

## 6. Buddy Allocator

### 6.1 Responsabilité

Le buddy est **l'autorité unique** sur l'état libre/alloué. Il ne connaît ni les mappings, ni le COW, ni les capabilities, ni l'OwnershipTable.

### 6.2 API publique

```rust
impl BuddyAllocator {
    /// Alloue un bloc de 2^order pages.
    /// Retourne un PhysBlock<BuddyReserved>.
    /// La metadata est stampée BuddyReserved (PAS Exclusive).
    /// L'appelant DOIT passer par OwnershipTable::claim().
    pub fn alloc_block(
        &self,
        order: u8,
        zone: ZoneType,
    ) -> Result<PhysBlock<BuddyReserved>, AllocError> {
        let base = self.alloc_inner(order, zone)?;

        // Stamper metadata: BuddyReserved
        let head = get_block_meta(base);
        head.order.store(order, Ordering::Release);
        head.block_state.store(BlockState::BuddyReserved as u8, Ordering::Release);
        head.refcount.store(REFCOUNT_UNUSED, Ordering::Release);
        head.flags.store(0, Ordering::Release);

        // Stamper sub-frames
        let head_pfn = (base.as_u64() / PAGE_SIZE) as u32;
        for i in 1..(1u64 << order) {
            let sub = get_slot(base + i * PAGE_SIZE).as_sub_mut();
            sub.head_pfn.store(head_pfn, Ordering::Release);
            sub.sentinel = SUB_FRAME_SENTINEL;
        }

        Ok(PhysBlock {
            handle: BlockHandle { base, order },
            _state: PhantomData,
        })
    }

    /// Libère un bloc. Le bloc DOIT être Released (typestate le garantit).
    pub fn free_block(&self, block: PhysBlock<Released>) {
        let handle = block.into_free();
        let meta = get_block_meta(handle.base);

        debug_assert_eq!(
            meta.block_state.load(Ordering::Acquire),
            BlockState::Free as u8,
            "freeing block not in Free state"
        );
        debug_assert_eq!(
            meta.refcount.load(Ordering::Acquire),
            REFCOUNT_UNUSED,
            "freeing block with live refcount"
        );

        self.free_inner(handle.base, handle.order);
    }

    /// Cache local (order-0 uniquement).
    pub fn alloc_cached(&self, cpu: CpuId) -> Result<PhysBlock<BuddyReserved>, AllocError>;
    pub fn free_cached(&self, block: PhysBlock<Released>, cpu: CpuId);
}
```

### 6.3 Ce qui change vs l'ancien code

| Aspect | Ancien | Nouveau |
|---|---|---|
| Type retourné | `PhysAddr` | `PhysBlock<BuddyReserved>` |
| Type accepté en free | `PhysAddr` | `PhysBlock<Released>` |
| Metadata stampée | `Exclusive` (incohérent) | `BuddyReserved` (cohérent) |
| Refcount init | CAS dans alloc | CAS dans `OwnershipTable::claim()` |
| Sub-frame stamping | Non fait | Fait dans `alloc_block()` |

### 6.4 Invariants du buddy

> **INV-BUDDY-1** : Un bloc dans une free-list a `block_state == Free`, `refcount == REFCOUNT_UNUSED`, et n'existe pas dans l'`OwnershipTable`.
>
> **INV-BUDDY-2** : Le buddy ne modifie jamais `refcount` après le stamp initial à `REFCOUNT_UNUSED`. Il ne lit que `order` et les list pointers.
>
> **INV-BUDDY-3** : `free_block()` n'accepte qu'un `PhysBlock<Released>`. Le typestate garantit que la séquence `MappedShared/MappedExclusive → Exclusive → Released` a été complétée.
>
> **INV-BUDDY-4** : Entre `alloc_block()` et `OwnershipTable::claim()`, le bloc est `BuddyReserved`. Ce n'est ni `Free` (plus dans la free-list) ni `Exclusive` (pas encore possédé).

---

## 7. Couche de propriété (Ownership Layer)

### 7.1 Responsabilité

Autorité unique sur la distinction **exclusif vs partagé**. Gère le refcount et la liste des caps par bloc. Synchronise le cache metadata.

### 7.2 API publique

```rust
impl OwnershipTable {
    /// Prend possession d'un bloc sorti du buddy.
    /// CAS refcount UNUSED→1. Enregistre le cap_id.
    pub fn claim(
        &self,
        block: PhysBlock<BuddyReserved>,
        cap_id: CapId,
    ) -> Result<PhysBlock<Exclusive>, OwnerError> {
        let handle = block.handle();
        let meta = get_block_meta(handle.base);

        // CAS atomique: UNUSED → 1
        meta.refcount.compare_exchange(
            REFCOUNT_UNUSED, 1,
            Ordering::AcqRel, Ordering::Acquire,
        ).map_err(|_| OwnerError::DoubleClaim)?;

        // Enregistrer dans la table
        let entry = OwnerEntry {
            state: BlockState::Exclusive,
            refcount: 1,
            caps: smallvec![cap_id],
        };
        self.entries.lock().insert(handle.base, entry);

        // Sync cache metadata
        meta.block_state.store(BlockState::Exclusive as u8, Ordering::Release);

        Ok(block.into_exclusive())
    }

    /// Ajoute un co-propriétaire (pour COW/fork).
    /// Incrémente le refcount. Transite en Shared si nécessaire.
    pub fn add_ref(
        &self,
        handle: BlockHandle,
        new_cap: CapId,
    ) -> Result<(), OwnerError> {
        let mut entries = self.entries.lock();
        let entry = entries.get_mut(&handle.base)
            .ok_or(OwnerError::NotFound)?;

        entry.refcount += 1;
        entry.caps.push(new_cap);

        if entry.refcount >= 2 {
            entry.state = BlockState::Shared;
        }

        // Sync cache metadata
        Self::sync_meta(handle, entry);

        Ok(())
    }

    /// Retire un co-propriétaire.
    /// Retourne le nouveau refcount.
    /// Si refcount atteint 0, prépare la libération.
    pub fn remove_ref(
        &self,
        handle: BlockHandle,
        cap_id: CapId,
    ) -> Result<RemoveRefResult, OwnerError> {
        let mut entries = self.entries.lock();
        let entry = entries.get_mut(&handle.base)
            .ok_or(OwnerError::NotFound)?;

        entry.caps.retain(|c| *c != cap_id);
        entry.refcount -= 1;

        let result = match entry.refcount {
            0 => {
                // Plus aucun propriétaire → préparer la libération
                entry.state = BlockState::Free;
                Self::sync_meta(handle, entry);

                // Retirer de la table
                entries.remove(&handle.base);

                // Stamper metadata pour le buddy
                let meta = get_block_meta(handle.base);
                meta.refcount.store(REFCOUNT_UNUSED, Ordering::Release);

                RemoveRefResult::Freed
            }
            1 => {
                // Retour en exclusif
                entry.state = BlockState::Exclusive;
                Self::sync_meta(handle, entry);
                RemoveRefResult::NowExclusive {
                    remaining_cap: entry.caps[0],
                }
            }
            _ => {
                // Toujours partagé
                Self::sync_meta(handle, entry);
                RemoveRefResult::StillShared {
                    refcount: entry.refcount,
                }
            }
        };

        Ok(result)
    }

    /// Libère un bloc exclusif (refcount 1→0).
    /// Le bloc ne doit plus être mappé.
    pub fn release(
        &self,
        block: PhysBlock<Exclusive>,
        cap_id: CapId,
    ) -> Result<PhysBlock<Released>, OwnerError> {
        let handle = block.handle();
        let result = self.remove_ref(handle, cap_id)?;

        match result {
            RemoveRefResult::Freed => Ok(PhysBlock {
                handle,
                _state: PhantomData,
            }),
            _ => Err(OwnerError::StillReferenced),
        }
    }

    /// Lecture du refcount (fast-path pour COW fault).
    /// Lit le cache atomique dans BlockMeta — pas de lock.
    pub fn refcount_fast(handle: BlockHandle) -> u32 {
        get_block_meta(handle.base).refcount.load(Ordering::Acquire)
    }
}

pub enum RemoveRefResult {
    /// Plus aucun propriétaire. Le bloc peut être rendu au buddy.
    Freed,
    /// Un seul propriétaire restant.
    NowExclusive { remaining_cap: CapId },
    /// Encore partagé.
    StillShared { refcount: u32 },
}
```

### 7.3 Invariants

> **INV-OWN-1** : `OwnerEntry.refcount == entry.caps.len()` à tout instant (sous le lock).
>
> **INV-OWN-2** : `refcount == 1` ⟹ `state == Exclusive`.
>
> **INV-OWN-3** : `refcount >= 2` ⟹ `state == Shared`.
>
> **INV-OWN-4** : Un bloc dans `OwnershipTable` n'est jamais dans une buddy free-list.
>
> **INV-OWN-5** : `BlockMeta.refcount` et `BlockMeta.block_state` sont toujours synchronisés avec `OwnerEntry` via `sync_meta()`.
>
> **INV-OWN-6** : Aucun autre module ne modifie `BlockMeta.refcount` ou `BlockMeta.block_state` sauf le buddy (qui stampe `BuddyReserved` / `Free`).

---

## 8. Capabilities mémoire (seL4-style)

### 8.1 MemCap — la capability EST l'identité

```rust
/// Capability mémoire. Jeton infalsifiable.
/// Le CapId est l'identité du bloc pour son propriétaire.
pub struct MemCap {
    pub id: CapId,

    /// État de la capability.
    pub cap_state: MemCapState,

    /// Permissions.
    pub perms: MemPerms,

    /// PID du propriétaire.
    pub owner: Pid,

    /// Parent dans le CDT (pour révocation hiérarchique).
    pub parent: Option<CapId>,

    /// Enfants dans le CDT.
    pub children: SmallVec<[CapId; 2]>,
}

pub enum MemCapState {
    /// Cap créée, bloc pas encore alloué (bref état transitoire).
    Pending,
    /// Cap active, bloc alloué.
    Active {
        block_base: PhysAddr,
        block_order: u8,
    },
}

bitflags! {
    pub struct MemPerms: u8 {
        const READ    = 0b0001;
        const WRITE   = 0b0010;
        const EXECUTE = 0b0100;
        const GRANT   = 0b1000;
    }
}
```

### 8.2 Flux d'allocation — un seul CapId, jamais de divergence

```rust
pub fn sys_mem_alloc(
    task: &Task,
    size: usize,
    perms: MemPerms,
) -> Result<CapId, SyscallError> {
    let order = size_to_order(size)?;

    // 1. Créer la capability (Pending). C'est ICI que le CapId naît.
    let cap_id = task.cap_table.lock().create_pending_mem_cap(perms, task.pid)?;

    // 2. Buddy: obtenir un bloc réservé
    let reserved_block = BUDDY.alloc_block(order, ZoneType::Normal)
        .map_err(|e| {
            // Cleanup: supprimer la cap Pending
            task.cap_table.lock().delete_mem_cap(cap_id).ok();
            SyscallError::OutOfMemory
        })?;

    // 3. Ownership: claim avec le CapId déjà créé
    let owned_block = OWNERSHIP.claim(reserved_block, cap_id)
        .map_err(|e| {
            // Cleanup impossible simplement — panic en debug, log en release
            panic!("claim failed after buddy alloc: {:?}", e);
        })?;

    // 4. Finaliser la capability avec les coordonnées physiques
    task.cap_table.lock().finalize_mem_cap(
        cap_id,
        owned_block.handle(),
    )?;

    // 5. Zéroter le bloc (sécurité: pas de fuite d'info)
    zero_block(owned_block.handle());

    // Note: owned_block est droppé ici. L'état vit dans
    // OwnershipTable et CapabilityTable, pas dans le PhysBlock.

    Ok(cap_id)
}
```

### 8.3 CapabilityTable — API

```rust
impl CapabilityTable {
    /// Crée une capability en état Pending. Retourne le CapId unique.
    pub fn create_pending_mem_cap(
        &mut self,
        perms: MemPerms,
        owner: Pid,
    ) -> Result<CapId, CapError>;

    /// Finalise une capability Pending → Active avec les coordonnées du bloc.
    pub fn finalize_mem_cap(
        &mut self,
        cap_id: CapId,
        handle: BlockHandle,
    ) -> Result<(), CapError>;

    /// Lookup + vérification de permissions.
    pub fn check_mem_cap(
        &self,
        cap_id: CapId,
        required: MemPerms,
    ) -> Result<&MemCap, CapError>;

    /// Lookup → BlockHandle pour un cap active.
    pub fn resolve_block(&self, cap_id: CapId) -> Result<BlockHandle, CapError>;

    /// Dérive une capability enfant (sous-permissions).
    /// Le parent doit avoir GRANT. L'enfant est ajouté au CDT.
    pub fn derive_mem_cap(
        &mut self,
        parent_cap: CapId,
        new_perms: MemPerms,
        new_owner: Pid,
    ) -> Result<CapId, CapError>;

    /// Révoque une capability et tous ses descendants (CDT walk).
    /// Retourne la liste des CapIds révoqués pour cleanup.
    pub fn revoke_mem_cap(
        &mut self,
        cap_id: CapId,
    ) -> Result<Vec<CapId>, CapError>;

    /// Supprime une seule capability leaf (sans enfants).
    pub fn delete_mem_cap(&mut self, cap_id: CapId) -> Result<(), CapError>;
}
```

### 8.4 Révocation — le flux complet

La révocation est le chemin critique. Grâce au `MappingIndex`, elle est O(caps × mappings/cap) :

```rust
pub fn revoke_capability(
    task: &Task,
    cap_id: CapId,
    cap_table: &mut CapabilityTable,
    mapping_index: &MappingIndex,
    ownership: &OwnershipTable,
    buddy: &BuddyAllocator,
) -> Result<(), RevokeError> {
    // 1. CDT walk: collecter tous les descendants (post-order)
    let revoked_caps = cap_table.revoke_mem_cap(cap_id)?;

    for revoked_cap in &revoked_caps {
        let handle = match cap_table.resolve_block(*revoked_cap) {
            Ok(h) => h,
            Err(_) => continue,  // Pending cap, nothing to clean
        };

        // 2. Unmap via reverse index — PAS de scan global
        let mappings = mapping_index.remove_all(*revoked_cap);
        for mref in &mappings {
            // Trouver l'address space du processus cible
            if let Some(target_as) = get_address_space(mref.pid) {
                match mref.page_size {
                    PageSize::Small => target_as.unmap_page(mref.vaddr).ok(),
                    PageSize::Huge => target_as.unmap_huge_page(mref.vaddr).ok(),
                };
            }
        }

        // 3. Décrémenter refcount dans l'ownership table
        match ownership.remove_ref(handle, *revoked_cap)? {
            RemoveRefResult::Freed => {
                // Dernier propriétaire → rendre au buddy
                let released = PhysBlock::<Exclusive> {
                    handle,
                    _state: PhantomData,
                }.into_released();
                buddy.free_block(released);
            }
            _ => {
                // D'autres caps référencent encore ce bloc
            }
        }
    }

    // 4. TLB shootdown global
    tlb::shootdown_all();

    Ok(())
}
```

### 8.5 Invariants

> **INV-CAP-1** : Le `CapId` naît dans `create_pending_mem_cap()` et n'est jamais dupliqué.
>
> **INV-CAP-2** : Les permissions d'une capability dérivée sont un sous-ensemble strict des permissions du parent.
>
> **INV-CAP-3** : `revoke(cap)` collecte tous les descendants via le CDT, unmappe via `MappingIndex`, décrémente via `OwnershipTable`, et libère via buddy si refcount→0.
>
> **INV-CAP-4** : `MappingIndex` est mis à jour à chaque map/unmap. Il n'y a jamais d'entrée fantôme.
>
> **INV-CAP-5** : Quand un processus meurt, `revoke_capability` est appelé sur chaque racine cap du processus.

---

## 9. VM Manager — Address Space

### 9.1 Responsabilité

Autorité unique sur les mappings. Maintient le `MappingIndex`. Ne possède pas les frames et ne modifie pas le refcount.

### 9.2 Nouveau VMA

```rust
pub struct VirtualMemoryRegion {
    pub start: VirtAddr,
    pub page_count: usize,
    pub flags: VmaFlags,
    pub vma_type: VmaType,
    pub page_size: PageSize,
    /// Capability associée (chaque VMA est backé par une cap).
    pub cap_id: CapId,
}

pub enum PageSize {
    Small,  // 4 KiB, order-0
    Huge,   // 2 MiB, order-9
}
```

### 9.3 API — plus de PhysAddr bruts

```rust
impl AddressSpace {
    /// Mappe un bloc physique. Enregistre dans MappingIndex.
    /// Le bloc doit être Exclusive (vérifié par typestate dans l'appelant).
    pub fn map_block(
        &self,
        handle: BlockHandle,
        vaddr: VirtAddr,
        flags: PageTableFlags,
        cap_id: CapId,
        mapping_index: &MappingIndex,
    ) -> Result<(), MapError> {
        match page_size_from_order(handle.order) {
            PageSize::Small => self.page_table.map_4kib(handle.base, vaddr, flags)?,
            PageSize::Huge => {
                assert_eq!(handle.order, 9);
                self.page_table.map_2mib(handle.base, vaddr, flags)?;
            }
        }

        // Enregistrer dans le reverse index
        mapping_index.register(cap_id, MappingRef {
            pid: self.pid,
            vaddr,
            page_size: page_size_from_order(handle.order),
        });

        Ok(())
    }

    /// Unmappe une page. Retourne le BlockHandle pour l'appelant.
    /// Met à jour MappingIndex.
    pub fn unmap_page(
        &self,
        vaddr: VirtAddr,
        cap_id: CapId,
        mapping_index: &MappingIndex,
    ) -> Result<BlockHandle, UnmapError> {
        let (phys, _flags) = self.page_table.translate(vaddr)
            .ok_or(UnmapError::NotMapped)?;

        self.page_table.unmap(vaddr)?;
        self.invalidate_tlb(vaddr);

        let handle = resolve_handle(phys);

        mapping_index.unregister(cap_id, self.pid, vaddr);

        Ok(handle)
    }

    /// Unmappe une huge page.
    pub fn unmap_huge_page(
        &self,
        vaddr: VirtAddr,
        cap_id: CapId,
        mapping_index: &MappingIndex,
    ) -> Result<BlockHandle, UnmapError> {
        assert!(vaddr.is_aligned(HUGE_PAGE_SIZE));
        let (phys, _flags) = self.page_table.translate(vaddr)
            .ok_or(UnmapError::NotMapped)?;

        self.page_table.unmap_2mib(vaddr)?;
        self.invalidate_tlb(vaddr);

        let handle = resolve_handle(phys);

        mapping_index.unregister(cap_id, self.pid, vaddr);

        Ok(handle)
    }

    /// Lookup: virtual → BlockHandle (pas PhysAddr brut).
    pub fn translate_to_handle(
        &self,
        vaddr: VirtAddr,
    ) -> Option<(BlockHandle, PageTableFlags)> {
        let (phys, flags) = self.page_table.translate(vaddr)?;
        Some((resolve_handle(phys), flags))
    }

    /// Change les permissions d'un mapping existant.
    pub fn protect_range(
        &self,
        vaddr: VirtAddr,
        page_count: usize,
        new_flags: PageTableFlags,
    ) -> Result<(), ProtectError>;

    /// Marque un PTE comme COW: retire WRITABLE, ajoute BIT_COW.
    pub fn mark_cow(&self, vaddr: VirtAddr) -> Result<(), CowError>;
}
```

### 9.4 Invariants

> **INV-VM-1** : Le VM manager ne libère jamais de frame au buddy et ne modifie jamais le refcount.
>
> **INV-VM-2** : Après tout unmap, TLB invalidation est faite avant retour.
>
> **INV-VM-3** : `MappingIndex` est cohérent avec les PTEs. Chaque `map_block()` fait `register()`, chaque unmap fait `unregister()`.
>
> **INV-VM-4** : Le VM retourne des `BlockHandle` (base+order), jamais des `PhysAddr` bruts hors de son implémentation interne.

---

## 10. COW (Copy-on-Write)

### 10.1 Périmètre v1.0

- **COW uniquement sur blocs order-0 (4 KiB).**
- Les blocs order-9 (huge pages) sont **copiés eagerly** à fork.
- Le flag COW vit exclusivement dans les PTEs (bit 9).

```rust
pub enum HugeForkStrategy {
    /// Copie immédiate du bloc 2M entier. Seule option v1.0.
    EagerCopy,
    /// TODO v2.0: Split en 512×4K puis COW sur chaque 4K.
    SplitThenCow,
}

pub const HUGE_FORK_STRATEGY: HugeForkStrategy = HugeForkStrategy::EagerCopy;
const PTE_BIT_COW: u64 = 1 << 9;
```

### 10.2 Résolution de COW fault — sans bypass

```rust
pub fn resolve_cow_fault(
    address_space: &AddressSpace,
    vaddr: VirtAddr,
    current_cap: CapId,
    ownership: &OwnershipTable,
    buddy: &BuddyAllocator,
    cap_table: &mut CapabilityTable,
    mapping_index: &MappingIndex,
) -> Result<(), FaultError> {
    // 1. Traduire en BlockHandle (pas PhysAddr brut)
    let (old_handle, pte_flags) = address_space.translate_to_handle(vaddr)
        .ok_or(FaultError::NotMapped)?;

    // 2. Vérifier COW
    if pte_flags & PTE_BIT_COW == 0 {
        return Err(FaultError::NotCow);
    }

    // 3. Vérifier order-0 (invariant v1.0)
    assert_eq!(old_handle.order, 0,
        "COW fault on order-{} block at {:?} — invariant violation",
        old_handle.order, vaddr);

    // 4. Lire le refcount via fast-path atomique
    let refcount = OwnershipTable::refcount_fast(old_handle);

    if refcount == 1 {
        // Cas 1: seul propriétaire → juste rendre writable
        address_space.protect_range(
            vaddr, 1,
            (pte_flags | WRITABLE) & !PTE_BIT_COW,
        )?;
    } else {
        // Cas 2: partagé → copier

        // 2a. Créer une nouvelle capability pour le nouveau bloc
        let new_cap = cap_table.create_pending_mem_cap(
            MemPerms::READ | MemPerms::WRITE,
            address_space.pid,
        )?;

        // 2b. Allouer un nouveau bloc order-0
        let new_reserved = buddy.alloc_block(0, ZoneType::Normal)?;
        let new_owned = ownership.claim(new_reserved, new_cap)?;
        let new_handle = new_owned.handle();

        // 2c. Finaliser la cap
        cap_table.finalize_mem_cap(new_cap, new_handle)?;

        // 2d. Copier le contenu (4 KiB)
        unsafe {
            core::ptr::copy_nonoverlapping(
                phys_to_virt(old_handle.base) as *const u8,
                phys_to_virt(new_handle.base) as *mut u8,
                PAGE_SIZE as usize,
            );
        }

        // 2e. Remapper sur la nouvelle frame
        //     Unregister old mapping, register new
        mapping_index.unregister(current_cap, address_space.pid, vaddr);
        address_space.remap(
            vaddr,
            new_handle.base,
            (pte_flags | WRITABLE) & !PTE_BIT_COW,
        )?;
        mapping_index.register(new_cap, MappingRef {
            pid: address_space.pid,
            vaddr,
            page_size: PageSize::Small,
        });

        // 2f. Retirer la référence de l'ancien bloc (via OwnershipTable)
        let result = ownership.remove_ref(old_handle, current_cap)?;

        match result {
            RemoveRefResult::Freed => {
                // Dernier propriétaire de l'ancien bloc → libérer
                let released = PhysBlock::<Exclusive> {
                    handle: old_handle,
                    _state: PhantomData,
                }.into_released();
                buddy.free_block(released);
            }
            RemoveRefResult::NowExclusive { remaining_cap } => {
                // L'autre propriétaire est maintenant seul.
                // Optionnel: pourrait rendre ses PTEs writable
                // (optimisation — pas obligatoire en v1.0).
            }
            RemoveRefResult::StillShared { .. } => {
                // Encore partagé par d'autres
            }
        }
    }

    Ok(())
}
```

### 10.3 Invariants COW

> **INV-COW-1** : Le bit COW n'existe que dans les PTEs. Pas de flag COW dans `BlockMeta.flags`.
>
> **INV-COW-2** : Un PTE avec COW a toujours `WRITABLE=0`.
>
> **INV-COW-3** : COW ne s'applique qu'aux blocs order-0 en v1.0.
>
> **INV-COW-4** : La résolution COW passe par `OwnershipTable::remove_ref()` et `MappingIndex`. Pas de manipulation directe de refcount.
>
> **INV-COW-5** : La résolution COW crée une nouvelle capability pour le nouveau bloc. L'ancienne cap perd sa référence à l'ancien bloc.

---

## 11. Huge Pages (2 MiB)

### 11.1 Chemin séparé

Les huge pages ont leur propre chemin, distinct des 4K. Pas de helper partagé.

```rust
impl AddressSpace {
    /// Mappe un bloc order-9 comme huge page (entrée PMD).
    pub fn map_huge_block(
        &self,
        handle: BlockHandle,
        vaddr: VirtAddr,
        flags: PageTableFlags,
        cap_id: CapId,
        mapping_index: &MappingIndex,
    ) -> Result<(), MapError> {
        assert_eq!(handle.order, 9, "map_huge_block requires order-9");
        assert!(vaddr.is_aligned(HUGE_PAGE_SIZE), "vaddr not 2M-aligned");

        self.page_table.map_2mib(handle.base, vaddr, flags)?;

        mapping_index.register(cap_id, MappingRef {
            pid: self.pid,
            vaddr,
            page_size: PageSize::Huge,
        });

        Ok(())
    }
}
```

### 11.2 Fork de huge pages (v1.0 : eager copy)

```rust
fn fork_huge_page(
    parent_as: &AddressSpace,
    child_as: &AddressSpace,
    vaddr: VirtAddr,
    parent_handle: BlockHandle,  // BlockHandle, pas PhysAddr
    flags: PageTableFlags,
    child_cap: CapId,
    buddy: &BuddyAllocator,
    ownership: &OwnershipTable,
    cap_table: &mut CapabilityTable,
    mapping_index: &MappingIndex,
) -> Result<(), ForkError> {
    // PAS de COW. Copie immédiate.
    assert_eq!(parent_handle.order, 9);

    // 1. Allouer nouveau bloc order-9
    let new_reserved = buddy.alloc_block(9, ZoneType::Normal)?;
    let new_owned = ownership.claim(new_reserved, child_cap)?;
    let new_handle = new_owned.handle();

    // 2. Finaliser la cap
    cap_table.finalize_mem_cap(child_cap, new_handle)?;

    // 3. Copier 2 MiB
    unsafe {
        core::ptr::copy_nonoverlapping(
            phys_to_virt(parent_handle.base) as *const u8,
            phys_to_virt(new_handle.base) as *mut u8,
            HUGE_PAGE_SIZE as usize,
        );
    }

    // 4. Mapper dans l'enfant
    child_as.map_huge_block(new_handle, vaddr, flags, child_cap, mapping_index)?;

    // Le parent garde sa huge page intacte.
    Ok(())
}
```

### 11.3 Invariants huge pages

> **INV-HUGE-1** : Un bloc order-9 n'est jamais passé à `resolve_cow_fault()`.
>
> **INV-HUGE-2** : Un mapping huge utilise une entrée PMD, jamais 512 PTEs.
>
> **INV-HUGE-3** : Le refcount d'un bloc order-9 s'applique au bloc entier.
>
> **INV-HUGE-4** : `map_huge_block` est le seul point d'entrée pour les huge pages. Pas de fallback 4K.

---

## 12. Cache local per-CPU

### 12.1 Périmètre

Le cache local est une **optimisation pure**. Order-0 uniquement.

### 12.2 Design

```rust
const LOCAL_CACHE_CAPACITY: usize = 256;
const LOCAL_CACHE_REFILL_BATCH: usize = 16;
const LOCAL_CACHE_FLUSH_BATCH: usize = 64;

struct LocalFrameCache {
    len: usize,
    /// PhysAddr stockées. Toutes order-0, état BuddyReserved ou Free
    /// (selon qu'elles viennent d'alloc ou de free).
    frames: [PhysAddr; LOCAL_CACHE_CAPACITY],
}
```

### 12.3 Invariants

> **INV-CACHE-1** : Toute frame dans le cache a `refcount == REFCOUNT_UNUSED` et n'existe pas dans `OwnershipTable`.
>
> **INV-CACHE-2** : Le cache ne contient que des blocs order-0.
>
> **INV-CACHE-3** : Le cache est transparent pour l'OwnershipTable, le VM, et les capabilities.

---

## 13. Fork

### 13.1 Algorithme complet

```rust
pub fn sys_fork(
    parent: &Task,
    buddy: &BuddyAllocator,
    ownership: &OwnershipTable,
    mapping_index: &MappingIndex,
) -> Result<Pid, ForkError> {
    let parent_as = &parent.address_space;
    let child_as = AddressSpace::new_user()?;

    // Tracking pour rollback
    let mut modified_parent_ptes: Vec<(VirtAddr, PageTableFlags)> = Vec::new();
    let mut child_caps: Vec<CapId> = Vec::new();

    let regions = parent_as.regions.lock().clone();

    for (_vaddr, vma) in &regions {
        match vma.page_size {
            PageSize::Small => {
                // ── 4K : COW ──────────────────────────────
                for page_idx in 0..vma.page_count {
                    let page_vaddr = vma.start + page_idx as u64 * PAGE_SIZE;

                    let (handle, flags) = match parent_as.translate_to_handle(page_vaddr) {
                        Some(hf) => hf,
                        None => continue, // demand-paged, not yet faulted
                    };

                    // Dériver une capability enfant depuis la cap parent
                    let child_cap = parent.cap_table.lock().derive_mem_cap(
                        vma.cap_id,
                        MemPerms::READ | MemPerms::WRITE,
                        child_as.pid,
                    )?;
                    child_caps.push(child_cap);

                    if flags.contains(WRITABLE) {
                        // Retirer WRITABLE du parent, ajouter COW
                        modified_parent_ptes.push((page_vaddr, flags));
                        parent_as.mark_cow(page_vaddr)?;
                    }

                    // Ajouter le refcount via OwnershipTable
                    ownership.add_ref(handle, child_cap)?;

                    // Mapper même frame dans l'enfant (read-only + COW)
                    let child_flags = (flags & !WRITABLE) | PTE_BIT_COW;
                    child_as.map_block(
                        handle, page_vaddr, child_flags,
                        child_cap, mapping_index,
                    )?;
                }
            }

            PageSize::Huge => {
                // ── 2M : Eager Copy (v1.0) ────────────────
                for page_idx in 0..vma.page_count {
                    let page_vaddr = vma.start + page_idx as u64 * HUGE_PAGE_SIZE;

                    let (handle, flags) = match parent_as.translate_to_handle(page_vaddr) {
                        Some(hf) => hf,
                        None => continue,
                    };

                    let child_cap = parent.cap_table.lock().create_pending_mem_cap(
                        MemPerms::READ | MemPerms::WRITE,
                        child_as.pid,
                    )?;
                    child_caps.push(child_cap);

                    fork_huge_page(
                        parent_as, &child_as, page_vaddr, handle, flags,
                        child_cap, buddy, ownership,
                        &mut parent.cap_table.lock(), mapping_index,
                    )?;
                }
            }
        }

        // Enregistrer le VMA dans l'enfant
        child_as.regions.lock().insert(vma.start, VirtualMemoryRegion {
            cap_id: child_caps.last().copied().unwrap_or(vma.cap_id),
            ..*vma
        });
    }

    // TLB shootdown global (parent a été modifié pour COW)
    tlb::shootdown_all();

    // Créer le task enfant...
    Ok(child_pid)
}
```

### 13.2 Rollback

```rust
fn rollback_fork(
    parent_as: &AddressSpace,
    child_as: &AddressSpace,
    modified_parent_ptes: &[(VirtAddr, PageTableFlags)],
    child_caps: &[CapId],
    ownership: &OwnershipTable,
    cap_table: &mut CapabilityTable,
    mapping_index: &MappingIndex,
    buddy: &BuddyAllocator,
) {
    // 1. Restaurer les PTEs du parent
    for (vaddr, original_flags) in modified_parent_ptes {
        parent_as.protect_range(*vaddr, 1, *original_flags).ok();
    }

    // 2. Révoquer toutes les capabilities enfant
    for cap_id in child_caps {
        revoke_capability_inner(
            *cap_id, cap_table, mapping_index, ownership, buddy,
        ).ok();
    }

    // 3. Détruire l'address space enfant
    child_as.destroy();

    // 4. TLB shootdown
    tlb::shootdown_all();
}
```

---

## 14. Invariants formels

### 14.1 Invariants globaux

| ID | Invariant | Vérifié par |
|---|---|---|
| **G-1** | Un bloc dans le buddy free-list est `Free`, `refcount=UNUSED`, absent de `OwnershipTable` | Typestate + buddy |
| **G-2** | Un bloc `Shared` a `refcount ≥ 2` et `caps.len() ≥ 2` dans `OwnershipTable` | OwnershipTable |
| **G-3** | Un bloc `Exclusive` a `refcount == 1` et `caps.len() == 1` | OwnershipTable |
| **G-4** | Tout mapping a une capability `Active` valide | CapabilityTable + MappingIndex |
| **G-5** | Un PTE COW a `WRITABLE=0` | VM manager |
| **G-6** | COW = order-0 uniquement (v1.0) | `resolve_cow_fault` assert |
| **G-7** | Huge page = entrée PMD | `map_huge_block` assert |
| **G-8** | `MappingIndex` est synchrone avec les PTEs | VM manager (map/unmap) |
| **G-9** | `revoke()` cascade via CDT + MappingIndex + OwnershipTable | `revoke_capability()` |
| **G-10** | `BlockMeta.{refcount,block_state}` = cache de `OwnerEntry` | `sync_meta()` |
| **G-11** | Aucune couche ne court-circuite une autre | Architecture |
| **G-12** | Entre buddy.alloc et ownership.claim, le bloc est `BuddyReserved` | Typestate |

### 14.2 Tests d'invariants (debug builds)

```rust
#[cfg(debug_assertions)]
pub fn verify_block_invariants(handle: BlockHandle, ownership: &OwnershipTable) {
    let meta = get_block_meta(handle.base);
    let meta_state = meta.block_state.load(Ordering::Acquire);
    let meta_rc = meta.refcount.load(Ordering::Acquire);

    let entries = ownership.entries.lock();

    if let Some(entry) = entries.get(&handle.base) {
        // Bloc dans la table → vérifier cohérence
        assert_eq!(meta_state, entry.state as u8,
            "BlockMeta.state ({}) != OwnerEntry.state ({:?})",
            meta_state, entry.state);
        assert_eq!(meta_rc, entry.refcount,
            "BlockMeta.refcount ({}) != OwnerEntry.refcount ({})",
            meta_rc, entry.refcount);
        assert_eq!(entry.refcount as usize, entry.caps.len(),
            "refcount ({}) != caps.len() ({})",
            entry.refcount, entry.caps.len());

        match entry.state {
            BlockState::Exclusive => assert_eq!(entry.refcount, 1),
            BlockState::Shared => assert!(entry.refcount >= 2),
            other => panic!("block in OwnershipTable with state {:?}", other),
        }
    } else {
        // Bloc absent de la table → doit être Free ou BuddyReserved
        assert!(
            meta_state == BlockState::Free as u8
            || meta_state == BlockState::BuddyReserved as u8,
            "block not in OwnershipTable but state = {}",
            meta_state
        );
        if meta_state == BlockState::Free as u8 {
            assert_eq!(meta_rc, REFCOUNT_UNUSED);
        }
    }
}

#[cfg(debug_assertions)]
pub fn audit_mapping_index(
    mapping_index: &MappingIndex,
    cap_table: &CapabilityTable,
) {
    let index = mapping_index.index.lock();
    for (cap_id, mappings) in index.iter() {
        // Chaque cap dans l'index doit exister et être Active
        let cap = cap_table.check_mem_cap(*cap_id, MemPerms::empty())
            .expect("MappingIndex references non-existent cap");
        assert!(matches!(cap.cap_state, MemCapState::Active { .. }),
            "MappingIndex references non-Active cap");

        // Chaque mapping doit correspondre à un PTE réel
        for mref in mappings {
            if let Some(target_as) = get_address_space(mref.pid) {
                assert!(target_as.translate_to_handle(mref.vaddr).is_some(),
                    "MappingIndex has phantom entry: cap={:?} vaddr={:?}",
                    cap_id, mref.vaddr);
            }
        }
    }
}
```

---

## 15. Plan de migration

### Phase 0 : Préparation (sans casser l'existant)

**Fichiers créés :**
- `memory/block.rs` — `BlockHandle`, `PhysBlock<S>`, états, transitions
- `memory/ownership.rs` — `OwnershipTable`, `OwnerEntry`, `BlockState`
- `memory/block_meta.rs` — `BlockMeta`, `SubFrameMeta`, `FrameMetaSlot`
- `memory/mapping_index.rs` — `MappingIndex`, `MappingRef`

**Actions :**
1. Écrire tous les types et tests unitaires.
2. Écrire les tests d'invariants (section 14.2).
3. **Rien n'est branché.** L'ancien code fonctionne.

### Phase 1 : Buddy → PhysBlock

**Fichiers modifiés :** `memory/buddy.rs`

**Actions :**
1. Type retour `alloc_block()`: `PhysAddr` → `PhysBlock<BuddyReserved>`.
2. Type param `free_block()`: `PhysAddr` → `PhysBlock<Released>`.
3. Stamper `BuddyReserved` (pas `Exclusive`).
4. Stamper sub-frames avec `head_pfn`.
5. Adapter tous les call-sites (le compilateur les signale).

### Phase 2 : FrameMeta → BlockMeta

**Fichiers modifiés :** `memory/frame.rs` → remplacé, `memory/buddy.rs`, `memory/heap.rs`

**Actions :**
1. Remplacer l'array 64B par 32B.
2. `get_meta()` → `get_block_meta()` avec support sub-frame.
3. Adapter le heap.

### Phase 3 : OwnershipTable + MappingIndex

**Fichiers modifiés :** `memory/cow.rs`, `memory/address_space.rs`, `syscall/fork.rs`

**Actions :**
1. Brancher `OwnershipTable` : tout passage de refcount passe par elle.
2. Brancher `MappingIndex` : tout map/unmap enregistre/désenregistre.
3. Remplacer `cow::frame_inc_ref()` → `ownership.add_ref()`.
4. Remplacer `cow::frame_dec_ref()` → `ownership.remove_ref()`.
5. VM retourne `BlockHandle` partout, plus de `PhysAddr` bruts hors impl.
6. COW fault utilise `translate_to_handle()`.
7. Supprimer `COW_LOCK` global.

### Phase 4 : Capabilities mémoire

**Fichiers modifiés :** `capability.rs`, `syscall/`

**Actions :**
1. Ajouter `MemCap` avec états `Pending`/`Active` et CDT.
2. `create_pending_mem_cap()` → `finalize_mem_cap()` (flux sans divergence de CapId).
3. `revoke_mem_cap()` avec CDT walk + MappingIndex + OwnershipTable.
4. Syscalls: `sys_mem_alloc`, `sys_mem_map`, `sys_mem_share`, `sys_mem_free`.
5. Fork dérive les capabilities parent→enfant.
6. Exit révoque toutes les racines cap.

### Phase 5 : Huge pages séparées

**Fichiers modifiés :** `memory/address_space.rs`, `syscall/fork.rs`

**Actions :**
1. `map_huge_block()` / `unmap_huge_page()` séparés.
2. Fork : eager copy avec `BlockHandle`, pas `PhysAddr`.
3. Assert dans `resolve_cow_fault`: order == 0.

### Phase 6 : Nettoyage + tests

1. Supprimer `frame.rs` (`PhysFrame`, `FrameMeta` 64B).
2. Supprimer `cow.rs` (fonctions legacy).
3. `cargo make kernel-test` — tous tests passent.
4. `cargo make fmt && cargo make clippy` — zéro warning.

### Ordre de compilation

```
Phase 0 → compile ✓ (nouveau code isolé + tests unitaires)
Phase 1 → compile ✓ (buddy retourne PhysBlock<BuddyReserved>)
Phase 2 → compile ✓ (metadata 32B, sub-frame support)
Phase 3 → compile ✓ (OwnershipTable + MappingIndex branchés)
Phase 4 → compile ✓ (capabilities mémoire, syscalls)
Phase 5 → compile ✓ (huge pages séparées, fork adapté)
Phase 6 → compile ✓ (nettoyage, tous tests passent)
```

---

## 16. TODO v2.0

### 16.1 COW sur huge pages (option split-then-fallback)

```
Implémenter HugeForkStrategy::SplitThenCow :
1. Au fork, splitter le mapping PMD en 512 PTEs (4K chacun)
2. Marquer chaque PTE comme COW
3. Créer 512 capabilities dérivées (ou une seule cap avec sub-range)
4. Chaque sous-frame obtient son propre OwnerEntry
5. Au fault COW, résoudre normalement (4K copy)
6. Re-collapse optionnel si toutes les 512 frames redeviennent exclusives

Référence: Linux wp_huge_pmd() → __split_huge_pmd() → do_wp_page()
```

### 16.2 Partial unmap de huge pages

```
Permettre de unmapper une partie d'un bloc order-9 :
1. Splitter le bloc dans le buddy (order-9 → sub-blocs)
2. Chaque sous-bloc obtient sa propre BlockMeta de tête
3. Re-stamper les sub-frames avec les nouveaux head_pfn
4. Distribuer l'OwnerEntry aux sous-blocs
5. Le MappingIndex est mis à jour pour chaque sous-bloc
```

### 16.3 Granularité fine de l'OwnershipTable

```
Remplacer le SpinLock global par un sharding ou per-zone lock :
- Shard par bits hauts de PhysAddr
- Ou lock-free avec ConcurrentHashMap
- Benchmark avant d'optimiser
```

### 16.4 Pages 1 GiB

```
PageSize::Giant (1 GiB, order-18).
Chemin séparé. Pas de COW. Eager copy ou split-to-2M à fork.
```

### 16.5 Optimisations futures

```
- Cache per-CPU pour order-9 (huge page cache)
- Batch TLB shootdown
- NUMA-aware zone selection
- Compaction
- Ballooning
```

---

## Annexe A : Correspondance ancien → nouveau code

| Ancien | Nouveau |
|---|---|
| `frame.rs::PhysFrame` | `block.rs::BlockHandle` (identifiant) + `PhysBlock<S>` (typestate) |
| `frame.rs::FrameMeta` (64B) | `block_meta.rs::BlockMeta` (32B) + `SubFrameMeta` (8B) |
| `frame.rs::get_meta()` | `block_meta.rs::get_block_meta()` + `resolve_handle()` |
| `cow.rs::frame_inc_ref()` | `ownership.rs::OwnershipTable::add_ref()` |
| `cow.rs::frame_dec_ref()` | `ownership.rs::OwnershipTable::remove_ref()` |
| `cow.rs::frame_set_cow()` | `address_space.rs::AddressSpace::mark_cow()` (PTE-only) |
| `cow.rs::handle_cow_fault()` | `cow.rs::resolve_cow_fault()` (via BlockHandle) |
| `buddy.rs` retourne `PhysAddr` | retourne `PhysBlock<BuddyReserved>` |
| `capability.rs::Capability` | `MemCap` + CDT + `MappingIndex` |
| (inexistant) | `ownership.rs::OwnershipTable` (source de vérité) |
| (inexistant) | `mapping_index.rs::MappingIndex` (reverse map) |

## Annexe B : Références

| Source | Concept emprunté |
|---|---|
| Asterinas OSTD | `UniqueFrame`/`Frame<M>` distinction typed/untyped, metadata array |
| seL4 | Untyped→Retype, Capability Derivation Tree, révocation hiérarchique |
| Redox OS | `Provider` enum (single source of truth), `PageInfo` dual-use free/allocated |
| Linux | `split_huge_pmd()` → fallback 4K pour COW (TODO v2.0) |
| Theseus OS | Taille de page explicite dans les abstractions |
| Cliffle / Hoverbear | Typestate pattern en Rust, move semantics |

## Annexe C : Glossaire

| Terme | Définition |
|---|---|
| **BlockHandle** | Identifiant léger copiable d'un bloc physique : `(base, order)` |
| **PhysBlock\<S\>** | Handle éphémère typé par état. Vérification locale, pas stockage. |
| **BlockMeta** | Metadata 32B en cache atomique, indexée par PFN de tête |
| **OwnershipTable** | Source de vérité centrale pour l'état de propriété et refcount |
| **MappingIndex** | Reverse map: `CapId → Vec<MappingRef>` pour la révocation |
| **MemCap** | Capability mémoire. Identité canonique d'un bloc pour son propriétaire. |
| **CDT** | Capability Derivation Tree. Parent→enfants pour révocation récursive. |
| **BuddyReserved** | État transitoire: sorti du buddy, pas encore possédé |
| **COW** | Copy-on-Write. Order-0 uniquement en v1.0. Flag dans les PTEs. |
| **PMD** | Page Middle Directory. Entrée de table de pages pour 2 MiB. |
| **HHDM** | Higher Half Direct Map. Mapping linéaire physique→virtuel. |
| **PFN** | Page Frame Number. `phys_addr / PAGE_SIZE`. |

---

*Fin du document de design v2. Toutes les critiques de la revue v1 sont corrigées.*
