# Analyse : Run queues du scheduler — VecDeque → Listes chaînées intrusives

**Date** : 2026-03-26
**Périmètre** : `process/sched_classes/real_time.rs`, `fair.rs`, `task.rs`, `scheduler.rs`

---

## 1. Diagnostic : pourquoi VecDeque est un problème

### 1.1 Le chemin de code dangereux

```
Timer interrupt (IRQ disabled)
  └─ timer_tick()
       └─ LOCAL_SCHEDULERS[cpu].try_lock_no_irqsave()  ← SpinLock acquis, IRQs off
            └─ update_current() → need_resched = true
  └─ maybe_preempt() → pick_next_task_local()
       └─ enqueue(task)  ← push_back sur VecDeque
            └─ Si capacity dépassée → alloc::alloc::realloc()
                 └─ buddy_allocator.alloc()
                      └─ zone.lock()  ← SECOND SPINLOCK en critical section
```

Le `push_back` sur un `VecDeque` plein appelle le global allocator depuis une section critique : interruptions désactivées, spinlock scheduler tenu. Le buddy allocator prend son propre spinlock. Si un autre CPU tient déjà ce lock, c'est un deadlock. Si l'allocateur retourne `null` (OOM), c'est un panic non récupérable.

### 1.2 État actuel dans le code

**RT class** (`real_time.rs:34,47`) :
```rust
pub struct RealTimeClassRq {
    queues: [VecDeque<Arc<Task>>; 100],  // 100 * sizeof(VecDeque) = 100 * 24B = 2.4 KB
    bitmap: u128,
}

// Pré-allocation de 4 slots par niveau
q.reserve(RT_PREALLOC_PER_PRIO);  // RT_PREALLOC_PER_PRIO = 4
```

**Problème concret** : la pré-allocation de 4 slots évite la ré-allocation pour les premiers 4 pushes. Mais :
- Le 5ème task au même niveau RT → `realloc()` en section critique
- `retain()` dans `remove()` peut compacter le buffer interne (pas de shrink automatique sur VecDeque, mais la copie des éléments restants est O(n))
- 100 × 4 = 400 `Arc<Task>` slots pré-alloués mais jamais utilisés simultanément → 100 allocations au démarrage pour des queues vides

**Fair class** (`fair.rs:101,105,218`) :
```rust
entities: BinaryHeap<Reverse<FairQueueItem>>,  // FairQueueItem = (Arc<Task>, u64)

// remove() :
let vec: Vec<_> = self.entities.drain().collect();  // alloc 1
let filtered: Vec<_> = vec.into_iter().filter(...).collect();  // alloc 2
self.entities = BinaryHeap::from(filtered);  // alloc 3 (heapify)
```

Trois allocations heap dans `remove()`. C'est le chemin de "task blocks" — pas le hot path du timer tick, mais c'est exécuté sous le scheduler lock.

### 1.3 Le vrai coût : `Arc<Task>` dans la queue

Chaque `push_back(task: Arc<Task>)` et `pop_front()` fait un incrément/décrément atomique du refcount. Ces opérations `AcqRel` sur x86_64 (MFENCE ou LOCK XADD) ont une latence de ~5-10 cycles chacune sur un cache hit, plus potentiellement un cache miss sur le refcount si la task struct a été évincée.

Ce n'est pas catastrophique, mais c'est du bruit dans le chemin de context switch.

---

## 2. Ce que font les autres OS

### Linux (sched_rt.c, sched_fair.c)

```c
// Intrusive doubly-linked list dans task_struct
struct list_head run_list;        // pour RT (embedded dans le TCB)
struct rb_node run_node;          // pour CFS (embedded dans le TCB)
u64 vruntime;                     // CFS virtual runtime

// RT run queue : tableau de tête de liste par priorité
struct rt_prio_array {
    DECLARE_BITMAP(bitmap, MAX_RT_PRIO+1); // 101 bits
    struct list_head queue[MAX_RT_PRIO];  // 100 têtes de liste
};
```

Zéro allocation. `list_head` est dans le TCB. Push/pop modifient les pointeurs `prev/next` directement dans le TCB. La queue head contient juste deux pointeurs (16B).

### FreeBSD (sched_ule.c)

```c
struct tdq {
    struct runq tdq_realtime;    // intrusive TAILQ par priorité
    struct runq tdq_timeshare;   // roue des timeshares
    struct runq tdq_idle;        // idle
};

// Dans le TCB (thread) :
TAILQ_ENTRY(thread) td_runq;    // deux pointeurs dans le TCB
```

Même principe : les pointeurs `tqe_next/tqe_prev` vivent dans le TCB.

### seL4 (tcb_queue.h)

```c
typedef struct tcb_queue {
    struct tcb *head;
    struct tcb *end;
} tcb_queue_t;

// Dans le TCB :
struct tcb *tcbSchedNext;   // un pointeur seulement (singly linked)
struct tcb *tcbSchedPrev;   // pour doubly linked (facultatif)
```

seL4 utilise une liste doublement chaînée avec des pointeurs raw dans le TCB. Chaque priorité a sa propre tête. Aucune allocation.

### Theseus OS (Rust, no_std)

```rust
// Theseus utilise des intrusive lists custom avec NonNull
struct RunQueue {
    queue: VecDeque<TaskRef>,  // ils utilisent VecDeque aussi... mais reconnaissent le problème
}
// https://github.com/theseus-os/Theseus/issues/563
// "VecDeque may allocate during push, which is unsafe in IRQ context"
```

Même problème documenté dans Theseus — ils l'ont reconnu comme un bug.

---

## 3. La solution : listes intrusives

### 3.1 Principe

Un nœud de liste intrusive vit **dans** le TCB, pas dans un nœud de liste séparé. La queue head ne contient que deux pointeurs (tête et queue). Zéro allocation.

```
Avant (VecDeque) :
  Queue head → [heap block: Arc<Task>*, Arc<Task>*, Arc<Task>*, ...]
                    ↓               ↓               ↓
                 Task A           Task B           Task C

Après (intrusive) :
  Queue head → Task A.next → Task B.next → Task C.next → None
               Task A.prev ← Task B.prev ← Task C.prev ← Queue tail
```

Le TCB **est** le nœud. Aucune allocation séparée.

### 3.2 Dépendance recommandée : `intrusive-collections`

La crate [`intrusive-collections`](https://github.com/Amanieu/intrusive-rs) d'Amanieu est la référence pour les listes intrusives en Rust `no_std` :
- `no_std` + `alloc` : ✓
- Doubly-linked list : ✓
- O(1) push/pop/remove par curseur : ✓
- Supporte `Arc<T>` comme propriétaire : ✓
- Utilisée dans Asterinas : ✓

```toml
# workspace/kernel/Cargo.toml
intrusive-collections = { version = "0.9", default-features = false }
```

---

## 4. Plan de migration concret

### 4.1 Étape 1 : ajouter les liens dans `Task`

```rust
// process/task.rs — ajouter dans struct Task :
use intrusive_collections::LinkedListLink;

pub struct Task {
    // ... champs existants ...

    /// Lien intrusive pour la RT run queue.
    /// Non-nul uniquement quand la task est dans une RT queue.
    pub(crate) rt_link: LinkedListLink,

    /// Lien intrusive pour la Fair run queue.
    /// Non-nul uniquement quand la task est dans la fair queue.
    pub(crate) fair_link: LinkedListLink,
}
```

`LinkedListLink` est 16 octets (deux pointeurs). Impact sur la taille de `Task` : +32 octets.

### 4.2 Étape 2 : déclarer les adaptateurs

```rust
// process/sched_classes/mod.rs ou un nouveau fichier intrusive_adapters.rs

use intrusive_collections::{intrusive_adapter, LinkedList, LinkedListLink};
use alloc::sync::Arc;
use crate::process::task::Task;

// RT adapter : Arc<Task> avec le lien rt_link
intrusive_adapter!(
    pub RtTaskAdapter = Arc<Task>: Task { rt_link: LinkedListLink }
);

// Fair adapter : Arc<Task> avec le lien fair_link
intrusive_adapter!(
    pub FairTaskAdapter = Arc<Task>: Task { fair_link: LinkedListLink }
);
```

### 4.3 Étape 3 : remplacer `RealTimeClassRq`

```rust
// process/sched_classes/real_time.rs

use intrusive_collections::{LinkedList, LinkedListLink};
use crate::process::sched_classes::intrusive_adapters::RtTaskAdapter;

/// Une queue FIFO pour un niveau de priorité RT.
/// Zéro allocation. Les nœuds vivent dans le TCB.
struct RtPrioQueue {
    list: LinkedList<RtTaskAdapter>,
    len: usize,
}

impl RtPrioQueue {
    const fn new() -> Self {
        Self {
            list: LinkedList::new(RtTaskAdapter::NEW),
            len: 0,
        }
    }

    fn push_back(&mut self, task: Arc<Task>) {
        // Pas d'allocation. Modifie task.rt_link directement.
        self.list.push_back(task);
        self.len += 1;
    }

    fn pop_front(&mut self) -> Option<Arc<Task>> {
        let task = self.list.pop_front()?;
        self.len -= 1;
        Some(task)
    }

    fn remove_by_id(&mut self, task_id: TaskId) -> bool {
        let mut cursor = self.list.front_mut();
        while let Some(task) = cursor.get() {
            if task.id == task_id {
                cursor.remove();
                self.len -= 1;
                return true;
            }
            cursor.move_next();
        }
        false
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn len(&self) -> usize {
        self.len
    }
}

pub struct RealTimeClassRq {
    /// 100 queues FIFO, une par niveau de priorité (0=min, 99=max).
    /// Chaque tête de liste occupe 2 pointeurs = 16B.
    /// Total : 100 * 16B = 1600B (vs 100 * VecDeque = 2400B + heap).
    queues: [RtPrioQueue; 100],
    /// Bitmap des niveaux non-vides (bit i = queues[i] non vide).
    bitmap: u128,
}

impl RealTimeClassRq {
    pub fn new() -> Self {
        // Pas de pré-allocation — les listes sont vides et ne coûtent rien.
        const EMPTY: RtPrioQueue = RtPrioQueue {
            list: LinkedList::new(RtTaskAdapter::NEW),
            len: 0,
        };
        Self {
            queues: [EMPTY; 100],
            bitmap: 0,
        }
    }
}

impl SchedClassRq for RealTimeClassRq {
    fn enqueue(&mut self, task: Arc<Task>) {
        let prio = match task.sched_policy() {
            SchedPolicy::RealTimeRR { prio } => prio.get(),
            SchedPolicy::RealTimeFifo { prio } => prio.get(),
            _ => return,
        };
        self.queues[prio as usize].push_back(task); // ← ZERO allocation
        self.set_bit(prio);
    }

    fn pick_next(&mut self) -> Option<Arc<Task>> {
        if self.bitmap == 0 { return None; }
        let highest = 127 - self.bitmap.leading_zeros() as u8;
        let q = &mut self.queues[highest as usize];
        let task = q.pop_front()?;          // ← ZERO allocation
        if q.is_empty() { self.clear_bit(highest); }
        Some(task)
    }

    fn remove(&mut self, task_id: TaskId) -> bool {
        let mut removed = false;
        let mut bits = self.bitmap;
        while bits != 0 {
            let i = bits.trailing_zeros() as usize;
            if self.queues[i].remove_by_id(task_id) {
                removed = true;
                if self.queues[i].is_empty() {
                    self.clear_bit(i as u8);
                }
                break; // un task n'est dans qu'une seule queue
            }
            bits &= !(1u128 << i);
        }
        removed
    }

    fn len(&self) -> usize {
        self.queues.iter().map(|q| q.len()).sum()
    }

    fn update_current(&mut self, rt: &CurrentRuntime, task: &Task, is_yield: bool) -> bool {
        // Inchangé
        if is_yield { return true; }
        match task.sched_policy() {
            SchedPolicy::RealTimeRR { .. } => rt.period_delta_ticks >= RT_RR_QUANTUM_TICKS,
            SchedPolicy::RealTimeFifo { .. } => false,
            _ => false,
        }
    }
}
```

### 4.4 Étape 4 : remplacer `FairClassRq`

La `BinaryHeap` pour le Fair scheduler est plus complexe à migrer car CFS a besoin d'une structure ordonnée par `vruntime`. Les options :

**Option A (court terme) — garder BinaryHeap, corriger `remove()`** :

```rust
// Éviter les 3 allocations dans remove() en filtrant en place
fn remove(&mut self, task_id: TaskId) -> bool {
    // BinaryHeap::retain() n'existe pas encore en stable Rust.
    // Alternative : utiliser un Vec intermédiaire mais pré-alloué.
    // SmallVec inline évite la ré-allocation pour les cas courants.
    let mut kept: SmallVec<[_; 64]> = SmallVec::new();
    let mut removed = false;
    while let Some(item) = self.entities.pop() {
        if item.0.id == task_id {
            removed = true;
        } else {
            kept.push(item);
        }
    }
    for item in kept {
        self.entities.push(item);
    }
    removed
}
```

Avec `SmallVec<[_; 64]>` : pour ≤64 tasks fairness, zéro allocation dans `remove()`.

**Option B (long terme) — liste intrusve triée ou RB-tree** :

```rust
// Idéalement : un RB-tree intrusive ordonné par vruntime (comme Linux CFS)
// Crate : intrusive-collections supporte aussi les RB-trees
use intrusive_collections::{RBTree, RBTreeLink};
use core::cmp::Ordering;

// Dans Task :
pub(crate) fair_link: RBTreeLink,

// Adapter avec clé = vruntime
intrusive_adapter!(pub FairRbAdapter = Arc<Task>: Task { fair_link: RBTreeLink });

impl intrusive_collections::KeyAdapter<'_> for FairRbAdapter {
    type Key = u64; // vruntime
    fn get_key(&self, task: &Task) -> u64 {
        task.vruntime.load(Ordering::Relaxed)
    }
}
```

Cela donne O(log n) pour insert, pick_min (pop leftmost), et remove. C'est exactement ce que fait Linux.

---

## 5. Comparaison des complexités

| Opération | VecDeque actuel | Intrusive LL | RB-Tree (Fair) |
|---|---|---|---|
| `enqueue` | O(1) amortized, **peut allouer** | O(1), **jamais alloue** | O(log n), **jamais alloue** |
| `pick_next` | O(1) | O(1) | O(log n) |
| `remove(id)` | O(n) + retain copy | O(n) scan, O(1) remove | O(log n) |
| Mémoire queue vide | ~24B + heap ptr | 16B (tête + queue) | 24B (racine + taille) |
| Mémoire par task | 0B (dans la queue) | 16B dans TCB | 24B dans TCB |
| Allocation runtime | Oui (si cap dépassée) | **Non** | **Non** |

---

## 6. Contrainte clé : un seul lien par structure

**Un `LinkedListLink` ne peut être que dans une seule liste à la fois.** C'est une garantie de `intrusive-collections` — si vous tentez d'insérer un nœud déjà lié, c'est un panic.

Cette contrainte est bénéfique : elle garantit qu'un task n'est jamais dans deux run queues simultanément. C'est un invariant que le scheduler doit de toute façon maintenir.

Si vous avez besoin de pools ou de structures secondaires (ex: blocked_tasks), utilisez soit un second lien (chaque Task peut avoir plusieurs `LinkedListLink`), soit continuer à utiliser `BTreeMap<TaskId, Arc<Task>>` pour les cold paths.

---

## 7. Impact sur la taille de `Task`

```
Avant :
  Task = ... (existant) ...

Après :
  Task = ... (existant) ...
       + rt_link:   LinkedListLink  = 16B
       + fair_link: LinkedListLink  = 16B (ou RBTreeLink = 24B)
  Total delta : +32B (ou +40B avec RB-tree)

KernelStack : 16 KB par task — le delta est négligeable (<0.2%)
```

---

## 8. Ce qu'il ne faut PAS faire

### 8.1 Ne pas utiliser `crossbeam_queue::ArrayQueue`

`ArrayQueue` est un MPMC lock-free, mais ne supporte pas de `remove()` arbitraire (pas de scan). Vous devriez drainer toute la queue pour trouver et retirer un element. Moins bon que l'intrusive list pour ce cas.

### 8.2 Ne pas utiliser `SmallVec` comme queue principale

`SmallVec<[Arc<Task>; N]>` n'offre pas de `pop_front()` O(1) — il faut décaler tous les éléments. C'est O(n) pour chaque context switch. Acceptable uniquement pour des queues de taille 1-2.

### 8.3 Ne pas utiliser `alloc::collections::LinkedList`

`LinkedList<Arc<Task>>` de la std/alloc alloue un nœud séparé par élément. C'est pire que VecDeque pour l'allocation — chaque `push` fait une allocation de nœud. C'est du "linked list theater" sans les bénéfices de l'intrusive.

---

## 9. Ordre de migration recommandé

```
Phase 1 (urgent — RT class) :
  1. Ajouter `intrusive-collections` à Cargo.toml
  2. Ajouter `rt_link: LinkedListLink` dans Task
  3. Implémenter RtPrioQueue avec LinkedList<RtTaskAdapter>
  4. Remplacer [VecDeque<Arc<Task>>; 100] par [RtPrioQueue; 100]
  5. Supprimer RT_PREALLOC_PER_PRIO (plus nécessaire)
  → Cargo test + selftest build

Phase 2 (moyen terme — Fair class remove()) :
  1. Remplacer les 3 allocations dans remove() par SmallVec inline
  → Correctif minimal, pas de migration de structure

Phase 3 (long terme — Fair class structure) :
  1. Ajouter `fair_link: RBTreeLink` dans Task
  2. Implémenter FairRbTree avec RBTree<FairRbAdapter>
  3. O(log n) insert/remove/min pour CFS
  → Amélioration de performance pour systèmes chargés (>16 tasks fair)
```

---

## 10. Références

| Source | Technique |
|---|---|
| Linux `kernel/sched/rt.c` | `struct list_head run_list` intrusive dans `task_struct` |
| Linux `kernel/sched/fair.c` | `struct rb_node run_node` + `vruntime` pour CFS |
| FreeBSD `sys/kern/sched_ule.c` | `TAILQ_ENTRY` macros intrusive dans `thread` |
| seL4 `include/sched.h` | `tcbSchedNext/Prev` raw pointers dans TCB |
| Asterinas `ostd/src/` | `intrusive-collections` crate avec `LinkedList` |
| Theseus OS issue #563 | "VecDeque may allocate during push, unsafe in IRQ context" |
| Amanieu/intrusive-rs | Crate de référence, no_std, supporte Arc, LL et RB-tree |

---

*La migration Phase 1 (RT class uniquement) est la plus urgente et la plus simple : deux ajouts dans Task, un remplacement de structure, zéro changement de sémantique observable. Elle élimine le risque de deadlock par allocation en section critique et réduit la taille mémoire des run queues vides de 2400B à 1600B.*
