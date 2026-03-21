# Strat9 Performance And Tracing Design

## Objectif

Construire une infrastructure de temps, métriques, profilage et traçage qui:

- reste minimaliste dans le kernel
- expose tout via des fichiers
- privilégie les formats stables et exportables
- permet de diagnostiquer:
  - CPU hotspots
  - contention de locks
  - latences IRQ / syscalls / wakeups
  - anomalies scheduler
  - goulots I/O

Le kernel produit des données brutes fiables.
Le userland fait l'analyse, l'agrégation, l'export et la visualisation.

## Principes

1. Tout est fichier.
Les contrôles, snapshots et flux de trace doivent être accessibles via VFS ou device files.

2. Pas de logique lourde sur le hot path.
Pas d'allocations, pas de formatage riche, pas de symbolisation, pas de JSON dans le kernel.

3. Le format canonique est une trace événementielle structurée.
Les flamegraphs, tableaux et timelines sont des vues dérivées.

4. Les compteurs et histogrammes ne remplacent pas les traces.
Ils servent au pilotage live, aux snapshots rapides et à l'alerte.

5. La clock de trace doit être explicitement définie.
Il faut distinguer source rapide locale et source corrélable cross-CPU.

## Références de conception

Les modèles à suivre sont:

- Linux `perf` et `ftrace` pour:
  - tracepoints statiques
  - buffers par CPU
  - sampling
  - compatibilité avec des outils externes
- FreeBSD `KTR` pour:
  - simplicité et faible overhead
- FreeBSD `hwpmc` pour:
  - intégration des compteurs matériels
- DTrace pour:
  - séparation provider / probe / consumer
  - stabilité des schémas d'événements
- Windows ETW pour:
  - événements structurés
  - sessions activables dynamiquement
  - séparation nette production / collecte / analyse
- Perfetto pour:
  - cible d'export timeline moderne
- Brendan Gregg flamegraph pour:
  - format dérivé CPU/off-CPU

## Ce qu'il ne faut pas faire

- ne pas implémenter un langage DTrace-like dans le kernel en première version
- ne pas stocker des chaînes arbitraires sur le hot path
- ne pas coupler la trace au logger texte
- ne pas faire dépendre les événements de structures Rust non stabilisées
- ne pas échantillonner les stacks avant d'avoir un système de temps et de trace propre

## Architecture générale

Le système est découpé en 4 sous-systèmes:

1. `time`

- source monotone
- source brute en cycles
- conversion cycles <-> temps
- qualité de clock

1. `metrics`

- compteurs
- gauges
- timers RAII
- histogrammes log2

1. `trace`

- événements structurés
- ring buffers par CPU
- activation dynamique
- export brut

1. `sample`

- profilage par échantillonnage
- RIP puis callchain
- export folded stacks

## Arborescence recommandée

Sous [workspace/kernel/src](/home/etc/src/strat9-os/workspace/kernel/src):

```text
perf/
  mod.rs
  time.rs
  clock.rs
  metrics.rs
  histogram.rs
  trace/
    mod.rs
    event.rs
    buffer.rs
    session.rs
    provider.rs
    export.rs
  sample/
    mod.rs
    cpu.rs
    stack.rs
  fs/
    mod.rs
    ctl.rs
    trace.rs
    counters.rs
    hists.rs
    clock.rs
```

Intégration initiale dans:

- [workspace/kernel/src/lib.rs](/home/etc/src/strat9-os/workspace/kernel/src/lib.rs)
- [workspace/kernel/src/process/scheduler](/home/etc/src/strat9-os/workspace/kernel/src/process/scheduler)
- [workspace/kernel/src/arch/x86_64/idt.rs](/home/etc/src/strat9-os/workspace/kernel/src/arch/x86_64/idt.rs)
- [workspace/kernel/src/sync](/home/etc/src/strat9-os/workspace/kernel/src/sync)
- [workspace/kernel/src/syscall](/home/etc/src/strat9-os/workspace/kernel/src/syscall)

## API temps

Le but est d'avoir une seule API publique pour le temps noyau:

```rust
pub enum ClockQuality {
    UnsyncedFastLocal,
    CalibratedMonotonic,
    SynchronizedMonotonic,
}

pub struct ClockInfo {
    pub quality: ClockQuality,
    pub freq_khz: u64,
    pub source: &'static str,
    pub per_cpu_skew_ns: u64,
}

pub fn raw_cycles() -> u64;
pub fn mono_ns() -> u64;
pub fn mono_us() -> u64;
pub fn cycles_to_ns(cycles: u64) -> u64;
pub fn ns_to_cycles(ns: u64) -> u64;
pub fn clock_info() -> ClockInfo;
```

### Règles

- `raw_cycles()` doit être la source la plus rapide possible
- `mono_ns()` doit être monotone et stable
- toutes les traces doivent préciser quelle clock est utilisée
- si le TSC n'est pas considéré invariant/synchronisé, le système doit l'indiquer

### Décision Strat9

En première version:

- `raw_cycles()` = `rdtsc()`
- `mono_ns()` = conversion calibrée TSC
- `ClockQuality` = `CalibratedMonotonic`

Plus tard:

- vérifier invariance TSC
- mesurer ou estimer skew SMP
- ajouter corrélation cross-CPU si nécessaire

## API métriques

Garder l'approche simple et statique.

```rust
pub struct Counter(AtomicU64);
pub struct Gauge(AtomicI64);

pub struct LatencyHist {
    buckets: [AtomicU64; 64],
}

pub struct ScopeTimer {
    start_cycles: u64,
    total_cycles: &'static AtomicU64,
    count: &'static AtomicU64,
}
```

API:

```rust
impl Counter {
    pub const fn new() -> Self;
    pub fn inc(&self);
    pub fn add(&self, v: u64);
    pub fn load(&self) -> u64;
}

impl Gauge {
    pub const fn new() -> Self;
    pub fn set(&self, v: i64);
    pub fn add(&self, v: i64);
    pub fn load(&self) -> i64;
}

impl LatencyHist {
    pub const fn new() -> Self;
    pub fn record_ns(&self, ns: u64);
    pub fn snapshot(&self) -> [u64; 64];
    pub fn reset(&self);
}
```

### Buckets

Utiliser des buckets log2 sur la latence en ns.
Exemple:

- bucket 0 = 0..1 ns
- bucket 1 = 2..3 ns
- bucket 10 = 1024..2047 ns

Ce n'est pas parfait, mais:

- très simple
- pas coûteux
- suffisant pour voir les ordres de grandeur

## Sous-système trace

### Objectif

Fournir des événements structurés horodatés, faible overhead, par CPU.

### Événements à implémenter en premier

- `sched.switch`
- `sched.wakeup`
- `sched.tick`
- `irq.enter`
- `irq.exit`
- `syscall.enter`
- `syscall.exit`
- `lock.wait.begin`
- `lock.wait.end`
- `lock.hold.begin`
- `lock.hold.end`
- `mm.page_fault`

### Schéma d'événement canonique

```rust
#[repr(C)]
pub struct TraceEvent {
    pub ts: u64,
    pub cpu: u16,
    pub kind: u16,
    pub size: u16,
    pub flags: u16,
    pub task_id: u64,
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
}
```

### Règles ABI

- `#[repr(C)]` obligatoire
- taille fixe en v1
- little-endian
- aucune donnée dépendante de la layout interne d'une struct Rust
- `kind` doit être un identifiant stable

### Enum de type

```rust
#[repr(u16)]
pub enum TraceKind {
    Invalid = 0,
    SchedSwitch = 1,
    SchedWakeup = 2,
    SchedTick = 3,
    IrqEnter = 10,
    IrqExit = 11,
    SysEnter = 20,
    SysExit = 21,
    LockWaitBegin = 30,
    LockWaitEnd = 31,
    LockHoldBegin = 32,
    LockHoldEnd = 33,
    PageFault = 40,
    CounterSample = 50,
    SampleIp = 60,
}
```

Ne jamais réutiliser un id supprimé.

### Encodage des champs

Exemples:

`sched.switch`

- `task_id` = task entrant
- `a0` = task sortant
- `a1` = raison
- `a2` = policy/class
- `a3` = reserved

`irq.enter`

- `task_id` = task courant
- `a0` = vector
- `a1` = cpl

`syscall.enter`

- `task_id` = task courant
- `a0` = syscall number
- `a1` = arg0
- `a2` = arg1
- `a3` = arg2

`lock.wait.begin`

- `a0` = lock class id
- `a1` = lock addr

`lock.wait.end`

- `a0` = lock class id
- `a1` = lock addr
- `a2` = waited_ns

## Ring buffer par CPU

### Choix

Un buffer ring par CPU, préalloué, écriture par le CPU local.

### Structure

```rust
pub struct TraceRing {
    pub write_idx: AtomicU64,
    pub read_idx: AtomicU64,
    pub dropped: AtomicU64,
    pub buf: &'static mut [TraceEvent],
}
```

### Politique

- overwrite autorisé ou non selon session
- par défaut:
  - pour debug live: overwrite autorisé
  - pour capture contrôlée: stop-on-full configurable

### Règles d'écriture

- pas de lock global
- le CPU propriétaire écrit
- le lecteur userland lit via snapshot ou stream
- barrière mémoire explicite avant publication de `write_idx`

### Taille initiale

Première version:

- 4096 événements par CPU

À rendre configurable plus tard via `/dev/perf/ctl`.

## Sessions et activation

Le système doit supporter une session active simple en v1.

```rust
pub struct TraceSession {
    pub enabled: AtomicBool,
    pub event_mask: AtomicU64,
    pub sample_hz: AtomicU32,
    pub mode_flags: AtomicU32,
}
```

### V1

- une seule session globale
- filtres simples par type d'événement
- sampling off par défaut

### Plus tard

- sessions multiples
- filtres par CPU
- filtres par task
- filtres par provider

## Interface fichier

Créer un device tree logique:

```text
/dev/perf/
  ctl
  clock
  providers
  events
  counters
  hists
  trace
  trace.raw
  sample.folded
  cpu/
    0/trace.raw
    1/trace.raw
```

### Sémantique

`/dev/perf/ctl`

- écritures texte de contrôle

`/dev/perf/clock`

- infos sur la clock active

`/dev/perf/providers`

- liste des providers et événements disponibles

`/dev/perf/events`

- schéma des ids et champs

`/dev/perf/counters`

- dump texte ou key=value des compteurs

`/dev/perf/hists`

- dump texte des histogrammes

`/dev/perf/trace.raw`

- flux binaire brut de tous les CPUs

`/dev/perf/cpu/N/trace.raw`

- flux binaire d'un CPU

`/dev/perf/sample.folded`

- sortie compatible flamegraph

### Protocole `ctl`

Commands v1:

```text
on
off
reset
mode overwrite on
mode overwrite off
event sched.switch on
event sched.switch off
event irq.enter on
event irq.exit on
sample cpu off
sample cpu 99
sample cpu 199
clock
snapshot
```

Réponses:

- `ok`
- `err <message>`

## Format texte stable

Prévoir un mode `key=value`.

Exemple `counters`:

```text
clock.source=tsc
clock.quality=calibrated
cpu.0.trace.dropped=0
trace.enabled=1
sched.switch.count=1234
irq.timer.count=9876
lock.wait.total_ns=4567890
```

Ce format doit rester scriptable et stable.

## Format d'export

### Canonique interne

- binaire `TraceEvent`

### Exports userland

À implémenter en userland:

1. texte
2. CSV
3. folded stacks
4. Perfetto / Chrome Trace

### Règle

Le kernel n'exporte pas directement du JSON Perfetto.
Le kernel fournit un flux brut stable.

## Sampling CPU

### V1

Échantillonnage RIP uniquement.

Événement:

`SampleIp`

- `task_id`
- `a0` = RIP
- `a1` = kernel/user bit

### V2

Callchain noyau.

### V3

Callchain mixte noyau + user si supporté.

### Source de sampling

Au départ:

- timer périodique dédié ou dérivé

Plus tard:

- PMU hardware si disponible

## Flamegraph

Le flamegraph n'est pas le format de base.

Il est produit à partir de:

- `SampleIp`
- puis plus tard callchains

### Sortie folded

Exemple:

```text
irq_exit;schedule;pick_next_task 120
sys_read;vfs_read;ext4_read_iter 540
spin_lock;wake_task 89
```

### Off-CPU flamegraph

Plus tard, on peut dériver un off-CPU flamegraph à partir des événements:

- `sched.switch`
- `sched.wakeup`
- `lock.wait.begin/end`

## Timeline type Perfetto

C'est la meilleure cible pour comprendre les goulots multi-sources.

Les événements suivants doivent être convertibles en timeline:

- task running
- task blocked
- IRQ ranges
- syscall ranges
- lock wait ranges
- lock hold ranges

### Pourquoi

Le flamegraph montre le coût agrégé.
La timeline montre l'ordre causal et les pauses.

## Locks et contention

Le système doit instrumenter les locks importants avec:

- classe de lock
- adresse de lock
- début d'attente
- fin d'attente
- durée d'attente
- début de possession
- fin de possession
- durée de possession

### LockClassId

Créer un enum stable:

```rust
#[repr(u16)]
pub enum LockClassId {
    Unknown = 0,
    Scheduler = 1,
    Buddy = 2,
    Slab = 3,
    Vfs = 4,
    Task = 5,
}
```

Ne pas logguer des noms dynamiques sur le hot path.

## Scheduler

Instrumentation minimale obligatoire:

- `sched.switch`
- `sched.wakeup`
- `sched.tick`
- `sched.idle_enter`
- `sched.idle_exit`
- `sched.preempt`

Le scheduler est la première source de goulots cachés.

## Syscalls

Instrumentation minimale:

- `syscall.enter`
- `syscall.exit`

Sur `exit`:

- code retour
- durée en ns

Les syscalls les plus coûteux pourront ensuite être histogrammés.

## IRQs

Instrumentation minimale:

- `irq.enter`
- `irq.exit`

Sur `irq.exit`:

- durée en ns
- vector

## Mémoire

Instrumenter au minimum:

- page fault
- alloc lente buddy
- alloc lente slab
- map/unmap coûteux

## Intégration logger

Ne pas faire dépendre `trace` du logger série.
Les logs texte de boot et la trace perf doivent rester séparés.

## Sécurité et robustesse

### Hard requirements

- aucune allocation dans `trace_event()`
- aucune panique dans les chemins trace
- si buffer plein:
  - incrémenter `dropped`
  - continuer
- si provider désactivé:
  - coût minimal

### API d'émission

```rust
#[inline]
pub fn trace_event(kind: TraceKind, task_id: u64, a0: u64, a1: u64, a2: u64, a3: u64);
```

Fast path:

- vérifier `session.enabled`
- vérifier bitmask event
- écrire dans buffer local CPU

## Versioning

Le format de trace doit être versionné explicitement.

Dans `/dev/perf/events` et `/dev/perf/trace.raw` header:

```text
perf.version=1
event.size=48
clock.source=tsc
clock.unit=ns
```

Si une rupture ABI arrive:

- incrémenter version
- garder l'ancien export si possible

## Plan d'implémentation recommandé

### PR 1: Temps et métriques

- créer `perf/time.rs`
- créer `perf/metrics.rs`
- factoriser l'API temps existante
- stabiliser `mono_ns()`
- ajouter histogrammes log2

Critère de sortie:

- temps unifié
- compteurs et timers RAII propres

### PR 2: Trace core

- créer `TraceEvent`
- créer ring par CPU
- créer session simple
- créer `trace_event()`
- exposer `/dev/perf/ctl`, `/dev/perf/events`, `/dev/perf/trace.raw`

Critère de sortie:

- on/off/reset
- capture brute lisible

### PR 3: Providers initiaux

- scheduler
- irq
- syscall
- lock

Critère de sortie:

- voir un switch task
- voir un syscall
- voir un lock wait

### PR 4: Userland tools

- `perfread dump`
- `perfread counters`
- `perfread perfetto`
- `perfread folded`

Critère de sortie:

- analyse offline possible

### PR 5: Sampling CPU

- RIP sampling
- export folded stacks

Critère de sortie:

- flamegraph CPU possible

### PR 6: Histos de latence et off-CPU

- wakeup latency
- lock wait latency
- syscall latency
- irq latency

Critère de sortie:

- goulots de latence visibles sans timeline complète

## Checklist de design avant merge

- l'événement a-t-il un id stable
- le schéma des champs est-il documenté
- l'écriture est-elle sans allocation
- le coût sur hot path est-il borné
- le flux est-il accessible via fichier
- l'export userland peut-il reconstruire une timeline
- peut-on dériver un flamegraph plus tard

## Décisions fermes pour Strat9

1. Le kernel produit le brut, le userland analyse.
2. Le format canonique est la trace structurée binaire.
3. Les flamegraphs sont dérivés du sampling.
4. Perfetto est une cible d'export, pas le format noyau.
5. Tout contrôle et toute lecture passent par des fichiers.
6. Une v1 simple et correcte vaut mieux qu'un pseudo-DTrace incomplet.

## Première implémentation concrète minimale

1. `mono_ns()` stable
2. `TraceEvent` fixe
3. ring buffer par CPU
4. `/dev/perf/ctl`
5. `/dev/perf/trace.raw`
6. événements:
   - `sched.switch`
   - `irq.enter`
   - `irq.exit`
   - `syscall.enter`
   - `syscall.exit`
   - `lock.wait.begin`
   - `lock.wait.end`
7. outil userland qui convertit en:
   - dump texte
   - Perfetto JSON
