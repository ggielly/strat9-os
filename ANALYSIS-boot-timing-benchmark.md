# Analyse : Boot timing + infrastructure de benchmark kernel

> Date : 2026-03-19 — À reprendre dans une session future.

## Contexte

Le kernel strat9-os n'affiche aucun temps écoulé pendant le boot. Les milestones existants
(`e9_println!("B0")`, `B1`, etc.) n'ont pas de timestamp. L'objectif est d'ajouter :

1. Un compteur TSC (`rdtsc`) exposé dès le premier cycle — seule source de temps fiable avant que l'APIC timer ne démarre
2. Des timestamps visibles sur chaque phase du boot via `serial_println!`
3. Une infrastructure légère de benchmark avec compteurs atomiques autour des sections critiques (IRQ, scheduler), exposés via les logs existants

## État des lieux

### Sources de temps existantes

| Source | Disponible quand | Granularité | Fichier |
|---|---|---|---|
| TSC (`rdtsc`) | Dès le 1er cycle | ~ns | **N'existe pas encore** — à ajouter |
| PIT (legacy) | Après `init_pit()` | 10ms (100Hz) | `arch/x86_64/timer.rs` |
| APIC Timer | Après calibration + `start_apic_timer_cached()` | 10ms (100Hz) | `arch/x86_64/timer.rs` |
| `TICK_COUNT` | Après scheduler init + timer start | 10ms | `process/scheduler/timer_ops.rs:220` — fn `ticks()` |
| `current_time_ns()` | Après scheduler | 10ms (dérivé de ticks) | `syscall/time.rs:21` |

### Constantes timer

- `TIMER_HZ = 100` (10ms par tick)
- `NS_PER_TICK = 10_000_000`
- PIT base : 1,193,182 Hz
- APIC divider : 16, calibré via PIT channel 2 (~10ms one-shot)

### Métriques scheduler existantes (dans `process/scheduler.rs`)

Compteurs per-CPU déjà présents :
- `CPU_TOTAL_TICKS`, `CPU_IDLE_TICKS`
- `CPU_RT_RUNTIME_TICKS`, `CPU_FAIR_RUNTIME_TICKS`
- `CPU_SWITCH_COUNT`, `CPU_PREEMPT_COUNT`
- `CPU_STEAL_IN_COUNT`, `CPU_STEAL_OUT_COUNT`
- `CPU_TRY_LOCK_FAIL_COUNT`

Snapshot functions : `cpu_usage_snapshot()`, `scheduler_metrics_snapshot()`, `reset_scheduler_metrics()`

Exposés via commande shell `uptime` (`shell/commands/util/mod.rs:29`) et `top`.

### Boot milestones existants (sans timestamp)

Dans `lib.rs` — `kernel_main()` :
```
B0  kernel_main entry          (~ligne 355)
B1  pre-IDT                    (~ligne 364)
B2  post-IDT                   (~ligne 368)
B5  pre-paging                 (après memory)
B6  post-paging                (après VMM)
B7  pre-scheduler              (~ligne 791)
B8  post-scheduler             (~ligne 797)
B9  pre-kthread                (~ligne 825)
BB  pre-process                (~ligne 860)
BG  pre-hardware               (~ligne 876)
BH  post-hardware              (~ligne 880)
```

### Macros de sortie

| Macro | Backend | Locks | Usage |
|---|---|---|---|
| `e9_println!` | Port 0xe9 (QEMU) | Aucun | Boot ultra-early, debug |
| `serial_println!` | UART 0x3F8 | Mutex (try_lock en IRQ) | Output normal |
| `serial_force_println!` | UART 0x3F8 | Raw spinlock + IRQ off | Panic/urgence |
| `log::info!` etc. | Serial via logger | Même que serial | Logging structuré |
| `vga_println!` | Framebuffer/VGA | — | Console graphique |

---

## Plan d'implémentation

### Étape 1 : Ajouter `rdtsc()` dans `arch/x86_64/mod.rs`

Wrapper inline à côté de `rdmsr`, `cpuid`, etc. (~ligne 207) :

```rust
#[inline]
pub fn rdtsc() -> u64 {
    let eax: u32;
    let edx: u32;
    unsafe {
        asm!("rdtsc", out("eax") eax, out("edx") edx, options(nomem, nostack));
    }
    ((edx as u64) << 32) | eax as u64
}
```

### Étape 2 : Créer `arch/x86_64/boot_timestamp.rs`

Module nouveau :

- `static BOOT_TSC: AtomicU64` — TSC capturé au tout début de `kernel_main`
- `static TSC_KHZ: AtomicU64` — fréquence TSC estimée (calibrée pendant l'init APIC timer, ou via CPUID leaf 0x15/0x16)
- `init()` — capture `BOOT_TSC = rdtsc()`
- `calibrate(known_interval_ns: u64, tsc_delta: u64)` — appelé après calibration APIC timer pour affiner TSC_KHZ
- `elapsed_ms() -> u64` — `(rdtsc() - BOOT_TSC) / TSC_KHZ`
- `elapsed_us() -> u64` — même chose en microsecondes

Fallback pré-calibration : estimation QEMU raisonnable (2 GHz = 2_000_000 KHz), affinée après calibration APIC.

Ajouter `pub mod boot_timestamp;` dans `arch/x86_64/mod.rs`.

### Étape 3 : Macro `boot_milestone!` dans `debug.rs`

```rust
#[macro_export]
macro_rules! boot_milestone {
    ($tag:expr) => {
        serial_println!(
            "[boot +{:>8}ms] {}",
            $crate::arch::x86_64::boot_timestamp::elapsed_ms(),
            $tag
        );
    };
}
```

### Étape 4 : Instrumenter `kernel_main` dans `lib.rs`

Ajouter `boot_timestamp::init()` après `init_serial()/init_logger()` (ligne ~356).

Remplacer les `serial_println!("[init] ...")` aux points clés par `boot_milestone!(...)` :

```
[boot +       0ms] kernel entry
[boot +       1ms] IDT initialized
[boot +      12ms] Memory manager ready
[boot +      45ms] Paging initialized
[boot +      78ms] APIC + SMP ready (2 CPUs)
[boot +     102ms] Scheduler initialized
[boot +     150ms] Hardware drivers ready
```

Garder les `e9_println!("B0")` etc. existants.

Points d'insertion dans `lib.rs` :
- Ligne ~355 : `boot_timestamp::init()` + premier milestone
- Ligne ~368 : post-IDT
- Ligne ~463 : post-memory
- Ligne ~608 : post-paging
- Ligne ~786 : post-SMP
- Ligne ~818 : post-scheduler + timer
- Ligne ~880 : post-hardware

### Étape 5 : Compteurs de benchmark pour sections critiques

Nouveau fichier `process/scheduler/perf_counters.rs` :

```rust
pub static IRQ_ENTER_COUNT: AtomicU64 = AtomicU64::new(0);
pub static IRQ_TOTAL_TSC: AtomicU64 = AtomicU64::new(0);
pub static SCHED_LOCK_COUNT: AtomicU64 = AtomicU64::new(0);
pub static SCHED_LOCK_TOTAL_TSC: AtomicU64 = AtomicU64::new(0);
pub static CTX_SWITCH_COUNT: AtomicU64 = AtomicU64::new(0);
pub static CTX_SWITCH_TOTAL_TSC: AtomicU64 = AtomicU64::new(0);
```

Helper RAII léger :

```rust
pub struct PerfScope {
    start: u64,
    accumulator: &'static AtomicU64,
    counter: &'static AtomicU64,
}

impl Drop for PerfScope {
    fn drop(&mut self) {
        let elapsed = rdtsc() - self.start;
        self.accumulator.fetch_add(elapsed, Ordering::Relaxed);
        self.counter.fetch_add(1, Ordering::Relaxed);
    }
}
```

Instrumenter :
- `timer_tick()` dans `timer_ops.rs` — entrée/sortie IRQ timer
- `yield_task()` / `maybe_preempt()` dans `runtime_ops.rs` — lock scheduler
- `finish_interrupt_switch()` dans `runtime_ops.rs` — context switch

Ajouter `pub mod perf_counters;` dans `process/scheduler/mod.rs`.

### Étape 6 : Exposer via commande shell `uptime`

Enrichir `cmd_uptime_impl()` dans `shell/commands/util/mod.rs` :

```
up 00:05:32  (33200 ticks @ 100 Hz)  12 tasks, 3 silos
perf: irq_timer avg=1.2us (33200 calls)  sched_lock avg=0.8us (1205 calls)  ctx_switch avg=3.4us (890 calls)
```

Conversion TSC→µs via `TSC_KHZ`.

---

## Fichiers à modifier/créer

| Fichier | Action |
|---|---|
| `workspace/kernel/src/arch/x86_64/mod.rs` | Ajouter `rdtsc()`, `pub mod boot_timestamp` |
| `workspace/kernel/src/arch/x86_64/boot_timestamp.rs` | **Nouveau** — module TSC + elapsed |
| `workspace/kernel/src/debug.rs` | Ajouter macro `boot_milestone!` |
| `workspace/kernel/src/lib.rs` | Appel `boot_timestamp::init()` + milestones dans `kernel_main` |
| `workspace/kernel/src/process/scheduler/perf_counters.rs` | **Nouveau** — compteurs AtomicU64 + PerfScope |
| `workspace/kernel/src/process/scheduler/mod.rs` | Ajouter `pub mod perf_counters` |
| `workspace/kernel/src/process/scheduler/timer_ops.rs` | Instrumenter `timer_tick()` |
| `workspace/kernel/src/process/scheduler/runtime_ops.rs` | Instrumenter `yield_task()`, `finish_interrupt_switch()` |
| `workspace/kernel/src/shell/commands/util/mod.rs` | Enrichir `cmd_uptime_impl()` avec stats perf |

## Vérification

1. `cargo make build-kernel-test` — compile sans erreur
2. `cargo make run-test-headless` — le boot affiche les timestamps `[boot +XXXms]`
3. Commande shell `uptime` — affiche les compteurs perf avec moyennes en µs
4. Les timestamps sont monotoniquement croissants
5. Après calibration APIC, les valeurs ms sont réalistes (~100-500ms pour un boot complet sous QEMU)
