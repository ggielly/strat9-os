# Strat9-OS : Architecture IPC : Modèle d'Isolation Hybride à 3 Niveaux

**Version** : 0.1.0  
**Date** : 2026-06-23  
**Statut** : Draft pour relecture architecturale  
**Auteur** : Guillaume Gielly  

---

## Table des matières

1. [Résumé exécutif](#1-résumé-exécutif)
2. [Problématique](#2-problématique)
3. [Fondations académiques](#3-fondations-académiques)
4. [Architecture actuelle : Analyse](#4-architecture-actuelle--analyse)
5. [Le modèle à 3 niveaux : Spécifications](#5-le-modèle-à-3-niveaux--spécifications)
6. [Niveau 1 : SFI (Software Fault Isolation)](#6-niveau-1-sfi-software-fault-isolation)
7. [Niveau 2 : Shared Memory Lock-Free](#7-niveau-2-shared-memory-lock-free)
8. [Niveau 3 : Isolation MMU Stricte](#8-niveau-3-isolation-mmu-stricte)
9. [Le NIC comme premier cas d'usage](#9-le-nic-comme-premier-cas-dusage)
10. [Modèle de sécurité](#10-modèle-de-sécurité)
11. [Analyse de performance](#11-analyse-de-performance)
12. [Plan d'implémentation](#12-plan-dimplémentation)
13. [Questions ouvertes](#13-questions-ouvertes)
14. [Annexes](#14-annexes)

---

## 1. Résumé exécutif

Ce document définit l'architecture IPC de Strat9-OS à travers un **modèle d'isolation hybride à 3 niveaux**. Chaque silo communique via un transport dont le niveau de confiance est déterminé au chargement.

| Niveau | Nom | Mécanisme | Isolation | Overhead |
|--------|-----|-----------|-----------|----------|
| **N1** | SFI | Appels de fonctions directs | Par confiance (Rust types) | ~3 cycles |
| **N2** | Shared Memory | Ring buffer atomique + futex | Par MMU (Ring 3) | ~200 cycles |
| **N3** | MMU Stricte | SYSCALL + Thread Migration | Par MMU (Ring 3 hermétique) | ~460 cycles |

**Objectif** : Le NIC utilise le Niveau 2 pour le data plane avec latence ~20× meilleure que l'IPC syscall actuel.

---

## 2. Problématique

### 2.1 Coût IPC actuel

```
Silos A → syscall → kernel → lock → copy → scheduler → syscall → Silos B
```

**Coût** : ~4000 cycles/message. Inacceptable pour du réseau à haut débit.

### 2.2 Dichotomie kernel-bypass vs kernel-based (Xu & Roscoe, HotOS 2025)

| Approche | Performance | Flexibilité | Isolation |
|----------|-------------|-------------|-----------|
| Kernel-bypass (DPDK) | Excellente | Faible | Faible |
| Kernel-based (Linux) | Moyenne | Excellente | Excellente |
| **Notre approche** | **Excellente (N2)** | **Excellente (N1)** | **Excellente (N3)** |

---

## 3. Fondations académiques

| Source | Principe | Niveau |
|--------|----------|--------|
| **SFI via Rust types** (VMware/HotOS) | Ownership/lifetimes = isolation gratuite | N1 |
| **Thread Migration L4** (Liedtke) | Transfert quantums CPU sans scheduler | N3 |
| **Singularity SIPs** (MSR) | Canaux typés sans MMU | N1 |
| **Tock Hybride** (SOSP) | Ring 0 Safe + Ring 3 MMU | Architecture globale |
| **NIC intégré** (Xu/Roscoe) | NIC = composant kernel trusté | NIC driver |

---

## 4. Architecture actuelle

### Composants IPC existants

```
ipc/port.rs          → Port (sync message-passing, lock-based)
ipc/channel.rs       → Channel (typed MPMC) + SyncChan
ipc/shared_ring.rs   → SharedRing (memory-mapped, pas lock-free)
ipc/semaphore.rs     → PosixSemaphore
ipc/reply.rs         → Request-reply pattern
```

### Path critique réseau actuel

```
NIC IRQ → NIC driver → copie Vec<u8> → net_recv() syscall → strate-net →
net_send() syscall → NIC driver → copie → NIC TX ring
```

**Overhead** : ~4000 cycles (2 syscalls).

---

## 5. Interface uniforme

```rust
pub trait IpcTransport: Send + Sync {
    fn send(&self, target: SiloId, msg: &[u8]) -> Result<(), IpcError>;
    fn recv(&self, buf: &mut [u8]) -> Result<usize, IpcError>;
    fn try_send(&self, target: SiloId, msg: &[u8]) -> Result<(), IpcError>;
    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<usize>, IpcError>;
    fn notify(&self);
}
```

### Matrice de décision (au chargement)

```
Manifeste CMOD v3 :
  ├─ 100% Rust Safe + cargo_geiger=0 ? → N1 (SFI)
  ├─ Haut débit + Ring 3 ?            → N2 (Shared Memory)
  └─ Tiers / legacy / unsafe ?        → N3 (MMU)
```

---

## 6. Niveau 1 : SFI (Software Fault Isolation)

**Privilege** : Ring 0  
**Transport** : Appels de fonctions directs via Arc/Box  
**Overhead** : ~3 cycles  
**Isolation** : Par confiance (Rust types), pas de MMU  

```rust
pub struct SfiTransport;
impl IpcTransport for SfiTransport {
    fn send(&self, target: SiloId, msg: &[u8]) -> Result<(), IpcError> {
        let silo = get_silo(target)?; // Pas de lock, pas de copy
        silo.enqueue_message(msg)?;
        Ok(())
    }
    fn recv(&self, buf: &mut [u8]) -> Result<usize, IpcError> {
        let current = current_silo()?;
        let msg = current.dequeue_message()?;
        let n = core::cmp::min(msg.len(), buf.len());
        buf[..n].copy_from_slice(&msg[..n]);
        Ok(n)
    }
}
```

**Garanties** : Le compilateur Rust empêche les bugs mémoire. Pas de protection contre les logic bugs. Audit obligatoire (cargo geiger = 0 unsafe).

**Cas d'usage** : Communication kernel<==>kernel (scheduler <==> NIC driver, scheduler <==> VFS).

---

## 7. Niveau 2 : Shared Memory Lock-Free

**Privilege** : Ring 3 (MMU isolé)  
**Transport** : Ring buffer atomique + futex notification  
**Overhead** : ~200 cycles  
**Isolation** : Par MMU  

### Layout mémoire

```
Page partagée (4096B) :
┌──────────────────────────────────────────┐
│ Header (64B) : magic, size, head, tail   │
├──────────────────────────────────────────┤
│ Ring buffer : N slots × (2 + slot_size)  │
└──────────────────────────────────────────┘
```

### Algorithme SPSC lock-free

```rust
fn ring_write(ring: &RingHeader, data: &[u8]) -> Result<(), RingError> {
    let tail = ring.tail.load(Ordering::Acquire);
    let head = ring.head.load(Ordering::Acquire);
    let next = (tail + 1) % ring.ring_size;
    if next == head { return Err(RingError::Full); }
    let slot = &ring.slots[tail as usize];
    let len = data.len().min(ring.slot_size as usize);
    slot.len.store(len as u16, Ordering::Relaxed);
    slot.data[..len].copy_from_slice(data);
    core::sync::atomic::fence(Ordering::Release);
    ring.tail.store(next, Ordering::Release);
    Ok(())
}

fn ring_read(ring: &RingHeader, buf: &mut [u8]) -> Result<usize, RingError> {
    let head = ring.head.load(Ordering::Acquire);
    let tail = ring.tail.load(Ordering::Acquire);
    if head == tail { return Err(RingError::Empty); }
    let slot = &ring.slots[head as usize];
    let len = slot.len.load(Ordering::Acquire) as usize;
    let n = len.min(buf.len());
    buf[..n].copy_from_slice(&slot.data[..n]);
    slot.len.store(0, Ordering::Release);
    ring.head.store((head + 1) % ring.ring_size, Ordering::Release);
    Ok(n)
}
```

### Notification via futex

```rust
// Consommateur
while ring_is_empty() { futex_wait(&futex_var, expected); }
ring_read(ring, buf);

// Producteur
ring_write(ring, data);
futex_wake(&futex_var, 1);
```

**Note** : UMONITOR/UMWAIT non recommandé (latence ~50-100µs, ne peut pas être réveillé par le kernel sans IRQ). Futex préféré.

**Cas d'usage** : NIC <==> strate-net, VFS <==> storage, framebuffer <==> display server.

---

## 8. Niveau 3 : Isolation MMU Stricte

**Privilege** : Ring 3 (ASpace séparé)  
**Transport** : SYSCALL + Thread Migration (L4-style)  
**Overhead** : ~460 cycles  
**Isolation** : Par MMU (hermétique)  

### Thread Migration

```rust
unsafe fn thread_migration(from: &TaskContext, to: &TaskContext) {
    // 1. Sauvegarder FPU/SSE (~100 cycles)
    // 2. Changer CR3 (address space) (~30 cycles)
    // 3. Restaurer registres du silo cible
    // 4. Saute au handler du silo B
}
```

**Risques** : Page faults, kernel preemption, stack overflow.  
**Mitigations** : Timeout, vérification pile au chargement, CLI/STI pair.

**Cas d'usage** : Drivers tiers, code legacy, modules non audités.

---

## 9. Le NIC comme premier cas d'usage

### Path optimisé avec N2

```
Packet arrive → NIC IRQ → NIC driver écrit dans RX ring →
futex_wake → strate-net lit le ring (0 syscall) →
traite le packet → écrit dans TX ring → NIC driver lit et envoie
```

**Overhead** : ~200 cycles (vs ~4000 cycles actuellement).

### Shared State NIC <==> Scheduler

```rust
#[repr(C)]
struct NicRoutingTable {
    count: AtomicU32,
    entries: [RoutingEntry; MAX_ROUTES], // {silo_id, core, state, rpc_count}
}
```

Le kernel met à jour à chaque context switch. Le NIC lit pour router les packets.

### Load-Aware Scheduling

```
Si rpc_pending[silo_X] > seuil_high → allouer un core
Si rpc_pending[silo_Y] < seuil_low → déscheduler
```

---

## 10. Modèle de sécurité

| Action | N1 (SFI) | N2 (Shared) | N3 (MMU) |
|--------|----------|-------------|----------|
| Lire mémoire kernel | Oui | Non | Non |
| Écrire mémoire kernel | Oui | Non | Non |
| Accéder scheduler state | Oui | Via table partagée | Non |
| Crash = kernel crash | Oui | Non | Non |

**Vérification au chargement** : cargo_geiger (0 unsafe → N1), dépendances C/C++ → N3.

---

## 11. Analyse de performance

| Métrique | Actuel | N1 | N2 | N3 |
|----------|--------|----|----|-----|
| Round-trip 64B | ~4000 cycles | ~6 | ~200 | ~460 |
| Latence RX packet | ~4000 cycles | ~3 | ~100 | ~230 |
| CPU usage/pkt | ~2% | ~0.01% | ~0.2% | ~0.5% |

---

## 12. Plan d'implémentation

| Phase | Description | Durée | Priorité |
|-------|-------------|-------|----------|
| 1 | Shared Memory Ring (N2) + futex | 2 sem | Haute |
| 2 | NIC + Shared Memory | 3 sem | Haute |
| 3 | SFI Transport (N1) | 1 sem | Moyenne |
| 4 | MMU Isolation + Thread Migration (N3) | 4 sem | Basse |
| 5 | NIC Scheduler Integration | 2 sem | Basse |

---

## 13. Questions ouvertes

1. Taille optimale du ring buffer (4K vs 16K) ?
2. Futex vs eventfd pour la notification ?
3. Multi-consumer support nécessaire ?
4. Backpressure quand le ring est plein ?
5. Sécurité du ring par un silo Ring 3 ?
6. Coût XSAVE dans la Thread Migration (~100 cycles) ?

---

## 14. Annexes

### Références

1. Xu, P., Roscoe, T. (2025). *The NIC should be part of the OS*. HotOS'25.
2. Liedtke, J. (1995). *On µ-Kernel Construction*. SOSP.
3. Hunt, G.C., Larus, J.R. (2007). *Singularity: Rethinking the Software Stack*.
4. Levy, A. et al. (2017). *Tock*. SOSP.
5. VMware Research. *System Programming in Rust: Beyond Safety*.
6. Axboe, J. (2019). *Efficient IO with io_uring*.

### Matériel cible

| Composant | Strat9-OS | ThinkPad X13 |
|-----------|-----------|--------------|
| CPU | x86_64 | Intel 11th gen |
| NIC | e1000e | Intel I219-V |
| RAM | 256 MB (QEMU) | 16 GB DDR4 |
| MMU | 4-level paging | 4-level paging |
| CXL | Non | Non (PCIe 4.0) |
