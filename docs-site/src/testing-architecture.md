# Architecture de tests Strat9-OS

> Objectif : non-régression systématique pour chaque module du système — kernel,
> ABI, IPC, mémoire, VFS, drivers, composants userspace (Silos/Strates).

## 1. Les 5 couches de test (pyramide)

```
        ┌─────────────────────────────────────┐
   L4   │  Tests end-to-end QEMU (ISO UEFI)    │  lents, peu, forte valeur
        ├─────────────────────────────────────┤
   L3   │  Self-tests kernel in-QEMU           │  (feature `selftest`)
        ├─────────────────────────────────────┤
   L2   │  Unit tests no_std sur hôte           │  logique pure, modules réels
        ├─────────────────────────────────────┤
   L1   │  Unit tests hôte (std)               │  ABI, parseurs, codecs
        ├─────────────────────────────────────┤
   L0   │  Assertions de conformité ABI        │  compile-time
        └─────────────────────────────────────┘
```

### L0 — Conformance ABI statique (compile-time)

- `assert_eq_size!` / `assert_eq_align!` sur **toutes** les structures `#[repr(C)]`
  traversant la frontière kernel ↔ userspace.
- Golden values des numéros de syscall : tout changement est une rupture d'ABI
  et doit être un commit explicite + bump de `ABI_VERSION_MINOR`.
- Fichier : `workspace/abi/tests/abi_stability.rs`.

### L1 — Tests unitaires hôte (std)

Tout ce qui est logique pure sans dépendance matérielle :
- crate `strat9-abi` entière (errno, flags, parsing IP, codec IPC, payloads) ;
- math safe (`safe_math`), Unicode, parseurs TOML de boot ;
- conversions POSIX ↔ Strat9 (musl-compat, relibc shims).

Exécution : `cargo make test-host` (paquet de crates, target `x86_64-unknown-linux-gnu`)
et `cargo make test-host-alloc` (variantes `alloc`). Les deux doivent rester **verts**.

### L2 — Tests unitaires `no_std` sur hôte

Pour la logique kernel testable sans matériel (allocateurs, anneaux IPC,
tables de capabilities, routage de schemes). Pattern retenu : la crate ombre
`workspace/kernel-l2-tests` compile les modules purs du kernel **verbatim**
(`#[path]`) dans une crate hôte qui fournit des fakes fonctionnels :
`sync/irq` (token factice), `arch/x86_64/percpu` (compteurs), `silo`,
translation HHDM (offset réel vers une arena hôte, donc l'allocateur buddy
travaille sur de la vraie mémoire). Les tests inline `#[cfg(test)]` du kernel
s'exécutent enfin. Cible : `cargo make test-kernel-l2`.

**Modules couverts** (state current) :

| Domaine | Modules |
|---------|---------|
| Mémoire | `memory/{boot_alloc, zone, frame, buddy}` — compilés verbatim |
| Sync | `sync/{fixed_queue, guardian, spinlock}` |
| IPC | `ipc/{message, lockfree_ring, mailbox}`, `ipc/channel` |
| VFS | routage de schemes (`kernel_vfs_scheme`, `kernel_vfs_fd`), pipes |
| Nommage | `namespace` |
| Boot | `boot/toml`, `boot/entry`, et les chemins `boot/{graphics, handoff, initfs, memory, transition}` |
| Syscall | mapping d'erreurs (`mirror/syscall.rs`) |
| Ordonnancement | `process/sched_classes/nice.rs` (nice → `sched_nice`) |

> Les « prochains candidats » `ipc/channel` et le routeur de schemes `vfs`
> mentionnés dans les versions précédentes de cette page sont **désormais couverts**.

### L3 — Self-tests kernel in-QEMU (feature `selftest`)

Le kernel dispose de `cargo make kernel-test` et de
`workspace/kernel/src/process/selftest.rs`. Convention :
- chaque sous-système déclare une fonction `<module>_selftest() -> Result` ;
- l'orchestrateur affiche `[selftest] PASS/FAIL <name>` sur le port série ;
- sortie vérifiable mécaniquement : `tools/scripts/selftest-log.py` reconnaît
  `[selftest] orchestrator start`, `[selftest] orchestrator done` et le marqueur
  de succès `[selftest][strate] PASS`.

### L4 — Tests d'intégration bout-en-bout QEMU

Silos utilisateurs dédiés (`test_mem`, `test_pid`, `test_exec`, …) lancés depuis
l'initfs ; le harnais QEMU vérifie la sortie série avec timeout.

Tâche cargo-make : **`cargo make qemu-tests`** (construit l'ISO UEFI de selftest
puis lance le harnais). Il n'existe pas de tâche `ci-qemu-tests`.

| Outil | Rôle |
|-------|------|
| `tools/scripts/qemu-selftest.sh` | Harnais QEMU : `--timeout`, `--smp`, `--mem`, `--log`, `--iso`, `--image`, `--firmware` |
| `tools/scripts/selftest-log.py` | Analyse du log série et verdict |
| `tools/scripts/create-uefi-image.sh` / `create-iso-uefi.sh` | Construction de l'image et de l'ISO |

---

## 2. Matrice module → couches

| Module | L0 | L1 | L2 | L3 | L4 |
|---|---|---|---|---|---|
| `strat9-abi` | ✅ | ✅ | — | — | — |
| `kernel/ipc` (codec, rings, mailbox, channels) | ✅ | ✅* | ✅ | ✅ | ✅ |
| `kernel/memory` (buddy, frame, boot_alloc) | — | partiel | ✅ | ✅ | ✅ (`test_mem_region`) |
| `kernel/process` (sched, signals, futex) | — | — | ✅ | ✅ | ✅ |
| `kernel/vfs` (schemes, router, pipes) | — | — | ✅ | ✅ | ✅ |
| `kernel/syscall` (mapping d'erreurs) | — | ✅ | ✅ | — | — |
| `strate-fs-abstraction` | — | ✅ | — | — | ✅ |
| `strate-fs-ext4` / `ramfs` | — | partiel | — | — | ✅ |
| `strat9-syscall` (error, dirent, flags) | — | ✅ | — | — | — |
| `strat9-bus-drivers` | — | ✅ (37 tests) | — | — | — |
| drivers (e1000, virtio, ahci) | — | partiel | — | ✅ | ✅ (loopback QEMU) |

\* via la crate ombre L2 ou l'extraction `pure`.

> `strat9-bus-drivers` a une suite de tests hôte de 37 tests répartie sur 7 fichiers,
> mais son crate **ne figure pas** dans la liste de paquets de `test-host`. Ces tests
> ne sont donc pas dans le gate CI actuel.

---

## 3. Conventions

1. **Nommage** : `tests/<module>_*.rs` (intégration), `#[cfg(test)] mod tests`
   (unitaires in-crate quand le crate compile en std pour les tests).
2. **Un test = un comportement** ; tables de cas (`for case in CASES`) privilégiées
   pour les parseurs/codecs.
3. **Golden values** pour toute constante cross-binaire (numéros syscall, layouts,
   opcodes IPC) : la régression est détectée même si aucun consumer n'est compilé.
4. **Roundtrip systématique** pour codecs : `decode(encode(x)) == x` + tests de
   corruption/troncature (octets aléatoires déterministes, pas de RNG non seedé).
5. Chaque PR qui touche un module doit être accompagnée des tests de sa couche.

---

## 4. CI

Stages GitLab (`.gitlab-ci.yml`), **dans cet ordre** :

```text
test  →  test-qemu  →  build  →  release
```

> Les versions précédentes de cette page indiquaient `test` **entre** `build` et
> `release`. C'est faux : `test` est le **premier** stage, et le stage `test-qemu`
> n'existait pas.

| Stage | Jobs | Contenu |
|-------|------|---------|
| `test` | `test-host` | `cargo make test-host` |
| `test` | `build-docs` | Construction du site de documentation |
| `test-qemu` | `build-selftest-iso` | `tools/ci/build-selftest-iso.sh` sur un runner taggé `[qemu, kvm, proxmox]` |
| `test-qemu` | `qemu-proxmox` | `./tools/scripts/qemu-selftest.sh --iso … --timeout 180` — `allow_failure: true` |
| `build` | `build-os-release` | Image de release |
| `release` | `release-latest` | Publication |

Le kernel compilé avec `--features selftest` est construit par `kernel-test`,
qui est **volontairement exclu de `ci-tests`** tant que le pin
`nightly-2026-07-20` n'est pas confirmé vert ; il reste couvert par le job
`qemu-proxmox`.

**Point à surveiller.** Le stage `build` construit encore la release via
`cargo make uboot-image-release`, c'est-à-dire par le chemin U-Boot marqué
`[LEGACY]`, et non par le chemin UEFI (`uefi-image-release`) que la CI QEMU
utilise. Voir `docs/mr-u-boot-replacement.md`.

---

## 5. Questions ouvertes (à arbitrer)

1. **L2 kernel-hôte** : l'extraction de modules purs (refactor plus large,
   meilleure couverture) ou la duplication des tests in-QEMU (zéro refactor,
   exécution plus lente) ? La crate ombre a résolu le problème sans refactor ;
   la question ne se pose plus que pour les modules qui restent couplés à l'arch.
2. **QEMU en CI** : le runner Proxmox est provisionné et `qemu-proxmox` est en
   `allow_failure`. Faut-il le rendre bloquant ?
3. **`test-host` incomplet** : ajouter `strat9-bus-drivers` (37 tests) à la liste
   de paquets, et décider du sort des crates sans suite hôte.
4. **Chemins morts** : `tools/scripts/rebuild-and-test.sh` assemble encore
   `bootloader/asm/x86_64/stage2.asm` par un chemin inexistant et cible le flux
   BIOS retiré ; `tools/scripts/test-boot.sh` démarre une image brute sans
   firmware et est désormais orphelin (la tâche `cargo make test-boot` fait le
   même travail en UEFI). Supprimer ou recâbler ?

## Voir aussi

- [Testing Findings Report](./testing-findings.md) — l'inventaire des findings numérotés et l'état de chaque correctif
- [ABI Overview](./abi.md) — la couche L0 en détail
