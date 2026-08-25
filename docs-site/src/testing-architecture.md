# Architecture de tests Strat9-OS

> Objectif : non-régression systématique pour chaque module du système — kernel,
> ABI, IPC, mémoire, VFS, drivers, composants userspace (Silos/Strates).
>
> Statut initial constaté : ~66 `#[test]` dans tout le workspace, concentrés sur
> `ipc/lockfree_ring`, `xfs-rs` et `fs-abstraction`. Aucun stage de test en CI.
> `cargo test --workspace` échoue côté hôte (`duplicate lang item panic_impl`)
> car le kernel et les composants sont `#![no_std]` ciblant `x86_64-unknown-none`.

## 1. Les 5 couches de test (pyramide)

```
        ┌─────────────────────────────────────┐
   L4   │  Tests end-to-end QEMU (ISO boot)    │  lents, few, high value
        ├─────────────────────────────────────┤
   L3   │  Self-tests kernel in-QEMU           │  (feature `selftest`)
        ├─────────────────────────────────────┤
   L2   │  Unit tests no_std on host           │  pure logic, gated
        ├─────────────────────────────────────┤
   L1   │  Unit tests host (std)               │  ABI, parsers, codecs
        ├─────────────────────────────────────┤
   L0   │  Static ABI conformance assertions   │  compile-time
        └─────────────────────────────────────┘
```

### L0 — Conformance ABI statique (compile-time)
- `static_assertions::assert_eq_size!` / `assert_eq_align!` / `const_assert!`
  sur **toutes** les structures `#[repr(C)]` traversant la frontière kernel ↔ userspace.
- Golden values des numéros de syscall : tout changement est une rupture d'ABI
  et doit être un commit explicite + bump de `ABI_VERSION_MINOR`.
- Fichier : `workspace/abi/tests/abi_stability.rs`.

### L1 — Tests unitaires hôte (std)
Tout ce qui est logique pure sans dépendance matérielle :
- crate `strat9-abi` entière (errno, flags, parsing IP, codec IPC, payloads) ;
- math safe (`safe_math`), unicode, parseurs TOML de boot ;
- conversions POSIX ↔ Strat9 (musl-compat, relibc shims).
- Exécution : `cargo test -p <crate>` — doit rester **vert en permanence**.

### L2 — Tests unitaires `no_std` sur hôte
Pour la logique kernel testable sans matériel (allocateurs, anneaux IPC,
tables de capabilities, routage de schemes) :
- Pattern recommandé : extraire la logique pure dans des modules sans dépendance
  arch (`mod pure`), tester ces modules avec `#[cfg(test)]` compilés pour hôte ;
- Alternative : harness de test custom embarqué dans l'image (voir L3).

### L3 — Self-tests kernel in-QEMU (feature `selftest`)
Le kernel dispose déjà de `cargo make kernel-test` + `selftest.rs`.
Convention à généraliser :
- chaque sous-système déclare une fonction `<module>_selftest() -> Result`;
- l'orchestrateur affiche `[selftest] PASS/FAIL <name>` sur le port série ;
- sortie vérifiable mécaniquement : grep `SELFTEST-FAIL` sur la sortie série.

### L4 — Tests d'intégration bout-en-bout QEMU
Silos utilisateurs dédiés (`test_mem_region`, `test_exec`, …) lancés depuis
l'initfs ; le harnais QEMU vérifie la sortie série (`TEST-PASS`/`TEST-FAIL`)
avec timeout. Cible cargo-make unique : `cargo make ci-qemu-tests`.

## 2. Matrice module → couches

| Module | L0 | L1 | L2 | L3 | L4 |
|---|---|---|---|---|---|
| `strat9-abi` | ✅ | ✅ | — | — | — |
| `kernel/ipc` (codec, rings, mailbox) | ✅ | ✅* | ✅ | ✅ | ✅ |
| `kernel/memory` (buddy, heap, cow) | — | partiel | ✅ | ✅ | ✅ (`test_mem_region`) |
| `kernel/process` (sched, signals, futex) | — | — | ✅ | ✅ | ✅ |
| `kernel/vfs` (schemes, router, ramfs) | — | — | ✅ | ✅ | ✅ |
| `strate-fs-abstraction` | — | ✅ | — | — | ✅ |
| `strate-fs-ext4/ramfs` | — | partiel | — | — | ✅ |
| drivers (e1000, virtio, ahci) | — | partiel | — | ✅ | ✅ (loopback QEMU) |

\* via extraction `pure` ou duplication contrôlée des constantes.

## 3. Conventions

1. **Nommage** : `tests/<module>_*.rs` (intégration), `#[cfg(test)] mod tests`
   (unitaires in-crate quand le crate compile en std pour les tests).
2. **Un test = un comportement** ; tables de cas (`for case in CASES`) privilégiées
   pour les parseurs/codecs.
3. **Golden values** pour toute constante cross-binaire (numéros syscall, layouts,
   opcodes IPC) : la régression est détectée même si aucun consumer n'est compilé.
4. **Roundtrip systématique** pour codecs : `decode(encode(x)) == x` + tests de
   corruption/troncature (bytes aléatoires déterministes, pas de RNG non seedé).
5. Chaque PR qui touche un module doit être accompagnée des tests de sa couche.

## 4. CI (roadmap)

Stage GitLab `test` entre `build` et `release` :
1. `cargo test --workspace --exclude strat9-kernel ...` (crates host-safe) ;
2. build kernel `--features selftest` (garde la compilation des selftests) ;
3. job optionnel QEMU : boot ISO + grep série (runner avec qemu-system-x86_64).

## 5. Questions ouvertes (à arbitrer)

1. **Base de branche** : branchée sur le HEAD de `fix/ipc-scheme-security-review`
   (5078255). Si vous préférez une base `main`, rebase trivial (fichiers nouveaux uniquement).
2. **L2 kernel-hôte** : préférer l'extraction de modules purs (refactor plus large,
   meilleure couverture) ou dupliquer les tests in-QEMU (zéro refactor, exécution
   plus lente) ? Recommandation : extraction progressive, en commençant par IPC.
3. **QEMU en CI** : un runner GitLab avec KVM/qemu est-il disponible ? Sinon TCG
   (lent mais suffisant pour L3/L4 courts).
