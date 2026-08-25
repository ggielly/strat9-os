# Rapport de tests — findings

> Issues découvertes par la suite anti-régression (`test/anti-regression-suite`).
> Chaque finding est référencé par un test qui le documente/pinne.

## F1 — Build kernel cassé par le nightly non épinglé (bloquant) — ✅ RÉSOLU
Épinglé sur `nightly-2026-08-20` (dernier bon vérifié : bisect 08-20 OK /
08-23 cassé, cause PR rust-lang/rust#160302 mergé le 23/08 à 21:33 UTC,
commit fb6531d550e0). Le code exige en outre `Step::forward/backward_overflowing`
(PR #155114, 09/07/2026) ⇒ fenêtre compatible [2026-07-10 .. 2026-08-22].
Correctif associé : `[profile.dev] opt-level = 0 → 1` car O0 déclenche une
ICE LLVM distincte (#158532) sur les intrinsèques AVX2. Builds debug,
release, selftest et gate hôte tous vérifiés verts.
`framebuffer/x86/avx2.rs` utilise `#[target_feature(enable = "avx2")]`.
Sur `rustc 1.100.0-nightly`, activer sse/avx sur une cible soft-float
(`x86_64-unknown-none`) est une **erreur dure** (lint `x86_softfloat_sse`).
`cargo make kernel` échoue sur toutes les branches.
**Options** :
1. (recommandé, immédiat) Épingler l'outilchain : `channel = "nightly-2026-06-xx"`
   dans `rust-toolchain.toml` — dernière version connue fonctionnelle ;
2. (long terme) Adapter `avx2.rs` : runtime detection + assembly inline
   ou wrapper compilé sans soft-float constraint.

## F2 — `VfsTimestamp::to_filetime` déborde — ⏳ à faire
`(secs + WINDOWS_EPOCH_OFFSET) as u64 * 10_000_000` sans arithmetic checkée :
panic debug / wrap release au-delà de ~an 60000. Entrée contrôlée par le disque
ou le réseau (chemins stat) ⇒ à traiter comme entrée hostile.
**Fix proposé** : `checked_mul` → `FsError::ArithmeticOverflow`.

## F3 — `FsCapabilities::xfs()/btrfs()` : valeurs PiB au lieu de EiB — ✅ RÉSOLU
XFS = 8 EiB réels ; btrfs clampé à u64::MAX (16 EiB = 2^64). Tests mis à jour.
Commentaires « 8 EiB »/« 16 EiB », chaînes littérales à 5 facteurs `1024`
⇒ valeurs réelles 8 **PiB** / 16 **PiB** (16 EiB ne tient même pas dans u64).
Décider : corriger les commentaires ou l'arithmétique.

## F4 — `parse_ipv6_literal` sur-accepte le `::` — ⏳ à durcir (RFC 4291)
RFC 4291 interdit `::` quand 8 groupes explicites sont déjà présents ;
le parseur accepte `1:2:3:4:5:6:7:8::`. Sans danger immédiat (sortie bien
formée) mais à durcir pour la conformité.

## F5 — `OpenReply` n'implémente pas `KnownLayout` — ✅ RÉSOLU
`KnownLayout` dérivé via zerocopy (déjà dépendance) sur toute la surface
de payloads `repr(C)` + `InlineBlobHeader`. Test de regression roundtrip
`decode_fixed` ajouté pour chaque struct fixe.

## F6 — `ENOTSUP = 52` n'est pas la valeur Linux — ✅ RÉSOLU
Renommé 52 → 95 (= Linux x86_64) : constante ABI, selftest kernel,
tests golden, entrée changelog ABI.

## F7 — Test unitaire préexistant cassé depuis longtemps
`strate-fs-abstraction/tests/unit_tests.rs` importait `fs_abstraction`
(ancien nom de crate) : aucun test de cette crate ne tournait depuis le
renommage. Corrigé — preuve que l'absence de CI de test laisse pourrir
la couverture silencieusement.

## F8 — Constantes POSIX fausses dans `strat9_syscall::flag` — ✅ RÉSOLU
Trouvé lors de la passe 2 par la table dorée Linux :
- `O_NOFOLLOW = 0o100000` → en réalité **O_CLOEXEC** sur Linux ; corrigé à `0o400000` ;
- `O_NOCTTY = 0o400000` → en réalité **O_NOFOLLOW** sur Linux (!) ; corrigé à `0o000400`,
  détecté par le test doré lui-même après le premier fix ;
- `O_DSYNC = 0o02000000` → **O_CLOEXEC** aussi ; corrigé à `0o10000`.
La traduction `posix_oflags_to_strat9` (crate abi) utilisait ses propres copies
correctes — mais tout composant consommant ces constantes directement cassait.
Leçon : les tables dorées attrapent ce que la relecture manuelle rate.

## Couverture ajoutée (L0/L1)

| Suite | Tests | Périmètre |
|---|---|---|
| `abi/tests/abi_stability.rs` | 10 | golden syscalls (169), layouts, magics |
| `abi/tests/errno_abi.rs` | 4 | valeurs Linux, convention de détection |
| `abi/tests/flags_translation.rs` | 8 | POSIX↔Strat9 exhaustif (1536 combos) |
| `abi/tests/ip_parsing.rs` | 9 | IPv4/IPv6 edge cases |
| `abi/tests/ipc_codec_roundtrip.rs` | 16 | codec bornes/roundtrip/endian |
| `abi/tests/ipc_payload_wire.rs` | 12 | wire format schemes VFS |
| `fs-abstraction/tests/safe_math_edge_cases.rs` | 23 | arith safe exhaustive |
| `fs-abstraction/tests/types_conformance.rs` | 13+1 | mode bits, FILETIME, caps |
| `abi/tests/ipc_handshake.rs` | 8 | handshake IPC wire + validation réservés |
| `abi/tests/data_types.rs` | 9 | SiloMode, DirentHeader, PCI, tailles structs |
| `syscall/tests/error_and_flags.rs` | 8 | Error↔errno roundtrip, demux RAX, flags Linux |
| `syscall/tests/dirent_wire.rs` | 10 | getdents packed parsing, SchemeV2, SigAbi |
| `intel-ethernet/tests/descriptors.rs` | 10 | layouts SDM 16B, anneaux Rx/Tx |
| `driver-net-proto/tests/wire_protocol.rs` | 3 | opcodes + headers IPC réseau |
| `alloc-freelist/tests/allocator.rs` | 6 | GlobalAlloc: alignement, réuse, OOM propre |

Porte CI : `cargo make ci-tests` — **162+ tests hôte verts** (stage GitLab `test`).

Porte CI : `cargo make ci-tests` (stage GitLab `test`, job `test-host`).

## Prochaines étapes proposées (L2/L3/L4)
1. L2 kernel-hôte : extraire la logique pure IPC/mémoire en modules testables hôte.
2. L3 : généraliser le pattern selftest (`PASS/FAIL` série grep-able) à tous
   les sous-systèmes kernel.
3. L4 : harnais QEMU automatisé (boot ISO + grep série + timeout) en job GitLab.
