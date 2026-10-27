# Rapport de tests — findings

> Issues découvertes par la suite anti-régression (`test/anti-regression-suite`).
> Chaque finding est référencé par un test qui le documente/pinne.
>
> **Comptages de tests recalculés le 2026-09-29** par `grep -c '#\[test\]'` sur
> l'arborescence `workspace/`, hors `target/` et hors `strate-fs-xfs`.

## F1 — Build kernel cassé par le nightly non épinglé — ⚠️ PARTIELLEMENT RÉSOLU

Le diagnostic reste valable : `framebuffer/x86/avx2.rs` utilise
`#[target_feature(enable = "avx2")]`, et sur un nightly récent activer SSE/AVX sur
une cible soft-float (`x86_64-unknown-none`) est une **erreur dure**
(lint `x86_softfloat_sse`).

**Mais l'état réel diffère de ce qu'annonce la version précédente de cette page :**

| Élément | Documenté ici | Réalité |
|---------|---------------|---------|
| Pin d'outilchain | `nightly-2026-08-20` | **`nightly-2026-07-20`** (`rust-toolchain.toml:14`) |
| Fenêtre compatible | `[2026-07-10 .. 2026-08-22]` | Non documentée ailleurs ; le pin est simplement `2026-07-20` |
| Correctif `[profile.dev] opt-level = 0 → 1` | « associé », statut ✅ | **Non appliqué** — `Cargo.toml:95` est toujours `opt-level = 0` |
| Statut global | ✅ RÉSOLU | `Makefile.toml:196-201` exclut **volontairement** `kernel-test` de `ci-tests` « until confirmed on the 07-20 pin » |

Le pin est en place, mais la fenêtre d analysing de bisect et le contournement
`opt-level` ne le sont pas, et le kernel selftest n'est pas dans le gate
`ci-tests`. Il reste couvert par le job QEMU `qemu-proxmox`.

---

## F2 — `VfsTimestamp::to_filetime` déborde — ⏳ TOUJOURS OUVERT

`strate-fs-abstraction/src/types.rs:113-121` fait toujours
`(windows_secs as u64) * 10_000_000` sans arithmétique vérifiée : panic en
debug, wrap en release au-delà de ~an 60000. Entrée contrôlée par le disque ou
le réseau (chemins `stat`) ⇒ à traiter comme une entrée hostile.

**Pinné** par un test `#[should_panic]` dans `types_conformance.rs:134-143`.

**Correctif proposé** : `checked_mul` → `FsError::ArithmeticOverflow`.

## F3 — `FsCapabilities::xfs()/btrfs()` : valeurs PiB au lieu de EiB — ✅ RÉSOLU

`capabilities.rs:105` vaut désormais `8 * Self::EIB` et `:146` clamp btrfs à
`u64::MAX`. Test mis à jour dans `types_conformance.rs:188-201`.

## F4 — `parse_ipv6_literal` sur-accepte le `::` — ⏳ TOUJOURS OUVERT

RFC 4291 interdit `::` quand 8 groupes explicites sont déjà présents ;
`abi/src/ip.rs:185-243` accepte toujours `1:2:3:4:5:6:7:8::`. Sans danger
immédiat (la sortie reste bien formée) mais à durcir pour la conformité.

**Pinné** par `abi/tests/ip_parsing.rs:179-185`.

## F5 — `OpenReply` n'implémente pas `KnownLayout` — ✅ RÉSOLU

`KnownLayout` est maintenant dérivé via zerocopy sur toute la surface de
payloads `repr(C)` (`abi/src/data.rs:234`, `ipc_codec.rs:63`), `decode_fixed`
l'exige (`ipc_codec.rs:268`), et un test de roundtrip existe par struct fixe
(`abi/tests/ipc_payload_wire.rs:222`).

## F6 — `ENOTSUP = 52` n'est pas la valeur Linux — ⚠️ RÉSOLU CÔTÉ ABI, PAS CÔTÉ KERNEL

`strat9_abi::errno::ENOTSUP` vaut **95** (`abi/src/errno.rs:92`) et le test
golden le verrouille (`abi/tests/errno_abi.rs:57`).

**Mais le kernel émet toujours `-52` :** `SyscallError::NotSupported = -52`
dans `kernel/src/syscall/error.rs:61`. Le noyau produit donc une valeur que
l'ABI ne définit pas. `SyscallError` ne définit par ailleurs ni `ELOOP` (40),
ni `EAFNOSUPPORT` (97), ni `EADDRINUSE` (98), ni `ECONNREFUSED` (111).

Cela affecte notamment le refus de `SYS_PROC_EXECVE` sur un processus
multi-threadé, qui renvoie `-52` là où l'appelant attend `ENOTSUP` = 95.

## F7 — Test unitaire préexistant cassé depuis longtemps — ✅ RÉSOLU

`strate-fs-abstraction/tests/unit_tests.rs:3` importe bien `strate_fs_abstraction`
(correct). Preuve que l'absence de CI laisse pourrir la couverture en silence.

## F8 — Constantes POSIX fausses dans `strat9_syscall::flag` — ✅ RÉSOLU

Trouvé par la table dorée Linux :
- `O_NOFOLLOW` corrigé à `0o0400000` (`abi/src/flag.rs:136`) ;
- `O_NOCTTY` corrigé à `0o000400` (`flag.rs:131`) — détecté par le test doré
  lui-même après le premier correctif ;
- `O_DSYNC` corrigé à `0o10000` (`flag.rs:37`).

> Note : la version précédente de cette page nommait la troisième constante
> `O_DSYNC = 0o02000000 → 0o10000`. Le symbole à `0o04000000` s'appelle
> `O_SYNC` (`flag.rs:34`), et `O_DSYNC` est bien à `0o10000`.

La traduction `posix_oflags_to_strat9` utilisait ses propres copies correctes —
mais tout composant consommant ces constantes directement cassait.

## F9 — Test inline `lockfree_ring::full_ring` faux depuis sa création — ✅ CORRIGÉ

`LockFreeRing::new(4, 64)` crée 4 slots (`next_power_of_two`), donc 4 writes
réussissent — le test attendait `Full` au 4ᵉ. Corrigé dans le bloc
`#[cfg(test)]` de `ipc/lockfree_ring.rs:267-276`, commentaire « F9 fix
(L2 host harness) » à l'appui.

## F10 — Port I/O `out 0xe9` dans les primitives de sync — ✅ CONTOURNÉ

`emit_trace_e9` (`kernel/src/sync/spinlock.rs:171-177, 262-267, 344-350`) émet
sur le port série E9 via `asm!("out 0xe9")` : instruction ring-0, `#GP` garanti
en userspace. Compilé hors du binaire de test uniquement sous le cfg
`kernel_l2_host`, posé par `workspace/kernel-l2-tests/.cargo/config.toml:5`.
Production inchangée.

## F11 — La mailbox d'événements N1 est LIFO — ⚠️ ÉPINGLÉ COMME SPÉCIFIÉ

`notify_scheduler` / `poll_scheduler_events` s'appuient sur `IntrusiveMailbox`,
dont l'ordre est explicitement documenté comme inversé à la réception
(`ipc/mailbox.rs:1-8, 87-97`). Les événements arrivent donc en ordre **inverse**
d'émission.

Sans gravité pour des événements indépendants, mais toute logique future
dépendant de l'ordre causal (SchedTick avant Wakeup…) héritera de cette
inversion. Épinglé **as implemented** par `push_pop_lifo_order`
(`mailbox.rs:373-382`) et par `kernel-l2-tests/tests/kernel_n1_semaphores.rs`.

## F12 — `get_initfs_file_bytes` ne retrouve pas les fichiers enregistrés avec préfixe — ⚠️ TOUJOURS OUVERT

Le boot enregistre les modules avec leur chemin complet
(`/initfs/<name>`), mais le lookup retire `/initfs/` avant recherche : clé
stockée `/initfs/fs-ext4`, clé cherchée `fs-ext4` → raté. Conséquence possible :
exec d'un binaire initfs par ce chemin cassé.

**La référence de fichier a changé** : le lookup est désormais dans
`vfs/scheme_router.rs:130-134` (et non plus `kernel_l2_scheme.rs`). Épinglé par
`kernel-l2-tests/tests/kernel_vfs_scheme.rs:141-153` ; à confirmer sur le
runtime QEMU.

## F13 — Écrire dans un pipe à lecture fermée boucle à l'infini — ✅ CORRIGÉ

Trouvé par le harnais L2 (le test pendait indéfiniment) :
`Pipe::write` (`vfs/pipe.rs:180-183`) évaluait « read end closed → `EPIPE` »
via `wait_until`, mais le bras `Err(_) => {}` avalait l'erreur et relançait la
boucle — spin 100 % CPU au lieu de `EPIPE`. Fix : propagation de l'erreur
fatale ; seul `Again` reste transitoire.

Impact production réel : tout processus écrivant dans un pipe dont le lecteur
est mort (pipelines du shell, IPC interne) se figeait.

## F14 — Limine v8.7 panique sur les kernels fraîchement construits — ✅ SANS OBJET

**Limine a été entièrement retiré du code.** Il ne reste que deux identifiants
de stub morts (`kernel/src/boot/mod.rs:56 pub mod limine_shim` et
`kernel/src/lib.rs:1589 pub mod boot_limine_shim`) plus des commentaires ;
aucune dépendance Limine n'existe.

Le dilemme « réparer Limine ou basculer sur le bootloader perso » a été tranché
par `docs/mr-u-boot-replacement.md` : le harnais QEMU utilise désormais
`cargo make qemu-tests` sur une **ISO UEFI** construite avec le bootloader
propre `strat9-bootloader.efi`. Le stage CI `test-qemu` en est la livraison.

> **Réserve** : le stage `build` de `.gitlab-ci.yml` construit encore la release
> via `cargo make uboot-image-release` — un chemin marqué `[LEGACY]`, pas le
> chemin UEFI que la CI QEMU valide. Voir [Testing Architecture](./testing-architecture.md#4-ci).

---

## Couverture L0 / L1 — tests hôte

Comptages vérifiés le 2026-09-29.

| Suite | Tests | Périmètre |
|---|---|---|
| `abi/tests/abi_stability.rs` | 10 | golden syscalls (169), layouts, magics |
| `abi/tests/wire_format.rs` | **25** | layouts `repr(C)` et endian de toutes les structs filaire |
| `abi/tests/ipc_codec_roundtrip.rs` | 16 | codec bornes / roundtrip / endian |
| `abi/tests/ipc_payload_wire.rs` | **13** | wire format schemes VFS *(12 documentés auparavant)* |
| `abi/tests/data_types.rs` | 9 | SiloMode, DirentHeader, PCI, tailles de structs |
| `abi/tests/ip_parsing.rs` | 9 | IPv4/IPv6 edge cases |
| `abi/tests/flags_translation.rs` | 8 | POSIX ↔ Strat9 exhaustif (1536 combinaisons) |
| `abi/tests/ipc_handshake.rs` | **7** | handshake IPC filaire + validation des réservés *(8 documentés auparavant)* |
| `abi/tests/errno_abi.rs` | 4 | valeurs Linux, fenêtre de détection, roundtrip noyau↔user |
| `fs-abstraction/tests/types_conformance.rs` | 13 | bits de mode, FILETIME, capabilities |
| `fs-abstraction/tests/safe_math_edge_cases.rs` | **13** | arithmétique sûre *(23 documentés auparavant — régression ou réécriture)* |
| `fs-abstraction/tests/unit_tests.rs` | 1 | smoke test (F7) |
| `syscall/tests/dirent_wire.rs` | **11** | parsing getdents packed, SchemeV2, SigAbi *(10 documentés)* |
| `syscall/tests/error_and_flags.rs` | 8 | roundtrip Error↔errno, démultiplexage RAX, flags Linux |
| `intel-ethernet/tests/descriptors.rs` | 10 | layouts SDM 16 B, anneaux Rx/Tx |
| `driver-net-proto/tests/wire_protocol.rs` | 3 | opcodes + en-têtes IPC réseau |
| `alloc-freelist/tests/allocator.rs` | 6 | GlobalAlloc : alignement, réemploi, OOM propre |
| `drivers/bus/tests/*` (7 fichiers) | **37** | brcmstb_gisb, firewall_scheme, moxtet, qcom_ssc_block_bus, sun50i_de2, ts_nbus, vexpress_config |

**Total tests hôte : 190**

Porte CI : `cargo make ci-tests` (stage GitLab `test`, job `test-host`).
`strat9-bus-drivers` **n'est pas** dans la liste de paquets de `test-host`
(`Makefile.toml:112-123`) : ses 37 tests ne sont pas dans le gate.

---

## Couverture L2 — code kernel réel sur hôte

Modules kernel compilés **verbatim** via `#[path]` dans la crate ombre
`workspace/kernel-l2-tests`, avec des fakes fonctionnels pour IRQ / percpu /
silo / HHDM (l'offset HHDM réel pointe vers une arena hôte, donc l'allocateur
buddy travaille sur de la vraie mémoire).

| Suite | Tests | Périmètre |
|---|---|---|
| `boot_memory.rs` | 23 | chemins mémoire du handoff de boot |
| `kernel_vfs_fd.rs` | 13 | OpenFile (offset partagé POSIX, permissions, EOF), FileDescriptorTable (réemploi du plus bas fd, dup `F_DUPFD`, cloexec), Nice saturé + AtomicNice |
| `boot_handoff.rs` | 11 | validation de `KernelArgs` (magic, version, étendues) |
| `kernel_sync_namespace.rs` | 10 | FixedQueue FIFO/wraparound/overflow, SpinLock réel, namespace bind/unbind/resolve longest-prefix |
| `boot_graphics.rs` | 10 | handoff du framebuffer |
| `kernel_pipes.rs` | 9 | pipes kernel : FIFO, wraparound 4096, cycle EOF/EPIPE (F13), registre PipeScheme |
| `kernel_channels.rs` | 9 | canal MPMC typé (multi-producteurs, cycle de disconnect), SyncChan registre + drain-first après destroy |
| `boot_initfs.rs` | 9 | enregistrement et lecture des modules initfs |
| `buddy_allocator.rs` | 6 | buddy réel sur mémoire hôte : alignement par ordre, épuisement → OOM propre, zéro après purpose-alloc, stress 2000 ops avec payload tags, tolérance double-free |
| `kernel_n1_semaphores.rs` | 6 | événements N1 (ordre LIFO épinglé, F11), sémaphores POSIX (comptage, destroy, registre) |
| `boot_transition.rs` | 9 | bascule de contexte de transition |
| `kernel_vfs_scheme.rs` | 7 | finalize_pseudo_stat, registre KernelScheme (`/initfs`), routeur global de schemes, F12 |

**Total tests L2 : 122** *(plus les tests `#[cfg(test)]` inline du kernel récupérés
par la crate ombre : lockfree_ring, mailbox, boot/toml)*

**Total toutes couches (`workspace/**/tests/*.rs`, hors `xfs-rs`) : 325**

> Les versions précédentes de cette page donnaient trois totaux mutuellement
> contradictoires — « 364 tests verts », « 327 tests verts » et « 162+ tests
> hôte verts ». Aucun n'était re-derivable. Le tableau ci-dessus est recompté et
> les trois lignes ont été supprimées.

---

## Candidats L2 restants

- Classes d'ordonnancement complètes (necessitent une fausse `AddressSpace`).
- Faux `userslice` pour les handlers read/write d'`IpcScheme` — bloqué par
  `memory/userslice.rs`, qui valide les pointeurs userspace contre les tables
  de pages x86 réelles ; il faudra une fausse de validation de région.

## Voir aussi

- [Testing Architecture](./testing-architecture.md) — les 5 couches et la CI
- [ABI Support Matrix](./abi-matrix.md) — l'état réel de la couverture POSIX
