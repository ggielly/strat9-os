# s9vm-guest — noyau invité bare-metal de validation

Image de noyau invitée minimale (ELF64 x86-64, `no_std`) qui démarre sous le
moniteur `s9vm` de strat9-os et valide le contrat de démarrage qu'un vrai
système d'exploitation invité recevra : bloc de paramètres de démarrage
`S9VMBP`, carte mémoire, ligne de commande, modules et tables ACPI.

Cette crate est **autonome** : elle ne fait pas partie du workspace hôte, ne
dépend d'aucune crate (uniquement `core`) et n'est pas encore branchée dans le
`Makefile` ni dans l'ISO (l'intégration est faite par le lead).

```
workspace/guest/s9vm-guest/
├── Cargo.toml        # crate no_std autonome ([workspace] vide)
├── s9vm-guest.ld     # script de link : chargement fixe à 0x100000, entrée _start
├── src/main.rs       # _start (global_asm!), guest_main, port debug, panic handler
└── README.md         # ce document
```

## Contrat de démarrage

La politique (`SYS_VMM_LOAD_IMAGE` + mise en place des tables de pages invitées)
charge l'image et entre dedans avec les garanties suivantes :

| Élément | Valeur |
|---|---|
| Adresse de chargement | `0x0010_0000` (segment `PT_LOAD` `R E`, aligné 4 Kio) |
| Type ELF | `ET_EXEC` (image à adresse fixe, sans relocation au chargement) |
| Point d'entrée | symbole `_start`, à `0x0010_0000` |
| Mode processeur | long mode 64 bits, pagination active |
| `CR3` | `0` — table de pages identité `0x0000_0000..0x0040_0000` (feuilles PD de 2 Mio) installée par la politique |
| `RDI` | adresse guest-physique du bloc de paramètres `S9VMBP` |
| IDT | aucune : le guest n'attend aucune interruption et n'exécute jamais `sti` |
| RSDP ACPI | attendu à l'adresse guest-physique `0x000E_0000` |
| Direction flag | `_start` exécute `cld` |

`_start` (assemblé par `core::arch::global_asm!`) installe la pile
(`__s9vm_guest_stack_top`, 16 Kio en `.bss`, alignée 16 octets), exécute `cld`,
puis `call guest_main` avec `RDI` inchangé. L'image ne dépend de rien en dehors
d'elle-même : ni allocateur, ni table de pages propre, ni symbole du noyau hôte.

Après le marqueur de succès `A`, le guest boucle sur `hlt` : chaque `hlt` est un
exit « policy » que la politique complète.

### Carte du bloc `S9VMBP` (little-endian, figée)

Référence : `workspace/kernel/src/s9vm/bootparams.rs`.

| Offset | Taille | Champ |
|---|---|---|
| `0x000` | 8 | magie `S9VMBP\0\0` (`u64` = `0x0000_5042_4D56_3953`) |
| `0x008` | 4 | version |
| `0x00C` | 4 | taille du bloc (1024) |
| `0x010` | 4 | drapeaux de boot |
| `0x014` | 4 | nombre d'entrées de carte mémoire (≤ 32) |
| `0x018` | 4 | nombre de modules/initrd (≤ 4) |
| `0x01C` | 4 | longueur de la ligne de commande (≤ 256) |
| `0x020` | 8 | adresse guest-physique du RSDP ACPI |
| `0x028` | 8 | base MMIO de la console virtio |
| `0x030` | 4 | ligne I/O APIC de la console |

Les entrées de carte mémoire et les modules suivent à `0x038`, la ligne de
commande à `0x2F8`.

## Protocole du port debug `0xE9`

Le guest publie un octet par `out dx, al` (`dx = 0xE9`). Le moteur s9vm réplique
ces exits dans le noyau (port debug du fast-path) : la politique ne voit que les
`hlt`.

| Octet(s) | Signification |
|---|---|
| `G` (`0x47`) | magie du bloc de paramètres `S9VMBP` validée |
| `M` (`0x4D`) | `memory_count > 0` |
| `A` (`0x41`) | RSDP trouvé, `rsdp_gpa` cohérent, checksum ACPI 1.0 valide |
| `F` (`0x46`) + code | échec ; le code est le numéro de l'étape (voir ci-dessous) |
| `P` (`0x50`) | panic Rust ; le guest halte ensuite (aucun code) |

Codes d'échec publiés après `F` :

| Code | Étape en échec |
|---|---|
| 1 | magie du bloc invalide (pas `S9VMBP`) |
| 2 | `memory_count == 0` |
| 3 | `rsdp_gpa` différent de `0x000E_0000` |
| 4 | signature `RSD PTR ` introuvable à l'adresse annoncée |
| 5 | checksum ACPI 1.0 du RSDP invalide |
| 6 | champ hors capacité (`module_count > 4` ou `cmdline_len > 256`) |

Séquence de succès attendue sur le port : `G`, `M`, `A`, puis des `hlt`
répétés. Séquence d'échec : `F`, code, puis `hlt`.

## Ce que le guest valide

1. **magie** : lecture `volatile` du `u64` à `RDI + 0x000`, comparaison à
   `S9VMBP\0\0` ;
2. **mémoire** : `u32` à `RDI + 0x014` non nul (un vrai OS reçoit au moins une
   région utilisable) ;
3. **champs** : `u32` à `RDI + 0x018` ≤ 4 et `u32` à `RDI + 0x01C` ≤ 256 ;
4. **RSDP** : `u64` à `RDI + 0x020` égal à `0x000E_0000` ; balayage de
   `0x000E_0000..0x0010_0000` par pas de 16 octets à la recherche du `u64`
   `RSD PTR ` ; l'adresse trouvée doit être celle annoncée par le bloc ;
5. **checksum ACPI 1.0** : la somme des 20 premiers octets du RSDP vaut
   `0 mod 256`.

Aucun accès mémoire n'est fait hors de la fenêtre identité de 4 Mio fournie par
la politique.

## Compilation

Toolchain épinglée du dépôt (`rust-toolchain.toml` : nightly avec la cible
`x86_64-unknown-none`). Depuis `workspace/guest/s9vm-guest` :

### PowerShell (Windows)

```powershell
$ld = (Resolve-Path .\s9vm-guest.ld).Path
$env:RUSTFLAGS = "-C relocation-model=static -C link-arg=-no-pie -C link-arg=-T$ld -C link-arg=--build-id=none"
cargo build --release --target x86_64-unknown-none
```

### Shell POSIX

```sh
export RUSTFLAGS="-C relocation-model=static -C link-arg=-no-pie \
  -C link-arg=-T$(pwd)/s9vm-guest.ld -C link-arg=--build-id=none"
cargo build --release --target x86_64-unknown-none
```

Les deux options de link sont indispensables :

- `-C relocation-model=static` et `-C link-arg=-no-pie` forcent un `ET_EXEC`
  (sans elles la cible produit un `ET_DYN` avec `DYNAMIC`/`.dynsym`) ;
- `-C link-arg=-T…/s9vm-guest.ld` impose l'adresse de chargement `0x100000` et
  l'entrée `_start` ;
- `-C link-arg=--build-id=none` évite une section `.note.gnu.build-id` inutile.

`-Z build-std=core` n'est pas nécessaire : la cible `x86_64-unknown-none`
fournit `core` précompilé avec la toolchain épinglée.

L'ELF produit est :

```
target/x86_64-unknown-none/release/s9vm-guest
```

(sans extension : la cible n'est pas Windows).

## Propriétés ELF attendues

```console
$ readelf -h target/x86_64-unknown-none/release/s9vm-guest
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Entry point address:               0x100000

$ readelf -l target/x86_64-unknown-none/release/s9vm-guest
  LOAD  0x0000000000001000 0x0000000000100000 0x0000000000100000
        0x00000000000001c3 0x00000000000001c3  R E   0x1000
  LOAD  0x0000000000002000 0x0000000000101000 0x0000000000101000
        0x0000000000000000 0x0000000000004000  RW    0x1000
```

Contrôles attendus :

- `e_type == ET_EXEC` (valeur 2) ;
- `e_entry` dans `0x0010_0000..0x0011_0000` (actuellement `0x100000`) ;
- deux `PT_LOAD` : `.text` `R E` chargé à `0x0010_0000`, `.bss` `RW`
  (`NOBITS`, 16 Kio pour la pile) à `0x0010_1000` ;
- **aucun chevauchement de page entre segments** : le loader du noyau
  (`s9vm::image`) rejette deux segments dont les plages alignées sur 4 Kio se
  recouvrent, c'est pourquoi `.bss` démarre sur la page suivante ;
- `p_vaddr % 4096 == p_offset % 4096` pour chaque `PT_LOAD` (congruence ELF) ;
- aucune entrée `DYNAMIC` ni `INTERP` (image totalement autonome) ;
- taille du fichier de l'ordre de 9 Kio (table des symboles comprise), empreinte
  mémoire chargée de 20 Kio (5 pages : `.text` + 4 pages de `.bss`).

Le symbole `_start` doit être le premier octet du segment exécutable et
`guest_main` suivre dans la même page. Le code est **position-indépendant dans
l'image** : `_start` calcule sa pile en RIP-relatif et `guest_main` n'utilise que
`RDI` et des adresses physiques du contrat, donc le loader peut choisir
n'importe quelle adresse de chargement alignée.

## Intégration (hors périmètre de cette crate)

Le lead branche l'image dans la staging ISO : copier l'ELF produit dans
l'initfs sous `/initfs/s9vm-guest`, puis lancer une politique qui lit ce fichier,
appelle `SYS_VMM_LOAD_IMAGE` (le loader relocalise l'entrée), installe les tables
de pages identité 0..4 Mio (`CR3 = 0`), écrit un bloc `S9VMBP` + les tables ACPI,
met `RDI` = GPA du bloc et lance le vCPU. Côté log, la politique s'attend à voir
`G`, `M`, `A` sur le port `0xE9`.

## Limites

- pas d'IDT, pas d'interruptions, pas de MMIO : le guest ne teste que le
  hand-off et ACPI ;
- pas d'allocateur ni de pile par vCPU : une seule pile statique de 16 Kio ;
- pas de pagination propre : il réutilise l'identité fournie par la politique ;
- pas de retour : `guest_main` termine par une boucle `hlt` (et le panic handler
  publie `P` avant de halter).
