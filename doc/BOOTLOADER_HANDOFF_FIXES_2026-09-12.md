# Bootloader UEFI : corrections de l'ordre 2

Branche : `fix/UEFI-bootloader`. Base de ce lot : `2ba3d24`.
Périmètre demandé : R03, R04, R07 et R08 de la [revue initiale](C:/src/strat9-os/doc/BOOTLOADER_REVIEW_2026-09-12.md).

Le lot ordre 1 avait corrigé l'allocation et la limite du nombre de modules côté loader, ainsi que le découpage et la longueur finale de la carte mémoire. Il restait à compléter R04 côté lecteur noyau. Ce lot ajoute cette validation, supprime la duplication du format et couvre les cas de régression précis de l'ordre 2.

## État des quatre constats

| Constat | Correction dans l'état final |
| --- | --- |
| R03 | Une seule `ModuleTable` définie dans l'ABI, de 5128 octets, est utilisée par le loader et le noyau. Le constructeur partagé vérifie la capacité et l'alignement du tampon avant toute écriture. Le loader lui transmet l'allocation avec sa taille, et réserve toujours deux pages. |
| R04 | La limite de 64 modules est partagée. Le producteur refuse 65 entrées sans modifier le tampon. Le lecteur vérifie l'adresse, l'alignement, les débordements, la taille annoncée et le compteur avant de former une tranche. Le noyau refuse une table invalide avant l'initialisation de ses allocateurs et réutilise ensuite la tranche validée. |
| R07 | La soustraction d'intervalles bornée de l'ordre 1 est conservée. Un test explicite couvre la région `[0x1000, 0x3000)` intersectant les tables `[0x2000, 0x4000)`, avec conservation des deux restes et sans sous-débordement. |
| R08 | Le loader publie le nombre final de descripteurs dans le tampon réservé. Sa capacité de 1024 entrées est désormais une constante partagée avec le noyau. Le lecteur refuse les tailles non multiples de 24 et les cartes trop longues ; la copie vers `MMAP_WORK` ne tronque plus silencieusement la carte. |

## Contrat de transfert

Le format binaire est conservé : `KernelArgs` reste à 132 octets, `ModuleEntry` à 80 octets, l'en-tête de `ModuleTable` à 8 octets et la table complète à 5128 octets. La version ABI reste 4. Un ancien producteur annonçant uniquement `8 + count * 80` octets est désormais refusé : le format retenu est explicitement la table fixe complète.

L'absence de modules est représentée par une table complète dont `count` vaut zéro, ou par la paire adresse/taille `(0, 0)`. Une paire incohérente est refusée. Le noyau exige une carte mémoire non vide.

Les méthodes Rust `KernelArgs::modules()` et `memory_regions()` retournent maintenant un `Result` et sont explicitement `unsafe`. Les contrôles de métadonnées ne peuvent pas prouver qu'une adresse physique est réellement mappée et lisible ; cette précondition appartient au chemin de démarrage. Les fonctions partagées `ModuleTable::write_into` et `read_from`, qui travaillent sur des tranches de mémoire existantes, sont sûres. Tous les appels du dépôt ont été adaptés. Le double ajout HHDM des données initfs (R06) reste un autre correctif.

## Vérification

Quinze cas de régression supplémentaires ont été ajoutés : onze dans [boot_handoff.rs](C:/src/strat9-os/workspace/kernel-l2-tests/tests/boot_handoff.rs) et quatre dans [boot_memory.rs](C:/src/strat9-os/workspace/kernel-l2-tests/tests/boot_memory.rs).

Ils couvrent notamment :

- 0, 1, 51, 52 et 64 modules, avec sentinelles autour du tampon ;
- 65 modules, compteur `u32::MAX`, table tronquée, tampon d'une seule page et adresse non alignée ;
- adresses et longueurs débordantes, paires adresse/taille incohérentes ;
- 1024 descripteurs acceptés et 1025 refusés ;
- le passage de 170 à 172 descripteurs, qui franchit une page de 4096 octets ;
- une carte finale plus courte que la carte préparatoire, sans publication des anciennes entrées.

La syntaxe Rust et le formatage des fichiers ciblés ont été contrôlés avec l'exécutable local `rustfmt` du toolchain `nightly-2026-07-20`. Pour le fichier noyau, l'analyse syntaxique a été faite sans reformater ses parties préexistantes. `git diff --check` a également été effectué.

**Aucune compilation, aucun test Rust, aucune création d'image et aucun démarrage QEMU/OVMF n'ont été exécutés.** Les quinze tests sont préparés, pas validés par exécution. Les contrôles statiques ne remplacent ni la vérification des types ni la validation du démarrage sur les cibles prévues.
