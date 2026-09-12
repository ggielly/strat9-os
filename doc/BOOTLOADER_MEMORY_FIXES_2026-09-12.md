# Bootloader UEFI : corrections de l'ordre 1

Branche : `fix/UEFI-bootloader`. Base : `537784a972245129de64c9c14d4910530e986528`.
Périmètre demandé : R01, R02, R05, R20 de la [revue initiale](C:/src/strat9-os/doc/BOOTLOADER_REVIEW_2026-09-12.md).
Les changements consolident le bootloader existant. Ils ne remplacent ni son protocole de démarrage ni l'ABI du noyau.

## Changements

| Constat | Correction |
| --- | --- |
| R01 | L'analyse ELF construit un plan sans écrire en mémoire physique. Le loader réserve ensuite l'image contiguë avec `AllocatePages`, met l'allocation à zéro et copie les segments après validation de toutes leurs plages source et destination. |
| R02 | Les tables de pagination sont construites avant `ExitBootServices`, dans une allocation UEFI dédiée. Leur budget découle du mapping actuel. Un curseur borné refuse toute page supplémentaire avant sa mise à zéro. L'adresse arbitraire `kernel_phys_end + 4 Mio` disparaît. |
| R05 | Chaque module occupe des pages UEFI dédiées, inscrites dans le registre de réservations. La carte finale marque ces pages `Reserved`, avec l'image noyau, les tables de pagination, la pile, la table des modules, l'environnement, la carte elle-même et `KernelArgs`. Les allocateurs du noyau ne doivent donc plus les traiter comme `Reclaim`. |
| R20 | Chaque allocation obligatoire est vérifiée avant la fermeture des services UEFI. Une erreur remonte son opération et son statut, puis libère les pages déjà obtenues. Aucun repli à `0x90000` ni poursuite avec une allocation nulle. Si la conversion de la carte finale échoue après `ExitBootServices`, un diagnostic autonome et borné précède un arrêt `cli`/`hlt`. |

Toutes les allocations permanentes sont placées sous 8 Gio, limite des mappings initiaux existants. Pour le noyau, l'adresse physique historique est demandée en premier. Si elle est occupée, une autre plage contiguë est demandée à UEFI ; le mapping virtuel et le point d'entrée restent identiques. Les adresses physiques du plan et de `KernelArgs` sont mises à jour. Cette opération exige la correspondance contiguë entre adresses physiques et virtuelles produite par le script de liaison actuel ; un ELF incompatible est refusé.

Le registre conserve les allocations jusqu'au transfert au noyau. Les tampons temporaires, les fichiers, le volume et le protocole de système de fichiers sont libérés avant la sortie UEFI. Après celle-ci, aucun chemin ajouté ne revient vers les services UEFI ou leur allocateur. Le helper `exit_boot_services` de `uefi` 0.39 reste responsable de sa propre carte finale et de ses tentatives de sortie ; sa politique interne d'échec n'est pas remplacée.

## Structures de transfert nécessaires à ces corrections

R03 et R04 ont été traités dans ce lot : réserver une table trop petite aurait conservé une écriture hors allocation malgré R01/R02. La table fixe entière est désormais allouée (`5128` octets, soit deux pages), même sans module. Le loader refuse plus de 64 modules avant l'écriture et vérifie ce nombre dans le constructeur de table. Des assertions statiques comparent sa disposition à celle de l'ABI.

Précision du suivi : ces corrections de R04 portaient sur le producteur. La validation de `count` et `modules_size` par le lecteur côté noyau restait à compléter. Elle est ajoutée dans le [lot ordre 2](C:/src/strat9-os/doc/BOOTLOADER_HANDOFF_FIXES_2026-09-12.md), qui mutualise également le format et ajoute les tests de limites.

R07 et R08 ont également été traités : les découpages tardifs de descripteurs ont été remplacés par une conversion unique qui soustrait les réservations par intersection. Elle accepte les réservations traversant plusieurs descripteurs, conserve les plages hors réservations, contrôle les débordements arithmétiques et vérifie chaque insertion. Les descripteurs adjacents de même type sont fusionnés quand leur ordre le permet.

Le tampon transmis contient au maximum 1024 descripteurs, capacité actuelle du tableau de travail du noyau. La conversion est vérifiée une première fois avant `ExitBootServices`, puis répétée sur la carte finale dans le même tampon. La taille publiée correspond au nombre effectivement produit. Un dépassement provoque une erreur explicite, jamais une troncature ou une écriture au-delà du tampon.

## Validation réalisée et restante

- Lecture croisée des appels avec les sources locales de `uefi` 0.39, de l'ABI, du script de liaison et des allocateurs du noyau.
- Analyse syntaxique et formatage par l'exécutable local `rustfmt` du toolchain `nightly-2026-07-20`, sans lancer Cargo ou rustc.
- Contrôle des espaces et conflits par `git diff --check`.
- Ajout de 11 tests hôtes dans [boot_memory.rs](C:/src/strat9-os/workspace/kernel-l2-tests/tests/boot_memory.rs), qui incluent les vrais modules purs du bootloader. Ils couvrent les intersections de réservations, les modules initialement reclaimables, la saturation du tampon, les plages invalides, l'épuisement de l'arène, les arrondis, l'analyse ELF sans écriture, la relocalisation physique et l'absence de copie partielle en cas d'erreur.

**Ces tests n'ont été ni compilés ni exécutés.** Aucune compilation, création d'image, session QEMU/OVMF ou validation matérielle n'a été lancée, conformément à la consigne. Le formatage ne vérifie ni les types Rust ni le comportement du firmware.

La validation de démarrage devra notamment couvrir l'adresse physique historique indisponible, les allocations UEFI en échec, 0/64/65 modules, une carte finale fragmentée, un démarrage OVMF avec et sans GOP et le matériel réel ciblé. L'injection des échecs du firmware n'est pas couverte par les tests purs ajoutés.

Les autres constats restent à traiter, notamment R06 (double conversion HHDM des modules), R09 (taille BSS fondée sur une marge de 8 Mio), R11 à R14 (transition CPU et couverture mémoire), ainsi que GOP et les attributs de cache. La relocalisation physique ne résout pas ces défauts et ce lot ne constitue pas une validation du démarrage complet.
