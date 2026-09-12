# Revue statique du bootloader strat9-os — 12 septembre 2026

Branche : `fix/UEFI-bootloader`. Révision examinée : `537784a972245129de64c9c14d4910530e986528`, identique à `origin/fix/UEFI-bootloader` après récupération du distant. La branche locale `main`, qui possède trois commits d'avance sur `origin/main`, a été conservée.

Cible confirmée par Guillaume : PC x86-64 UEFI réels et QEMU/OVMF. Lors de la revue initiale, aucune compilation, aucun assemblage, aucun test Cargo, aucune création d'image et aucun démarrage QEMU n'ont été exécutés. Le code n'avait pas été modifié et ce rapport était le seul fichier ajouté.

**Suivi du 12 septembre :** les corrections demandées pour R01, R02, R05 et R20 ont ensuite été implémentées dans l'arbre de travail, avec les corrections nécessaires des structures de transfert R03, R04, R07 et R08. Voir la [note de correction et ses limites de validation](C:/src/strat9-os/doc/BOOTLOADER_MEMORY_FIXES_2026-09-12.md). Les constats et numéros de ligne ci-dessous décrivent la révision auditée initialement ; ils ne constituent pas une nouvelle revue du code corrigé. Aucune compilation ni exécution du bootloader n'a été effectuée après correction.

**Avis de revue : je déconseille de considérer cette version comme un bootloader fiable sur matériel réel.** Plusieurs défauts indépendants peuvent provoquer une corruption mémoire ou empêcher le démarrage. Les corrections prioritaires concernent la propriété de la mémoire physique, les structures de transfert, le chargement ELF et la transition CPU. Un démarrage réussi avec une disposition mémoire particulière ne démontre pas la validité de ces invariants.

La revue couvre intégralement les quatre sources Rust du bootloader, l'ABI partagée, le script de liaison x86-64, le stub d'entrée et les consommateurs immédiats du noyau : carte mémoire, allocateurs, initfs, framebuffer et ACPI. Elle inclut les tâches UEFI de `Makefile.toml`, les scripts d'image et le harnais QEMU. Les sources BIOS historiques ont également été lues ; leurs incompatibilités sont recensées séparément. Les autres sous-systèmes du noyau ne font pas l'objet d'un audit complet ici. Le fichier `RTK.md` référencé par les instructions est absent des emplacements vérifiés.

Les constats portent sur l'état complet de la branche, y compris les défauts antérieurs à son écart avec `main`. Ils ne sont pas tous des régressions introduites dans cette branche. P1 signifie « à corriger avant de compter sur ce chemin de démarrage » ; P2 signifie « défaut fonctionnel, de robustesse ou de protection à corriger ensuite ». Les conséquences dépendant du firmware, du CPU ou du contenu des fichiers sont explicitement conditionnées. Aucun constat n'est présenté comme une reproduction sur une machine physique.

**Ordre conseillé des corrections**

Le [lot ordre 2](C:/src/strat9-os/doc/BOOTLOADER_HANDOFF_FIXES_2026-09-12.md) complète désormais R03/R04/R07/R08 : format partagé, validation du lecteur noyau et tests ciblés. Le lot ordre 1 avait déjà corrigé la production de ces structures ; son contrôle côté noyau pour R04 était encore incomplet. Les tests restent non exécutés, conformément à la consigne de ne pas compiler.

| Ordre | Domaine | Constats |
| --- | --- | --- |
| 1 | Réserver la mémoire avant de l'écrire ; préserver les objets vivants | R01, R02, R05, R20 |
| 2 | Corriger tailles, limites et découpage des structures transférées | R03, R04, R07, R08 |
| 3 | Charger l'ELF selon ses segments ; fiabiliser le passage CPU | R09 à R14 |
| 4 | Rétablir l'initfs de bout en bout | R06, R21, R27 |
| 5 | Corriger GOP, mappings et protections | R15 à R19 |
| 6 | Rendre les images et leur validation fiables | R22 à R26 |

**Constats détaillés**

**R01 — [P1] Le noyau est écrit en mémoire physique sans réservation UEFI.**

Emplacements : [elf.rs:88](C:/src/strat9-os/workspace/bootloader/src/elf.rs:88), [main.rs:82](C:/src/strat9-os/workspace/bootloader/src/main.rs:82), [main.rs:306](C:/src/strat9-os/workspace/bootloader/src/main.rs:306).

`parse_elf64` effectue directement des `copy_nonoverlapping` vers les adresses physiques calculées, généralement à partir de 1 Mio. Aucun `AllocatePages` ne réserve ces destinations avant la copie. Une adresse basse et accessible n'est pas nécessairement libre. Elle peut contenir des allocations, du code, des tables ou des données du firmware. Même si la zone est libre au moment de la copie, les opérations UEFI suivantes, notamment le chargement des modules et GOP, peuvent la réattribuer.

Le découpage tardif de la carte, après `ExitBootServices`, ne protège ni le firmware pendant la copie ni le noyau contre ces allocations intermédiaires. Il ne traite d'ailleurs que `Free`, pas un noyau situé dans une région devenue `Reclaim`.

Correction : séparer validation et chargement ; réserver toutes les pages de destination avant toute écriture, vérifier le résultat et conserver leurs réservations dans la carte finale. Si une adresse physique imposée est indisponible, échouer proprement ou charger ailleurs avec un mapping virtuel adapté. Les règles de propriété avant et après la sortie du firmware sont décrites dans les [services mémoire UEFI](https://uefi.org/specs/UEFI/2.10_A/07_Services_Boot_Services.html).

**R02 — [P1] L'allocateur des tables de pages écrit dans une zone arbitraire.**

Emplacements : [paging.rs:41](C:/src/strat9-os/workspace/bootloader/src/paging.rs:41), [paging.rs:65](C:/src/strat9-os/workspace/bootloader/src/paging.rs:65), [main.rs:583](C:/src/strat9-os/workspace/bootloader/src/main.rs:583).

`NEXT_FRAME = (kernel_phys_end + 4 MiB) & !0xFFF` ne consulte aucune carte mémoire. Chaque allocation incrémente cette adresse puis met la page à zéro. La marge de 4 Mio ne garantit ni RAM disponible, ni absence de recouvrement avec des modules, le loader encore exécuté, sa pile, les nouvelles allocations ou des tables ACPI/runtime. Il n'existe pas de borne supérieure de l'arène.

Marquer la zone réservée après sa mise à zéro ne répare pas ce qui a déjà été écrasé. Le problème est indépendant de R01 et subsisterait même avec un chargement ELF correctement réservé.

Correction : fournir au constructeur de mappings un allocateur de frames provenant exclusivement de pages détenues par le loader, avec capacité explicite, échec contrôlé et suivi exact de toutes les frames. Les tables peuvent être préparées avant la sortie des Boot Services ; sinon il faut un véritable allocateur fondé sur la carte finale.

**R03 — [P1] La table des modules déborde de son allocation pour 0 à 51 modules.**

Emplacements : [modules.rs:35](C:/src/strat9-os/workspace/bootloader/src/modules.rs:35), [modules.rs:43](C:/src/strat9-os/workspace/bootloader/src/modules.rs:43), [main.rs:390](C:/src/strat9-os/workspace/bootloader/src/main.rs:390).

`module_table_size(n)` annonce `8 + 80*n` octets. Pour 0 à 51 modules, l'appelant réserve une seule page de 4 096 octets. `write_module_table` crée pourtant une référence vers la structure fixe de 64 entrées et initialise tout son tableau : cette structure occupe 5 128 octets. L'écriture dépasse donc la réservation de 1 032 octets. Le cas ordinaire d'une petite initfs suffit ; aucun fichier malformé n'est nécessaire.

La zone débordée peut être réutilisée ensuite pour l'environnement, ce qui masque partiellement le dommage sans rendre l'écriture valide.

Correction : choisir un seul format. Soit réserver systématiquement `size_of::<ModuleTable>()`, soit définir un en-tête suivi de `n` entrées et n'écrire que cette plage, sans fabriquer une référence vers une structure plus grande que l'allocation.

**R04 — [P1] Plus de 64 modules sont annoncés, mais seules 64 entrées sont produites.**

Emplacements : [modules.rs:44](C:/src/strat9-os/workspace/bootloader/src/modules.rs:44), [modules.rs:50](C:/src/strat9-os/workspace/bootloader/src/modules.rs:50), [boot.rs:195](C:/src/strat9-os/workspace/abi/src/boot.rs:195).

L'énumération n'est pas limitée. `table.count` reçoit le nombre total, tandis que l'écriture s'arrête à 64. Le lecteur ABI fabrique ensuite une tranche de `count` entrées sans vérifier la capacité ou `modules_size`. À partir de 65 fichiers chargés, il interprète de la mémoire non initialisée comme des noms, adresses et tailles ; avec davantage de fichiers, la lecture sort aussi du tableau fixe.

Correction : vérifier la limite avant le chargement, refuser explicitement son dépassement, ou adopter un tableau réellement variable. Le noyau doit également valider `count <= capacité` et `header + count*entry_size <= modules_size`, avec calculs contrôlés. Mutualiser le format entre loader et ABI.

**R05 — [P1] Les données des modules deviennent réallouables avant leur utilisation.**

Emplacements : [modules.rs:163](C:/src/strat9-os/workspace/bootloader/src/modules.rs:163), [main.rs:290](C:/src/strat9-os/workspace/bootloader/src/main.rs:290), [kernel/lib.rs:638](C:/src/strat9-os/workspace/kernel/src/lib.rs:638), [kernel/lib.rs:697](C:/src/strat9-os/workspace/kernel/src/lib.rs:697).

Les buffers sont conservés via `mem::forget`, mais leur type mémoire UEFI est converti en `Reclaim`. Les réservations du loader ne couvrent que la table des modules, pas leur contenu. Le noyau initialise ses plages protégées avec `[None; ...]`, puis accepte `Free | Reclaim` dans les allocateurs avant l'enregistrement de l'initfs. Oublier un `Vec` empêche sa destruction Rust ; cela ne soustrait pas ses pages à l'allocateur physique du noyau.

Les métadonnées mémoire, les bitmaps ou les allocations suivantes peuvent écraser les exécutables initfs. Le VFS conserve les buffers comme fichiers statiques, ce qui impose de les préserver bien au-delà de l'entrée du noyau.

Correction : réserver les pages couvrant chaque buffer avant toute allocation du noyau et les conserver jusqu'à la fin de leur utilisation. Un registre unique doit distinguer les objets encore vivants des allocations du loader réellement récupérables. Inclure aussi l'image du noyau si son type firmware est `LOADER_DATA`/`Reclaim` ; la protection actuelle limitée à `Free` n'y suffit pas.

**R06 — [P1, intégration noyau] L'adresse d'un module reçoit deux fois l'offset HHDM.**

Emplacements : [kernel/lib.rs:291](C:/src/strat9-os/workspace/kernel/src/lib.rs:291), [kernel/lib.rs:250](C:/src/strat9-os/workspace/kernel/src/lib.rs:250), [memory/mod.rs:45](C:/src/strat9-os/workspace/kernel/src/memory/mod.rs:45).

`register_boot_modules` transforme `module.base` avec `phys_to_virt`, puis transmet le résultat à `register_initfs_module`, qui répète cette transformation. Elle n'est pas idempotente : elle additionne l'offset avec `wrapping_add`.

Exemple vérifié arithmétiquement : pour `phys=0x10000000`, l'adresse attendue est `0xFFFFFF0010000000`, mais l'adresse enregistrée devient `0xFFFFFE0010000000`. Elle appartient à PML4[508], non mappé par le loader, au lieu de PML4[510]. La lecture des fichiers initfs peut donc produire un défaut de page même si leur contenu a été parfaitement chargé et réservé. Le mode `selftest` lit même les premiers octets pendant l'enregistrement.

Correction : passer l'adresse physique à `register_initfs_module`, ou modifier explicitement son contrat pour accepter une adresse virtuelle. Des types distincts pour les deux espaces empêcheraient cette erreur.

**R07 — [P1] Le découpage final autour des tables de pages peut sous-déborder.**

Emplacement : [main.rs:600](C:/src/strat9-os/workspace/bootloader/src/main.rs:600).

Le code calcule `r_end - pt_end.max(r_base)` dès qu'une région intersecte l'arène. Une intersection n'implique pas que `pt_end <= r_end`. Lorsque l'arène traverse plusieurs descripteurs, cette soustraction devient négative. Exemple : région `[0x1000,0x3000)`, tables `[0x2000,0x4000)` ; la taille droite vaut `-0x1000`, soit `0xFFFFFFFFFFFFF000` avec arithmétique u64 sans vérification.

Avec vérification des débordements, le loader panique après la sortie du firmware. Sans elle, une fausse région immense est ajoutée et copiée ; le nombre obsolète décrit en R08 peut la masquer aujourd'hui, mais elle reste une corruption de carte et devient visible si R08 seul est corrigé.

Correction : calculer d'abord l'intersection `[max(start), min(end))`, puis les restes avec ses bornes ; ajouter une partie droite uniquement si l'extrémité de l'intersection est inférieure à `r_end`. Utiliser une seule routine de soustraction d'intervalles pour toutes les réservations.

**R08 — [P1] La capacité et la longueur de la carte mémoire sont figées avant sa finalisation.**

Emplacements : [main.rs:366](C:/src/strat9-os/workspace/bootloader/src/main.rs:366), [main.rs:490](C:/src/strat9-os/workspace/bootloader/src/main.rs:490), [main.rs:625](C:/src/strat9-os/workspace/bootloader/src/main.rs:625).

`mmap_count`, la réservation du buffer et `args.memory_map_size` sont calculés avant les découpages finaux. Ceux-ci ajoutent des descripteurs en augmentant `region_count`. La dernière copie utilise ce nouveau nombre, sans agrandir le buffer ; le noyau, lui, reçoit encore l'ancienne longueur.

Deux défauts en résultent : écriture hors réservation quand la capacité est franchie, et omission des restes libres ajoutés en fin de carte. Exemple vérifié : 170 descripteurs de 24 octets réservent 4 096 octets ; après un découpage ajoutant deux entrées, la copie de 4 128 octets déborde de 32 octets. Même sans dépassement de page, une grande région remplacée par `Reserved` peut perdre ses restes libres du point de vue du noyau.

Correction : préallouer une capacité couvrant toutes les entrées possibles, borner les ajouts, puis renseigner `memory_map_size` seulement après la dernière réservation. Refuser une carte trop grande plutôt que la tronquer silencieusement à 512 entrées.

**R09 — [P1] Le chargement du BSS est remplacé par une marge arbitraire de 8 Mio.**

Emplacements : [elf.rs:9](C:/src/strat9-os/workspace/bootloader/src/elf.rs:9), [elf.rs:77](C:/src/strat9-os/workspace/bootloader/src/elf.rs:77), [elf.rs:102](C:/src/strat9-os/workspace/bootloader/src/elf.rs:102), [boot64.S:21](C:/src/strat9-os/workspace/kernel/src/boot/boot64.S:21).

Un `PT_LOAD` avec `p_filesz == 0` est ignoré, précisément le cas normal d'un segment BSS pur. La fin physique est estimée avec `p_filesz + 8 MiB`, sans utiliser `p_memsz`. Le script de liaison définit pourtant un segment BSS distinct, et `_start` efface réellement toute la plage `__bss_start..__bss_end`, pile comprise. Si cette plage dépasse la marge, l'effacement accède à des pages non mappées et le démarrage échoue avant Rust.

Je ne prétends pas que le BSS du binaire de cette révision dépasse 8 Mio : aucun ELF correspondant n'a été produit ou mesuré pendant cette revue. Le défaut est l'absence de garantie pour un ELF valide, notamment lorsque les statiques évoluent. Les champs `bss_virt_*` construits à partir du plus grand `virt_addr` retenu ne décrivent pas non plus le véritable BSS et ne sont pas utilisés par le stub pour son effacement.

Correction : prendre tous les `PT_LOAD` de taille mémoire non nulle, réserver et mapper `p_memsz`, copier `p_filesz` et mettre à zéro le reste. Si un ancien ELF présente un segment aberrant, corriger le script de liaison ou le refuser explicitement. Le contrat ELF autorise les segments sans octets dans le fichier et définit le complément nul : [System V ABI, Program Header](https://www.sco.com/developers/devspecs/gabi41.pdf).

**R10 — [P1] Un ELF invalide peut déclencher des écritures avant d'être rejeté, ou être accepté sans chargement.**

Emplacements : [elf.rs:44](C:/src/strat9-os/workspace/bootloader/src/elf.rs:44), [elf.rs:64](C:/src/strat9-os/workspace/bootloader/src/elf.rs:64), [elf.rs:88](C:/src/strat9-os/workspace/bootloader/src/elf.rs:88).

Les contrôles ne couvrent pas `e_machine`, `e_type`, les versions ELF, `p_filesz <= p_memsz`, les additions d'extrémités, l'alignement, les recouvrements et l'appartenance du point d'entrée à un segment exécutable. `offset + phentsize` et `p_offset + copy_size` ne sont pas contrôlés contre le débordement. La borne physique porte uniquement sur le début de destination, pas sur la totalité de la copie.

Lorsque la condition de copie est fausse, le segment est quand même enregistré et la fonction peut retourner `Ok`. Un fichier tronqué ou un `p_paddr` hors plage devient alors un faux chargement réussi suivi d'un saut vers de la mémoire incorrecte. Enfin, la fonction copie les premiers segments avant d'avoir validé les suivants.

Correction : un premier passage pur produit un plan intégralement validé, sans aucune écriture physique. Un second passage réserve et charge. Toute condition incompatible doit retourner une erreur explicite. Vérifier également que le layout virtuel est celui réellement supporté ; le mapper actuel ignore les `virt_addr` individuels et suppose un bloc contigu à `0xFFFFFFFF80000000`.

**R11 — [P1] Le dernier marqueur série modifie RAX/RDX sans le déclarer à Rust.**

Emplacement : [main.rs:709](C:/src/strat9-os/workspace/bootloader/src/main.rs:709).

Le bloc `asm!` exécute `mov dx, 0x3F8` et `mov al, 0x3E`, sans opérande d'entrée ou de sortie pour ces registres. Le compilateur peut y conserver une valeur vivante utilisée par l'appel immédiatement suivant à `context_switch`, notamment avec optimisation. Les lectures volatiles placées avant ce bloc ne protègent pas les registres ensuite choisis par le compilateur.

Correction : utiliser `in("dx") 0x3F8u16` et `in("al") b'>'` avec un corps limité à `out dx, al`, ou déclarer les registres modifiés en sorties. Le caractère `noreturn` du bloc de transition suivant ne rend pas valide ce bloc-ci, qui retourne au code Rust. Les [règles Rust sur l'assembleur intégré](https://dev-doc.rust-lang.org/stable/reference/inline-assembly.html) exigent de préserver les registres non déclarés en sortie.

**R12 — [P1] Le bootloader exige des pages de 1 Gio sans vérifier leur support CPU.**

Emplacements : [paging.rs:73](C:/src/strat9-os/workspace/bootloader/src/paging.rs:73), [paging.rs:217](C:/src/strat9-os/workspace/bootloader/src/paging.rs:217).

Le mapping d'identité utilise systématiquement des PDPTE avec `PS=1`. Le mode long ne garantit pas les pages de 1 Gio : la capacité correspond à `CPUID.80000001H:EDX[26]`. Sur un CPU ou une configuration de virtualisation qui ne l'expose pas, la première traduction concernée après `mov cr3` échoue. Le contrôle de capacités plus tard dans le noyau arrive trop tard.

Correction : utiliser des pages de 2 Mio pour le chemin de base, puis les pages de 1 Gio si détectées. Vérifier avant leur utilisation NX/PAT et les autres prérequis explicitement retenus. La distinction entre mode long et pages de 1 Gio est documentée dans le [manuel système Intel, section 4.5](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3a-part-1-manual.pdf). Je n'affirme pas ici le jeu exact de capacités d'une version QEMU non examinée.

**R13 — [P1] La limite fixe de 8 Gio ne garantit pas que le code de transition et ses données restent accessibles.**

Emplacements : [paging.rs:19](C:/src/strat9-os/workspace/bootloader/src/paging.rs:19), [paging.rs:232](C:/src/strat9-os/workspace/bootloader/src/paging.rs:232), [main.rs:701](C:/src/strat9-os/workspace/bootloader/src/main.rs:701).

Le loader n'impose aucune borne d'adresse aux allocations UEFI, ni au placement de sa propre image et de sa pile par le firmware. Pourtant, après le remplacement de CR3, seules les adresses physiques inférieures à 8 Gio sont couvertes par l'identité/HHDM initial. Le code continue quelques instructions dans l'image EFI ; `args` se trouve encore sur sa pile et sera lu ensuite par `kmain`. Un placement au-dessus de cette limite rend le chemin inaccessible.

Le problème concerne aussi les objets choisis par `alloc_from_free` et le démarrage du gestionnaire mémoire : [frame.rs:730](C:/src/strat9-os/workspace/kernel/src/memory/frame.rs:730) utilise `try_alloc`, sans restriction aux pages accessibles, avant `map_all_ram`. L'extension ultérieure du HHDM ne corrige pas cet accès préalable.

Correction : déduire les mappings de la carte physique et des objets vivants ; mapper explicitement le trampoline, sa pile et le handoff, ou copier le trampoline dans une allocation contrôlée. Tant que le HHDM n'est pas complet, toutes les allocations utilisées doivent être restreintes à sa couverture. Ce risque dépend du placement, pas uniquement de la quantité totale de RAM installée.

**R14 — [P1] Le changement de CR3 n'établit pas un état d'interruptions maîtrisé.**

Emplacements : [main.rs:242](C:/src/strat9-os/workspace/bootloader/src/main.rs:242), [paging.rs:205](C:/src/strat9-os/workspace/bootloader/src/paging.rs:205), [boot64.S:10](C:/src/strat9-os/workspace/kernel/src/boot/boot64.S:10).

Aucun `cli` n'apparaît dans le chemin du loader avant ou autour du remplacement des tables. Le premier `cli` explicite se trouve dans `_start`, après le changement de CR3 et le saut. Si IF est encore actif et qu'une interruption matérielle survient dans cet intervalle, elle utilise l'IDT et l'environnement hérités du firmware, alors que l'espace d'adressage a changé. Le succès d'`ExitBootServices` n'est pas un contrat de handoff CPU complet pour le noyau.

Correction : une fois la sortie UEFI réussie, désactiver explicitement les interruptions avant de modifier l'environnement d'exécution, garder un chemin de transition minimal, puis installer les tables de descripteurs et la gestion des exceptions appartenant à l'OS. Documenter aussi DF et les états CR0/CR4/EFER requis. Ne pas désactiver les interruptions arbitrairement avant les appels firmware qui en ont besoin.

**R15 — [P1] La sélection GOP peut choisir un mode sans framebuffer physique.**

Emplacements : [main.rs:122](C:/src/strat9-os/workspace/bootloader/src/main.rs:122), [main.rs:144](C:/src/strat9-os/workspace/bootloader/src/main.rs:144).

Le mode est choisi uniquement selon sa surface. Un mode `BltOnly` peut gagner, puis `frame_buffer()` est appelé sans contrôle. Ce format ne fournit pas le framebuffer requis par le noyau et l'API uefi-rs consultée refuse cet accès. Le repli prévu quand GOP est absent ne couvre pas ce cas où GOP existe avec un mode incompatible.

Correction : filtrer les formats réellement supportés avant le choix, conserver un mode compatible déjà actif si nécessaire, ou poursuivre sans framebuffer. Vérifier la taille physique fournie et la géométrie, pas seulement la résolution. La définition de `PixelBltOnly` figure dans la [spécification GOP](https://uefi.org/specs/UEFI/2.10/12_Protocols_Console_Support.html).

**R16 — [P2] Les canaux RGB/BGR sont inversés et les formats Bitmask sont inventés.**

Emplacement : [main.rs:153](C:/src/strat9-os/workspace/bootloader/src/main.rs:153).

Dans le format GOP `Rgb`, le rouge est l'octet de poids faible sur x86 little-endian ; son décalage vaut 0 et celui du bleu 16. Le code fournit l'inverse. Pour `Bgr`, il inverse aussi la convention correcte. Le noyau applique directement ces décalages dans [vga/types.rs:452](C:/src/strat9-os/workspace/kernel/src/arch/x86_64/vga/types.rs:452), ce qui échange rouge et bleu à l'écran.

Le cas `_` attribue arbitrairement un format 32 bits à un mode `Bitmask`, sans lire les masques fournis. Le calcul du pitch suppose lui aussi quatre octets par pixel avant validation du format.

Correction : corriger les décalages des deux formats standard ; extraire et valider les masques personnalisés et leur largeur effective, ou refuser ces modes. Référence : [formats de pixels GOP](https://uefi.org/specs/UEFI/2.10/12_Protocols_Console_Support.html).

**R17 — [P2] Le mapping du framebuffer crée une page de 4 Kio tous les 2 Mio.**

Emplacement : [paging.rs:155](C:/src/strat9-os/workspace/bootloader/src/paging.rs:155).

Pour chaque page physique, le code alloue une table PT, n'écrit que `PT[0]`, puis incrémente l'indice du répertoire PD. Le résultat est discontinu : `FRAMEBUFFER_BASE` est présent, `FRAMEBUFFER_BASE + 0x1000` est absent, la deuxième page physique apparaît à `FRAMEBUFFER_BASE + 0x200000`. Le plafonnement à 512 PD ne couvre en outre que 2 Mio de données physiques, insuffisants même pour plusieurs résolutions courantes.

Nuance : cette branche transmet actuellement `fb_phys` au noyau, dont la console utilise le HHDM. Elle contourne donc le défaut de la fenêtre `0xFFFF_DEAD...` ; je n'en déduis pas que le premier affichage actuel provoque systématiquement ce défaut de page. Le mapping annoncé dans l'environnement et la documentation reste faux.

Correction : remplir 512 entrées PTE par PT, puis avancer le PD ; prendre en compte le décalage éventuel de l'adresse physique dans sa première page. Vérifier les limites à chaque niveau, sans interruption silencieuse du mapping.

**R18 — [P2] Le noyau, ses données et les alias physiques restent tous inscriptibles et exécutables.**

Emplacements : [paging.rs:85](C:/src/strat9-os/workspace/bootloader/src/paging.rs:85), [paging.rs:111](C:/src/strat9-os/workspace/bootloader/src/paging.rs:111), [paging.rs:136](C:/src/strat9-os/workspace/bootloader/src/paging.rs:136).

Les mappings utilisent partout `PRESENT | WRITABLE`, sans NX. Les `p_flags` ELF sont lus mais jamais exploités. Activer NXE sans poser de bits NX ne rend aucune page non exécutable. Le noyau conserve ces tables actives ; sa routine `paging::init` ne reconstruit pas des protections pour l'image.

Correction : code RX, données et piles RW/NX, constantes R/NX lorsque possible ; restreindre aussi les alias HHDM/identité des pages du noyau, faute de quoi un alias inscriptible contourne la protection de son adresse principale. Établir CR0.WP dans le contrat de handoff. Il s'agit d'un défaut de confinement d'une corruption en mode superviseur ; les entrées examinées n'accordent pas à elles seules un accès direct Ring 3.

**R19 — [P2] La politique de cache du framebuffer n'est pas cohérente avec son chemin d'accès réel.**

Emplacements : [paging.rs:165](C:/src/strat9-os/workspace/bootloader/src/paging.rs:165), [paging.rs:222](C:/src/strat9-os/workspace/bootloader/src/paging.rs:222), [vga/api.rs:183](C:/src/strat9-os/workspace/kernel/src/arch/x86_64/vga/api.rs:183).

Le loader programme l'entrée PAT 4 en WC et ne la sélectionne que sur la fenêtre dédiée au framebuffer. Le noyau utilise cependant l'alias HHDM, créé avec l'indice PAT 0. `ensure_identity_map_range` conserve les mappings déjà présents et ne change pas leurs attributs. Le WC annoncé n'est donc pas appliqué à l'alias réellement utilisé ; si les deux fenêtres sont utilisées, leurs sélections PAT diffèrent. Le type effectif dépend aussi des MTRR et de l'état PAT hérité.

Correction : définir une politique explicite RAM/MMIO/framebuffer, programmer PAT selon la séquence d'invalidation requise et rendre les alias compatibles. Ne pas déduire le type de cache d'un simple commentaire. Pour les pages de 2 Mio/1 Gio, bit 7 est PS et bit 12 est PAT ; dans une PTE 4 Kio, bit 7 est PAT. Plusieurs commentaires actuels confondent ces rôles. Référence : [manuel système Intel, paging et PAT](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3a-part-1-manual.pdf).

**R20 — [P1] Les échecs d'allocation sont transformés en adresses arbitraires ou ignorés.**

Emplacements : [main.rs:376](C:/src/strat9-os/workspace/bootloader/src/main.rs:376), [main.rs:387](C:/src/strat9-os/workspace/bootloader/src/main.rs:387), [main.rs:399](C:/src/strat9-os/workspace/bootloader/src/main.rs:399).

Si la carte mémoire ne peut pas être allouée, le loader écrit à `0x90000` sans vérifier que cette zone est libre, RAM, suffisamment grande ou réservée. Cette adresse n'est pas universellement disponible sur les PC. Les échecs de pile, table de modules et environnement retournent zéro et le démarrage continue avec un handoff incomplet ; un `stack_base` nul devient même un sommet de pile à `0x10000` lors de l'addition.

La pile de transition est rapidement remplacée par le stub, ce qui peut masquer ce dernier cas ; cela ne justifie pas d'accepter des allocations échouées.

Correction : retourner `Result`/`Option` et traiter chaque échec obligatoire avant la transition. Préparer les ressources quand une erreur peut encore être rapportée proprement ; après la sortie UEFI, utiliser un diagnostic autonome et un arrêt contrôlé. Supprimer le repli à une adresse fixe non possédée.

**R21 — [P1, images] Les images debug cherchent leurs modules dans un profil différent de celui construit.**

Emplacements : [Makefile.toml:439](C:/src/strat9-os/Makefile.toml:439), [Makefile.toml:153](C:/src/strat9-os/Makefile.toml:153), [create-uefi-image.sh:78](C:/src/strat9-os/tools/scripts/create-uefi-image.sh:78).

`uefi-image` et `selftest-image` dépendent des tâches `*-release` pour les modules, mais imposent `STRAT9_PROFILE=debug`. Le script utilise cette variable pour le kernel, le loader et tous les modules. Sur un dépôt sans anciens artefacts debug, les modules nouvellement produits en release ne sont donc pas copiés. Leur absence ne fait qu'émettre un avertissement ; l'image est annoncée réussie. Avec des artefacts debug anciens, l'image peut contenir des modules périmés.

Correction : séparer le profil du noyau/loader de celui des modules, ou construire tous les éléments dans le profil effectivement copié. Exiger un manifeste des fichiers indispensables et refuser une image incomplète. L'autodécouverte ne doit pas ramasser silencieusement des exécutables résiduels.

**R22 — [P2, images] Le volume FAT dépasse d'un Mio la partition ESP GPT.**

Emplacements : [create-uefi-image.sh:129](C:/src/strat9-os/tools/scripts/create-uefi-image.sh:129), [create-uefi-image.sh:134](C:/src/strat9-os/tools/scripts/create-uefi-image.sh:134).

La partition va de 1 Mio à 256 Mio, soit 255 Mio. Le volume FAT temporaire est formaté avec 256 Mio, puis écrit à l'offset de 1 Mio. Son extrémité est donc à 257 Mio, hors de la partition déclarée. L'image disque globale est assez grande pour dissimuler le dépassement, mais un lecteur qui respecte les bornes GPT ne peut pas accéder à tout le volume annoncé par son BPB. Le défaut peut apparaître lors du remplissage de l'ESP ou avec un firmware plus strict.

Correction : définir la fin à `début + taille`, ou déduire exactement la taille FAT du nombre de secteurs de la partition. Vérifier la cohérence GPT/BPB lors de la validation d'image.

**R23 — [P2, images] Le script peut annoncer une image UEFI réussie composée uniquement de zéros.**

Emplacement : [create-uefi-image.sh:163](C:/src/strat9-os/tools/scripts/create-uefi-image.sh:163).

Sans les outils attendus, le dernier repli crée seulement un fichier vide de 512 Mio puis imprime « UEFI image created ». Il ne contient ni système de fichiers ni loader. C'est un succès mensonger de la chaîne de production.

Correction : vérifier les dépendances avant de toucher à l'image et retourner un statut d'erreur si aucun mode de création supporté n'est disponible. Vérifier explicitement `mcopy`, `mkfs.fat` et l'outil de partitionnement utilisé.

**R24 — [P2, validation] Le harnais peut déclarer PASS après un arrêt prématuré du noyau.**

Emplacement : [qemu-selftest.sh:207](C:/src/strat9-os/tools/scripts/qemu-selftest.sh:207).

Le verdict exige uniquement au moins un marqueur PASS et aucun marqueur FAIL. Si QEMU se termine après un premier test réussi mais avant la fin de l'orchestrateur, la boucle sort et ce critère suffit à annoncer le succès. `MARKER_DONE` est utilisé pour interrompre l'attente, mais n'est pas exigé pour le verdict. Le statut de sortie QEMU n'est pas non plus intégré au résultat.

Correction : exiger le marqueur de complétion, vérifier le statut de fin attendu et, si la suite est fixe, son nombre de tests. Un résultat partiel est incomplet, même sans ligne FAIL. Cette correction est nécessaire pour que les futures validations du loader constituent une preuve exploitable.

**R25 — [P2, validation] Une image disque UEFI passée à `--image` démarre sans OVMF.**

Emplacements : [qemu-selftest.sh:127](C:/src/strat9-os/tools/scripts/qemu-selftest.sh:127), [qemu-selftest.sh:158](C:/src/strat9-os/tools/scripts/qemu-selftest.sh:158).

Le choix du firmware dépend du suffixe `.iso`. Une image `strat9-os-uefi.img` utilise le chemin qualifié de legacy, sans pflash OVMF. Le harnais lance alors le firmware par défaut plutôt que le firmware UEFI nécessaire, malgré l'option `--image` et le format produit par les tâches actuelles.

Correction : choisir le firmware indépendamment du conteneur disque/ISO ; utiliser OVMF pour les deux sorties UEFI, réserver un mode BIOS explicitement distinct aux artefacts historiques.

**R26 — [P2, images] Une erreur de xorriso peut être masquée par le pipeline.**

Emplacements : [create-iso-uefi.sh:11](C:/src/strat9-os/tools/scripts/create-iso-uefi.sh:11), [create-iso-uefi.sh:64](C:/src/strat9-os/tools/scripts/create-iso-uefi.sh:64).

Le script utilise `set -e` mais pas `pipefail`. Le statut de `xorriso ... | tail -5` est celui de `tail`. Si xorriso échoue après avoir créé un fichier partiel, les commandes `ls` et `file` peuvent réussir et le script annonce une ISO correcte. Une absence totale de fichier sera repérée plus tard par `ls`, mais pas nécessairement une sortie partiellement écrite.

Correction : contrôler le statut du producteur (`pipefail` ou exécution sans pipeline masquant), produire dans un fichier temporaire et n'annoncer/publier le résultat qu'après validation.

**R27 — [P2] Les erreurs et transformations de noms de modules peuvent produire une initfs incomplète sans diagnostic.**

Emplacements : [modules.rs:100](C:/src/strat9-os/workspace/bootloader/src/modules.rs:100), [modules.rs:135](C:/src/strat9-os/workspace/bootloader/src/modules.rs:135), [modules.rs:188](C:/src/strat9-os/workspace/bootloader/src/modules.rs:188).

Les caractères non ASCII sont supprimés lors de l'énumération ; un fichier peut être rouvert sous un autre nom, voire charger un fichier différent si ce nom existe. Le chemin fixe de 64 unités réserve 12 caractères au préfixe et un au terminateur : le nom réellement ouvrable n'a que 51 caractères. Les noms plus longs sont tronqués lors de l'ouverture. Les échecs d'ouverture, de métadonnées et de lecture sont ensuite ignorés avec `continue`.

Correction : conserver le nom UCS-2 du firmware pour ouvrir le fichier ; appliquer une politique explicite de noms ABI (accepter, encoder ou refuser), détecter les collisions et distinguer les modules obligatoires des fichiers facultatifs. À chaque échec, indiquer le nom et le statut UEFI.

Les lectures du noyau ([main.rs:67](C:/src/strat9-os/workspace/bootloader/src/main.rs:67)) et des modules ([modules.rs:166](C:/src/strat9-os/workspace/bootloader/src/modules.rs:166)) ignorent également le nombre d'octets lu. Comparer le total à la taille annoncée permet de refuser une fin de fichier prématurée plutôt que d'accepter le complément préinitialisé à zéro. Il ne s'agit pas de supposer que chaque lecture de gros fichier sera partielle : l'API uefi-rs consultée gère déjà le découpage des gros transferts.

**Autres limites à résoudre ou à documenter**

- **ABI documentaire incohérente.** La constante partagée vaut 4, la structure actuelle fait 132 octets et ne contient pas de champs de pile ; plusieurs commentaires annoncent v2/v3, 136 octets ou une adresse framebuffer virtuelle. Le README décrit encore des champs absents et une identité de 4 Gio. Le code effectif passe une adresse framebuffer physique et mappe 8 Gio. Ces incohérences ne causent pas un décalage entre les deux crates actuellement liées à la même ABI, mais rendraient un consommateur indépendant incorrect. Références : [boot.rs:66](C:/src/strat9-os/workspace/abi/src/boot.rs:66), [README.md:45](C:/src/strat9-os/workspace/bootloader/README.md:45).
- **Fenêtre environnement non extensible.** [paging.rs:188](C:/src/strat9-os/workspace/bootloader/src/paging.rs:188) réécrit la même entrée PD pour chaque page et n'utilise que `PT[0]`. À partir de deux pages, seule la dernière subsiste. Le tampon actuel de 4 096 octets limite l'environnement à une page : défaut latent, pas un blocage actuel. Le noyau utilise aujourd'hui `cmdline_ptr` physique.
- **Série obligatoire et incohérence du débit.** Les boucles sur COM1 après la sortie du firmware n'ont aucun délai maximal. Si LSR ne signale jamais THRE, le boot reste bloqué pour un diagnostic facultatif ; l'absence d'un UART peut aussi simplement retourner `0xFF` selon la plateforme, donc elle ne bloque pas systématiquement. Le diviseur 3 configure 38 400 bauds alors que l'environnement annonce 115 200. Référence : [main.rs:244](C:/src/strat9-os/workspace/bootloader/src/main.rs:244). Prévoir une écriture bornée et une configuration unique.
- **ACPI : préférer explicitement ACPI 2+.** Le premier GUID correspondant est choisi, sans priorité à `ACPI2_GUID`. Si deux pointeurs distincts sont publiés, l'ordre de la table décide de l'accès XSDT/RSDT. Les checksums sont déjà contrôlés par le noyau : leur absence dans le loader n'est donc pas, isolément, un défaut de validation de bout en bout. Références : [main.rs:167](C:/src/strat9-os/workspace/bootloader/src/main.rs:167), [acpi/mod.rs:147](C:/src/strat9-os/workspace/kernel/src/acpi/mod.rs:147).
- **Frontière UEFI peu explicite.** Fermer les fichiers et relâcher les protocoles avant la sortie facilite la vérification des durées de vie. Sur le chemin nominal actuel, le saut final ne revient pas, donc je ne signale pas à tort une destruction automatique des `Vec` ou des handles après la sortie. L'appel à `memory_map` immédiatement avant le wrapper est redondant, pas une preuve de clé mémoire périmée : `exit_boot_services` est précisément l'API qui obtient/finalise la carte. Références : [main.rs:241](C:/src/strat9-os/workspace/bootloader/src/main.rs:241), [API boot uefi-rs 0.39](https://docs.rs/uefi/0.39.0/uefi/boot/index.html).
- **Diagnostics de panic.** Les features `logger`/`panic_handler` sont activées mais `uefi::helpers::init()` n'est pas appelé. La documentation 0.39 associe cet appel à l'activation complète de ces aides. Prévoir surtout un chemin fatal autonome après `ExitBootServices`, lorsque la console firmware n'est plus disponible. Je ne conclus pas que cette absence empêche l'allocateur global de fonctionner. Référence : [documentation uefi-rs 0.39](https://docs.rs/uefi/0.39.0/uefi/).
- **Profils Cargo locaux trompeurs.** Les profils déclarés dans le manifeste du membre bootloader ne pilotent pas les profils d'un workspace ; les profils racine déterminent notamment l'optimisation et LTO. Regrouper ces choix à la racine afin que les intentions soient vérifiables. Ce point a été vérifié dans la [documentation des workspaces Cargo](https://doc.rust-lang.org/cargo/reference/workspaces.html?highlight=workspace), sans compilation.
- **Configuration firmware de développement partagée.** Les tâches `run-uefi` utilisent directement `/usr/share/OVMF/OVMF_VARS_4M.fd` en écriture, contrairement au harnais qui en fait une copie. Cela peut échouer faute de droits ou partager des variables persistantes entre essais. Utiliser une copie privée par session : [Makefile.toml:519](C:/src/strat9-os/Makefile.toml:519).
- **Sécurité de démarrage à spécifier.** Cette revue ne démontre pas une chaîne d'authentification du noyau et des modules. Le code charge un ELF comme données puis lui transfère le contrôle. Si Secure Boot fait partie des exigences futures, définir séparément les objets authentifiés, les clés et la politique d'échec. Ce n'est pas présenté comme un défaut bloquant d'une exigence que tu n'as pas formulée.

**Chemin BIOS historique**

Le README présente ce chemin comme archivé ; il reste physiquement dans `workspace/bootloader/asm`. Il ne constitue pas un repli compatible avec le noyau actuel.

| Problème observé | Référence | Conséquence |
| --- | --- | --- |
| ABI version 1 et anciens offsets | [stage2.asm:238](C:/src/strat9-os/workspace/bootloader/asm/x86_64/stage2.asm:238) | Le noyau attend la version 4 ; le contrat transmis est incompatible. |
| Copie avec les 32 bits bas de `p_paddr`, sans mapping higher-half | [stage2.asm:194](C:/src/strat9-os/workspace/bootloader/asm/x86_64/stage2.asm:194) | Le layout actuel lié à `0xFFFFFFFF80000000` n'est pas chargé/mappé correctement ; l'identité ne couvre que le premier Gio. |
| Lecture fixe de 896 Kio de l'ELF et absence du deuxième passage annoncé | [stage2.asm:58](C:/src/strat9-os/workspace/bootloader/asm/x86_64/stage2.asm:58) | Les segments au-delà du tampon ne sont pas disponibles ; le tampon `[0x10000,0xF0000)` traverse aussi des zones PC non assimilables à de la RAM libre. |
| Carte mémoire synthétique de 2 à 256 Mio, sans découverte E820 | [stage2.asm:228](C:/src/strat9-os/workspace/bootloader/asm/x86_64/stage2.asm:228) | Mémoire absente/réservée potentiellement annoncée libre. |
| Makefile assemblant séparément deux fichiers conçus pour être inclus ensemble | [asm/Makefile:2](C:/src/strat9-os/workspace/bootloader/asm/Makefile:2) | Incompatibilité déjà documentée dans son propre commentaire ; aucune compilation exécutée pour la vérifier. |

Il faut annoncer clairement « BIOS historique non supporté par le noyau courant » et éviter que les tâches de validation modernes le sélectionnent implicitement. La remise en état de ce chemin serait un chantier séparé.

**Architecture de correction proposée**

Un petit ensemble de composants aux responsabilités explicites suffirait ; le problème n'appelle pas une accumulation de marges physiques fixes.

1. Un parseur ELF pur retourne une liste validée de segments et les exigences de mappings, sans écrire dans la machine.
2. Un gestionnaire de mémoire de boot possède toutes les allocations : noyau, modules, tables, piles, handoff et buffers temporaires. Chaque plage a une durée de vie et un propriétaire.
3. Un constructeur de tables reçoit ce gestionnaire ; il crée des mappings continus, bornés, avec droits et types de cache explicites.
4. Une finalisation unique produit la carte mémoire et les structures ABI avec des capacités et des longueurs cohérentes. Rien de vivant ne doit rester dans une région immédiatement récupérable.
5. Un trampoline minimal prend le relais après la sortie UEFI, établit les prérequis CPU et utilise uniquement des pages dont la présence est démontrée.
6. Le noyau valide d'abord l'en-tête/version du handoff, puis ses tailles, puis les données pointées. La conversion physique/virtuelle s'effectue une seule fois à une frontière identifiable.

**Vérifications effectuées sans compilation**

Les constats ont été recoupés entre producteurs et consommateurs, puis six calculs ont été exécutés dans l'outil JavaScript pour vérifier les bornes et les adresses. Ce sont des vérifications arithmétiques des formules du code, pas une exécution du bootloader ni un simulateur CPU.

| Calcul | Résultat |
| --- | --- |
| Table fixe de modules | `8 + 64*80 = 5128` octets |
| Table annoncée pour 17 modules | `1368` octets, réservation arrondie `4096`, écriture fixe `5128` |
| Carte de 170 puis 172 régions | Réservation `4096`, copie finale `4128`, dépassement `32` |
| Reste droit d'une réservation débordant une région | `0x3000 - 0x4000` devient `0xFFFFFFFFFFFFF000` en u64 sans vérification |
| Double HHDM pour `0x10000000` | `0xFFFFFE0010000000` au lieu de `0xFFFFFF0010000000` |
| Placement de la deuxième page framebuffer | `base + 2 MiB` au lieu de `base + 4 KiB` |
| GPT/FAT | Partition de `255 MiB`, volume de `256 MiB`, écart `1 MiB` |

Les détails UEFI/CPU/Rust ont été confrontés aux références primaires citées près des constats. Le lockfile fixe uefi-rs à 0.39.0. La documentation générale de cette version était accessible ; plusieurs pages de source versionnées ne l'étaient pas via le navigateur. Des sources uefi-rs courantes ont servi de recoupement sur GOP et les lectures, sans prétendre constituer une inspection exhaustive du source exact 0.39.0. Aucun résultat de compilation, de désassemblage du binaire courant ou de test matériel n'est revendiqué.

**Validation à prévoir après correction — non exécutée**

| Niveau | Cas significatifs | Critère |
| --- | --- | --- |
| Parseur ELF sur hôte | BSS pur, BSS >8 Mio, fichiers tronqués, dépassements u64, mauvais type/machine, segments qui se recouvrent, entrée hors segment | Rejet avant écriture ou plan complet, borné et cohérent |
| Mémoire de boot | Réservation au début/au milieu/à la fin, réservation traversant plusieurs descripteurs, 170/171/512 entrées, arène épuisée | Régions disjointes, pas de débordement, conservation des octets attendus, aucune plage vivante libre |
| Modules | 0/1/17/51/52/64/65 fichiers, noms longs/non ASCII, absence d'un module obligatoire, lecture écourtée | Format borné, erreurs explicites, mêmes octets après initialisation des allocateurs |
| Tables de pages | Première/dernière page et frontières 4 Kio/2 Mio/1 Gio, framebuffer non aligné, trous physiques, réservations hautes | Traductions et droits exacts ; aucune page de table hors allocation |
| QEMU/OVMF | CPU sans pages de 1 Gio, mémoire 512 Mio/2 Gio/16 Gio, GOP absent, petits et grands modes, image disque et ISO | Entrée noyau, mémoire et initfs valides, complétion de la suite exigée |
| Matériel réel | Plusieurs firmwares, RGB/BGR/Bitmask, UART absent, ESP proche de sa capacité | Diagnostic exploitable, aucun placement bas supposé, aucun hang de logging |

Le premier jalon utile est un boot minimal prouvant l'intégrité de la mémoire et du handoff. Les corrections graphiques et l'extension des tests devraient ensuite s'appuyer sur cette base stabilisée.

