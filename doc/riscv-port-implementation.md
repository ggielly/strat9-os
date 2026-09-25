# Port RISC-V 64 bits — état et feuille de route

> Ce document décrit le travail restant pour la branche `hal-arch-facade`. Il ne constitue pas une déclaration de support matériel : le port RISC-V n’est pas encore démarrable ni utilisable comme cible système.

## Périmètre

Cible initiale : `riscv64imac-unknown-none-elf`, QEMU `virt`, entrée en mode superviseur via OpenSBI. Le firmware transmet le hart ID dans `a0` et l’adresse du Device Tree Blob (DTB) dans `a1`. Le DTB est la source de vérité pour les plages mémoire et les périphériques présents ; ne pas coder en dur des adresses supposées de QEMU.

Le port doit d’abord atteindre un démarrage déterministe sur un seul hart, une console série, une gestion des traps et une mémoire virtuelle cohérente. SMP, espace utilisateur et périphériques additionnels viennent ensuite.

## État constaté

| Domaine | État actuel | Conséquence |
|---|---|---|
| Cible et tâches | `targets/riscv64-strat9.json`, la cible dans `rust-toolchain.toml`, `Makefile.riscv` et `tools/scripts/run-qemu-riscv.sh` existent. | Le parcours de build/QEMU est amorcé ; le noyau doit être chargé directement par OpenSBI, fourni par QEMU, et le démarrage complet n’est pas encore validé ; ne pas le confondre avec un boot RISC-V opérationnel. |
| Façade d’architecture | `workspace/kernel/src/arch/facade_riscv.rs` et les types neutres de `arch::xshim` existent. | L’abstraction est amorcée, mais des chemins partagés et la compatibilité de pagination restent à assainir. |
| Compatibilité x86 | Plusieurs interfaces sans équivalent RISC-V échouent maintenant explicitement plutôt que de simuler un succès. | Conserver ce comportement jusqu’à l’existence d’une implémentation réelle. |
| Capacités CPU | Les sorties RISC-V `/proc/cpuinfo` et `/sys/cpu/*` indiquent que vendor, modèle et ISA ne sont pas encore découverts ; le filtrage des fonctionnalités de composants reste x86-only. | Ajouter la découverte ISA via DTB avant d’annoncer des capacités RISC-V ou d’accepter un format de composant RISC-V. |
| Entrée et boot | Le contrat OpenSBI, l'entrée `_start`, le linker RISC-V, le DTB, le buddy et Sv39 sont activés au boot ; le chemin s'arrête après activation paginée. | Traps, timer et espace utilisateur restent à installer. |
| Boot ABI | `workspace/abi/src/boot.rs` définit `STRAT9_BOOT_ABI_VERSION = 1` et un `KernelArgs` de 160 octets avec des champs ACPI. | Le DTB ne peut pas être ajouté silencieusement à cette structure : tout changement doit être versionné et coordonné avec le chargeur. |
| Mémoire virtuelle | `arch/xshim_riscv_stub.rs` contient une traduction Sv48 partielle et des opérations PTE, mais ne fournit pas encore un mapper RISC‑V complet. Le mapper Sv39 de `arch/riscv64/paging.rs` mappe la RAM et les 16 plages MMIO du DTB, puis active `satp`. | Le chemin physique direct et les traps restent à brancher sur ce mapper. |
| Interruptions et temps | Le trap handler S‑mode direct gère le timer et les interrupts externes ; le PLIC est découvert via le DTB, et le timer S‑mode utilise `stimecmp`/`SBI` à 100 Hz. | Le routage des sources matérielles et le scheduler restent à réaliser. |
| Périphériques | La console série RISC-V est amorcée ; le modèle de pilote reste défini par `doc/HARDWARE.md` et `docs-site/src/driver-model.md`. | Pas de découverte DTB ni de pilote VirtIO-MMIO complet établi. |
| Exécution | Pas de contexte RISC-V, transition utilisateur, syscall `ecall` ou gestionnaire de traps complet. | Le noyau ne peut pas encore exécuter les charges de travail attendues. |
| Validation | Les tâches RISC-V de build et d’exécution existent dans `Makefile.toml` et `Makefile.riscv`. | Les critères de démarrage complet restent à valider après implémentation de la mémoire et des traps. |

Les éléments ci-dessus sont un état de travail, pas une liste exhaustive de capacités. Toute fonctionnalité ne figurant pas explicitement comme implémentée doit être considérée comme absente ou non validée.

## Règles de conception et contrats

1. **La façade porte les abstractions, pas des simulacres.** Les services utilisables par le code partagé doivent avoir un contrat commun et une implémentation RISC-V réelle. Une opération indisponible doit échouer clairement ; elle ne doit pas retourner un succès fictif.
2. **Le code partagé ne dépend pas d’un backend x86.** Les références à APIC, IDT, I/O ports ou aux types x86 restent confinées aux modules x86 ou à des interfaces explicitement propres à cette architecture.
3. **Le boot ABI est versionné.** `KernelArgs` est actuellement une structure `repr(C)` de 160 octets, version 1. Ne pas ajouter, réordonner ni réinterpréter ses champs pour transmettre le DTB sans décision ABI documentée, changement de version et mise à jour coordonnée du chargeur et du noyau. Étudier une extension versionnée ou un contrat d’entrée RISC-V séparé.
4. **L’ABI syscall reste stable.** `doc/NATIVE_SYSCALLS.md` définit les numéros et la sémantique existants, avec une convention d’appel x86_64. RISC-V doit fournir son adaptateur d’architecture autour de `ecall` sans modifier implicitement les numéros ou la sémantique. Toute évolution incompatible exige une version explicite.
5. **Le DTB décrit la plateforme réellement démarrée.** Parser les nœuds nécessaires et valider les adresses, tailles, interruptions et transports. QEMU `virt` peut exposer UART, PLIC, timer fourni par SBI et périphériques VirtIO-MMIO ; leur présence et leurs paramètres doivent venir du DTB.
6. **Le modèle de mémoire doit correspondre au matériel et au compilateur.** Choisir Sv39 ou Sv48 explicitement, vérifier le mode pris en charge et utiliser le même choix dans le boot, le mapper, les allocateurs et les tests d’intégration futurs. Ne pas déduire qu’un mode est disponible du seul nom de la cible Rust.

## Contrat d'entrée OpenSBI

L'entrée RISC-V est indépendante de `KernelArgs` version 1. Le noyau est lié à `0x80200000` et reçoit les registres suivants au transfert OpenSBI :

- `a0` : identifiant du hart ;
- `a1` : adresse physique du DTB au format FDT, avec des champs big-endian.

`boot/boot64r.S` installe la pile, désactive les interruptions superviseur, initialise `gp`, efface `.bss`, parke les harts non principaux et appelle `arch::riscv64::boot::riscv_boot_entry`. Le chemin Rust conserve le pointeur et la taille du DTB dans `RiscvBootInfo` après validation de sa signature, de sa taille, de sa version, des plages de sa structure et de sa table de réservations mémoire. Un DTB absent ou invalide est signalé sur la console puis le hart principal est arrêté proprement.

Cette première étape valide le DTB, découvre les régions RAM et réservées, initialise l’allocateur boot, les métadonnées de frames et le buddy, puis exécute un test allocation/libération. Elle s’arrête ensuite volontairement et ne doit pas être considérée comme un démarrage système complet. Le mapper Sv39/Sv48, les traps, le timer et l'espace utilisateur dépendent des phases P2 et suivantes. `KernelArgs` version 1 reste inchangé ; le DTB ne doit pas y être ajouté implicitement.

`RiscvBootInfo::memory_regions` fournit maintenant un parseur FDT minimal, sans allocation : il parcourt les nœuds `memory@...` et `/reserved-memory`, hérite des `#address-cells`/`#size-cells`, extrait les propriétés `reg` et vérifie les débordements, les tailles nulles et les chevauchements par catégorie. La carte n'est pas encore remise à l'allocateur physique ; cette étape et le mapper natif restent les prochaines parties de P2.

## Feuille de route

Les phases sont ordonnées par dépendances. Une phase n’est terminée que lorsque ses critères d’acceptation sont documentés et reproductibles. Les builds et essais sont à réaliser par le mainteneur au moment voulu ; cette feuille de route ne les exécute pas.

### P0 — Stabiliser la frontière HAL (branche courante)

**But :** rendre la séparation x86/RISC-V cohérente avant d’ajouter le boot.

- **P0.1 — Inventorier les points d’entrée d’architecture.** Classer les appels partagés en services HAL, fonctions propres à x86 et fonctions propres à RISC-V. Utiliser `workspace/kernel/src/arch/` comme frontière de référence.
- **P0.2 — Supprimer les shims de pagination transitoires.** Déplacer le contrat de pagination dans une interface d’architecture stable, puis retirer `paging_compat` et les chemins `xshim` qui ne servent qu’à préserver une ancienne signature. Garder uniquement les types réellement neutres.
- **P0.3 — Isoler les pilotes I/O historiques.** Les modules PCnet/RTL8139, ATA legacy et UHCI sont réservés à x86 ; les appels d’initialisation PCnet/RTL8139 sont également gardés par architecture. Restreindre les pilotes utilisant les ports x86 à x86 et définir les interfaces de console/périphérique indépendantes du transport.
- **P0.4 — Auditer les échecs explicites.** Vérifier chaque stub RISC-V : aucune API de contrôle (IRQ, TLB, SMP, PCI, contexte, syscall) ne doit annoncer qu’une opération a réussi si elle n’est pas prise en charge.
- **Critère de sortie :** le code commun dépend des contrats HAL, les dépendances x86 restent isolées, et les opérations RISC-V non implémentées sont identifiables comme telles.

### P1 — Établir un démarrage RISC-V reproductible

**But :** atteindre une entrée noyau identifiable sur QEMU `virt` sans prétendre démarrer le système complet.

- **P1.1 — Formaliser le contrat OpenSBI.** Documenter l’état attendu à l’entrée (mode, hart ID, DTB, registres et alignement), la plage de chargement et le transfert de contrôle. Ajouter un point d’entrée/linker script RISC-V cohérent avec la cible.
- **P1.2 — Définir le transfert du DTB.** Décider comment le pointeur `a1` parvient au code Rust. Ne pas modifier `KernelArgs` version 1 en place ; choisir une extension ou un contrat versionné, et couvrir l’interopérabilité avec le chargeur.
- **P1.3 — Ajouter le parcours de build et d’exécution.** Créer des tâches Makefile distinctes pour compiler et lancer QEMU `virt`, avec sortie console visible et paramètres de machine centralisés. Laisser les paramètres x86 inchangés.
- **P1.4 — Ajouter une première validation du DTB.** Vérifier le magic, la taille et les limites du blob avant de parcourir les nœuds. Prévoir des erreurs explicites pour les entrées invalides.
- **Critère de sortie :** le noyau entre depuis OpenSBI, affiche un message de démarrage sur la console et traite proprement un DTB absent ou invalide ; le contrat de démarrage est documenté.

### P2 — Initialisation plateforme et mémoire

**But :** remplacer les stubs de plateforme et la traduction partielle par des services réels, utilisables dans le noyau.

- **P2.1 — Découvrir la mémoire via le DTB.** Extraire les régions RAM et réservées, préserver le blob tant qu’il est utilisé et vérifier les débordements/chevauchements avant de configurer l’allocateur physique.
- **P2.2 — Fixer le mode de pagination.** Décider et documenter Sv39 ou Sv48 pour la cible initiale, y compris les extensions CPU requises et la disposition virtuelle du noyau.
- **P2.3 — Implémenter le mapper natif.** Créer les tables de pages, mapper et démapper des régions, gérer les permissions, alignements, grandes pages le cas échéant, invalidations locales et erreurs. Remplacer les opérations de compatibilité par ce contrat.
- **P2.4 — Mettre en place les traps.** Installer `stvec`, sauvegarder/restaurer le contexte d’interruption, décoder `scause`/`stval`, traiter les exceptions synchrones et produire un diagnostic fatal sans continuer dans un état incohérent.
- **P2.5 — Gérer le timer et les interruptions.** Définir le contrat SBI utilisé pour programmer le timer, initialiser les interruptions superviseur et découvrir/configurer le contrôleur via DTB. Commencer par un seul hart.
- **Critère de sortie :** mémoire physique et virtuelle initialisées à partir des informations plateforme ; faults et interruptions inattendus diagnostiqués ; timer superviseur observable sans recourir aux interfaces APIC/PIC.

### P3 — Hart local, ordonnanceur et appels système

**But :** permettre les opérations noyau fondamentales sur RISC-V avec un seul hart.

- **P3.1 — Implémenter les données locales au hart.** Définir l’initialisation et l’accès sûrs aux données per-hart, notamment la pile de trap et l’état courant, avant toute activation SMP.
- **P3.2 — Implémenter le changement de contexte.** Sauvegarder/restaurer les registres requis par l’ABI RISC-V et le noyau. Définir explicitement le traitement de l’état flottant/vectoriel selon les extensions retenues.
- **P3.3 — Raccorder l’ordonnanceur.** Remplacer les hooks RISC-V provisoires par le chemin réel de préemption et de réveil, en s’appuyant sur le timer de P2.
- **P3.4 — Implémenter l’entrée syscall `ecall`.** Extraire numéro et arguments conformément à l’ABI RISC-V, appeler la couche syscall existante et retourner le résultat selon une convention documentée. Conserver la sémantique de `doc/NATIVE_SYSCALLS.md`.
- **Critère de sortie :** tâches noyau commutables sur un hart, timer de préemption opérationnel et syscall de diagnostic appelable par un contexte RISC-V contrôlé.

### P4 — Espace utilisateur

**But :** charger et exécuter un premier programme sans étendre implicitement les ABI publiques.

- **P4.1 — Définir la frontière noyau/utilisateur.** Spécifier les permissions de pages, les piles, la transition superviseur/utilisateur et les règles de retour après trap.
- **P4.2 — Adapter le chargement ELF.** Vérifier les classes, machines, segments, tailles et permissions attendues pour RISC-V avant de mapper les segments.
- **P4.3 — Ajouter la bibliothèque d’amorçage utilisateur.** Fournir l’assembleur d’entrée et le wrapper syscall RISC-V, sans dupliquer ni altérer les numéros de syscall.
- **P4.4 — Valider les erreurs de frontière.** Couvrir les accès interdits, les arguments invalides et la terminaison contrôlée d’un processus.
- **Critère de sortie :** un binaire utilisateur minimal démarre, utilise au moins un syscall existant et termine sans endommager l’état du noyau.

### P5 — Console et premiers pilotes déclarés par plateforme

**But :** faire évoluer le démarrage minimal vers un environnement utilisable, avec découverte conforme au modèle de pilotes.

- **P5.1 — Compléter la console UART.** Découvrir le périphérique et ses interruptions via DTB ; séparer le service console du pilote matériel.
- **P5.2 — Ajouter VirtIO-MMIO.** Commencer par le transport et un périphérique nécessaire au scénario choisi. Ne pas supposer PCI : choisir le transport d’après le DTB et le contrat matériel.
- **P5.3 — Intégrer les pilotes au modèle commun.** Respecter l’enregistrement et les interfaces décrits dans `docs-site/src/driver-model.md` et `doc/HARDWARE.md`.
- **P5.4 — Raccorder stockage et système de fichiers.** Choisir un périphérique et un chemin de boot minimaux, puis traiter les erreurs d’initialisation sans bloquer la console de diagnostic.
- **Critère de sortie :** découverte d’au moins un périphérique DTB et utilisation d’un pilote via le modèle commun ; démarrage diagnostiquable même si le périphérique est absent.

### P6 — SMP et élargissement de plateforme

**But :** ne passer au multi-hart qu’après la stabilisation des primitives uniprocesseur.

- **P6.1 — Démarrer les harts secondaires.** Définir le protocole SBI de démarrage, les piles et données locales, puis synchroniser leur arrivée avant de les rendre ordonnanceurs.
- **P6.2 — Implémenter la cohérence des TLB.** Définir invalidation locale et shootdown inter-harts avant de partager des espaces d’adressage modifiables.
- **P6.3 — Traiter les courses d’initialisation.** Rendre les allocateurs, locks, IRQ et pilotes sûrs avec plusieurs harts.
- **P6.4 — Étendre les périphériques et capacités.** Ajouter réseau, RNG, affichage ou extensions ISA uniquement selon les besoins documentés et les ressources DTB disponibles.
- **Critère de sortie :** plusieurs harts exécutent et synchronisent des tâches sans corruption mémoire ; les invalidations inter-harts sont effectives.

## Plan de correction du build RISC-V

Le build release observé le 2026-09-25 échoue avec 99 erreurs et 29 avertissements. Ce relevé décrit un instantané du code, pas un contrat permanent. Corriger par lots de causes racines : les signatures divergentes produisent souvent plusieurs erreurs en cascade. Après chaque lot, le mainteneur relance le même build RISC-V et actualise cette liste ; ne pas masquer les erreurs en ajoutant des stubs qui réussissent.

### C1 — Isoler les chemins explicitement x86

- **C1.1 — Corriger les appels d’initialisation x86.** Garder les appels `arch::gdt::init()` et `hardware::storage::ata_legacy::init()` dans les configurations x86, comme leurs modules et leurs dépendances. Auditer les appels similaires aux modules conditionnels.
- **C1.2 — Retirer l’assembleur x86 du code partagé.** Les accès aux registres `ecx`, `eax` et `edx` dans `syscall/process.rs` doivent être soit sous `cfg(target_arch = "x86_64")` avec une API commune explicite, soit remplacés par une implémentation RISC-V correcte si ce service est requis sur RISC-V. Ne pas réécrire les registres en registres RISC-V sans spécifier le contrat.
- **C1.3 — Séparer les mécanismes x86 de N3.** `ipc/n3.rs` interroge CPUID et manipule des concepts CR3/PCID. Déclarer ce chemin non disponible sur RISC-V tant qu’un mécanisme propre à l’architecture n’est pas spécifié ; ne pas simuler PCID ni les changements de CR3.
- **Critère de sortie :** aucun symbole x86 conditionnel ni registre assembleur x86 n’est résolu par le build RISC-V via un shim.

### C2 — Stabiliser la façade d’architecture

- **C2.1 — Unifier CPUID et description CPU.** Les affichages RISC-V de `procfs` et `/sys/cpu` n’annoncent plus les champs x86 et déclarent les valeurs non découvertes ; le filtrage des exigences de fonctionnalités des composants reste x86-only. Le type neutre de capacités/propriétés CPU et la découverte ISA via DTB restent à réaliser. Garder les informations x86 détaillées derrière le backend x86.
- **C2.2 — Définir le contrat de décision de retour d’interruption.** Le chemin `maybe_preempt_from_interrupt`, qui construit une décision compatible `iretq`, est maintenant compilé uniquement sur x86 ; ne pas recopier son type vers RISC-V avant d’avoir défini le trap frame et le retour `sret`.
- **C2.3 — Compléter la façade au besoin réel, pas à l’identique.** Les initialisations TSS/GDT/SYSCALL sont maintenant réservées à x86. Restent les incompatibilités `arch::gdt`, `arch::cpuid`, VGA/panic et les types de retour : résoudre chacune selon des interfaces HAL stables. L’absence de GDT/VGA sur RISC-V doit être reflétée par des API communes adaptées ou par des appels conditionnels, pas par des fonctions vides annonçant une initialisation.
- **Critère de sortie :** les consommateurs partagés utilisent des contrats HAL stables et ne connaissent pas les détails CPUID/GDT/VGA propres à x86.

### C3 — Rendre les primitives mémoire réellement neutres

- **C3.1 — Choisir un propriétaire des types d’adresse et de frame.** Les types d’adresse neutres restent des alias des types OSTD ; `PhysAddr` supporte maintenant `Hash` et `AddAssign`, et `PhysFrame` expose une construction alignée. Formaliser encore si OSTD est le contrat HAL commun ou si `xshim` doit posséder ses types.
- **C3.2 — Fixer les signatures `Translate` et `Mapper`.** Le walk de compatibilité RISC-V retourne maintenant le `TranslateResult` attendu par les appelants, avec `NotMapped` explicite. Définir les contrats neutres complets et corriger encore les signatures mapper, erreurs de mapping et l’implémentation réelle.
- **C3.3 — Corriger les opérations de types à la source.** `PhysAddr` prend en charge le hash et l’incrément requis ; les frames 4 KiB/2 MiB valident leur alignement à la construction. Auditer les conversions restantes et les débordements sans ajouter d’opérations qui masquent une erreur d’adresse.
- **C3.4 — Maintenir les implémentations par architecture.** Le mapper RISC-V ne doit pas prétendre que `OffsetPageTable` x86 ou son frame allocator fonctionne. Gater le code x86 en attendant P2, puis brancher l’implémentation Sv39/Sv48 choisie.
- **Critère de sortie :** compilation des consommateurs de mémoire sans adapter des structures x86 au moyen de stubs RISC-V ; les erreurs de mapping restent observables.

### C4 — Aligner découverte PCI et pilotes

- **C4.1 — Confirmer le contrat PCI du noyau.** L’API locale retourne des paires adresse/périphérique et ne possède pas certains champs/méthodes attendus (`prog_if`, configuration PCI, activation d’espace I/O). Documenter la signature canonique avant adaptation des NIC, VirtIO et syscall PCI.
- **C4.2 — Mettre les pilotes PCI x86 hors du build RISC-V initial.** Gater les pilotes dépendant de PCI legacy ou de ports I/O tant que leur transport n’est pas portable ; inclure aussi leurs appels d’initialisation. Ne pas dériver `Debug` ou ajouter des méthodes fictives pour faire disparaître les erreurs.
- **C4.3 — Garder VirtIO-MMIO comme chemin plateforme RISC-V initial.** La découverte PCI VirtIO ne remplace pas le transport MMIO décrit par le DTB. Porter un transport PCI seulement si une plateforme RISC-V ciblée le justifie.
- **Critère de sortie :** le build initial ne compile que les transports disponibles sur la plateforme ciblée, et aucune découverte de périphérique absente n’est simulée.

### C5 — Traiter les surfaces console, shell et périphériques

- **C5.1 — Décider le périmètre de l’interface `top`.** L’import `Strat9RatatuiBackend` ne résout pas sur RISC-V et les types VGA diffèrent. Soit fournir un backend série adapté au contrat de rendu réellement nécessaire, soit ne pas compiler cette commande sur la cible ; ne pas faire de l’interface VGA une dépendance du boot minimal.
- **C5.2 — Remplacer la dépendance panic VGA par le diagnostic série.** Adapter `boot/panic.rs` au contrat console commun et résoudre les appels de formatage/type qui divergent sans supposer un framebuffer présent.
- **C5.3 — Résoudre les signatures HID/VirtIO.** Aligner les appels `hardware/usb/hid.rs` sur les fonctions effectivement exposées, puis confirmer si ces chemins sont requis pour l’incrément QEMU virt initial.
- **C5.4 — Réparer les appels shell et trace en lots séparés.** Les erreurs de `shell/mod.rs`, commandes système et `trace/mod.rs` incluent des types numériques et arités différents. Adapter chaque appel au contrat réel du backend ; garder le shell hors du premier jalon de boot s’il dépend d’UI non disponible.
- **Critère de sortie :** la console série et le chemin panic ne dépendent pas de VGA ; les commandes non prises en charge ne sont pas exposées comme opérationnelles.

### Ordre d’exécution et jalons de validation

1. Traiter C1 et C2.1 en priorité : ils isolent les erreurs de compilation strictement liées à l’architecture.
2. Traiter C3 en décision d’API avant les adaptations des consommateurs ; ne pas empiler les corrections de type site par site.
3. Traiter C4 en choisissant explicitement le sous-ensemble de pilotes cible, puis C5 pour le chemin minimal console/panic.
4. Relancer la compilation après chaque lot et classer les erreurs restantes par fichier et cause racine. Ne poursuivre que si le nombre d’erreurs baisse ou si les erreurs restantes sont mieux isolées.
5. Quand la compilation atteint zéro erreur, valider séparément le démarrage QEMU et les contrats de boot/mémoire décrits dans les phases P1/P2 ; un build réussi ne signifie pas que le port est démarrable.

## Décisions à prendre avant implémentation

- **Mode de pages :** Sv39 est retenu pour l’étape QEMU `virt` (512 Mio, 39 bits virtuels, 3 niveaux) ; Sv48 reste à réévaluer pour les cibles avec un espace virtuel plus large. Les tables Sv39 et les plages MMIO découvertes dans le DTB sont construites au boot, puis `satp` est activé après le handoff buddy.
- **Boot ABI :** choisir extension versionnée ou contrat d’entrée RISC-V distinct ; documenter le producteur et le consommateur du DTB ainsi que sa durée de vie.
- **SBI :** fixer la version minimale et les extensions d’extension SBI nécessaires pour timer et démarrage secondaire ; définir le comportement lorsque le firmware ne les expose pas.
- **État flottant :** fixer les extensions réellement activées et la politique de sauvegarde/restauration pour les tâches.
- **Dépendances :** décider si un parseur FDT existant est acceptable ou si le noyau maintient un parseur minimal ; limiter les allocations et valider toutes les longueurs.
- **Compatibilité :** maintenir x86_64 fonctionnel durant les changements de façade et éviter les modifications ABI non versionnées.

## Prochain incrément recommandé

Le contrat d'entrée OpenSBI, la découverte DTB, l’initialisation buddy, Sv39, le trap handler S‑mode, le PLIC et le timer à 100 Hz sont matérialisés. Les 16 plages MMIO découvertes dans le DTB sont mappées avant l’activation de `satp`. L’étape suivante est le routage des sources PCI, puis l’espace utilisateur.

## Références du dépôt

- `workspace/kernel/src/arch/` — façade, backends et shims d’architecture.
- `workspace/abi/src/boot.rs` — version et layout du contrat de boot.
- `targets/riscv64-strat9.json` et `rust-toolchain.toml` — cible et toolchain.
- `Makefile.toml` — tâches de build et d’exécution actuelles.
- `doc/NATIVE_SYSCALLS.md` — contrat des appels système.
- `doc/HARDWARE.md` et `docs-site/src/driver-model.md` — contraintes matériel et modèle de pilotes.
