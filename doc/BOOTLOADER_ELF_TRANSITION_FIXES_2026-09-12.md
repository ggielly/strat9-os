# Bootloader UEFI : corrections de l'ordre 3

Branche : `fix/UEFI-bootloader`. Base de ce lot : `57b6420`.
Périmètre : R09 à R14 de la [revue initiale](C:/src/strat9-os/doc/BOOTLOADER_REVIEW_2026-09-12.md), pour PC x86-64 UEFI et QEMU/OVMF.

Les corrections prolongent le bootloader existant et ses réservations UEFI. Le format binaire de `KernelArgs` et la version ABI restent inchangés.

| Constat | Correction implémentée |
| --- | --- |
| R09 | Tous les `PT_LOAD` non vides en mémoire sont chargés, y compris les segments BSS purs. L'étendue allouée et mappée provient de `p_memsz`. Le chargeur efface les queues nulles, les intervalles entre segments et le complément de page ; la marge arbitraire de 8 Mio disparaît. Le stub efface également le dernier octet du BSS grâce à `cld; rep stosb`. |
| R10 | Un passage sans écriture valide l'en-tête, les versions, l'architecture x86-64, le type `ET_EXEC`, la table des programmes, les limites arithmétiques, les tailles, les alignements, l'ordre et les recouvrements. Le point d'entrée doit appartenir aux octets présents dans le fichier d'un segment exécutable. Les dispositions physiques et virtuelles incompatibles sont refusées. Toutes les sources sont revérifiées avant la première écriture de chargement. |
| R11 | Le dernier marqueur COM1 déclare explicitement `in("dx")` et `in("al")`. Les lectures volatiles utilisées comme protection contre les clobbers disparaissent. |
| R12 | Identité et HHDM utilisent exclusivement des feuilles de 2 Mio. Un contrôle CPUID vérifie PSE, MSR, PAE, PAT, FXSR, SSE/SSE2, NX, mode long et largeur physique avant le chargement. Les pages de 1 Gio ne sont plus un prérequis. |
| R13 | Le plan couvre l'image EFI complète, la RAM allouable, les régions ACPI/runtime et le framebuffer, avec un budget de tables calculé. La carte finale est contrôlée contre ce plan. La transition charge la pile réservée avant CR3 et saute ensuite directement au noyau, sans accès à l'ancienne pile. L'allocation des métadonnées de frames vérifie aussi l'accessibilité HHDM réelle. |
| R14 | Après `ExitBootServices`, IF et DF sont explicitement effacés. La transition normalise les bits requis de CR0/CR4/EFER, sélectionne PCID zéro si nécessaire, désactive PCIDE/PGE et invalide ainsi les traductions globales héritées. Le stub installe une GDT et une IDT appartenant au noyau avant le nettoyage BSS et l'appel Rust. |

Le traitement des segments suit la distinction entre taille fichier et taille mémoire, ainsi que la congruence des alignements décrites par la [System V ABI, Program Header](https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html). Le contrat des opérandes assembleur est documenté dans la [référence Rust](https://doc.rust-lang.org/reference/inline-assembly.html). Les règles de pagination, CR0/CR4/EFER et descripteurs sont référencées dans le [manuel système Intel](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3a-part-1-manual.pdf).

Le layout accepté reste celui du script de liaison : image statique commençant à `0xFFFFFFFF80000000`, dans une fenêtre virtuelle de 1 Gio, avec au plus 16 en-têtes de programmes. Les segments dynamiques, interpréteur et TLS sont refusés. Les champs `bss_virt_*` décrivent exactement la queue nulle du dernier `PT_LOAD`, qui correspond au segment BSS distinct du script actuel ; les autres queues nulles sont également effacées par le chargeur.

La couverture physique est arrondie au Gio, jusqu'au minimum entre la capacité du CPU et 512 Gio. Cette limite correspond au slot PML4 réservé au HHDM ; une région requise au-delà provoque une erreur avant la sortie UEFI. Les allocations permanentes restent sous 8 Gio. Pour 512 Gio couverts et une image noyau de 1 Gio, identité, HHDM et noyau nécessitent 1541 pages de tables, avant les mappings optionnels. Une modification inattendue de la carte finale hors couverture entraîne un arrêt contrôlé après la sortie UEFI.

Les modes LA57 et CET actifs sont refusés explicitement. L'IDT provisoire contient 256 portes menant à un arrêt avec marqueur E9 `!`. Elle réside hors BSS et utilise la pile courante, sans IST. Ce mécanisme ne garantit pas la récupération d'un défaut de pile ou la maîtrise des NMI pendant le remplacement initial des tables. La GDT/TSS/IDT normale du noyau prend ensuite le relais.

Quatorze tests supplémentaires sont préparés : six dans [boot_memory.rs](C:/src/strat9-os/workspace/kernel-l2-tests/tests/boot_memory.rs) et huit dans [boot_transition.rs](C:/src/strat9-os/workspace/kernel-l2-tests/tests/boot_transition.rs). Ils couvrent notamment un BSS pur de 12 Mio + 3 octets, les sentinelles autour des destinations, les ELF incompatibles, l'absence de pages de 1 Gio, les prérequis CPU manquants, une image EFI au-dessus de 8 Gio, la RAM dispersée en adresses hautes, les limites physiques et l'épuisement du budget de tables.

La syntaxe et le formatage Rust ciblés ont été contrôlés avec `rustfmt` du toolchain local `nightly-2026-07-20`. Pour `frame.rs`, seule l'analyse syntaxique a été réalisée, sans reformater le fichier. `git diff --check` passe. Le chemin assembleur, les sélecteurs et le placement des sections ont été relus statiquement.

**Aucune compilation, aucun assemblage, aucun test Rust, aucune création d'image et aucun démarrage QEMU/OVMF n'ont été exécutés.** Les tests ajoutés restent non exécutés ; les contrôles ci-dessus ne vérifient ni les types Rust ni l'encodage assembleur et ne démontrent pas le démarrage.

Les corrections initfs de l'ordre 4 et GOP/protections/cache de l'ordre 5 restent à traiter. En particulier, ce lot ne corrige pas les alias de cache du framebuffer ni la programmation PAT recensés en R19.
