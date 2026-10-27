# Bootloader UEFI : corrections de l'ordre 4

Branche : `fix/UEFI-bootloader`. Base de ce lot : `90b22df`.
Périmètre demandé : R06, R21 et R27 de la [revue initiale](C:/src/strat9-os/doc/BOOTLOADER_REVIEW_2026-09-12.md).
Cibles : PC x86-64 UEFI et QEMU/OVMF.

| Constat | Correction implémentée |
| --- | --- |
| R06 | L'enregistrement initfs reçoit un `ModuleEntry` contenant une adresse physique. Une conversion unique et contrôlée produit l'adresse virtuelle pour le VFS. Le même convertisseur est utilisé par le repli de chargement d'init. Le noyau contrôle les noms, doublons et limites numériques avant ses allocations, et refuse une erreur d'enregistrement VFS. |
| R21 | `STRAT9_PROFILE` sélectionne le noyau/loader ; `STRAT9_MODULE_PROFILE` sélectionne indépendamment les modules. Les tâches existantes produisent et copient leurs modules en release. Un manifeste fixe les fichiers attendus ; l'autodécouverte des exécutables résiduels disparaît. Les sources manquantes, vides ou sans en-tête ELF64 little-endian sont refusées avant de toucher au staging ou à l'image. |
| R27 | Les chemins conservent exactement les unités UCS-2 acceptées du nom firmware. Aucun caractère n'est supprimé, aucun nom n'est tronqué. Les échecs de répertoire, énumération, ouverture, métadonnées, allocation et lecture remontent avec le nom, l'opération et le statut sur la console UEFI et E9. Une lecture courte reste une erreur. |

Le chemin du noyau utilise désormais `/initfs/init` puis `/initfs/strate-init`, ce dernier étant le nom produit par le manifeste normal. Le descripteur VFS est fermé après la lecture. Les données enregistrées restent dans les pages réservées du bootloader ; les fichiers vides de données sont conservés avec un pointeur valide et une longueur nulle. Le format binaire partagé et la version ABI restent inchangés.

La politique de noms est explicite : 1 à 63 caractères ASCII parmi les lettres, chiffres, point, tiret et soulignement. Les composants `.` et `..`, les séparateurs, les caractères non ASCII et les noms terminant par un point sont refusés. La casse est conservée ; les collisions sont recherchées sans distinction de casse pour respecter le comportement FAT. Le préfixe `\\boot\\initfs\\` occupe 13 unités : le nouveau chemin réserve donc 77 unités, terminateur compris, pour accepter réellement les 63 caractères de l'ABI. La capacité précédente ne permettait que 50 caractères de nom.

L'initfs est un répertoire plat. Les sous-répertoires sont ignorés explicitement avec diagnostic E9, hors entrées `.` et `..`. Les fichiers présents doivent tous être chargés correctement. Le répertoire et un exécutable non vide nommé exactement `init` ou `strate-init` sont obligatoires pour ce chemin UEFI ; une initfs absente ou vide n'est plus présentée comme un démarrage complet.

Les tampons `FileInfo` sont explicitement alignés sur 8 octets. Leur capacité de 4 Kio est bornée : une entrée firmware dépassant cette capacité provoque une erreur explicite. L'alignement et les signatures d'API ont été vérifiés dans les sources locales de `uefi` 0.39.

Le [manifeste](C:/src/strat9-os/tools/uefi-modules.manifest) contient 14 exécutables de base et 8 exécutables de test sélectionnés uniquement par `STRAT9_INCLUDE_TESTS=1`. Une fois sélectionnés, ces fichiers de test sont eux aussi obligatoires.

| Tâche | Noyau/loader | Modules | Tests utilisateurs embarqués |
| --- | --- | --- | --- |
| `uefi-image` | debug | release | Non |
| `uefi-image-release` | release | release | Non |
| `selftest-image` | debug, noyau avec selftest | release | Oui, 8 fichiers |

La tâche selftest dépend maintenant aussi des producteurs `strate-silo-test-release` et `strate-mem-test-release`. Le manifeste associe chaque binaire à son producteur Cargo Make. Un test contrôle ces correspondances contre les noms déclarés dans les fichiers Cargo.toml. Un manifeste alternatif peut être choisi explicitement avec `STRAT9_MODULE_MANIFEST` ; ses entrées restent soumises aux mêmes limites. Le contrôle d'en-tête de l'imageur ne remplace pas la validation ELF complète par le noyau.

Sept tests Python/Bash ont été exécutés avec succès dans [test_uefi_modules.py](C:/src/strat9-os/tools/scripts/tests/test_uefi_modules.py). Ils utilisent uniquement des fichiers simulés dans un répertoire temporaire du dépôt, supprimé après vérification de son chemin. Ils couvrent la copie du profil release, l'exclusion des résidus debug et non listés, les fichiers manquants/vides/incompatibles, les groupes de test, les collisions de noms, les limites de longueur et les dépendances des tâches. Ils n'appellent pas les scripts de création d'image.

Neuf tests Rust supplémentaires sont préparés dans [boot_initfs.rs](C:/src/strat9-os/workspace/kernel-l2-tests/tests/boot_initfs.rs), sans exécution : conversion HHDM unique, chemins UCS-2 jusqu'à 63 caractères, noms rejetés, collisions FAT, plages invalides, limites du nombre de modules, fichiers vides et passage de la table ABI à une vue lisant les octets d'un tampon hôte.

Les contrôles `rustfmt`, l'analyse syntaxique Bash et `git diff --check` passent. Le grand fichier noyau a seulement été analysé syntaxiquement, sans reformater ses parties préexistantes.

**Aucune compilation, aucun assemblage, aucun test Rust, aucune création d'image et aucun démarrage QEMU/OVMF n'ont été exécutés.** La gestion des erreurs UEFI et le démarrage complet restent à valider sur les cibles. Les défauts GOP/protections/cache de l'ordre 5 et GPT/outils/harnais de l'ordre 6 restent hors de ce lot.
