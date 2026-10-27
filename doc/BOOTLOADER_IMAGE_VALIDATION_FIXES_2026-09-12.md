# Corrections ordre 6 — images UEFI et harnais de validation

Branche : `fix/UEFI-bootloader`. Constats traités : **R22, R23, R24, R25 et R26** de la revue du 12 septembre 2026. Ces changements conservent le bootloader existant.

## Images disque et ISO

**R22.** Le disque GPT conserve sa taille de 512 Mio et son ESP de 256 Mio. L'ESP commence au secteur 2 048 et se termine au secteur **526 335 inclus**, soit exactement **524 288 secteurs de 512 octets**. Le volume FAT possède cette même longueur et annonce 2 048 secteurs cachés. Les positions sont transmises en secteurs explicites à Parted, dont cette unité demande des positions exactes. [Manuel GNU Parted](https://www.gnu.org/s/parted/manual/html_node/unit.html).

Le nouveau validateur Python lit le MBR protecteur, les deux en-têtes GPT et leurs tableaux de partitions. Il contrôle les CRC, l'accord des copies, les GUID, les bornes de l'ESP et sa cohérence avec le BPB FAT32. Il vérifie également le nombre de clusters, la capacité des FAT, le cluster racine, les signatures FSInfo et la copie du secteur d'amorçage. Ces contrôles reprennent les propriétés structurelles du format GPT ; ils ne valident pas l'exécution du loader. [Spécification UEFI, GPT](https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html).

**R23.** Le repli produisant un fichier rempli de zéros a disparu. Les exécutables effectivement employés sont vérifiés avant la création des fichiers temporaires. Une dépendance, un noyau, un loader ou un module obligatoire manquant arrête le script. Chaque FAT est contrôlée par `fsck.fat -n`, puis le loader, le noyau et chaque module sont relus avec `mcopy` et comparés octet par octet aux sources.

**R26.** `xorriso` s'exécute sans pipeline susceptible de masquer son statut, avec un seuil d'arrêt `FAILURE`. L'ISO temporaire est rouverte : son catalogue doit annoncer une entrée UEFI amorçable sans émulation, qui désigne `/efiboot.img`. Ce fichier est ensuite extrait et comparé au volume FAT contrôlé avant insertion. La forme du rapport est celle publiée par le mainteneur de xorriso. [Exemple du rapport El Torito](https://lists.gnu.org/archive/html/bug-xorriso/2014-11/msg00001.html), [seuil d'arrêt xorriso](https://lists.gnu.org/archive/html/grub-devel/2010-04/msg00176.html).

Les producteurs travaillent dans un répertoire temporaire privé sous `build`. Le nom final de l'image est remplacé par renommage sur le même système de fichiers, après tous les contrôles. Un échec de copie, de formatage, de validation ou de production ISO conserve l'ancienne image. La publication du disque restaure aussi l'ancien staging si son renommage final échoue. Le nettoyage ne supprime que le répertoire temporaire résolu et vérifié.

Le staging est désormais `build/<STRAT9_IMAGE_BASENAME>-uefi-root` ; l'ancien `build/uefi_iso_root` n'est plus consommé. Il contient une copie du manifeste et du choix d'inclusion des modules de test. Ainsi, l'ISO selftest utilise le staging selftest, et l'ISO normale utilise le sien. Les tâches Cargo Make existantes créent ce staging dans leur dépendance `uefi-image` ou `selftest-image`.

L'ESP incorporée à l'ISO est dimensionnée d'après les fichiers, avec une marge pour les métadonnées et un minimum de 64 Mio. Les clusters font explicitement un secteur : une petite image doit conserver suffisamment de clusters pour être classée FAT32. Le disque conserve son ESP fixe de 256 Mio ; un dépassement de capacité fait échouer les copies.

## Verdict et firmware du harnais

**R24.** Un succès exige désormais simultanément :

- exactement un début et une fin d'orchestrateur, dans cet ordre ;
- le résultat `[selftest][strate] PASS` entre ces marqueurs, sans doublon ni autre PASS inattendu dans le protocole `[selftest]` ;
- aucun FAIL, échec de création ou timeout signalé par l'orchestrateur ;
- un arrêt demandé au moniteur QEMU après réception de la fin, puis un statut de sortie QEMU égal à zéro.

Le noyau reste normalement en fonctionnement après la fin de l'orchestrateur. Le harnais lui laisse ce comportement et demande `quit` au moniteur HMP pour arrêter l'émulateur. Il attend sa fin effective ; une sortie prématurée, un statut non nul, un timeout global ou un arrêt qui dépasse cinq secondes échoue. [Documentation du moniteur QEMU](https://www.qemu.org/docs/master/system/monitor).

Le parseur retire les couleurs SGR et le préfixe horodaté produits par `serial.rs`, et accepte LF/CRLF. Il ne recherche pas arbitrairement les marqueurs au milieu d'autres messages. Les deux diagnostics d'échec de l'orchestrateur qui ne portaient pas encore le mot FAIL le portent maintenant explicitement.

**Limite du protocole :** le résultat de succès structuré existant est celui du scénario `strate`. Les autres tâches internes ont leurs propres messages, et leur disparition du scheduler n'est pas une preuve de succès. Ce lot empêche un résultat partiel ou un timeout de l'orchestrateur de devenir PASS ; il ne transforme pas tous les tests noyau en résultats structurés indépendants. Toute extension du protocole doit mettre à jour la liste des résultats attendus et ses régressions.

**R25.** Le firmware et le conteneur sont indépendants. `--iso` sélectionne le lecteur CD, `--image` un disque raw en mode snapshot ; tous deux utilisent UEFI par défaut, quelle que soit l'extension du fichier. Le mode historique nécessite `--firmware bios` et un artefact explicite ; cela ne rend pas le noyau courant compatible avec l'ancien bootloader BIOS.

Le harnais recherche CODE/VARS ensemble dans les emplacements connus, avec les noms `_4M.fd`, `.4m.fd` ou `.fd`. Cela inclut `/usr/share/edk2/x64` utilisé par le paquet Arch actuel. Une autre installation peut utiliser `--ovmf-code` et `--ovmf-vars`, ou les variables `OVMF_CODE` et `OVMF_VARS`. Les deux fichiers doivent être fournis ensemble. Les variables firmware sont copiées pour chaque session. [Fichiers officiels du paquet Arch edk2-ovmf](https://archlinux.org/packages/extra/any/edk2-ovmf/files/).

Un artefact explicitement demandé mais absent n'est jamais remplacé par une autre image construite implicitement. Sans argument d'image, le seul choix automatique est l'ISO UEFI selftest ; `--skip-build` interdit sa construction automatique. Les logs de travail sont privés à chaque session, puis conservés dans `build/qemu-selftest.log` et `build/qemu-selftest.log.qemu`, ou au chemin donné par `--log` et son suffixe `.qemu`. La CI archive les deux.

## Dépendances et validation effectuée

Les producteurs demandent Bash, les utilitaires GNU usuels, Python 3, `parted` pour le disque, `mkfs.fat` et `fsck.fat` (dosfstools), `mcopy` (mtools), et `xorriso` pour l'ISO. Le provisionnement Arch installe désormais explicitement Python. Le harnais demande également Python 3 ; les tests hôte utilisent Python 3.11 ou plus pour le test existant du manifeste Cargo Make.

La tâche `test-uefi-tools`, ajoutée aux dépendances de `ci-tests`, exécute uniquement les tests Python/Bash. Sa commande directe, depuis la racine du dépôt, est :

```sh
python3 -B -m unittest discover -s tools/scripts/tests -p 'test_*.py' -v
```

**34 tests réussis**, dont les sept tests initfs de l'ordre 4. Ils couvrent les métadonnées GPT/FAT synthétiques, les copies GPT incohérentes, le dépassement FAT d'un Mio, les dépendances absentes, les copies corrompues, les erreurs de publication, l'ISO partielle, les marqueurs incomplets ou colorés, les erreurs et délais de l'émulateur simulé, et les choix ISO/raw/UEFI/BIOS. Les tests d'orchestration remplacent explicitement les outils de production et de validation des images par des fonctions simulées ; les validateurs Python réels sont testés séparément sur des métadonnées synthétiques. Ils ne prouvent donc pas l'interopérabilité avec les versions installées de Parted, dosfstools, mtools et xorriso.

Les scripts modifiés sont vérifiés avec `bash -n`, le diff avec `git diff --check`, et le petit changement Rust est analysé par rustfmt sans produire de code machine. **Aucune compilation, aucun assemblage, aucune image de production et aucun démarrage QEMU ou matériel réel n'ont été exécutés.**

Restent à exécuter lorsque ces opérations seront demandées : production d'un disque et d'une ISO avec les outils réels, puis démarrage de chacun sous OVMF et sur PC UEFI. La publication utilise le renommage atomique d'un fichier ; elle ne constitue pas une transaction durable après panne de courant entre le staging et l'image. Deux producteurs visant simultanément le même nom d'image et le même répertoire de sortie doivent être sérialisés.
