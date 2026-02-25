# Conventions d'architecture des drivers

Ce document definit la structure a respecter pour ajouter de nouveaux drivers materiels dans Strat9-OS, sans dispersion du code.

## Objectifs

- Regrouper les drivers par type de materiel.
- Separer clairement la logique kernel et la logique reusable.
- Garder une integration uniforme avec VFS et les schemes.
- Prepararer la migration vers une future strate `driver` en silo userspace.

## Arborescence de reference

### 1) Crates drivers hors kernel (reutilisables)

Les crates de drivers vivent sous:

`workspace/drivers/`

Exemple NIC actuel:

- `workspace/drivers/nic/net-core`
- `workspace/drivers/nic/nic-buffers`
- `workspace/drivers/nic/nic-queues`
- `workspace/drivers/nic/intel-ethernet`
- `workspace/drivers/nic/e1000`
- `workspace/drivers/nic/driver-net-proto`

Pour les prochains domaines:

- `workspace/drivers/storage/...`
- `workspace/drivers/video/...`
- `workspace/drivers/input/...`

Regle: un crate = une responsabilite claire.

### 2) Integration kernel (orchestration materielle)

Le kernel expose les points d'entree dans:

`workspace/kernel/src/hardware/`

Structure:

- `hardware/nic/` pour reseau
- `hardware/storage/` pour disque/volume
- `hardware/video/` pour affichage
- `hardware/virtio/` pour le socle commun VirtIO (helpers/shared types), pas pour les drivers finaux

## Convention de nommage

- Driver concret par bus/type: `virtio_net.rs`, `virtio_block.rs`, `e1000_drv.rs`, etc.
- Module d'integration domaine:
  - `hardware/nic/mod.rs`
  - `hardware/storage/mod.rs`
  - `hardware/video/mod.rs`
- Les crates hors kernel utilisent des noms stables et explicites (sans suffixes temporaires).

## Regles d'implementation

1. **Hors kernel**:
   - Mettre la logique de protocole/controleur dans un crate dedie.
   - Eviter les dependances au kernel (pas d'acces direct VFS, scheduler, syscalls kernel).
   - Exposer des traits/interfaces minimales pour DMA/MMIO si necessaire.

2. **Dans le kernel**:
   - Garder les adapters materiel dans `hardware/<domaine>/`.
   - Centraliser la detection/probe dans le module domaine.
   - Enregistrer les devices via une registry de domaine (`nic::register_device`, etc.).

3. **VirtIO**:
   - Le code partage reste dans `hardware/virtio/common.rs`.
   - Les drivers concrets sont ranges par domaine:
     - `hardware/nic/virtio_net.rs`
     - `hardware/storage/virtio_block.rs`

## Init et ordre de boot

- Ne pas initialiser un driver necessitant paging/MMIO tant que paging n'est pas pret.
- Garder les gardes defensives (`is_initialized`) dans les probes sensibles.
- Faire l'init hardware dans la phase kernel appropriee (apres memory/paging/VFS selon besoin).

## VFS et schemes

- Chaque domaine expose son scheme dedie si necessaire:
  - ex. NIC -> `/dev/net` via un scheme `net`.
- Les operations user/kernel passent par VFS + syscalls, pas par des chemins ad hoc.

## Compatibilite future avec la strate driver (silos)

- Les crates hors kernel doivent rester reutilisables par un processus driver en silo.
- Definir un proto IPC stable par domaine (ex. `driver-net-proto`).
- Conserver la meme abstraction fonctionnelle entre:
  - implementation kernel-resident
  - implementation silo-hosted

## Checklist pour ajouter un nouveau driver

1. Creer/mettre a jour les crates dans `workspace/drivers/<domaine>/...`.
2. Ajouter l'integration kernel dans `hardware/<domaine>/...`.
3. Ajouter les dependances de chemin dans `workspace/kernel/Cargo.toml`.
4. Mettre a jour les `members` dans le `Cargo.toml` workspace.
5. Brancher l'init dans `hardware/<domaine>/mod.rs` et l'init globale si necessaire.
6. Exposer le scheme VFS (`/dev/...`) si requis.
7. Ajouter une garde defensive si la sonde depend de paging/MMIO.
8. Verifier avec `cargo check -p strat9-kernel`.

## Regle d'or

Tout nouveau driver doit etre range:

- par **domaine materiel** (`nic`, `storage`, `video`, ...),
- avec une separation nette entre **crate reusable hors kernel** et **adaptation kernel**.
