Architecture multi-strate filesystem pour strat9-os

Tableau de suivi







ID



Tache



Etat



Fichier principal



Note





srv-dir



Creer /srv dans le squelette VFS au boot



Termine



workspace/kernel/src/vfs/mod.rs



Deja present dans la liste des repertoires init (\"srv\")





bootstrap-label



Enrichir le bootstrap IPC avec un label



Termine



workspace/kernel/src/syscall/dispatcher.rs



Format ajoute: payload[0]=len, payload[1..]=label UTF-8





ext4-dynamic-bind



ext4 bind dynamique sur /srv/strate-fs-ext4/{label}



Termine



workspace/components/strate-fs-ext4/src/main.rs



Lit label bootstrap, ajoute alias /srv/...





ramfs-dynamic-bind



ramfs bind dynamique sur /srv/strate-fs-ramfs/{label}



Termine



workspace/components/strate-fs-ramfs/src/main.rs



Alias /srv/... + support bootstrap label





generic-mount



Mount generique source -> target



Termine



workspace/kernel/src/shell/commands/vfs/mod.rs



FS_DRIVERS supprime, mount <source> <target>





strate-spawn-cmd



Commande strate spawn



Termine



workspace/kernel/src/shell/commands



Support --as, --dev et lancement via kernel silo helper





strate-ls-cmd



Commande strate ls



Termine



workspace/kernel/src/shell/commands



Affiche id/nom/etat/tasks/label via snapshot noyau





unbind-bootstrap



Generaliser sys_ipc_bind_port



Termine



workspace/kernel/src/syscall/dispatcher.rs



Bootstrap declenche sur /srv/strate-fs-*, legacy retire





silo-label



Ajouter strate_label au silo



Termine



workspace/kernel/src/silo/mod.rs



Champ ajoute + MAJ auto depuis bind /srv/strate-fs-*

Todo list operationnelle





srv-dir - /srv cree au boot dans le squelette VFS.



bootstrap-label - format bootstrap implemente (handle + label).



ext4-dynamic-bind - parser label et binder dynamiquement.



ramfs-dynamic-bind - binder dynamiquement avec meme convention.



generic-mount - passer a mount <source> <target>.



strate-spawn-cmd - creer commande spawn et passage de params.



strate-ls-cmd - ajouter listing des strates actives.



unbind-bootstrap - retirer special-case chemin.



silo-label - persister label dans metadata Silo.

Probleme actuel

Aujourd'hui, chaque strate FS est un singleton avec un chemin IPC hardcode :

flowchart LR
    subgraph kernel [Kernel VFS]
        MountTable["MountTable (global)"]
    end
    Ext4["strate-fs-ext4\nbind('/fs/ext4')"] --> MountTable
    Ramfs["strate-fs-ramfs\nbind('/ram')"] --> MountTable
    MountTable -->|"resolve('/fs/ext4/file')"| Ext4





Le chemin /fs/ext4 est code en dur dans le binaire ext4 (strate-fs-ext4/src/main.rs, ligne 409)



Le bootstrap du volume est hardcode pour / et /fs/ext4 dans le kernel (syscall/dispatcher.rs, ligne 877)



La MountTable refuse les doublons : impossible de monter deux ext4

Avec 300 volumes ext4, ca ne tient pas.



Architecture proposee : Service Registry + Spawn parametrise

Principe : separation en 3 couches

flowchart TD
    subgraph userCmd [Commandes utilisateur]
        Spawn["strate spawn strate-fs-ext4\n--dev /dev/sda1 --as data"]
        Mount["mount /srv/strate-fs-ext4/data /mnt/data"]
        List["strate ls"]
    end

    subgraph srvNamespace ["/srv — registre de services"]
        Srv0["/srv/strate-fs-ext4/data"]
        Srv1["/srv/strate-fs-ext4/backup"]
        Srv2["/srv/strate-fs-ext4/logs"]
        SrvR["/srv/strate-fs-ramfs/tmp"]
    end

    subgraph userMounts [Montages utilisateur]
        Mnt0["/mnt/data"]
        Mnt1["/mnt/backup"]
        Mnt2["/var/log"]
        MntT["/tmp"]
    end

    Spawn --> Srv0
    Srv0 -.->|mount| Mnt0
    Srv1 -.->|mount| Mnt1
    Srv2 -.->|mount| Mnt2
    SrvR -.->|mount| MntT

Couche 1 — Service Registry (/srv) : chaque strate s'enregistre sous /srv/<type>/<label> au lieu d'un chemin fixe.

Couche 2 — Spawn parametrise : le createur du silo passe le label + la capability volume. Le strate n'a plus de chemin hardcode.

Couche 3 — Mount generique : mount <source> <target> prend un chemin source (dans /srv) et le rebind a un chemin cible. Plus besoin de la table FS_DRIVERS.



Detail de chaque couche

Couche 1 : Convention de nommage /srv





Repertoire: /srv/<strate-type>/<label>



Exemples:





/srv/strate-fs-ext4/data — instance ext4 pour le volume "data"



/srv/strate-fs-ext4/backup — instance ext4 pour le volume "backup"



/srv/strate-fs-ramfs/scratch — instance ramfs "scratch"



/srv/strate-fs-xfs/archive — instance xfs "archive"

Le label est soit fourni par l'utilisateur (--as data), soit auto-genere (inst-{silo_id}).

L'interet : c'est exactement le modele /srv de Plan 9. Le service existe dans le namespace independamment du point de montage final.

Couche 2 : Spawn parametrise des strates

Aujourd'hui, le strate ext4 recoit son volume via un message bootstrap envoye par le kernel apres ipc_bind_port("/fs/ext4"). Pour supporter N instances :

Option A — Parametre via IPC bootstrap (changement minimal) :





Le spawner (init, shell, ou un "strate-manager") cree le silo, passe la volume capability via silo_config, et envoie un message bootstrap enrichi contenant le label.



Le strate utilise le label pour binder a /srv/strate-fs-ext4/{label}.



Impact minimal sur le binaire ext4 : il lit le label depuis le bootstrap au lieu d'un chemin hardcode.

Option B — Parametre via argv/stack (plus propre a terme) :





Passer argv[1] = label, argv[2] = /dev/sda1 au strate comme un processus normal.



Necessite un vrai passage d'arguments ELF (pas encore implemente dans load_and_run_elf).

Recommandation : Option A a court terme (le mecanisme de bootstrap existe deja), Option B quand le loader ELF supportera argv.

Couche 3 : Mount generique (source -> target)

Transformer la commande mount pour qu'elle soit purement generique :

mount /srv/strate-fs-ext4/data /mnt/data
mount /srv/strate-fs-ramfs/scratch /tmp
umount /mnt/data

La logique kernel est deja la : vfs::resolve(source) retourne le DynScheme, puis vfs::mount(target, scheme) le rebind. La table FS_DRIVERS actuelle disparait — mount n'a plus besoin de connaitre les types de FS.



Cycle de vie complet (exemple : 3 volumes ext4)

sequenceDiagram
    participant User as Utilisateur/Shell
    participant Kernel as Kernel
    participant S1 as strate-fs-ext4 #1
    participant S2 as strate-fs-ext4 #2
    participant S3 as strate-fs-ext4 #3

    User->>Kernel: strate spawn strate-fs-ext4 --dev sda1 --as data
    Kernel->>Kernel: silo_create + silo_config(volume_cap_sda1, label="data")
    Kernel->>S1: load ELF + bootstrap(volume_handle, "data")
    S1->>Kernel: ipc_bind_port("/srv/strate-fs-ext4/data")
    
    User->>Kernel: strate spawn strate-fs-ext4 --dev sda2 --as backup
    Kernel->>S2: load ELF + bootstrap(volume_handle, "backup")
    S2->>Kernel: ipc_bind_port("/srv/strate-fs-ext4/backup")

    User->>Kernel: strate spawn strate-fs-ext4 --dev sdb1 --as logs
    Kernel->>S3: load ELF + bootstrap(volume_handle, "logs")
    S3->>Kernel: ipc_bind_port("/srv/strate-fs-ext4/logs")

    User->>Kernel: mount /srv/strate-fs-ext4/data /mnt/data
    User->>Kernel: mount /srv/strate-fs-ext4/backup /mnt/backup
    User->>Kernel: mount /srv/strate-fs-ext4/logs /var/log



Modifications necessaires par fichier

Kernel





workspace/kernel/src/vfs/mod.rs : dans init(), ajouter rootfs.ensure_dir("srv") pour creer /srv au boot



workspace/kernel/src/silo/mod.rs : ajouter un champ strate_label: Option<String> a Silo pour tracker le label



workspace/kernel/src/syscall/dispatcher.rs : generaliser le bootstrap dans sys_ipc_bind_port pour ne plus hardcoder /fs/ext4



workspace/kernel/src/shell/commands/vfs/mod.rs : remplacer FS_DRIVERS par un mount generique mount <source> <target>

Strate ext4





workspace/components/strate-fs-ext4/src/main.rs : lire le label depuis le bootstrap message, binder a /srv/strate-fs-ext4/{label} au lieu de /fs/ext4

Strate ramfs





workspace/components/strate-fs-ramfs/src/main.rs : meme logique, binder a /srv/strate-fs-ramfs/{label}

Shell (nouvelles commandes)





strate spawn <type> --dev <device> --as <label> : spawn une instance



strate ls : lister les strates en cours



strate stop <label> : arreter une instance



mount <source> <target> : generique (plus de table FS_DRIVERS)



umount <target> : inchange



Scalabilite

Avec cette architecture, 300 instances ext4 = 300 entrees sous /srv/strate-fs-ext4/, chacune avec son propre port IPC et sa propre volume capability. Le cout est :





300 ports IPC (leger : ~200 bytes chacun)



300 entrees dans la MountTable pour /srv/... + 300 pour les points de montage utilisateur



La resolution reste O(n) sur la longueur du prefixe (deja triee), pas sur le nombre de montages du meme type

Aucun goulot d'etranglement structurel a ce niveau.