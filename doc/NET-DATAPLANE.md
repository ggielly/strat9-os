# Réseau Strat9 : data plane partagé, hotplug et QoS

> Branche : `feature/net-dataplane-refactor`
> Objectif : remplacer le chemin « un syscall + un `Box` par paquet » par un
> data plane en mémoire partagée inspiré de vmxnet3/ESXi, tout en gardant le
> modèle silo/strate/capability.

---

## 1. Ce qui a changé

### 1.1 Autorité

- `SYS_NET_OPEN` crée une capability `ResourceType::Nic` pour le silo appelant
  (familles `NET`, `DRV`, `SYS` uniquement).
- `SYS_NET_SEND`, `SYS_NET_RECV`, `SYS_NET_INFO`, `SYS_NET_REGISTER` et tous
  les nouveaux appels exigent cette capability. Un silo sans capability ne
  peut plus sniffer ni injecter de trames.

### 1.2 Chemins

| Chemin | Syscalls | Copies noyau↔stack | Usage |
|---|---:|---:|---|
| Legacy `NET_SEND/RECV` | 1/paquet | 2 | bring-up, fallback |
| `NET_RX_BATCH/TX_BATCH` | 1/lot | 1/trame | compatibilité batch |
| **Queue partagée** | 1 kick/poll | **0** | data plane nominal |

La queue partagée (`NetQueue`) contient :

- un header `NetQueueHeader` (magic `STNQ`, features, epoch, link, stats) ;
- un anneau RX et un anneau TX de 256 descripteurs de 16 octets ;
- deux pools de 256 slots de 2048 octets ;
- deux bitmaps d’allocation de slots.

Le layout est défini une seule fois dans `abi/src/net.rs` et partagé par le
noyau et `strate-net`.

### 1.3 IRQ et TX

- Le handler IRQ est borné à 64 paquets, sans allocation, sans log, sans TX.
- Le TX est vidé par `SYS_NET_KICK` (ou automatiquement après `NET_SEND`),
  donc il ne dépend plus d’une IRQ RX.
- Le doorbell est regroupé : le backend smoltcp publie ses descripteurs puis
  appelle `flush()` une fois par `poll()`.

### 1.4 Hotplug

- `NetworkDevice` expose `epoch`, `quiesce`, `resume`, `reset`, `queue_count`,
  `features`, `mtu`, `link_speed_mbps`.
- `hotplug` publie `DEVICE_ADD/REMOVE`, `LINK_UP/DOWN`, `QUIESCE/RESUME`
  dans une file fixe.
- Un thread noyau `nic-hotplug` scanne le bus PCI toutes les 500 ms
  (`hotplug::start_watchdog`) et publie les différences. C’est la source
  portable en attendant l’IRQ de slot PCIe / SCI ACPI.
- `SYS_PCI_RESCAN` invalide le cache PCI et réénumère.
- `SYS_NET_DEVICE_EVENT`, `SYS_NET_QUIESCE`, `SYS_NET_RESUME` exposent le
  cycle de vie au silo réseau.
- `ipc_bind_port` remplace atomiquement les mounts `/net` et
  `/srv/strate-*` : un strate peut redémarrer et reprendre son nom.
- Le superviseur de `strate-init` relance un strate (max 3 fois) via
  `silo_start`.

### 1.5 Offloads et files

- `net-core` négocie un masque `features`.
- e1000 annonce `CSUM_RX` : `SECRC` active la validation matérielle et le
  pilote jette les trames `TCPE`/`IPE`. smoltcp est configuré en
  `Checksum::Tx` pour ne pas re-vérifier en logiciel.
- Le TX checksum, TSO et LRO restent logiciels (le descripteur legacy e1000
  ne porte pas les métadonnées L4 nécessaires, et smoltcp n’expose pas TSO).
- Chaque device expose **deux queues software RSS** : l’IRQ hache la trame
  (FNV-1a sur L3/L4) et pousse dans la queue correspondante ; `strate-net`
  mappe les deux et les poll en round-robin.
- e1000 : link mis en cache, RDT par lots de 8.
- virtio-net : buffers RX/TX recyclés via `tx_pool`.

### 1.6 IPC et VFS

`IPC_MESSAGE_SIZE` passe de 256 à **1024 octets** (payload 1008).

Pour les flux TCP, `IpcScheme` crée en plus un **anneau bulk de 32 KiB**
(`kernel/src/vfs/bulk.rs`) :

1. le noyau alloue un `SharedRing` et le mappe dans l’espace du serveur ;
2. il envoie `OPCODE_BULK_SETUP` avec `{fid, base, len}` ;
3. un `READ` de plus de 1000 octets demande au serveur d’écrire directement
   dans l’anneau ; le noyau copie anneau → buffer client ;
4. un `WRITE` de plus de 990 octets copie client → anneau, puis envoie
   `data_len` au serveur qui lit l’anneau et appelle `send_slice` ;
5. `OPCODE_BULK_TEARDOWN` + `unmap_range` à la fermeture.

Un `read()` de 16 KiB ne fait plus qu’un seul RPC (au lieu de 17 en 1 KiB,
71 en 256 octets), et le serveur écrit directement dans l’anneau partagé.

### 1.7 vSwitch et QoS (socle)

`kernel/src/hardware/nic/switch.rs` fournit :

- `PortId` (portset 16 bits + port 16 bits), `Port`, `PortSink` ;
- FDB avec apprentissage, flood, broadcast ;
- `IoChain` + `FilterAction` (Accept/Drop/Redirect) ;
- `TokenBucket` pour le shaping.

Ce socle n’est pas encore branché sur un modèle de NIC invitée, mais il
partage la sémantique d’ESXi (`Port_Input` → IOChain → portset → port).

---

## 2. Contrat ABI de la queue

```text
0x0000  NetQueueHeader
0x0100  RX descriptors  (256 × 16)
0x1100  TX descriptors  (256 × 16)
0x2100  réservé / stats
0x3000  RX pool         (256 × 2048)
0x83000 TX pool         (256 × 2048)
0x103000 fin
```

Un descripteur :

```rust
struct NetFrameDesc {
    slot: u32,
    len: u16,
    flags: u16, // SOP, EOP, CSUM_OK, NEED_COMP, VLAN, TRUNCATED
    vlan: u16,
    rss: u16,
}
```

Règles :

1. un producteur et un consommateur par sens ;
2. `head`/`tail` monotones, index = `counter & (size - 1)` ;
3. un slot est alloué par bitmap et libéré par le consommateur ;
4. le producteur publie le descripteur après avoir écrit la donnée ;
5. le consommateur ne libère le slot qu’après usage.

---

## 3. Migration d’un pilote

Pour qu’un pilote expose une queue partagée :

1. retourner `features()` et `mtu()` corrects ;
2. implémenter `queue_count()` (1 pour l’instant) ;
3. dans le chemin RX, écrire la trame dans `NetQueue::push_rx` ;
4. dans le chemin TX, consommer `NetQueue::pop_tx` et transmettre ;
5. appeler `queue.event.notify()` après un RX ;
6. implémenter `quiesce/resume/reset` et incrémenter `epoch`.

Le pilote legacy peut continuer à utiliser `receive`/`transmit` : le noyau
copie alors dans la queue partagée, ce qui préserve la compatibilité.

---

## 4. Limites connues

- L’IRQ de slot PCIe / SCI ACPI n’est pas encore branchée : le hotplug est
  détecté par le scan 500 ms de `nic-hotplug`. Les événements sont publiés,
  mais le rebind automatique du pilote reste à faire dans `strate-bus`.
- L’IOMMU est modélisé (`hardware/iommu.rs` : domaines, IOVA, mappings), mais
  la programmation matérielle DMAR/IVRS (root/context/second-level tables,
  invalidation) reste à faire ; `enabled()` retourne `false`.
- TX checksum, TSO et LRO restent logiciels. RX checksum est offloadé sur
  e1000 (`CSUM_RX`) et annoncé à smoltcp.
- Le multi-queue est logiciel (deux queues par device, hash FNV-1a) ; le
  RSS Toeplitz matériel et MSI-X par queue restent à câbler.
- L’anneau bulk couvre les flux TCP ; UDP reste sur le chemin inline (les
  datagrammes sont petits).
