# Dump console Bluetooth — côté OS

Deux dossiers :

- `windows/` : client Python `s9dump.py` (BLE NUS, pas d'appairage).
- `diagnose.sh` : lit un log série et dit où la chaîne Bluetooth s'arrête.

## Pourquoi rien ne sort sous QEMU

`qemu-system-x86_64 -device help` de cette machine **n'expose aucun dongle
Bluetooth émulé**. En plus, plusieurs tâches `run-*` n'attachent même pas de
contrôleur USB, et le driver xHCI est encore noté comme fragile avec le xHCI
de QEMU (`BAR0 unassigned`).

Donc, si tu ne vois aucune ligne `[USB-BT]` dans le log : c'est normal, il n'y
a rien à détecter.

## Tester avec un vrai dongle (passthrough)

```
# sur l'hôte Linux : libérer le dongle de la pile Bluetooth
sudo modprobe -r btusb
lsusb                       # noter bus/addr, ou vendor:product

# lancer l'OS avec xHCI + le dongle
BT_USB_HOST='usb-host,hostbus=1,hostaddr=5' cargo make run-bt-debug
# ou
BT_USB_HOST='usb-host,vendorid=0x0a12,productid=0x0001' cargo make run-bt-debug

tools/bt-dump/diagnose.sh build/serial-bt.log
```

Le log série est dans `build/serial-bt.log`, les marqueurs E9 dans
`build/qemu-debugcon-bt.log`.

## Lire le log à la main

| Ligne | Signification |
|---|---|
| `[USB] Initializing USB subsystem` | le sous-système USB tourne |
| `[xHCI] Found 1 controller(s)` | contrôleur xHCI initialisé |
| `[USB] dev aaaa:bbbb class=xx/yy/zz` | device énuméré |
| `[USB-BT] Probing ...` | device class 0x00/0xE0, lecture du descriptor |
| `[USB-BT] Attached ...` | interface HCI trouvée, endpoints configurés |
| `[VFS] Mounted /dev/bt` | schéma userspace monté |
| `[strate-bt] starting` | strate présente dans l'image et lancée |
| `[strate-bt] device opened` | `/dev/bt/hci0` ouvert, advertising lancé |

Points de panne typiques :

- dongle sur EHCI/UHCI ou derrière un hub → **non supporté** (xHCI, port racine) ;
- `[USB-BT] Probing` sans `Attached` → interface `E0/01/01` absente ou
  `setup_endpoint` en échec (voir warnings au-dessus) ;
- `Attached` mais pas de `strate-bt` → l'image n'a pas été reconstruite avec
  `cargo make uefi-image` (tâche `strate-bt-release` + manifest) ;
- `device opened` mais rien côté Windows → firmware du dongle (Intel/Realtek/
  Broadcom), radio Windows, ou distance.

## Firmware Realtek RTL8761BU (`0bda:a728`)

Ce dongle (Bluetooth 5.4, full-speed) est un **RTL8761BU** : il énumère comme
un bootloader ROM et ne fait rien d'utile tant que le patch RAM n'est pas
chargé. Linux le confirme :

```
Bluetooth: hci0: RTL: loading rtl_bt/rtl8761bu_fw.bin
Bluetooth: hci0: RTL: fw version 0xdfc6d922
```

`strate-bt` implémente le même chemin que `btrtl.c` :

1. `0xFC61` (chip subver) → doit valoir `0x8761` ;
2. `0xFC6D` (ROM version) → `chip_id = rom_version + 1` ;
3. parse du blob v1 `Realtech` (patch `chip_id`, version injectée, config
   ajoutée) ;
4. download par fragments de 252 octets via `0xFC20` (index 0..0x7f puis
   1.., bit `0x80` sur le dernier) ;
5. relecture de `Read Local Version` pour confirmer.

Les blobs sont copiés dans l'initfs par `create-uefi-image.sh` depuis
`workspace/assets/firmware/` :

```
cp /lib/firmware/rtl_bt/rtl8761bu_fw.bin \
   /lib/firmware/rtl_bt/rtl8761bu_config.bin \
   workspace/assets/firmware/
cargo make uefi-image
```

Logs attendus :

```
[strate-bt] Realtek RTL8761BU firmware ready
```

Si le blob manque :

```
[strate-bt] Realtek: /initfs/rtl8761bu_fw.bin missing
```

Le parseur est testé contre le vrai blob (30 210 octets, 120 fragments,
`fw_version 0xdfc6d922`).

## Vérification de l'image (faite sur ce dépôt)

Le dongle branché sur Linux est `0bda:a728` (Realtek **RTL8761BU**,
full-speed) :

- interface 0 : HCI `E0/01/01`, interrupt IN `0x81`, bulk OUT `0x02`,
  bulk IN `0x82` — exactement ce que `btusb` attend ;
- port racine xHCI, pas de hub ;
- firmware Linux : `rtl8761bu_fw.bin` + `rtl8761bu_config.bin`.

Ce qui a été vérifié dans l'image reconstruite :

- `boot/initfs/strate-bt` présent, ELF64, contient les 15 chaînes Realtek ;
- `rtl8761bu_fw.bin` présent, md5 identique à la source
  (`e6da3f44…`), `rtl8761bu_config.bin` présent ;
- `silo.toml` contient le silo `bt` → `/initfs/strate-bt` ;
- le noyau expose `/dev/bt`, prépare la tâche `silo-102/strate-bt` et
  enregistre `/initfs/strate-bt` (57 368 octets).

Deux blocages restent, **hors Bluetooth** :

1. Sous QEMU (`qemu-xhci`), `HCSPARAMS1` renvoie **0 port** au noyau alors que
   QEMU expose 8 ports : le BAR0 est à `0x8_0000_0000` (au-dessus de 4 Gio) et
   la lecture MMIO du noyau renvoie 0. Aucun device USB n'est donc énuméré.
2. Le build courant panique dans `vmalloc` (`KernelMapFailed`) pendant le stage
   matériel, avant la strate. L'image précédente passait ce point : régression
   mémoire/paging à corriger avant tout test BT.

Sur matériel réel (X13), le BAR xHCI du PCH est généralement sous 4 Gio ; le
point 1 peut donc ne pas se produire, mais le point 2 est à vérifier.

> Le firmware de cette section est celui du **dongle RTL8761BU**. Le
> Bluetooth **interne** du X13 (`0489:e0cd`) est un **MediaTek MT7921**
> (MT7961, BT 5.2). Il est maintenant pris en charge par le même transport :
> le chargement MTK utilise `BT_RAM_CODE_MT7961_1_2_hdr.bin` (532 Kio,
> présent dans `workspace/assets/firmware/`), le protocole WMT (`0xFC6F`,
> event vendor `0xE4`) et des control transfers EP0 via `/dev/bt/ctl`.
> Logs attendus : `[strate-bt] MTK: downloading firmware` puis
> `[strate-bt] MediaTek MT7961 firmware ready`.
>
> Deux corrections de transport ont été nécessaires pour ce device :
> routage de la classe **0xEF** (Interface Association) et indexation des
> endpoints par **DCI** (`2*num + direction`) : le MT7921 utilise EP2 OUT
> et EP2 IN, comme le dongle Realtek, et les deux partageaient le même slot.




