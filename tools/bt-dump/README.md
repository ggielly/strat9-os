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

