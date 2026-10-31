# Câblage USB Bluetooth — appliqué

Ce document décrivait un patch à appliquer. Il a été **appliqué** directement
dans l'arbre ; voir `doc/BT_DUMP.md` pour la conception d'ensemble.

Résumé des modifications réelles :

## `workspace/kernel/src/hardware/usb/mod.rs`

- `pub mod btusb;` et `pub mod class;`
- `btusb::init()` appelé après `uhci::init()`.

## `workspace/kernel/src/hardware/usb/xhci.rs`

- Constantes `EP_TYPE_BULK_OUT = 2`, `EP_TYPE_BULK_IN = 6`.
- `handle_interrupt()` route les complétions du slot Bluetooth vers
  `btusb::on_transfer()` (IN) ou `btusb::tx_complete()` (OUT) ; HID garde son
  chemin.
- La boucle de ré-armement ne ré-arme plus bulk OUT avec l'ancien buffer :
  elle appelle `btusb::fill_bulk_out()` et saute l'endpoint si la file TX est
  vide.
- `impl XhciController::submit_bulk_out(slot, ep)` ajouté en fin de fichier.
- L'énumération appelle `class::enumerate_device(self, port, slot, desc)`.
  Le contrôleur est passé par référence car l'énumération a lieu dans
  `XhciController::new()`, **avant** la publication dans le registre global :
  un `get_controller(0)` renverrait `None`.

## `workspace/kernel/src/hardware/usb/{ehci,uhci}.rs`

- Restent sur `hid::enumerate_device`. Ces contrôleurs n'ont pas de bulk ;
  Bluetooth est xHCI-only pour l'instant.

## `workspace/kernel/src/vfs/mod.rs`

- `pub mod bt_scheme;`, `pub mod log_scheme;`
- `bt_scheme::init_bt_scheme()` (idempotent) et
  `log_scheme::init_log_scheme()` à la fin de `vfs::init`.

## Point d'attention non résolu

`hid::enumerate_device()` appelle encore `xhci::get_controller(0)`, qui est
`None` pendant `XhciController::new()`. Le chemin HID xHCI ne configure donc
probablement pas ses endpoints aujourd'hui. Le nouveau chemin Bluetooth a été
écrit pour éviter ce piège (contrôleur passé en argument). Corriger HID de la
même façon est un correctif séparé, à valider sur matériel.
