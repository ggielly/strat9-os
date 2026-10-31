# s9dump — console BLE (Windows)

```
pip install bleak
python s9dump.py                                # scan S9-DUMP* (10 s)
python s9dump.py --address AA:BB:CC:DD:EE:FF    # adresse connue = plus rapide
python s9dump.py --log dump.txt --no-stdin
```
L'appareil apparaît dans **Paramètres > Bluetooth et appareils** sous `S9-DUMP…`.
Laissez la carte en scan et relancez (`--scan-timeout` allonge la recherche).
Pas d'appairage nécessaire : la connexion GATT directe suffit.
Commandes (une ligne + Entrée) : `pause`, `resume`, `stats`.
(`dump <n>` est réservé au rejeu historique, pas encore implémenté.)
Sortie typique (DATA sur stdout, alertes sur stderr) :

```
[scan] found S9-DUMP (AA:BB:CC:DD:EE:FF)
boot: strat9 microkernel
[--- lost 1234 bytes ---]   [--- gap: 3 frames ---]
```
Ctrl-C quitte proprement ; reconnexion auto après 1 s.
Tests : `python3 -m unittest -v test_s9frame.py test_s9dump.py`

## Erreur `WinError -2147023838` (0x80070422)

Le service Bluetooth Windows est arrêté/désactivé, ou aucun adaptateur n'est
actif. Ce n'est pas le client : `bleak` ne peut pas ouvrir la radio.

1. `services.msc` → **Bluetooth Support Service** (`bthserv`) → *Automatique* → **Démarrer**.
2. Paramètres → Bluetooth et appareils : vérifier que le Bluetooth est activé.
3. Vérifier l'adaptateur : `Get-PnpDevice -Class Bluetooth` et `Get-Service bthserv`.
4. VM / Windows Server : le Bluetooth de l'hôte n'est généralement pas exposé ;
   passer un dongle USB en passthrough, ou lancer le client sur le PC hôte.

Le client affiche désormais cette aide une fois, puis espace les tentatives
(1 s → 2 s → 4 s … 30 s) au lieu de boucler toutes les secondes.
