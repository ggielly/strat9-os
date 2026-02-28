# Strat9-OS Network Passthrough (TAP + Routed Host)

Ce mode remplace `-netdev user` (NAT QEMU) par un TAP Linux relié au host.
Les silos passent par `strate-net`, mais le trafic sort via la machine hôte (forward + NAT).

## 1) Préparer le host

```bash
cargo make net-setup-routed STRAT9_UPLINK_IFACE=enp3s0 STRAT9_TAP_IFACE=strat9tap0
```

- `STRAT9_UPLINK_IFACE`: interface physique de sortie Internet du host.
- `STRAT9_TAP_IFACE`: interface TAP utilisée par QEMU.

Le script configure:
- TAP `strat9tap0` en `192.168.76.1/24`
- `dnsmasq` DHCP sur TAP (range `192.168.76.9-200`)
- `ip_forward=1`
- règles `iptables` de forwarding/NAT

## 2) Lancer Strat9-OS avec passthrough TAP

```bash
cargo make run-gui-net-tap STRAT9_TAP_IFACE=strat9tap0
```

ou headless:

```bash
cargo make run-net-tap STRAT9_TAP_IFACE=strat9tap0
```

## 3) Nettoyage host

```bash
cargo make net-teardown-routed STRAT9_UPLINK_IFACE=enp3s0 STRAT9_TAP_IFACE=strat9tap0
```

## Notes

- Ce mode est Linux.
- Les commandes setup/teardown utilisent `sudo`.
- Pour un vrai L2 LAN (DHCP routeur physique), il faut un bridge/macvtap côté host, pas le mode routed NAT.
