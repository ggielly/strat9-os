# Intel Wi-Fi 6 AX201 (QuZ, 802.11ax 2x2) driver

`no_std` driver core for the Intel AX201 CNVi module found on the ThinkPad
X13 (and many 2019-2021 Intel laptops). It is split from the kernel so the
protocol/WPA2 logic can be unit-tested on the host.

| Piece | File | Status |
|-------|------|--------|
| PCI identity + gen2 register map | `regs.rs` | implemented |
| TLV firmware parser | `fw.rs` | implemented, tested |
| PCIe gen2 transport (APM, RFH/TFH, command ring, context-info self-load, alive wait) | `transport.rs` | implemented, not hardware-validated |
| RX MPDU/notification dispatching | `device.rs` | implemented (heuristic descriptor offset) |
| MAC/PHY/ADD_STA/ADD_STA_KEY/scan commands | `cmd.rs` | implemented (field layouts from API 77) |
| Scan/auth/assoc MLME | `mlme.rs` | implemented, tested |
| WPA2-PSK 4-way + group key handshake | `wpa2.rs` | implemented, tested |
| SHA-1/HMAC/PBKDF2/AES/CCMP/key-wrap | `crypto/` | implemented, RFC test vectors |
| 802.11 frames, RSN/HT/VHT/HE IEs, CCMP | `dot11.rs` | implemented, tested |
| **TX data queue (`iwl_tx_cmd_v9`)** | `device.rs::tx_80211` | **TODO** |
| **Firmware key install wiring + queue allocation** | `device.rs` | **TODO** |

## Why the AX201 is different

The AX201 is a **CNVi** part: the MAC/PHY live in the PCH and the module is
enumerated as an Intel PCI function (QuZ family), but firmware still runs on
the integrated CPU. Linux drives it through `iwlwifi` with:

* `iwl_qu_mac_cfg`: `gen2 = true`, `integrated = true`, device family 22000,
  `mac_addr_from_csr = 0x380`.
* firmware `iwlwifi-QuZ-a0-hr-b0-77.ucode` (API 77).
* context-info **v1** self-load (`CSR_CTXT_INFO_BA = 0x40`) — not the AX210+
  context-info v2 path.

PCI IDs accepted: `02f0`, `06f0`, `34f0`, `3df0`, `4df0`, `43f0`, `a0f0`
(standard / medium-latency / long-latency Qu SKUs).

## Firmware

Intel's ucode blob cannot be committed. Copy the one matching your kernel:

```sh
cp /lib/firmware/iwlwifi-QuZ-a0-hr-b0-77.ucode workspace/assets/firmware/
```

`tools/scripts/create-uefi-image.sh` copies `workspace/assets/boot/wifi.toml`
and every `workspace/assets/firmware/*.ucode` into `/boot/initfs`, which the
kernel exposes as `/initfs/<name>`.

## Configuration

`workspace/assets/boot/wifi.toml`:

```toml
[wifi]
enabled = true
ssid = "HomeNet"
passphrase = "correct horse battery staple"
country = "FR"
firmware = "/initfs/iwlwifi-QuZ-a0-hr-b0-77.ucode"
# optional direct join (no scan):
# bssid = "aa:bb:cc:dd:ee:ff"
# channel = 6
```

`psk = "<64 hex digits>"` can replace `passphrase`. Unknown keys are rejected
on purpose so a typo cannot silently disable encryption.

## Kernel integration

`workspace/kernel/src/hardware/nic/iwlwifi_drv.rs`:

1. probes PCI for the QuZ IDs,
2. maps BAR0 and enables bus-master/memory space,
3. reads `/initfs/wifi.toml`,
4. runs `WifiDevice::init()` (firmware self-load + alive wait),
5. starts the station MLME.

It currently **does not register a `NetworkDevice`**: the TX data queue is the
last missing hardware piece. Registering a device whose `transmit()` always
fails would make strate-net pick a dead interface. `link_up()` in
`WifiDevice` is therefore false until `tx_80211()` programs real TFDs.

## Testing

```sh
cargo test -p iwlwifi-ax201 --lib
```

30 tests cover RFC 3394 key wrap, RFC 3610 CCM, FIPS-197 AES, RFC 2202
HMAC-SHA1, RFC 6070 PBKDF2, the WPA2 PMK/PTK derivation, the full 4-way
handshake against a simulated AP, beacon/RSN parsing, CCMP protect/unprotect,
the TLV firmware parser, the context-info layout and the command offsets.

## References

* Linux `drivers/net/wireless/intel/iwlwifi/` — `iwl-csr.h`, `iwl-fh.h`,
  `iwl-prph.h`, `pcie/trans-gen2.c`, `pcie/ctxt-info.c`, `pcie/rx.c`,
  `pcie/tx-gen2.c`, `cfg/22000.c`, `fw/file.h`, `fw/api/*.h`.
* FreeBSD `sys/contrib/dev/iwlwifi/` (same Intel code base).
* IEEE 802.11-2016 §9 (MAC frames), §12.5 (CCMP), §12.7 (RSNA/WPA2).
* RFC 3394 (AES key wrap), RFC 3610 (CCM), RFC 2898 (PBKDF2).

## Next steps for hardware bring-up

1. Implement `tx_80211()` with `iwl_tx_cmd_v9` (TB0 = TX command, TB1 = MPDU)
   on a queue allocated by `ADD_STA` (`tfd_queue_msk`).
2. Match the exact command sizes/versions for API 77 (`MAC_CONTEXT_CMD`,
   `PHY_CONTEXT_CMD`, `ADD_STA` v10, `ADD_STA_KEY` v2/v3).
3. Validate the RX MPDU descriptor length for the specific firmware build
   (the parser tries 24/28/32-byte offsets).
4. Install PTK/GTK in firmware after the 4-way handshake and enable the TX
   queue; set `link_up()` only then.
5. Add regulatory/NVM handling (`LARI_CONFIG_CHANGE`) for 5 GHz channels.
6. Feed SNonce from the kernel CSPRNG instead of the current deterministic
   mix (already marked in `device.rs`).
