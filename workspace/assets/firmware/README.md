# Guest firmware for s9vm

This directory holds the firmware images an s9vm world can install instead of
building its own stub ROM.

## SeaBIOS 1.17.0

| File | Purpose | Size | SHA-256 |
|---|---|---|---|
| `seabios-1.17.0.bin` | official main BIOS (`bios.bin`) | 262144 | `fdf5d27097f3126c8708102482859f9b538e187126e79bb0da99e0b02a45cd15` |
| `seabios-vgabios-stdvga-1.17.0.bin` | SeaVGABIOS standard-VGA option ROM | 35840 | `373675d9cbb08973cf4921a6e83ac191134d2836348c29d27a738189ff73ab48` |

### Provenance

Both images come from the **official SeaBIOS release** at
<https://www.seabios.org/downloads/>, not from a distribution package.

| Item | Value |
|---|---|
| Project | SeaBIOS (LGPL-3.0-or-later) - <https://www.seabios.org/> |
| Version | **1.17.0** (latest) |
| BIOS archive | <https://www.seabios.org/downloads/bios.bin-1.17.0.gz> |
| BIOS archive SHA-256 | `188dc9693c5e0d150bbf4403ab96755538f8518e52250db86e6f749194f44069` |
| BIOS binary SHA-256 | `fdf5d27097f3126c8708102482859f9b538e187126e79bb0da99e0b02a45cd15` |
| Source archive | <https://www.seabios.org/downloads/seabios-1.17.0.tar.gz> |
| Source archive SHA-256 | `5159a35fac5c1579dd5d702001033c826ce45d30d3bd657ec1b2695455997712` |

`seabios-1.17.0.bin` is the **unmodified** official `bios.bin`, decoded from
the gzip archive above.

`seabios-vgabios-stdvga-1.17.0.bin` is built from the official source archive
because seabios.org does not publish a prebuilt VGA ROM. Exact build inputs:

```sh
# official source tree, with an i386-elf cross toolchain:
CONFIG_QEMU=y
CONFIG_VGA_STANDARD_VGA=y
CONFIG_VGA_STDVGA_PORTS=y
CONFIG_BUILD_VGABIOS=y
CONFIG_VGA_VBE=y
CONFIG_VGA_PCI=y
CONFIG_VGA_VID=0x1234
CONFIG_VGA_DID=0x1111
CONFIG_DEBUG_LEVEL=1

make CROSS_PREFIX=i386-elf- PYTHON=python out/vgabios.bin
```

The resulting ROM has the `0x55AA` signature, size code `0x46` (35840 bytes)
and a modulo-256 checksum of zero.

`tools/scripts/fetch-seabios.py` downloads and verifies the official BIOS and
the source archive; it also verifies the committed VGA ROM against the hash
above.

### How s9vm uses them

* The official `bios.bin` is a **256 KiB flat ROM**. It is installed at
  `0xC0000`, so its reset vector (`F000:FFF0`, linear `0xFFFF0`) is the
  processor reset vector. It is a **raw BIOS image**, not an option ROM: it has
  no `0x55AA` trailer, which is normal for a SeaBIOS build.
* Its **zero-filled prefix** extends to `0xDE060`, where the ROM code starts.
  The VGA option ROM is installed there at `0xC0000`, and also registered in
  `fw_cfg` as `vgaroms/vgabios-stdvga.bin`. SeaBIOS clears that window during
  POST and redeploys the ROM from `fw_cfg` (the QEMU-compatible path), so the
  final ROM location does not depend on the pre-install copy. The installer
  only allows the overlap when the replaced BIOS bytes are zero.
* The FreeDOS 1.4 floppy (`../disks/freedos-1.4-boot.img`) is presented through
  the emulated 82077AA floppy controller and DMA channel 2. CMOS `0x10 = 0x40`
  advertises one 1.44 MiB drive, and CMOS `0x3D = 0x01` selects the floppy
  first, which is what the QEMU build of SeaBIOS reads without `fw_cfg`.

### Licence

SeaBIOS and SeaVGABIOS are distributed under the GNU LGPL v3 (or later). The
files here are either unmodified (the BIOS) or built from the official source
(the VGA ROM); the source is available at <https://www.seabios.org/>.
