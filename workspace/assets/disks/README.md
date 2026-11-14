# FreeDOS 1.4 boot floppy for s9vm

`freedos-1.4-boot.img` is the FreeDOS **1.4 Floppy Edition** boot disk
(`144m/x86BOOT.img`), patched so that it boots to the DOS prompt inside an
s9vm world and signals success to the kernel selftest.

## Provenance

| Item | Value |
|---|---|
| Project | FreeDOS (GPL-2.0) — <https://www.freedos.org/> |
| Version | **1.4** (released 2025-04) |
| Archive | `FD14-FloppyEdition.zip` from <https://www.ibiblio.org/pub/micro/pc-stuff/freedos/files/distributions/1.4/> |
| Member | `144m/x86BOOT.img` |
| Original size | 1 474 560 bytes (1.44 MiB, FAT12, 80×2×18×512) |
| Original SHA-256 | `552f7cbb0625960c050a3e682a4d2121cc2ffdfa9dc9d592ccd49edf179333dc` |
| Patched SHA-256 | `c75964ca584741a0207fd120a9d35bf9986089deb3c0f1d5688583de6efcd83d` |

## Patch (deterministic)

The image is the byte-for-byte official boot disk with three FAT12 entries
rewritten in place (no cluster added, no FAT change). It is reproducible:

```bash
python scripts/patch-freedos-boot-image.py <copy of x86BOOT.img>
```

The script verifies the official SHA-256, rewrites the three payloads, prints
the resulting hash and is idempotent.

1. `\FDCONFIG.SYS` (cluster 96) — the multilingual boot menu (`MENU …` and
   `MENUDEFAULT=1,10`) is replaced by the plain configuration directives and a
   direct `SHELL=` line, so the boot is deterministic and does not wait for a
   keyboard/menu timeout. There is deliberately **no** `@echo off` line: that is
   a batch directive, and the FreeDOS kernel reports
   `CONFIG.SYS error in line 0` and echoes the line when it finds one here.
   ```
   !COUNTRY=001,858:\FREEDOS\BIN\COUNTRY.SYS
   !LASTDRIVE=Z
   !BUFFERS=20
   !FILES=40
   SHELL=\FREEDOS\BIN\COMMAND.COM \FREEDOS\BIN /E:2048 /P=\FDAUTO.BAT
   ```
2. `\FDAUTO.BAT` (cluster 93) — the installer launcher is replaced by:
   ```
   @ECHO OFF
   ECHO s9vm: FreeDOS 1.4 booting
   ECHO FreeDOS 1.4 booted under s9vm
   S9VMK.COM
   ```
3. `\SETUP.BAT` is renamed to `\S9VMK.COM` (same cluster, its long-name entry is
   dropped) and its first cluster holds an 8-byte COM program:
   ```
   B0 4B        mov al, 0x4B      ; 'K'
   BA E9 00     mov dx, 0x00E9    ; s9vm debug port
   EE           out dx, al
   CD 20        int 20h           ; terminate
   ```

`S9VMK.COM` writes the success marker `K` that the kernel DOS runner
(`s9vm/dosboot.rs`) and the QEMU `-debugcon` verification both watch for.

## Hello/DIR demo image

`freedos-hello.img` is derived from the same official boot disk and keeps the
FreeDOS kernel and `COMMAND.COM`. Only two text files are replaced:

1. `\FDAUTO.BAT`:
   ```
   @ECHO OFF
   ECHO Hello world, from FreeDOS
   DIR
   S9VMK.COM
   ```
2. `\FDCONFIG.SYS` — the very same plain directives as the selftest image (the
   two images share this file; only `FDAUTO.BAT` differs):
   ```
   !COUNTRY=001,858:\FREEDOS\BIN\COUNTRY.SYS
   !LASTDRIVE=Z
   !BUFFERS=20
   !FILES=40
   SHELL=\FREEDOS\BIN\COMMAND.COM \FREEDOS\BIN /E:2048 /P=\FDAUTO.BAT
   ```

`S9VMK.COM` is unchanged, so the run still ends on the `K` marker after `DIR`
has printed the root directory. Boot it with `vm test hello` or
`s9vm.selftest=freedos_hello`; the dry regression is
`s9vm.selftest=freedos_hello_dry`.

| Image | Size | SHA-256 |
|---|---|---|
| `freedos-hello.img` | 1 474 560 bytes | `c84188150531f3566fd548156dbd316c96dc2dfa2779f1f0800d66bd1b03adab` |

The original `freedos-1.4-boot.img` is untouched (still the marker-oriented
selftest image).

## Verification

* QEMU + SeaBIOS, TCG, headless: booting this image on a floppy controller and
  capturing port `0xE9` with `-debugcon file:…` yields exactly `K` (FreeDOS
  kernel loaded, `COMMAND.COM` started, `FDAUTO.BAT` executed, COM program ran).
  Re-checked after the FDCONFIG.SYS fix (image `c75964ca…`).
* s9vm on VT-x: `vm test 10` boots the floppy for real — the VGA text shows the
  FreeDOS kernel banner, `FreeCom 0.86`, the two `s9vm` ECHO lines and the `K`
  marker (`PASS`, 4 538 exits / 4 360 BIOS calls / `int=0`).
* s9vm: `s9vm.selftest=freedos_dry` verifies the image installation without
  VT-x; `s9vm.selftest=freedos` boots it for real on a VT-x host and expects the
  VGA text to contain `FreeDOS` plus the `K` marker.
