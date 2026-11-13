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
| Patched SHA-256 | `cce511dbda59a585206451378344910b5c9329869705e3066d9fd548de951e4c` |

## Patch (deterministic)

The image is a byte-for-byte copy of the official boot disk with three FAT12
entries rewritten in place (no cluster added, no FAT change):

1. `\FDCONFIG.SYS` (cluster 96) — the multilingual boot menu (`MENU …` and
   `MENUDEFAULT=1,10`) is replaced by the plain configuration directives and a
   direct `SHELL=` line, so the boot is deterministic and does not wait for a
   keyboard/menu timeout:
   ```
   @echo off
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
3. `\SETUP.BAT` is renamed to `\S9VMK.COM` (same cluster, size 9) and its first
   cluster holds a 9-byte COM program:
   ```
   B0 4B        mov al, 0x4B      ; 'K'
   BA E9 00     mov dx, 0x00E9    ; s9vm debug port
   EE           out dx, al
   CD 20        int 20h           ; terminate
   ```

`S9VMK.COM` writes the success marker `K` that the kernel DOS runner
(`s9vm/dosboot.rs`) and the QEMU `-debugcon` verification both watch for.

## Verification

* QEMU + SeaBIOS, TCG, headless: booting this image on a floppy controller and
  capturing port `0xE9` with `-debugcon file:…` yields exactly `K` (FreeDOS
  kernel loaded, `COMMAND.COM` started, `FDAUTO.BAT` executed, COM program ran).
* s9vm: `s9vm.selftest=freedos_dry` verifies the image installation without
  VT-x; `s9vm.selftest=freedos` boots it for real on a VT-x host and expects the
  VGA text to contain `FreeDOS` plus the `K` marker.
