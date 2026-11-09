#!/bin/sh
# 1. NVRAM périmé : le supprimer, la tâche le recrée depuis /usr/share/OVMF
rm -f build/OVMF_VARS.fd

# 2. Contenu réel de l'ESP de l'image disque
ls -l build/strat9-os-uefi-root/efi/boot/BOOTX64.EFI \
      build/strat9-os-uefi-root/boot/kernel.elf
mdir -i build/strat9-os-uefi.img@@1M ::/EFI/BOOT     # mtools

# ou : sudo mount -o loop,offset=1048576,ro build/strat9-os-uefi.img /mnt && ls -R /mnt/EFI /mnt/boot


