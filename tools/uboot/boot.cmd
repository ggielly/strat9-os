# U-Boot boot script for Strat9-OS
# Loads kernel ELF and initrd from FAT32 boot partition

# Set load addresses
setenv kernel_addr_r 0x1000000
setenv initrd_addr_r 0x40000000
setenv fdt_addr_r 0x48000000

# Load kernel ELF from FAT32 partition
echo "Loading kernel from boot partition..."
load mmc 0:1 ${kernel_addr_r} /boot/kernel.elf

# Load initrd (modules CPIO) if present
if load mmc 0:1 ${initrd_addr_r} /boot/initrd.cpio; then
    echo "Initrd loaded"
    setenv bootargs "initrd=${initrd_addr_r}"
else
    echo "No initrd found, loading modules from FAT32..."
    setenv bootargs ""
fi

# Boot the kernel ELF
echo "Booting kernel..."
bootelf ${kernel_addr_r}
