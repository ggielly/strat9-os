# strat9-os bootloader

Multi-stage bootloader for strat9.

## References

### Source code inspired by

- **Redox OS Bootloader**: <https://gitlab.redox-os.org/redox-os/bootloader>
  - Multi-stage BIOS/UEFI architecture
  - `KernelArgs` protocol
  - GDT and mode transitions

- **MaestroOS**: <https://github.com/llenotre/maestro>
  - Memory management (buddy allocator)
  - VGA console with ANSI escape codes
  - Linux compatibility approach

### Technical documentation

- [OSDev Wiki - Bootloader](https://wiki.osdev.org/Bootloader)
- [OSDev Wiki - Protected Mode](https://wiki.osdev.org/Protected_Mode)
- [OSDev Wiki - Long Mode](https://wiki.osdev.org/Long_Mode)
- [Intel Software Developer Manual](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html)
- [AMD64 Architecture Programmer's Manual](https://www.amd.com/en/support/tech-docs)

## License

Licensed under the GPLv3.
