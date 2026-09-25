// Simple 64-bit boot stub for QEMU -kernel (Linux boot protocol style)
// For Multiboot-style boot, see boot.S

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("boot64.S"), options(att_syntax));

#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(include_str!("boot64r.S"));
