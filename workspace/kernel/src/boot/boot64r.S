.section .text.init, "ax", @progbits
.balign 4
.globl _start
.type _start, @function
_start:
    la sp, __kernel_stack_top
    csrw sie, zero
    csrrc t0, sstatus, 0x2
    bnez a0, .Lpark

    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    la t0, __bss_start
    la t1, __bss_end
.Lbss_loop:
    bgeu t0, t1, .Lbss_done
    sd zero, 0(t0)
    addi t0, t0, 8
    j .Lbss_loop

.Lbss_done:
    call riscv_boot_entry

.Lpark:
    wfi
    j .Lpark

.size _start, .-_start

.globl riscv_kernel_stack_top
riscv_kernel_stack_top:
    .dword __kernel_stack_top

.globl riscv_kernel_start
riscv_kernel_start:
    .dword __kernel_start

.globl riscv_kernel_end
riscv_kernel_end:
    .dword __kernel_end

.section .note.GNU-stack, "", @progbits
