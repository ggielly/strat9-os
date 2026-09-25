.section .text.switch, "ax", @progbits
.balign 4
.globl riscv_switch_context
.type riscv_switch_context, @function
riscv_switch_context:
    mv t0, a0
    addi sp, sp, -32
    sd s1, 0(sp)
    sd s0, 8(sp)
    sd ra, 16(sp)
    sd a0, 24(sp)
    sd sp, 0(t0)
    mv sp, a1
    ld s1, 0(sp)
    ld s0, 8(sp)
    ld ra, 16(sp)
    ld a0, 24(sp)
    addi sp, sp, 32
    ret
.size riscv_switch_context, .-riscv_switch_context

.globl riscv_restore_first_context
.type riscv_restore_first_context, @function
riscv_restore_first_context:
    mv sp, a0
    ld s1, 0(sp)
    ld s0, 8(sp)
    ld ra, 16(sp)
    ld a0, 24(sp)
    addi sp, sp, 32
    ret
.size riscv_restore_first_context, .-riscv_restore_first_context

.section .note.GNU-stack, "", @progbits
