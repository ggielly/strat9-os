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

.section .bss.riscv_test, "aw", @nobits
.balign 16
riscv_test_frame_a: .skip 32
riscv_test_frame_b: .skip 32
riscv_test_stack: .skip 4096
riscv_test_saved_sp: .skip 8
riscv_test_saved_ra: .skip 8
riscv_test_saved_a0: .skip 8
riscv_test_saved_s0: .skip 8
riscv_test_saved_s1: .skip 8
riscv_test_saved_b: .skip 8
riscv_test_flag: .skip 8

.text
.globl riscv_context_self_test
.type riscv_context_self_test, @function
riscv_context_self_test:
    la t0, riscv_test_saved_sp
    sd sp, 0(t0)
    la t0, riscv_test_saved_ra
    sd ra, 0(t0)
    la t0, riscv_test_saved_a0
    sd a0, 0(t0)
    la t0, riscv_test_saved_s0
    sd s0, 0(t0)
    la t0, riscv_test_saved_s1
    sd s1, 0(t0)

    la t0, riscv_test_frame_a
    sd zero, 0(t0)
    sd zero, 8(t0)
    la t1, riscv_context_test_finish
    sd t1, 16(t0)
    sd zero, 24(t0)

    la t0, riscv_test_frame_b
    sd zero, 0(t0)
    sd zero, 8(t0)
    la t1, riscv_context_test_stage_b
    sd t1, 16(t0)
    sd zero, 24(t0)

    la t0, riscv_test_frame_a
    mv a0, t0
    call riscv_restore_first_context

riscv_context_test_stage_b:
    la t0, riscv_test_saved_b
    sd sp, 0(t0)
    la a0, riscv_test_saved_b
    la a1, riscv_test_frame_a
    call riscv_switch_context
.Ltest_park:
    wfi
    j .Ltest_park

riscv_context_test_finish:
    la t0, riscv_test_flag
    li t1, 1
    sd t1, 0(t0)
    la t0, riscv_test_saved_sp
    ld sp, 0(t0)
    la t0, riscv_test_saved_s1
    ld s1, 0(t0)
    la t0, riscv_test_saved_s0
    ld s0, 0(t0)
    la t0, riscv_test_saved_a0
    ld a0, 0(t0)
    la t0, riscv_test_saved_ra
    ld ra, 0(t0)
    ret
.size riscv_context_self_test, .-riscv_context_self_test

.section .note.GNU-stack, "", @progbits
