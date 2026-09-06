; fill_avx2.asm
; Implements SIMD AVX2 fill routine using dav1d's x86inc.asm calling convention abstraction.
; Uses unaligned stores so arbitrary framebuffer x offsets remain safe.

%define   private_prefix                          strat9_fb
%include  "src/framebuffer/x86/asm/x86inc.asm"

SECTION   .text

; void framebuffer_fill_avx2(uint32_t *dst, uint32_t color, size_t count)
; r0 = dst, r1 = color, r2 = count (pixels)
INIT_YMM  avx2
cglobal   framebuffer_fill,                       3, 4, 1, dst, color, count, tmp
    ; Broadcast color (in r1d) into ymm0
          vpbroadcastd                            m0, r1d

    ; Calculate how many 8-pixel blocks we have
          mov                                     tmpq, countq
          shr                                     tmpq, 3         ; count / 8
          test                                    tmpq, tmpq
          jz                                      .tail

.loop:
          vmovdqu                                 [dstq], m0
          add                                     dstq, 32
          dec                                     tmpq
          jnz                                     .loop

.tail:
    ; Handle remaining pixels (0-7)
          and                                     countq, 7
          jz                                      .end

.tail_loop:
          mov                                     [dstq], r1d
          add                                     dstq, 4
          dec                                     countq
          jnz                                     .tail_loop

.end:
          RET
