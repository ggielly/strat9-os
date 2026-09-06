; blit_avx2.asm
; Implements SIMD AVX2 blit routine using dav1d's x86inc.asm.
; Uses unaligned stores so arbitrary framebuffer x offsets remain safe.

%define   private_prefix                          strat9_fb
%include  "src/framebuffer/x86/asm/x86inc.asm"

SECTION   .text

; void framebuffer_blit_avx2(uint32_t *dst, const uint32_t *src, size_t count)
; r0 = dst, r1 = src, r2 = count (pixels)
INIT_YMM  avx2
cglobal   framebuffer_blit,                       3, 4, 1, dst, src, count, tmp
          mov                                     tmpq, countq
          shr                                     tmpq, 3         ; count / 8 blocks
          test                                    tmpq, tmpq
          jz                                      .tail

.loop:
          vmovdqu                                 m0, [srcq]
          vmovdqu                                 [dstq], m0
          add                                     srcq, 32
          add                                     dstq, 32
          dec                                     tmpq
          jnz                                     .loop

.tail:
    ; Handle remaining pixels (0-7)
          and                                     countq, 7
          jz                                      .end

.tail_loop:
          mov                                     tmpd, [srcq]
          mov                                     [dstq], tmpd
          add                                     srcq, 4
          add                                     dstq, 4
          dec                                     countq
          jnz                                     .tail_loop

.end:
          RET
