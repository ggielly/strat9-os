#                             strat9                                                                         boot stub : U-Boot / PVH entry point (x86_64)
#
# Minimal: CLI, stack setup,  BSS                                                                            clear, jump to Rust.
#                             All                                                                            CPU feature setup (SSE, OSXSAVE, etc.) is done in Rust.

.section                      .boot.text,                                                                    "ax"
.code64
.global                       _start
_start:
                              cli

                              Save                                                                           DTB pointer (rdi = 1st arg in System V ABI)
                              movq                                                                           %rdi, %r15

                              Setup                                                                          bootstrap stack
                              leaq                                                                           boot_stack_top(%rip), %rsp

                              Clear                                                                          BSS
                              leaq                                                                           __bss_start(%rip), %rdi
                              leaq                                                                           __bss_end(%rip), %rcx
                              subq                                                                           %rdi, %rcx
                              xorl                                                                           %eax, %eax
                              rep                                                                            stosb

                              Restore                                                                        DTB pointer to rdi
                              movq                                                                           %r15, %rdi

                              Call                                                                           Rust entry point
                              call                                                                           kmain

.halt_loop:
                              cli
                              hlt
                              jmp                                                                            .halt_loop

#                             ---------------------------------------------------------------------------
#                             Stack                                                                          switch trampoline
#
#                             void                                                                           switch_stack(uint64_t                                         ;
#
#                             Switches                                                                       RSP to `new_rsp`, then calls `entry` with no arguments.
#                             Used                                                                           to migrate off the bootstrap stack once a proper stack is allocated.
#                             ---------------------------------------------------------------------------
.global                       switch_stack
switch_stack:
                              movq                                                                           %rdi, %rsp      # new_rsp
                              andq                                                                           $~0xf, %rsp     # align to 16 bytes (SysV ABI requirement)
                              callq                                                                          *%rsi           # call entry (address in rsi)
                              entry                                                                          should                                                        ; if it returns, halt
                              cli
                              hlt
                              jmp                                                                            .-1

#                             Bootstrap                                                                      stack                                                         ; real stack is allocated early in Rust.
.section                      .bss
.align                        16
boot_stack_bottom:
                              8192                                                                           # 8 KB bootstrap stack
boot_stack_top:
