#                             strat9                                                                         boot stub : U-Boot / PVH entry point (x86_64)
#
# Minimal: CLI, stack setup,  BSS                                                                            clear, jump to Rust.
#                             All                                                                            CPU feature setup (SSE, OSXSAVE, etc.) is done in Rust.

.section                      .boot.text,                                                                    "ax"
.code64
.global                       _start
_start:
                              cli

                              # Save kernel args pointer (rdi = 1st arg in System V ABI)
                              # Must happen BEFORE BSS zero which clobbers rdi.
                              movq                                                                           %rdi, %r15

                              # E9: 'A' at start
                              mov                                                                            $0xE9, %dx
                              mov                                                                            $'A', %al
                              out                                                                            %al, %dx

                              # Zero BSS before anything else.
                              # __bss_start/__bss_end are linker symbols covering the
                              # entire .bss section (including statics like Mutex locks).
                              lea                                                                     __bss_start(%rip), %rdi
                              lea                                                                     __bss_end(%rip), %rcx
                              sub                                                                     %rdi, %rcx
                              shr                                                                     $3, %rcx           # /8 for qwords
                              xor                                                                     %rax, %rax
                              rep                                                                     stosq

                              # E9: 'B' after BSS clear
                              mov                                                                            $0xE9, %dx
                              mov                                                                            $'B', %al
                              out                                                                            %al, %dx

                              # Setup                                                                         bootstrap stack
                              leaq                                                                           boot_stack_top(%rip), %rsp
                              andq                                                                           $-16, %rsp

                              # E9: 'C' after stack setup
                              mov                                                                            $0xE9, %dx
                              mov                                                                            $'C', %al
                              out                                                                            %al, %dx

                              # NOTE: BSS clear skipped -- page tables don't cover the
                              # full .bss.stack range, and the stack doesn't need zeroing.

                              # E9: 'D' after (skipped) BSS clear
                              mov                                                                            $0xE9, %dx
                              mov                                                                            $'D', %al
                              out                                                                            %al, %dx

                              # Restore                                                                       kernel args pointer to rdi
                              movq                                                                           %r15, %rdi

                              # E9: '1' right before call kmain
                              mov                                                                            $0xE9, %dx
                              mov                                                                            $'1', %al
                              out                                                                            %al, %dx

                              # Call                                                                          Rust entry point
                              call                                                                           kmain

                              # E9: '2' if kmain returned (should never happen)
                              mov                                                                           $0xE9, %dx
                              mov                                                                           $'2', %al
                              out                                                                           %al, %dx

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
entry:                        # should not return; if it does, halt
                              cli
                              hlt
                              jmp                                                                            .-1

# Bootstrap stack - placed at end of BSS in linker script (last .bss section).
.section                      .bss.stack,                                                                    "aw", @nobits
.align                        16
boot_stack_bottom:
                              .skip                                                                          65536           # 64 KB bootstrap stack
boot_stack_top:
