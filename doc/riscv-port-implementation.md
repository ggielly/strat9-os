# Strat9-OS — Document d'implémentation du port RISC-V (riscv64, QEMU virt)

> Statut : proposition v1 (analyse statique du code à la date du 2026-08-25).
> Périmètre : portage du kernel Bedrock + Silos vers `riscv64` sur QEMU `virt`,
> avec refactor préalable de la couche arch (`cfg(arch)` + traits communs).
> Source des estimations : audit ligne par ligne du dépôt (2 agents d'audit + revue manuelle).

---

## 0. Résumé exécutif

Strat9-OS est un microkernel Rust `no_std` très fortement couplé à x86_64 :

| Métrique | Valeur |
|---|---|
| Code Rust total (workspace) | ~143 000 lignes / 477 fichiers |
| Couche arch x86_64 (`kernel/src/arch/x86_64/`, 28 fichiers) | ~10 600 lignes |
| Usages `asm!` / `naked_asm!` | ~115 dans 32 fichiers |
| Références directes à la crate `x86_64 = "0.15"` | ~639 usages dans ~60 fichiers |
| Fichiers référençant `crate::arch::x86_64::...` hors du dossier arch | ~71 fichiers (531 occurrences), dont `lib.rs` (61), `process/scheduler.rs` (58), `memory/userslice.rs` (20), `boot/panic.rs` (17), `ipc/n3.rs` (10)… |
| Dépendances arch-dépendantes | `x86_64`, `uart_16550`, `raw-cpuid`, `limine 0.6.5`, `cc`, `nasm-rs`, feature `abi_x86_interrupt` |

**Ce qui est déjà portable** (grosse valeur, à ne pas casser) :
ABI syscall maison (`strat9-abi`), dispatcher syscall, IPC (canaux/rings/mailbox,
sauf trampolines asm de `n3.rs`), VFS/schemes, capabilities, silo manager,
scheduler (logique, hors hooks arch), buddy/heap/COW/vmalloc (hors types
d'adresses), composants userspace (strate-init/console/fs/net/wasm…),
mécanisme `.component_entries`.

**Ce qui doit être réécrit** : boot (Limine/asm → SBI/OpenSBI + DeviceTree),
traps & interruptions (GDT/IDT/TSS/APIC/PIC → `stvec` + PLIC), context switch &
entrée syscall (SYSCALL/SYSRET/SWAPGS → `ecall`/`sret`/`sscratch`), pagination
(PML4 x86 → Sv48), timers (PIT/TSC/APIC-timer → CLINT/SBI), per-CPU (GS base →
`sscratch`), ACPI → FDT.

**Estimation globale : ~3–4 mois-personne** pour un boot userspace minimal
(serial + shell Chevron) sur QEMU virt, dont 4–6 semaines de refactor HAL
préalable qui bénéficieront aussi au futur port aarch64 (déjà listé
« medium-term » dans HARDWARE.md).

---

## 1. État des lieux du couplage x86_64

### 1.1 Cartographie par module

| Module | Couplage | Détail |
|---|---|---|
| `boot/` | 🔴 total | Limine protocol, `boot.S`/`boot64.S` (real→protected→long mode), linker scripts `elf64-x86-64` higher-half, section `.requests` |
| `arch/x86_64/` | 🔴 par définition | gdt/idt/tss/apic/x2apic/ioapic/pic/msi/smp/percpu/syscall/tlb/timer/cpuid/io(port I/O)/serial/vga/keyboard PS/2/mouse/speaker/pci(ports+ECAM)/ring3_diag |
| `memory/` | 🔴→🟡 | Logique générique (buddy, COW, vmalloc, zones) mais types `PhysAddr/VirtAddr/PageTableFlags/OffsetPageTable` de la crate `x86_64` partout ; HHDM fourni par Limine ; `paging.rs` = walker PML4 |
| `process/` | 🔴 partiel | Context switch naked_asm (fxsave/xsave, iret frame, sélecteurs GDT), trap frame user (iret_cs/ss), ELF loader rejette tout sauf EM_X86_64, sigreturn trampoline posé sur pile user |
| `syscall/` | 🟡 | Dispatcher + sémantique portables ; `fork/exec/mmap/process.rs` utilisent la crate `x86_64` ; `SYS_ARCH_PRCTL` (350) x86-spécifique ; `utsname.machine="x86_64"` |
| `ipc/` | 🟡 | Tout portable sauf `n3.rs` (2 `naked_asm!` trampolines, lecture rsp/rbp) et debug `out 0xE9` |
| `sync/` | 🟢 | Atomics std ; seuls 3 `out 0xE9` debug dans spinlock.rs. RISC-V nécessite extension A (LR/SC) |
| `hardware/` | 🟠 mixte | VirtIO logique portable mais transport PCI BAR uniquement (QEMU virt = virtio **MMIO**) ; AHCI/NVMe/ATA/e1000*/rtl8139/pcnet inutiles sur virt ; RTC CMOS ports 0x70/71 ; EC ports 0x62/66 absent |
| `framebuffer/` | 🟠 | Dispatch `cfg(target_arch)` déjà présent avec backend aarch64/neon — bon modèle ; backends SSE2/AVX2/AVX512 (nasm via build.rs) à remplacer par RVV ou scalar |
| `acpi/` | 🔴 remplacement | QEMU virt RISC-V expose du DeviceTree, pas d'ACPI. Parser DTB requis |
| `shell/`, `vfs/`, `silo/`, `namespace/`, `capability.rs`, `entropy`, `kaslr` | 🟢/🟠 | Portable ; hooks arch dispersés (61 refs dans lib.rs, VGA dans shell, keyboard layout FR dans lib.rs) ; entropy = rdrand/rdseed → SBI/Zkr/jitter |
| Userspace (`components/`) | 🟢 | Bins no_std parlant l'ABI strat9 ; seul `components/syscall/src/lib.rs` (asm `syscall` ×7) et `strate-silo-test/main.rs` à réécrire en `ecall` (~1–2 j). `sdk/musl` a déjà `arch/riscv64` en amont |
| Build | 🟠 | `targets/*.json` x86 uniquement (features `+rdrnd,+rdseed`, f80, panic=unwind) ; Makefile.toml câblé limine-image ; `rust-toolchain.toml` targets=[x86_64-unknown-none] |

### 1.2 Points de fuite arch hors `arch/`

Les pires fichiers (occurrences `arch::x86_64`) :

```
lib.rs 61 · process/scheduler.rs 58 · shell/mod.rs 25 · process/scheduler/runtime_ops.rs 21
memory/userslice.rs 20 · boot/panic.rs 17 · process/elf.rs 16 · shell/output.rs 14
process/task.rs 14 · memory/buddy.rs 13 · ipc/n3.rs 10 · ostd/cpu.rs 8 · hardware/mod.rs 8 ...
```

La couche `ostd/` (« OSTD-like abstraction », inspirée Asterinas) est déclarée
platform-independent mais appelle encore `arch::x86_64` en dur
(`CpuId::current_racy()` → GS base, EarlyWriter → serial COM1). C'est la bonne
ébauche de façade : il faut la finir.

### 1.3 Ce que l'asm! réel contient

Sur les ~115 sites : majorité de `out 0xE9` debug (port QEMU debug — remplaçable
par une macro `debug_putc!` portable), `invlpg`/`mov cr3` dans ostd/mm.rs,
rdmsr/wrmsr/swapgs/syscall/naked_asm context-switch — ces derniers sont
concentrés dans arch/ et process/. Le périmètre asm réel à porter est donc plus
proche de 30–40 sites significatifs.

---

## 2. Architecture cible

### 2.1 Décisions structurantes

1. **Refactor `cfg(arch)` avant port** : `kernel/src/arch/mod.rs` devient une
   façade neutre exposant les primitives via traits ; `arch/x86_64/` et
   `arch/riscv64/` implémentent derrière `#[cfg(target_arch)]`. Aucun fichier
   hors de `arch/` ne référence plus directement `x86_64::`.
   Traits minimum :
   - `InterruptController` (enable/disable/register_handler/eoi)
   - `TlbOps` (flush_local/flush_all/shootdown)
   - `PerCpu` (current_cpu_index/kernel_rsp set/get)
   - `TimerSource` (set_oneshot_ns/now_ns)
   - `BootProtocol` (memmap/hhdm/framebuffer/initfs/cmdline → KernelArgs)
   - `SerialOut` (putc early)
   - `ContextFrame` (save/restore/switch, layout trap frame)
2. **KernelArgs reste le contrat de boot** (`strat9_abi::boot`, repr(C),
   magic/version). Ajouter champs `dtb_base/dtb_size` versionnés
   (abi_version++). Le backend SBI remplit la même struct que Limine.
3. **HHDM auto-géré** : sur RISC-V pas de HHDM bootloader → choisir
   `0xffff_c000_0000_0000` (ou aligner sur la convention Linux sv48) et mapper
   toute la RAM explicitement dès `paging::init` (le code `map_all_ram`
   existant fait déjà ça côté x86).
4. **QEMU virt riscv64 comme plateforme de référence** : OpenSBI (fw_jump ou
   `-bios default`), harts S-mode @ `0x80200000`, a0=hartid, a1=DTB.
5. **DeviceTree obligatoire** : nouvelle dépendance kernel (crate `fdt` ou
   parser maison) remplaçant acpi/ : mémoire, CPU harts, ns16550a UART
   (0x10000000), CLINT, PLIC, PCIe ECAM, virtio-mmio (0x10001000+, IRQ 1..8),
   rtc-goldfish.
6. **Paging Sv48** (4 niveaux, même profondeur qu'aujourd'hui) : nouveau module
   `arch/riscv64/paging.rs` (format PTE V/R/W/X/A/D, PPN, PA 44 bits) ; garder
   l'API actuelle de memory/paging (map/unmap/translate/flags) pour ne pas
   toucher aux appelants.
7. **Traps** : `stvec` direct, handler naked_asm sauvegardant le frame complet
   (x1..x31 + sstatus/sepc/stval/scause + FP/D/V si sstatus.FS=Dirty),
   dispatch Rust sur `scause`. Le stack-switch kernel/user (ex-TSS RSP0) se
   fait via `sscratch` (même design que le per-CPU GS actuel).
8. **Syscall entry** : `ecall` U-mode → trap ; numéro en a7, args a0–a6, retour
   a0 (psABI riscv ; 7 args utiles vs 6 en x86 — l'ABI strat9 n'utilise que 6,
   pas de changement nécessaire). Le dispatcher est inchangé.
9. **Interruptions** : PLIC pour IRQ externes (UART, virtio, goldfish RTC) ;
   IPI via SBI `send_ipi` (+ clint si utile) ; timer via SBI `set_timer` +
   STIP. MSI/IMSIC reporté en phase tardive.
10. **SMP** : harts secondaires démarrés par `sbi_hart_start` ; la logique de
    bring-up/rendezvous/per-cpu du `smp.rs` actuel est transposable.

### 2.2 Nouvelle cible et build

- `targets/riscv64-strat9.json` :
  - llvm-target `riscv64-unknown-strat9`, pointer-width 64, little-endian,
  - features `+m,+a,+c,+f,+d` (A requis pour les atomics ; `max-atomic-width: 64`),
  - code-model medium, relocation static, panic strategy : **abort**
    (recommandé ; l'actuel unwind n'a pas de sens sans tables compatibles),
  - disable-redzone N/A.
- `rust-toolchain.toml` : ajouter `riscv64imac-unknown-none-elf` (ou target
  custom) ; nightly conservé (`alloc_error_handler` etc. — vérifier les
  features instables utilisées : `abi_x86_interrupt` disparaît côté riscv).
- Linker script `linker-riscv.ld` : plat à `0x80200000`, garder
  `.component_entries`, alignement 16 pour les frames.
- build.rs : garder cc pour boot.S riscv ; supprimer nasm-rs sous cfg x86_64.
- Makefile.toml : nouvelles tâches `run-riscv` :
  `qemu-system-riscv64 -machine virt -cpu rv64 -smp 4 -m 512M -nographic
  -bios opensbi/fw_jump.elf -kernel <kernel.elf> -drive ...` ;
  conserver le chemin x86 intact pendant toute la transition.

---

## 3. Jalons (milestones)

### Jalon R0 — Prérequis HAL (x86 inchangé, tout doit continuer à booter)
Objectif : zéro référence `arch::x86_64` hors de `arch/`.
1. Créer `kernel/src/arch/mod.rs` façade + traits (voir §2.1).
2. Migrer les 531 call-sites vers la façade (par domaines : memory, process, ipc, shell, hardware, boot, sync, vfs).
3. Remplacer les `out 0xE9` épars par macro `debug_putc!` routée via SerialOut.
4. Isoler les types d'adresses : soit wrapper propre autour de PhysAddr/VirtAddr, soit adopter types maison dans `ostd/mm`.
5. CI : `make check` sur les deux cfg futurs (x86 vert, riscv peut être feature-gated off).

### Jalon R1 — Hello world RISC-V (1 hart, serial)
- Target JSON, toolchain, linker script, stub boot S-mode (`_start` : hartid/DTB, clear BSS, pile, sstatus.FS, saut Rust).
- Serial ns16550a MMIO (réutiliser uart_16550 en mode MMIO).
- Panic handler, logger, KernelArgs rempli depuis FDT minimal (mémoire + UART).
- Livrable : prompt serial sur QEMU virt `-nographic`.

### Jalon R2 — Traps + timer + paging Sv48
- stvec + frame de trap complet + dispatch scause.
- Timer SBI/CLINT, ticks NS_PER_TICK, interruption STIP.
- Sv48 : map kernel, HHDM, phys_to_virt/virt_to_phys, translate, sfence.vma + TlbOps.
- Buddy/frame allocator alimentés par la memmap FDT.
- Livrable : kernel qui tourne avec interruptions timer, page faults dumpés proprement.

### Jalon R3 — Syscalls + Ring 3 (1 silo)
- ecall entry + sscratch per-cpu, retour sret.
- Context switch (task.rs) version riscv, FP save/restore (F/D).
- ELF loader : accepter EM_RISCV, PIE/ASLR OK.
- Port du crate userspace `strat9_syscall` en `ecall`.
- Livrable : strate-silo-test ou hello binaire ring-3 qui fait des syscalls.

### Jalon R4 — IPC + VFS + shell (Chevron sur série)
- Port trampolines n3.rs, mailbox, rings.
- VFS/schemes/procfds, ramfs, console strate.
- Livrable : shell Chevron interactif sur UART, ls/cat/uptime fonctionnels.

### Jalon R5 — Drivers + stockage + réseau
- PLIC complet, PCI ECAM via FDT, transport virtio-MMIO.
- virtio-block + ext4/ramfs sur disque, virtio-net + stack IPv4/UDP/TCP, virtio-rng (remplace rdrand pour entropy/kaslr).
- Livrable : montage ext4, ping/telnetd depuis QEMU (user networking).

### Jalon R6 — SMP + finalisation
- sbi_hart_start, per-cpu par hart, scheduler multi-hart, TLB shootdown IPI.
- Framebuffer : virtio-gpu + backend blit scalar puis RVV (dispatch cfg existant).
- Musl/relibc cross riscv64 (shim ABI strat9), composants recompilés.
- Docs : mise à jour HARDWARE.md (RISC-V → « supported »), docs-site/boot-sequence.md, NATIVE_SYSCALLS.md (convention a7/a0-a6).

---

## 4. Tickets prêts à ouvrir

Format : `[Rn] Titre — scope — estimation — dépendances`.

**R0 (HAL)**
- [R0.1] Créer façade `arch::` + traits (InterruptController, TlbOps, PerCpu, TimerSource, BootProtocol, SerialOut, ContextFrame) — arch/mod.rs — 3 j — aucune
- [R0.2] Migrer memory/* vers façade (types adresses, paging API, tlb) — 5 j — R0.1
- [R0.3] Migrer process/* (scheduler, task, timer ops) vers façade — 5 j — R0.1
- [R0.4] Migrer ipc/n3.rs trampolines derrière trait ContextFrame — 2 j — R0.1
- [R0.5] Migrer boot/panic/logger/debug + entropy (trait RngSeed) — 2 j — R0.1
- [R0.6] Migrer shell/, vfs/, hardware/, framebuffer/ (macro debug_putc!) — 3 j — R0.1
- [R0.7] Nettoyer Cargo deps : x86_64/raw-cpuid/uart_16550/limine sous cfg x86_64 — 1 j — R0.2-R0.6

**R1 (boot)**
- [R1.1] targets/riscv64-strat9.json + rust-toolchain + CI check — 0,5 j — R0.7
- [R1.2] Stub boot S-mode (_start, BSS, pile, FPU) + linker script 0x80200000 — 2 j — R1.1
- [R1.3] Serial MMIO ns16550a + panic/log — 1 j — R1.2
- [R1.4] Parser FDT minimal (mem, uart, harts, chosen) — 3 j — R1.2
- [R1.5] Backend BootProtocol-SBI remplissant KernelArgs (+ dtb_base/dtb_size dans strat9-abi) — 2 j — R1.4
- [R1.6] Tâches cargo-make run-riscv / image initfs riscv — 1 j — R1.1

**R2 (noyau)**
- [R2.1] Trap frame naked_asm + dispatch scause (équivalent idt.rs) — 5 j — R1
- [R2.2] Timer SBI/CLINT + calibration — 2 j — R2.1
- [R2.3] Sv48 paging + HHDM + TlbOps(sfence.vma) — 8 j — R2.1
- [R2.4] Brancher buddy/boot_alloc/frame sur memmap FDT — 2 j — R2.3
- [R2.5] PerCpu via sscratch (port percpu.rs) — 2 j — R2.1

**R3 (ring 3)**
- [R3.1] ecall/sret syscall entry + set_kernel_rsp — 3 j — R2.5
- [R3.2] Context switch task.rs riscv + FP save — 5 j — R2.1
- [R3.3] ELF loader EM_RISCV + tests abi_layout — 2 j — R3.2
- [R3.4] Crate userspace strat9_syscall: asm ecall — 1 j — R3.1
- [R3.5] Signaux : trampoline sigreturn frame riscv — 2 j — R3.2

**R4/R5/R6** (détaillées à l'ouverture) : n3 traps (2 j), PLIC (5 j), PCI ECAM+FDT (3 j), virtio-MMIO transport (5 j), virtio-block+ext4 (3 j), virtio-net+stack (5 j), virtio-rng/entropy (1 j), goldfish RTC (1 j), SMP/IPI (8 j), virtio-gpu+blit (5 j), musl cross shim (10 j optionnel).

Total indicatif : ~90–100 jours-homme de dev effectif, cohérent avec l'estimation 3–4 mois-personne avec marge debug (le debug QEMU/OpenSBI prend toujours plus de temps que prévu).

---

## 5. Risques & points de vigilance

1. **panic=unwind** : la cible x86 utilise unwind ; décider tôt si riscv passe en abort (recommandé) ou si on garde l'unwind (coût élevé, peu utile en no_std kernel).
2. **Features nightly** : `abi_x86_interrupt` n'existe pas pour riscv — le dispatch d'exceptions doit être entièrement maison (déjà prévu R2.1). Vérifier `alloc_error_handler`, `naked_asm` (stabilisé ?), `negative_impls` sous la nouvelle target.
3. **A-extension obligatoire** pour les atomics du code existant (spin, crossbeam-queue, heapless) — imposer `+a` dans la target, ne jamais viser rv64imac sans A.
4. **TLB shootdown** : sfence.vma est par-hart — l'infra IPI existante (broadcast_panic_halt, shootdown SMP) doit être opérationnelle avant R6, sinon corruption mémoire silencieuse.
5. **Endianness/layout ABI** : riscv64 est LE comme x86_64 → codec IPC (240 octets, LE implicite) OK tel quel. Les structs packed/align(64) de abi/data.rs restent valides (LP64).
6. **SYS_ARCH_PRCTL(350)** : ARCH_SET_FS/GS → à mapper sur TP (TLS) riscv ; impact musl (TLS via TP).
7. **Framebuffers** : pas de fb linéaire au boot sur virt — le path VGA/vgabuf/Limine-fb de shell/top doit passer par virtio-gpu (ou rester headless jusqu'à R6).
8. **PS/2 keyboard/mouse, speaker, EC, thermal** : inexistants sur virt — prévoir stubs cfg pour ne pas bloquer le boot (lib.rs appelle speaker::beep_phase ×N et keyboard_layout::set_french_layout).
9. **WIP parallèle** : chantier CORDIC au socle en cours (tick_cordic, save v18) — coordonner les merges sur lib.rs/process (fichiers les plus chauds).

## 6. Sources dans le dépôt

- Couplage : `workspace/kernel/src/arch/x86_64/` (28 fichiers, ~10,6 kL), 115 asm!/32 fichiers, crate x86_64 dans ~112 fichiers.
- Boot : `src/boot/{limine.rs,entry.rs,boot.S,boot64.S}`, `linker*.ld`, `targets/*.json`, `Makefile.toml`.
- ABI : `workspace/abi/src/*`, `doc/NATIVE_SYSCALLS.md`, `docs-site/src/{abi,syscalls,boot-sequence}.md`.
- Composants : `workspace/components/*`, `kernel/libs/component*`, `sdk/musl` (arch/riscv64 présent en amont).
- Référence roadmap existante : `HARDWARE.md` § Future hardware targets (RISC-V QEMU virt = medium-term).
