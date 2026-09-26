# Changelog

<!-- AUTO-CHANGELOG:START -->

## Project stats

- **Total commits:** `588`
- **Latest tag:** `0.1.0`
- **Repository:** [git.strat9-os.org](https://git.strat9-os.org/strat9-os/strat9-os)

## Recent commits (auto-generated)

- 2026-08-26 [`b4f818a`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/b4f818ae6873260ad7abc0170a60faa88c894344) ok
- 2026-08-26 [`31e8021`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/31e80214156e2b02e9ac57a1a25a3941d8c90b6f) fix(arch,riscv64): dedupe duplicated stub modules in facade_riscv
- 2026-08-26 [`e9b9ce4`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/e9b9ce4c3fafe1256d2e8cb2b9a2f27ba9ead1c2) fix(arch,riscv64): SegmentSelector newtype for gdt stub, safe unmap on stub mapper
- 2026-08-26 [`baa2c29`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/baa2c29b167c3cdc59a0855ff103e064ff27b9b1) feat(ostd): Add/Sub<u64> operator impls for neutral PhysAddr/VirtAddr
- 2026-08-26 [`7aa40ea`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/7aa40ea586f6cce38b0c3a208b302cc2787d03b8) fix(arch,riscv64): mapper::MapToError path fix inside OffsetPageTable impl
- 2026-08-26 [`27908f6`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/27908f66793d66d515536da16bee4c82eac6f493) feat(arch,riscv64): working Sv48 translate walker in stub mapper
- 2026-08-26 [`010af6a`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/010af6a243144d99d2e901c013ba397e9510bc88) feat(ipc,riscv64): Sv48 tagged-pointer layout for IntrusiveMailbox
- 2026-08-26 [`94d757f`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/94d757f5a7cb333d7ab75bf4dc242927f1c12c7d) feat(arch,riscv64): PciDevice config-space accessors (stubbed, R5 wires ECAM)
- 2026-08-26 [`deb59a1`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/deb59a1a7fbfc4a037a9b25f4985940d6013503b) fix(arch,riscv64): MouseEvent struct + u8 KEY_* scancode parity with x86
- 2026-08-26 [`04a24c5`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/04a24c5ba31f35bd5f9149bba97e1c3a2430d7a2) fix(arch,riscv64): restore unmap (tuple PhysFrame+MapperFlush) on stub mapper
- 2026-08-26 [`faee718`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/faee718841f67d6b62fe6e52a5d2df3a6b7d433d) fix(arch,riscv64): unmap returns PhysFrame, Cr3::write/Cr3Flags::empty stubs
- 2026-08-26 [`4c30841`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/4c308415c18f787aa296551a72d4ae89a1e79362) fix(arch,riscv64): sealed PortValue trait for port stub (kills E0034)
- 2026-08-26 [`3e08494`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/3e084942d8cc3c82d0dda733bb01e172c2863e19) fix(arch,riscv64): port stub typed read/write impls, drop stale traits
- 2026-08-26 [`e151bad`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/e151bad94e8e3c544b1cf6a29a17ab2e020a4f05) fix(arch): annotate ambiguous PhysFrame::containing_address call-sites
- 2026-08-26 [`a619064`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/a61906487d45ac13cd61216b619bed706b9a2c64) refactor(arch): Port trait-based reads, gate top TUI behind x86_64
- 2026-08-25 [`4d9897a`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/4d9897a6cfbca56dc240136871a2a247598b007f) fix(arch,riscv64): dedupe stubs, align keyboard read_char, FrameAllocator cfg
- 2026-08-25 [`319f260`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/319f2609402726db83a35e33335f984a9ef64e46) fix(arch,riscv64): align stub signatures with x86 call-sites
- 2026-08-25 [`95f89d1`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/95f89d11913372bdcc54297f6cba670459646510) feat(arch,riscv64): full PciDevice struct + PCI surface stubs
- 2026-08-25 [`870e7fb`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/870e7fb25db2f6d55e2c1c74ce82ae1b181a9188) feat(arch,riscv64): Mapper trait surface on Sv48 skeleton
- 2026-08-25 [`26755c2`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/26755c276f885d12c95bc83a565b5531660172bd) feat(arch,riscv64): real Sv48 scaffolding in x86_64-stub, ostd pointer helpers
- 2026-08-25 [`acc11a1`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/acc11a180b757f852686002e8aad757160712b26) refactor(arch): gate VGA-UI commands behind x86_64, complete riscv framebuffer_info stub
- 2026-08-25 [`1c60a70`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/1c60a700597ef17e5804a31d2ff866bf2fe6a633) refactor(arch): route debug breadcrumbs + ahci rep movsb through per-arch paths
- 2026-08-25 [`dc616fa`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/dc616fa7be6e693a96330d3cff49dbaac0880ef8) refactor(arch): unify x86_64 crate access via x86_crate_shim, complete riscv stubs
- 2026-08-25 [`d1ca15c`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/d1ca15c99789e52364094988fff27aacdbb5dc06) refactor(arch): replace port-0xE9 debug putc with arch-routed serial
- 2026-08-25 [`f926367`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/f926367f65dd2ae622412ec1ccc71b4dee486a2a) refactor(arch): route shared code through arch::xshim, gate limine/x86 deps
- 2026-08-25 [`e98ed5e`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/e98ed5e0bf15554f370a10798137cdcd8b1a3cbd) refactor(arch): migrate remaining call-sites to arch facade
- 2026-08-25 [`9e75f89`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/9e75f89596da79618fcd1133953aba556b3c4392) refactor(arch): migrate process/ and syscall/ call-sites to arch facade
- 2026-08-25 [`6108b74`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/6108b74039edf06964faa7770a642bfd795c7a3f) refactor(arch): introduce arch facade, migrate sync/ostd/memory call-sites
- 2026-08-25 [`1e2edef`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/1e2edefa984ced2436346ee020657db5120b4291) ci: retry pipeline (rustup download flake)
- 2026-08-25 [`9297cfe`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/9297cfe52d9ada4b55db1f3f0783dd10b49b4af2) build: pin Rust toolchain to nightly-2026-07-20
- 2026-07-18 [`bbb6107`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/bbb610798d13e2d0992532f639e33c1811dccec5) Merge branch 'improve-buddy-allocator' into 'main'
- 2026-07-18 [`abb7dd7`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/abb7dd7e60991de111632e72ae8658adccdf8697) feat(buddy): harden, optimize, and add kernel.toml configuration
- 2026-07-17 [`5832b19`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/5832b19921a8b3d7e59ec9de6391de6f391f1921) docs: update published documentation
- 2026-07-17 [`1a72181`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/1a72181f479278893775d6a3b19126f4b24b5999) docs: update published documentation
- 2026-07-17 [`0e0766a`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/0e0766a34c3b95f8e4de1d84f4cf4912da91ee4f) docs: update published documentation
- 2026-07-17 [`f94c369`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/f94c369709b3200794bfad047d09249a928a5ff3) Merge branch 'feat/vt100-console' into 'main'
- 2026-07-17 [`057447f`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/057447f5d091361dbc59cce83cde1ea8fb6e6713) feat(console): replace custom ANSI parser with vte crate
- 2026-07-17 [`5d53b0f`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/5d53b0fba04bd9c2bd1b58366fafce327c821eb6) Merge branch 'improve-vfs-all' into 'main'
- 2026-07-17 [`fe68f9a`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/fe68f9aacb1b70b8601cbdde1423be75628255d1) fix(vfs,console,scheduler): VFS improvements, console perf, panic backtrace
- 2026-07-15 [`425c2cd`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/425c2cd18dc1e6f065be037f4d087474356e426e) docs: update published documentation
- 2026-07-15 [`3612d4a`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/3612d4a43fcad2f260491ad1b4534da937e880f4) docs: update published documentation
- 2026-07-15 [`545e1b8`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/545e1b805bfd73eda9bc894ce1a161f3883aeb2d) Merge branch 'fix/console-performance' into 'main'
- 2026-07-15 [`44e4aa7`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/44e4aa70d7a7300c943048683ac54b6a534f57cc) perf(console): optimize rendering pipeline
- 2026-07-14 [`c3a9ecb`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/c3a9ecb885529735cb459e8600d99e8e90d9836c) Merge branch 'feat/heapless-vec-deque' into 'main'
- 2026-07-14 [`3a5eb69`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/3a5eb69d9b3041f89c205e184b4afe15c07ee44d) feat(silo): replace Vec with heapless::Vec for bounded fields
- 2026-07-09 [`c85c70f`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/c85c70f3b4f397ff9ace27674bfdfab7c077f649) Merge branch 'feature/ipc-access-levels' into 'main'
- 2026-07-09 [`ab22b0d`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/ab22b0d9b010dd704cf6044580b4f310c5748524) feat: 3-level IPC transport, N3 MMU thread migration, graphical silo, NIC/E1000 fixes
- 2026-06-25 [`848baaf`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/848baaf594c7a9fbd7f951c3959790dc26c1383e) Merge branch 'feat/input-to-userspace' into 'main'
- 2026-06-25 [`5a3d69c`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/5a3d69c4e10c4cfc67976a837751ce50292f9032) feat: migrate input system to userspace
- 2026-06-24 [`1b98905`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/1b9890594097a56a13f632ecb9f2a2a6b0e9f431) Merge branch 'test/smp-hardware-debug' into 'main'

<!-- AUTO-CHANGELOG:END -->
