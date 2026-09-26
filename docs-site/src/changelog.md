# Changelog

<!-- AUTO-CHANGELOG:START -->

## Project stats

- **Total commits:** `660`
- **Latest tag:** `0.1.0`
- **Repository:** [git.strat9-os.org](https://git.strat9-os.org/strat9-os/strat9-os)

## Recent commits (auto-generated)

- 2026-09-23 [`dec6766`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/dec676674d7c935126b8eea77b8bde72979727ff) Merge branch 'ELF-tuning-and-fix' into 'main'
- 2026-09-23 [`e724272`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/e724272e9bb7d4ddadb3f3a5cdcdcbf3c95e582e) Fix : unify logging to log::*, reject null ET_EXEC entry, warn on zero-size COPY relocs
- 2026-09-14 [`4c008c5`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/4c008c5cc3702bc915374b90a13518fec9268a9a) docs: update published documentation
- 2026-09-13 [`981429b`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/981429b03d580bf5e7dd51a7003628f176683285) Merge branch 'fix/UEFI-bootloader' into 'main'
- 2026-09-13 [`3898c50`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/3898c5074c07d2b5bdbd13b505a51ccfe92a0e30) feat(bootloader, kernel, abi): homemade strat9 UEFI bootloader : rewrite with scheduler and memory hardening
- 2026-08-28 [`228eaa5`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/228eaa541a22686b510eab7224464c74012f7c29) fix: regenerate corrupted Cargo.lock (stray merge conflict markers from rebase)
- 2026-08-28 [`93dd0e5`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/93dd0e5fbfea6eba551f12df3a03cdf86655d90a) kernel: integrate cpuid.rs leaf1 detection diagnostics from ramfs-hardening WIP
- 2026-08-28 [`4eb5b3d`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/4eb5b3d734ec46eab7861f08485c9ce017bf5cd8) Merge branch 'enhance-async-implementation' into 'main'
- 2026-08-28 [`00d83d7`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/00d83d71214282e5fd47d942446593aad18d3739) feat(kernel): async I/O overhaul : userspace ring mapping, deferred completions, Scheme trait redesign
- 2026-08-28 [`6738421`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/6738421e2e93a7dcc9b3030f4c2b257b6280051b) Merge branch 'fix/errno-and-capabilities' into 'main'
- 2026-08-28 [`c03feb2`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/c03feb24811b210174712aa7be5a9e097e32a80d) fix(abi): ENOTSUP 52→95, XFS EiB constant fix, decode_fixed roundtrip tests
- 2026-08-27 [`50a807d`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/50a807df4a2e2be5ca9ef7c803f0a5df34113d72) fix(framebuffer): update fill and blit operations to use dynamic detection
- 2026-08-27 [`7807362`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/7807362668fc98f2aa5dbea312f3e50662cf5553) Merge branch 'feat/graphics-performance' into 'main'
- 2026-08-27 [`7ed9263`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/7ed9263109ac3fba8d14cda9ece0b7772f76a0e1) style: apply rustfmt to paging.rs and framebuffer.rs
- 2026-08-24 [`aaf0fb6`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/aaf0fb632687a87130464df0eb67a7bca1ef2cfb) fix(kernel): work around nightly LLVM ISel abort on pshufb/movntdq
- 2026-08-24 [`7087cff`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/7087cffae28c256938700560f1bb00eefb5eb3ad) refactor(graphics): CanvasBuffer hygiene - S4/S5/S6 partial
- 2026-08-24 [`0e0d5fe`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/0e0d5fe7b198864e3763aa46f9c3c7cc2b8c54a4) perf(graphics): streaming stores for large fills/blits (S2)
- 2026-08-24 [`4aec188`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/4aec188c3e8206f5a02db4e7a15b7d6e180a6871) perf(graphics): Write-Combining framebuffer via dedicated PAT entry; unified present throttling
- 2026-08-23 [`6b3cecc`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/6b3ceccd7ffbeb179c2952050f706c749f6fde7a) perf(graphics): batched blit API and lockless framebuffer info getters
- 2026-08-23 [`75af9ad`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/75af9adef3742b94e66b89c546a3260d90e491db) perf(graphics): zero-copy VirtIO GPU presentation with coalesced damage
- 2026-08-23 [`706577f`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/706577f3e4ca9d85728fa1cd85f760a9bb641909) perf(graphics): SIMD pixel ingest + explicit-width wire protocol for /dev/display
- 2026-08-23 [`d4f597d`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/d4f597d9d086c4450aaf3500d27c2b821a73a4cd) perf(graphics): event-driven compositor with partial damage present
- 2026-08-27 [`067772e`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/067772e9315b102d784ddfd8ca3f7b4f6c648c48) Merge branch 'feat/Replace-Limine-bootloader-with-U-Boot-for-multi-architecture-support' into 'main'
- 2026-08-27 [`3ca6d7c`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/3ca6d7c6e61014fe2ad305f22e5bf75c0bdaeebd) feat: Add U-Boot setup script and boot protocol implementation
- 2026-08-27 [`df64d6d`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/df64d6d703fdf2ff0071f1ab8ced90647153f19f) Merge branch 'fixing-the-network-again' into 'main'
- 2026-08-27 [`eccb4d1`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/eccb4d178eabb9eb3070ec09f179556b292c1d4c) fix(net): ICMP reply handling + wasmi upgrade + clippy fixes
- 2026-08-27 [`25cc18b`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/25cc18bd5fcf4c13196353f7d58949f8592b1288) Merge branch 'feat/hal-arch-facade' into 'main'
- 2026-08-26 [`e725386`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/e725386af47ca1033326c74873b4691e9cd7f78e) ok
- 2026-08-26 [`7262385`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/7262385fd627431898a1423a0721dca8075719cc) fix(arch,riscv64): dedupe duplicated stub modules in facade_riscv
- 2026-08-26 [`892cb03`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/892cb03ff1ff04707db577bd2c14f72ba3211d6b) fix(arch,riscv64): SegmentSelector newtype for gdt stub, safe unmap on stub mapper
- 2026-08-26 [`580b86f`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/580b86f94a889f23df94e69dbcf3d1df442a3ffb) feat(ostd): Add/Sub<u64> operator impls for neutral PhysAddr/VirtAddr
- 2026-08-26 [`4260fbc`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/4260fbc8627daa57cd2f853c2a5e540480e8322a) fix(arch,riscv64): mapper::MapToError path fix inside OffsetPageTable impl
- 2026-08-26 [`60b50c6`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/60b50c68fe4d3144d2781b91a268e04aa0ab16db) feat(arch,riscv64): working Sv48 translate walker in stub mapper
- 2026-08-26 [`529715a`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/529715a7ad45ae0c5e96429fa0eb047bdd10c749) feat(ipc,riscv64): Sv48 tagged-pointer layout for IntrusiveMailbox
- 2026-08-26 [`c086395`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/c0863955d190741a9ae1f0472d822cbaecd04cef) feat(arch,riscv64): PciDevice config-space accessors (stubbed, R5 wires ECAM)
- 2026-08-26 [`a790379`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/a7903794e027df236e63a2eae06b333b8e19c765) fix(arch,riscv64): MouseEvent struct + u8 KEY_* scancode parity with x86
- 2026-08-26 [`3e447a2`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/3e447a2f866e0bc7b175c486d47bcf22aae3efa7) fix(arch,riscv64): restore unmap (tuple PhysFrame+MapperFlush) on stub mapper
- 2026-08-26 [`bf02f88`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/bf02f8866041b9a89a423ac46981862e36635797) fix(arch,riscv64): unmap returns PhysFrame, Cr3::write/Cr3Flags::empty stubs
- 2026-08-26 [`dc404b5`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/dc404b5b3ad1688134828ddb2673cab16e75e894) fix(arch,riscv64): sealed PortValue trait for port stub (kills E0034)
- 2026-08-26 [`6d3f772`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/6d3f7723f47e783074ca6f955db5547f3d99ce3a) fix(arch,riscv64): port stub typed read/write impls, drop stale traits
- 2026-08-26 [`c9dbfb0`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/c9dbfb0e086b59d2bd003ce623fb17863ccb62fa) fix(arch): annotate ambiguous PhysFrame::containing_address call-sites
- 2026-08-26 [`8731a50`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/8731a5069e8c39860b905406a96e33f22f41f956) refactor(arch): Port trait-based reads, gate top TUI behind x86_64
- 2026-08-25 [`1da8196`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/1da8196961cc7851832f7b4efcdf235e27619ec4) fix(arch,riscv64): dedupe stubs, align keyboard read_char, FrameAllocator cfg
- 2026-08-25 [`daf86f5`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/daf86f567c28b137fad449eebd753b7ec9af24d3) fix(arch,riscv64): align stub signatures with x86 call-sites
- 2026-08-25 [`922d429`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/922d42965ec6257e63cabb2f5fb28171d7986b64) feat(arch,riscv64): full PciDevice struct + PCI surface stubs
- 2026-08-25 [`acba1cf`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/acba1cf298b64a068b40a3c0811a43a4f9576e45) feat(arch,riscv64): Mapper trait surface on Sv48 skeleton
- 2026-08-25 [`62d200e`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/62d200e60f23891c170aafd4f734374f910f3774) feat(arch,riscv64): real Sv48 scaffolding in x86_64-stub, ostd pointer helpers
- 2026-08-25 [`e96df8f`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/e96df8f0d54c6156f4be44509d3306033cbb08f1) refactor(arch): gate VGA-UI commands behind x86_64, complete riscv framebuffer_info stub
- 2026-08-25 [`c587b62`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/c587b6234fa5462576dc232ccea8535386feae10) refactor(arch): route debug breadcrumbs + ahci rep movsb through per-arch paths
- 2026-08-25 [`88c5283`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/88c52834c3a0af3c6f01f14f3d7364f32a862281) refactor(arch): unify x86_64 crate access via x86_crate_shim, complete riscv stubs

<!-- AUTO-CHANGELOG:END -->
