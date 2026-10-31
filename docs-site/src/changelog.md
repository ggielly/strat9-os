# Changelog

<!-- AUTO-CHANGELOG:START -->

## Project stats

- **Total commits:** `858`
- **Latest tag:** `0.1.0`
- **Repository:** [git.strat9-os.org](https://git.strat9-os.org/strat9-os/strat9-os)

## Recent commits (auto-generated)

- 2026-10-31 [`39a5290`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/39a5290eee0f125c41865eceba4e57c81935901e) Enhance TCP listener management and logging
- 2026-10-31 [`a08f12a`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/a08f12ae3e800e623bbe208051a771a0f672e657) tools: improve GPL header script for Rust files and update website links kernel: enhance idle task handling with explicit yield to prevent deadlocks syscall: refine network receive logic to handle multiple queues effectively
- 2026-10-31 [`f2b7eb0`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/f2b7eb032c624c5bcfe699d0729bc27d05939e72) Refactor TUI and syscall handling
- 2026-10-31 [`e851b19`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/e851b19db6053103e9f99078d5f8ecb121896019) shell: launch ping from /initfs/ping
- 2026-10-30 [`5383d49`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/5383d49c83be2e99553d0c449baf1a319c940ed3) kernel: enhance IDT and PAT handling, improve shell parser and output functions
- 2026-10-30 [`84ef5e4`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/84ef5e4f0bdd85ccde024f1c7e65ca201959a38e) docs: update published documentation
- 2026-10-30 [`627a5b7`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/627a5b757a4aa70e3c0c723d810347c3fd26e148) abi/net: allow documented unsafe ring primitives under the workspace lint
- 2026-10-30 [`7a38863`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/7a388638e288183d877111ff31544d040a90c21d) Fix some stuff.
- 2026-10-30 [`f41d977`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/f41d977c5d3e8374400f94435f181d6a2dc8117d) Fix build after Code-refactor integration
- 2026-10-29 [`a7baa3a`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/a7baa3ae3ae1a615b87a26350c5d8b7985611315) Refactor silo memory management and enhance syscall functionality
- 2026-10-29 [`97cb28a`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/97cb28adf1aa53af61b1133db3181e1d2c9f9a9c) Implement framebuffer write-combining support and FPU state preservation
- 2026-10-29 [`dca6331`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/dca633126d1f9e8dce9e12e124f01326bbb2a732) feat(vfs): add NVMe block device support under /dev/nvme0n1
- 2026-10-29 [`7a14f0f`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/7a14f0f16763aa5a174a01f7ff0bf2f719b5a689) feat(storage): implement flush method for block devices to ensure data durability. Users's fsync() reachs now the hardware.
- 2026-10-28 [`7cbfc75`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/7cbfc7536bd68965d37945dd33f146be27e8b152) feat(storage): migrate AHCI, NVMe and virtio-blk DMA to device addresses
- 2026-10-28 [`ae81774`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/ae8177432968290f32c28c6a3f8ec7b215bafa07) feat(nic): migrate DMA programming to IOMMU device addresses
- 2026-10-28 [`62e40ef`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/62e40efb60b484b5e5bafb04f0d531a7ec68b6bc) feat(iommu): finish P1/P2 with QI, IR/MSI, IVMD, bounce buffers and strate-iommu boot wiring
- 2026-10-28 [`8a0b5ff`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/8a0b5ff7c6c4688407524b7b7412df171c0e8169) Add -device intel-iommu inside qemu
- 2026-10-28 [`e9e41d3`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/e9e41d3b48d1227faa8dce63a3de792b46a7c70f) fix(iommu): make the boot banner unconditional and add a shell iommu command
- 2026-10-28 [`5ccb269`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/5ccb26910068ceb1ab43ec656ec463a7976b7c70) feat(iommu): P1 policy/robustness and P2 shadow tables, superpages and batch DMA
- 2026-10-28 [`db8ae4d`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/db8ae4db6bd95a93910e6de14d3ecb517ee2c870) feat(iommu): P0 domain/IOVA management, DMAR parser and DMA isolation ABI
- 2026-10-28 [`e5ddd2b`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/e5ddd2b6a9329ca7bcfc12a6275ee3611e3113f0) fix(boot): defer the NIC hotplug watchdog until the scheduler is running
- 2026-10-28 [`764d072`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/764d072f0faaedf36f3289d85fe6ef2aaaf927b5) fix(boot): start NIC hotplug after timers and quiet periodic PCI rescans
- 2026-10-28 [`7278974`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/7278974e7729db867d71a9872bcd35765437e086) fix(ping): restore alloc_error_handler feature gate and Layout import
- 2026-10-28 [`a126639`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/a12663900c104051df15fb02c91600b10be26a1b) refactor: remove unused alloc_error_handler feature from ping utility
- 2026-10-28 [`2f07be9`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/2f07be9bd8cb0f93b67600492aa446ced8311763) test(abi): align ipc_payload_wire with the real 24-byte OpenReply
- 2026-10-28 [`861ee54`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/861ee546838667511ad42236df8b1ca8522f9069) fix: unblock kernel build after 1 KiB IPC and net queue changes
- 2026-10-28 [`9ef21eb`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/9ef21ebf385bd205cbee8de8f713c59d181527a9) Fix compilation
- 2026-10-28 [`ab30389`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/ab30389193742a99a4368709945d6ab63c6986bb) docs: network data plane, bulk VFS rings and hotplug notes
- 2026-10-28 [`e109204`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/e10920414ea12581538af9c161e8ad7723327b44) net: bulk VFS rings, multi-queue RSS, PCI hotplug polling and RX checksum offload
- 2026-10-28 [`61d03a5`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/61d03a5f11a1d65bdcaa623aa2b5af2d23f6bc33) net: reset RX refill batch counter on controller reinit
- 2026-10-28 [`1a93b50`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/1a93b50f27336a719f9c98a775b775466460ef02) net: hotplug event capability check and mount replacement cleanup
- 2026-10-28 [`d82d29c`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/d82d29c1627a4bf09c268fcbb094a7b24b207ce7) net: post-audit fixes for token lifetime, queue ownership and supervisor restart
- 2026-10-28 [`9d15fed`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/9d15fed44964c5c5a441dedf59fd1f76fa79eeee) net(P2-P4): offload negotiation, hotplug, IOMMU bookkeeping, vSwitch/QoS, bulk IPC
- 2026-10-28 [`c4d4a13`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/c4d4a13ea4d9ba4c9d2a25d6a803fe589f492c32) net(P1): zero-copy shared queue between kernel and strate-net
- 2026-10-28 [`215eab6`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/215eab6cf813b566c5c49cf8b16cc4e6608bf662) net(P0): capability-gated syscalls, bounded IRQ, shared queue foundation
- 2026-10-27 [`a5abadb`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/a5abadbbecf5de2eb02e0bce2cbf0e64778259d7) Merge branch 'ELF-tuning-and-fix' into HEAD
- 2026-10-27 [`f76ffc3`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/f76ffc3f7522d26eda94447d3a0e5eb5cb3916c0) Merge branch 'feature/console-display-strates' into HEAD
- 2026-10-27 [`af6560c`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/af6560c462050268cf1230edc5861554f5076ac7) Merge boot ABI branch and repair duplicated additions
- 2026-10-27 [`024c393`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/024c39314d4003ae56cab1c43d66aa62ec87e631) Merge remote-tracking branch 'origin/fix/boot-abi-consistency' into integration/merge-all
- 2026-10-27 [`e0d0c42`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/e0d0c424a0e6055e7efa0b1091c99fabdb51b8f4) Merge remote-tracking branch 'origin/fix/ramfs-hardening' into integration/merge-all
- 2026-10-27 [`ea7c302`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/ea7c302996f627819d6e6ace15cc161b5162dad6) Merge remote-tracking branch 'origin/Fix-and-enhance-networking' into integration/merge-all
- 2026-10-27 [`c3c177c`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/c3c177c178380821b1d56a9e6892aff37a31f466) Merge remote-tracking branch 'origin/refactor/decompose-load-elf-task-inner' into integration/merge-all
- 2026-10-27 [`c629b18`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/c629b18a90f71b64d1ac6b36ebbbda526678b96b) Merge remote-tracking branch 'origin/fix/boot-process' into integration/merge-all
- 2026-10-27 [`6798cfe`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/6798cfe244873d50c236702ab7836935f9afc2d9) display: add bounded snapshot capture stream
- 2026-10-27 [`7b344a3`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/7b344a398eac3d377203cba974ffe32615a3c8e8) display: refuse byte-stream reads on write-only screen handles
- 2026-10-27 [`02e51cd`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/02e51cd2c806b269243a56fd9fede98d77269e12) video: adopt the bootloader framebuffer for the display scheme
- 2026-10-27 [`9916a78`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/9916a78171c4b5979b630d040dada587a01ae97a) vfs: list direct child mounts and ensure /dev/display is mounted
- 2026-10-27 [`cffb84e`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/cffb84ea24ba000654d5c123dec82d13cd818cb6) Fix missing unsafe
- 2026-10-27 [`c1a9fa4`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/c1a9fa442f2f35052c7f145941592a6ede95a7b3) console: MAP_SHARED frame-backed display surface
- 2026-10-27 [`9dee8c6`](https://git.strat9-os.org/strat9-os/strat9-os/-/commit/9dee8c6968728746a7f343734af4e3d4b8aa97ff) console: row-batched glyphs, DMG2 damage list, glyph atlas

<!-- AUTO-CHANGELOG:END -->
