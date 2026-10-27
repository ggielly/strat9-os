# Strat9 OS

An experimental operating system kernel written in Rust, booting on **x86_64** through a homemade UEFI bootloader. A **riscv64** port is in progress as a stub; there is no aarch64 port. See [Boot Sequence](./boot-sequence.md) for the full chain.

---

## Quick start

<div class="api-card">

**Building and running**

```bash
# Build the UEFI bootloader, the kernel and every userspace component,
# then assemble the bootable image (OVMF/UEFI, ESP on a GPT disk)
cargo make uefi-image
cargo make uefi-image-release     # same, with a release kernel and bootloader

# Boot it under OVMF, serial on stdio (4 cores, 2 GiB)
cargo make run-uefi

# Boot it with a graphics device, USB tablet, virtio-net and a telnet
# forward on localhost:2222
cargo make run-uefi-gui
```

Tasks come from `Makefile.toml` (`cargo make --list-tasks` to enumerate them). The
`Makefile.builder.toml` file that still carries `build-all` / `run-gui` is **legacy and
unreferenced** — nothing invokes it, and it targets the retired BIOS/ISO path.

[Build & publishing guide](./publishing.md) · [Source repository](https://git.strat9-os.org/strat9-os/strat9-os)

</div>

---

## Architecture guides

| Guide | Description |
|-------|-------------|
| [Architecture Overview](./architecture.md) | Kernel subsystems, design principles, and data flow diagrams |
| [Silo System](./silo.md) | Process isolation, resource limits, pledge/unveil, module loading |
| [Memory Management](./memory-model.md) | Buddy allocator, slab heap, COW, page tables, vmalloc |
| [Boot Sequence](./boot-sequence.md) | BIOS → bootloader → UEFI bootloader → kernel init flow |
| [IPC Mechanisms](./ipc-mechanisms.md) | Channels, shared rings, semaphores, futexes |
| [IPC Transport Architecture](./architecture-ipc-access-levels.md) | 3-level hybrid IPC model (TypeSafe / LockFree / MMU) |
| [Driver Model](./driver-model.md) | Component trait, PCI, NIC, storage, USB drivers |
| [Syscall Reference](./syscalls.md) | Complete syscall table with parameters and errors |
| [ABI Overview](./abi.md) | Kernel/userspace ABI definitions and versioning |
| [ABI Changelog](./abi-changelog.md) | Recent ABI changes (auto-generated) |
| [ABI Support Matrix](./abi-matrix.md) | Syscall and struct compatibility matrix |
| [Syscall Layer](./syscall.md) | Userspace syscall wrappers and error handling |
| [Changelog](./changelog.md) | Project changelog (auto-generated from git) |
| [Publishing](./publishing.md) | Build, release, and deployment instructions |

---

## API reference by category

### Core

The kernel, ABI definitions, and bootloader : the foundation of the OS.

| Crate | Description | API |
|-------|-------------|-----|
| **strat9-kernel** | OS kernel: scheduler, memory management, drivers, IPC | [docs](./api/strat9_kernel/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/kernel) |
| **strat9-abi** | ABI definitions shared between kernel and userspace (syscalls, data structs, flags, errno) | [docs](./api/strat9_abi/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/abi) |
| **strat9-bootloader** | UEFI bootloader: scheduler, ELF loading, page tables, module handoff | [docs](./api/strat9_bootloader/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/bootloader) |

### Syscall & Userspace

Userspace libraries for interacting with the kernel.

| Crate | Description | API |
|-------|-------------|-----|
| **strat9-syscall** | High-level syscall wrappers, error mapping, and constants | [docs](./api/strat9_syscall/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/syscall) |
| **strate-init** | Init process: system bootstrap and service management | [docs](./api/strate_init/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-init) |
| **rendezlarjan** | Userspace synchronization primitives (thread rendezvous) | [docs](./api/rendezlarjan/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/rendezlarjan) |

### Component Framework

Trait-based component model for drivers and services.

| Crate | Description | API |
|-------|-------------|-----|
| **component** | Component trait and registration framework | [docs](./api/component/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/kernel/libs/component) |
| **component-macro** | Derive macros for component registration | [docs](./api/component_macro/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/kernel/libs/component-macro) |
| **strat9-bus-drivers** | Bus driver infrastructure (PCI, VirtIO) | [docs](./api/strat9_bus_drivers/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/drivers/bus) |
| **strate-bus** | Bus abstraction layer | [docs](./api/strate_bus/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-bus) |
| **strat9-components-api** | Shared component API types and traits | [docs](./api/strat9_components_api/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/api) |

### Network Drivers

Intel Ethernet and NIC queue management. These live under `workspace/drivers/nic/`, not `workspace/drivers/net/`.

| Crate | Description | API |
|-------|-------------|-----|
| **e1000** | Intel E1000/E1000e network driver | [docs](./api/e1000/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/drivers/nic/e1000) |
| **intel-ethernet** | Intel Ethernet common register definitions | [docs](./api/intel_ethernet/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/drivers/nic/intel-ethernet) |
| **driver-net-proto** | Network protocol driver abstractions | [docs](./api/driver_net_proto/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/drivers/nic/driver-net-proto) |
| **nic-queues** | NIC TX/RX queue management | [docs](./api/nic_queues/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/drivers/nic/nic-queues) |
| **nic-buffers** | NIC buffer allocation and management | [docs](./api/nic_buffers/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/drivers/nic/nic-buffers) |
| **net-core** | Network core utilities | [docs](./api/net_core/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/drivers/nic/net-core) |

### Filesystem

Filesystem abstraction and implementations.

| Crate | Description | API |
|-------|-------------|-----|
| **strate-fs-abstraction** | Filesystem abstraction layer with safe math and Unicode | [docs](./api/strate_fs_abstraction/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-fs-abstraction) |
| **strate-fs-ext4** | ext4 filesystem implementation | [docs](./api/strate_fs_ext4/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-fs-ext4) |
| **strate-fs-ramfs** | In-memory RAM filesystem | [docs](./api/strate_fs_ramfs/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-fs-ramfs) |

`strate-fs-xfs` lives in `workspace/components/strate-fs-xfs` but is **excluded from the Cargo workspace** (missing `strate-fs-abstraction` dependency), so no API page is generated for it.

### Networking

Network stack, silo network service, and tools. `strate-net-silo` is the *binary* target of the `strate-net` crate, not a separate crate.

| Crate | Description | API |
|-------|-------------|-----|
| **strate-net** | Network stack (TCP/UDP/ICMP) and the `strate-net-silo` binary | [docs](./api/strate_net/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-net) |
| **dhcp-client** | DHCP client status monitor | [docs](./api/dhcp_client/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/netutils/dhcp-client) |
| **ping** | ICMP ping utility | [docs](./api/ping/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/netutils/ping) |
| **udp-tool** | UDP scheme test utility | [docs](./api/udp_tool/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/netutils/udp-tool) |
| **telnetd** | Telnet server | [docs](./api/telnetd/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/netutils/telnetd) |
| **ice-candidate** | ICE candidate discovery over scheme UDP | [docs](./api/ice_candidate/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/netutils/ice-candidate) |

### Console, input & graphics

| Crate | Description | API |
|-------|-------------|-----|
| **strate-console** | Console rendering and display driver | [docs](./api/strate_console/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-console) |
| **strate-console-admin** | Interactive console shell with silo management (binary `console-admin`) | [docs](./api/strate_console_admin/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-console-admin) |
| **strate-input** | Keyboard and mouse input tasks | [docs](./api/strate_input/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-input) |
| **strate-graphical** | Graphical/compositor silo | [docs](./api/strate_graphical/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-graphical) |

### System Services

Admin interfaces, compatibility layers, and experimental features.

| Crate | Description | API |
|-------|-------------|-----|
| **strate-web-admin** | Web-based admin interface (binary `web-admin`) | [docs](./api/strate_web_admin/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-web-admin) |
| **strate-wasm** | WebAssembly runtime support | [docs](./api/strate_wasm/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-wasm) |
| **strate-webrtc** | WebRTC support | [docs](./api/strate_webrtc/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-webrtc) |
| **musl-compat** | musl libc syscall-dispatcher compatibility layer | [docs](./api/musl_compat/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/musl-compat) |
| **alloc-freelist** | Free-list allocator for userspace | [docs](./api/alloc_freelist/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/alloc-freelist) |

### Testing

Test binaries ship inside their parent crates; `test_syscalls`, `test_exec` and `test_pid` are `[[bin]]` targets of `silo-test`, and `test_mem` is a `[[bin]]` target of `mem-test`. They have no separate API pages.

| Crate | Binaries | API |
|-------|----------|-----|
| **silo-test** | `test_pid`, `test_syscalls`, `test_exec`, `test_exec_helper` | [docs](./api/silo_test/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-silo-test) |
| **mem-test** | `test_mem`, `test_mem_stressed`, `test_mem_region`, `test_mem_region_proc` | [docs](./api/mem_test/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-mem-test) |

---

## Building docs locally

```bash
# Build the full docs site (mdBook + rustdoc)
bash tools/scripts/build-docs-site.sh

# Serve locally
python3 -m http.server --directory build/docs-site 8000

# Check for broken links
python3 tools/scripts/check-links.py --site-dir build/docs-site
```
