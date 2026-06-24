# Strat9 OS

An experimental operating system kernel written in Rust, targeting x86_64 (primary) and aarch64 (secondary).

---

## Quick start

<div class="api-card">

**Building from source**

```bash
# Build the full OS image (bootloader + kernel)
cargo make build-all

# Run in QEMU
cargo make run-gui

# Run with SMP (multi-core)
cargo make run-gui-smp
```

[Build guide](./publishing.md) · [Source repository](https://git.strat9-os.org/strat9-os/strat9-os)

</div>

---

## Architecture guides

| Guide | Description |
|-------|-------------|
| [Architecture Overview](./architecture.md) | Kernel subsystems, design principles, and data flow diagrams |
| [Silo System](./silo.md) | Process isolation, resource limits, pledge/unveil, module loading |
| [Memory Management](./memory-model.md) | Buddy allocator, slab heap, COW, page tables, vmalloc |
| [Boot Sequence](./boot-sequence.md) | BIOS → bootloader → Limine → kernel init flow |
| [IPC Mechanisms](./ipc-mechanisms.md) | Channels, shared rings, semaphores, futexes |
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
| **strat9-bootloader** | BIOS/UEFI bootloader: stage1 MBR, stage2 protected/long mode switch | [docs](./api/bootloader/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/bootloader) |

### Syscall & Userspace

Userspace libraries for interacting with the kernel.

| Crate | Description | API |
|-------|-------------|-----|
| **strat9-syscall** | High-level syscall wrappers, error mapping, and constants | [docs](./api/strat9_syscall/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/syscall) |
| **strate-init** | Init process: system bootstrap and service management | [docs](./api/strate_init/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-init) |

### Component Framework

Trait-based component model for drivers and services.

| Crate | Description | API |
|-------|-------------|-----|
| **component** | Component trait and registration framework | [docs](./api/component/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/component) |
| **component-macro** | Derive macros for component registration | [docs](./api/component_macro/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/component-macro) |
| **strat9-bus-drivers** | Bus driver infrastructure (PCI, VirtIO) | [docs](./api/strat9_bus_drivers/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/bus-drivers) |
| **strate-bus** | Bus abstraction layer | [docs](./api/strate_bus/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-bus) |

### Network Drivers

Intel Ethernet and NIC queue management.

| Crate | Description | API |
|-------|-------------|-----|
| **e1000** | Intel E1000/E1000e network driver | [docs](./api/e1000/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/drivers/net/e1000) |
| **intel-ethernet** | Intel Ethernet common register definitions | [docs](./api/intel_ethernet/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/drivers/net/intel-ethernet) |
| **driver-net-proto** | Network protocol driver abstractions | [docs](./api/driver_net_proto/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/drivers/net/proto) |
| **nic-queues** | NIC TX/RX queue management | [docs](./api/nic_queues/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/drivers/net/nic-queues) |
| **nic-buffers** | NIC buffer allocation and management | [docs](./api/nic_buffers/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/drivers/net/nic-buffers) |
| **net-core** | Network core utilities | [docs](./api/net_core/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/drivers/net/core) |

### Filesystem

Filesystem abstraction and implementations.

| Crate | Description | API |
|-------|-------------|-----|
| **strate-fs-abstraction** | Filesystem abstraction layer with safe math and Unicode | [docs](./api/strate_fs_abstraction/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-fs-abstraction) |
| **strate-fs-ext4** | ext4 filesystem implementation | [docs](./api/fs_ext4/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-fs-ext4) |
| **strate-fs-ramfs** | In-memory RAM filesystem | [docs](./api/strate_fs_ramfs/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-fs-ramfs) |

### Networking

Network stack, silo network service, and tools.

| Crate | Description | API |
|-------|-------------|-----|
| **strate-net** | Network stack (TCP/UDP/ICMP) | [docs](./api/strate_net/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-net) |
| **strate-net-silo** | Network silo service (TCP/UDP listener) | [docs](./api/strate_net_silo/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-net) |
| **dhcp-client** | DHCP client status monitor | [docs](./api/dhcp_client/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/netutils/dhcp-client) |
| **ping** | ICMP ping utility | [docs](./api/ping/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/netutils/ping) |
| **udp-tool** | UDP scheme test utility | [docs](./api/udp_tool/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/netutils/udp-tool) |
| **telnetd** | Telnet server | [docs](./api/telnetd/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/netutils/telnetd) |
| **ice-candidate** | ICE candidate discovery over scheme UDP | [docs](./api/ice_candidate/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/netutils/ice-candidate) |

### System Services

Admin interfaces, compatibility layers, and experimental features.

| Crate | Description | API |
|-------|-------------|-----|
| **strat9-components-api** | Shared component API types and traits | [docs](./api/strat9_components_api/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/api) |
| **strate-console-admin** | Interactive console shell with silo management | [docs](./api/console_admin/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-console-admin) |
| **strate-web-admin** | Web-based admin interface | [docs](./api/web_admin/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-web-admin) |
| **strate-wasm** | WebAssembly runtime support | [docs](./api/strate_wasm/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-wasm) |
| **strate-webrtc** | WebRTC support | [docs](./api/strate_webrtc/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-webrtc) |
| **musl-compat** | musl libc compatibility layer | [docs](./api/musl_compat/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/musl-compat) |
| **alloc-freelist** | Free-list allocator | [docs](./api/alloc_freelist/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/alloc-freelist) |

### Testing

| Crate | Description | API |
|-------|-------------|-----|
| **silo-test** | Silo integration tests | [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-silo-test) |
| **mem-test** | Memory subsystem tests | [docs](./api/test_mem/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-mem-test) |
| **test-syscalls** | Syscall integration tests | [docs](./api/test_syscalls/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-mem-test) |
| **test-exec** | Exec syscall tests | [docs](./api/test_exec/index.html) · [source](https://git.strat9-os.org/strat9-os/strat9-os/tree/main/workspace/components/strate-mem-test) |

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
