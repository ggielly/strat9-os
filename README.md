# Strat9-OS

Strat9-OS is an Operating System based on a modular microkernel written in Rust. The kernel provides scheduling, IPC, memory primitives, and interrupt routing. Everything else (filesystems, networking, drivers...) runs as isolated userspace components called Silos, also written in Rust.

The goal is to run various native binaries (ELF, JS, WASM..) inside the silo environment => IPC => kernel. And give features to silos like network stack, filesystem, etc. with Strates.

The Chevron shell can manage silos and strates with a bunch of commands.

Architecture concept summary: Bedrock is the microkernel, Silos are isolated Ring-3 execution units, Strates are functional layers hosted inside Silos and they can discuss together. Silos are isolated eachother.

## Architecture

- Kernel (Bedrock) in Ring 0 : minimal, `#![no_std]`.
- Silos are in Ring 3 : isolated components communicate via IPC.
- **IPC Transport Manager** : 3-level hybrid isolation model (TypeSafe / LockFree / MMU)
- Strate are in Silo : network stack, filesystem, etc.
- Capabilities gate access to resources.
- Plan 9 style scheme model for resources.

## Status, some highlights

This project is in active development and not production-ready. The ABI is still not stabilized. The documentation can be built and published using the `publish-doc.sh` script.

### Screenshots from QEMU : bootsequence and Chevron shell

![Graphics test](doc/boot_welcome.png)
*Chevron and boot*

![Top - process monitor](doc/top.png)
*2D framebuffered process monitor like (top command)*

![ls and uptime](doc/ls_uptime.png)
*ls and uptime*

![Networking](doc/network.png)
*Networking*

![Strate](doc/strate.png)
*strate screen management*

![Memory and CPU info](doc/mem_cpu.jpg)
*Memory and CPU information*

![Graphics test](doc/gfx-test.jpg)
*Graphics subsystem test*

#### Kernel

    - SMP boot with per-CPU data, TSS/GDT, GSBase-based SYSCALL, per-CPU caches and per-CPU scheduler
    - Two-stage allocator: buddy allocator for early boot and a dedicated kernel allocator (CoW support, heap/kmalloc/slab)
    - Virtual memory: 4-level paging, HHDM, CR3 switching, page-fault handling (COW, mmap), user/kernel mappings
    - Preemptive multitasking with APIC/x2APIC and per-CPU timers
    - Limine boot path and bootable ISO
    - Scheduler with priority/round-robin and CPU hotplug support
    - IPC: 3-level transport manager (TypeSafe / LockFree ring / MMU), synchronous ports, capability manager, VFS scheme router
    - ELF loader and Ring-3 execution (userspace silos)
    - POSIX interval timers and signal infrastructure
    - Interrupts & exceptions: IDT, IRQ handling, exception dumps and backtraces
    - Device model: PCI discovery, VirtIO and legacy drivers (block, net), console drivers
    - Debugging & tooling: early serial/VGA output, configurable log levels, QEMU run targets and ISO tooling
    - ACPI support and power management
    - Optional Linux ABI compatibility shim for ELF binaries

#### Userspace components

    - EXT4 filesystem
    - RamFS filesystem
    - XFS filesystem (WiP and disabled) 
    - VirtIO block and net drivers (kernel-side)
    - libc (musl : statically linked, Linux ABI compatibility)
    - IPv4 network stack with UDP/TCP/ICMP support, dhcp client, telnet server
    - e1000/e1000e and virtio NIC drivers
    - WASM native execution strate
    - CLI for managing silo and strate : memory management, start, stop, delete...
    - Basic commands : cat, ls, uptime, reboot, shutdown, cd, top
    - VFS with /proc /sys ...

```mermaid
graph TD
    subgraph Ring 3 [Userspace / Silos]
        direction TB
        App[Application]:::app
        Drivers[Drivers & Services]:::sys

        subgraph Silo_JS [JIT JS Silo]
            JS_Runtime[JIT JS Runtime]:::app
        end

        subgraph Silo_Native [Native Silo]
            ELF[ELF Binary]:::app
        end
    end

    subgraph Ring 0 [Kernel / Bedrock]
        Kernel[Bedrock Kernel]:::kernel
        Sched[Scheduler]:::kernel
        IPC_MGR[IPC Transport Manager]:::kernel
        N1[N1 TypeSafe]:::kernel
        N2[N2 LockFree Ring]:::transport
        N3[N3 MMU Migration]:::transport
        MM[Memory Manager]:::kernel
        NIC[NIC Driver]:::kernel

        Kernel --- Sched
        Kernel --- IPC_MGR
        IPC_MGR --> N1
        IPC_MGR --> N2
        IPC_MGR --> N3
        Kernel --- MM
        Kernel --- NIC
    end

    JS_Runtime -.->|N2 Ring| Net[Net Stack]:::sys
    JS_Runtime -.->|N2 Ring| FS[Filesystem]:::sys
    ELF -.->|N1 or N2| Console[Console Driver]:::sys
    Net -.->|N2 Ring| NIC
    NIC -.->|N2 Ring| Net

    classDef kernel fill:#f96,stroke:#333,stroke-width:2px;
    classDef transport fill:#fc9,stroke:#333,stroke-width:2px;
    classDef sys fill:#8cf,stroke:#333,stroke-width:1px;
    classDef app fill:#8f9,stroke:#333,stroke-width:1px;
```

## Build

### Prerequisites

- Rust nightly with `rust-src` and `llvm-tools-preview`.
  The version is **pinned** in [`rust-toolchain.toml`](rust-toolchain.toml)
  (currently `nightly-2026-07-20`) : newer nightlies break the kernel build
  (the `x86_64` crate no longer compiles against the `Step` trait, and LLVM
  rejects this target's `sse` feature toggling). `cargo` picks the pinned
  toolchain up automatically through rustup; do not replace the pin with
  the floating `nightly` channel.
- QEMU.

### Commands

#### Install the Rust toolchain

```bash
# Installs exactly the pinned version from rust-toolchain.toml:
rustup toolchain install
cargo --version   # run once inside the repo so rustup activates it
```

To upgrade the pin, bump the date in `rust-toolchain.toml`, then verify the
whole workspace still builds before committing:

```bash
cargo +<new-date> check -p strat9-kernel --target x86_64-unknown-none
cargo +<new-date> check -p strat9-bus-drivers --target x86_64-unknown-none
```

#### Compile the kernel and run it

```bash
cargo make kernel
cargo make limine-image
cargo make run-gui-smp or cargo make run-gui (for single CPU test)
```

or

```bash
cargo make
```

## Hardware support

See [HARDWARE.md](HARDWARE.md) for a complete list of supported drivers, tested platforms, and future hardware targets.

### Currently booting on

- QEMU
- VMware Workstation
- Lenovo ThinkPad X13

## Repository way of life

- `workspace/kernel/` : the strat9-os kernel : Bedrock
- `workspace/components/` : userspace components
- `workspace/bootloader/` : custom multi-stage BIOS bootloader (legacy, kept for reference). The active boot path is the external [Limine](https://github.com/limine-bootloader/limine) bootloader, configured by `limine.conf`
- `doc/` : specifications and design docs
- `tools/` : build and helper scripts

### Related specifications

TODO...

## License

All the code is under GPLv3. See THIRD_PARTY_LICENCES.txt for more informations about librairies and software shared. Many thanks to the authors !
