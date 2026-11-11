# s9vm-guest — bare-metal guest validation kernel

Minimal guest kernel image (ELF64 x86-64, `no_std`) that boots under the s9vm
hypervisor of strat9-os and validates the boot hand-off a real operating system
receives: `S9VMBP` boot parameters, memory map, command line, initrd module and
ACPI tables, then brings up its own processor state (GDT, IDT, page tables),
takes one local APIC timer interrupt and drives the virtio console, block and
network devices.

This crate is **standalone**: it is not part of the host workspace, depends on
no crate at all (only `core`) and is linked at a fixed guest-physical address.

```
workspace/guest/s9vm-guest/
├── Cargo.toml            # standalone no_std crate (empty [workspace])
├── s9vm-guest.ld         # link script: fixed 0x100000 load address, _start
├── src/main.rs           # _start (global_asm!), guest_main, GDT/IDT/paging
├── src/guest_acpi.rs    # pure ACPI window parser (shared with host tests)
├── src/virtio.rs         # shared virtio-mmio v2 transport helpers
├── src/virtio_console.rs # virtio-console transmit driver
├── src/virtio_blk.rs     # virtio-block read driver
├── src/virtio_net.rs     # virtio-net transmit driver
└── README.md             # this document
```

## Boot contract

The policy (`SYS_VMM_LOAD_IMAGE` plus guest page tables it installs) loads the
image and enters it with the following guarantees:

| Element | Value |
|---|---|
| Load address | `0x0010_0000` (`PT_LOAD` `R E`, 4 KiB aligned) |
| ELF type | `ET_EXEC` (fixed-address image, no relocation at load time) |
| Entry point | symbol `_start`, at `0x0010_0000` |
| CPU mode | 64-bit long mode, paging enabled |
| `CR3` | `0` — identity mapping `0x0000_0000..0x0040_0000` (2 MiB PD leaves) installed by the policy |
| `RDI` | guest-physical address of the `S9VMBP` boot-parameter block |
| IDT | none at entry: the guest installs its own; interrupts are enabled only for the bounded timer-interrupt probe |
| ACPI RSDP | expected at guest-physical `0x000E_0000` |
| Initrd | module entry #1: GPA `0x0020_0000`, cpio `newc` archive (optional) |
| Direction flag | `_start` executes `cld` |

`_start` (assembled by `core::arch::global_asm!`) installs the stack
(`__s9vm_guest_stack_top`, 16 KiB in `.bss`, 16-byte aligned), executes `cld`,
then `call guest_main` with `RDI` unchanged. The image depends on nothing
outside itself: no allocator, no kernel symbol.

The policy-provided page tables are only used until the guest switches to its
own tables. Both map the same low 4 MiB identity window, so the switch is
transparent to the running code and its stack.

After the last success marker the guest loops on `hlt`: every `hlt` is a
"policy" exit that the policy completes.

### `S9VMBP` block map (little-endian, frozen)

Reference: `workspace/kernel/src/s9vm/bootparams.rs`.

| Offset | Size | Field |
|---|---|---|
| `0x000` | 8 | magic `S9VMBP\0\0` (`u64` = `0x0000_5042_4D56_3953`) |
| `0x008` | 4 | layout version (1) |
| `0x00C` | 4 | block size (1024) |
| `0x010` | 4 | boot flags |
| `0x014` | 4 | memory-map entry count (≤ 32) |
| `0x018` | 4 | module/initrd entry count (≤ 4) |
| `0x01C` | 4 | command-line length (≤ 256) |
| `0x020` | 8 | ACPI RSDP guest-physical address |
| `0x028` | 8 | console virtio-mmio base |
| `0x030` | 4 | console I/O APIC line |
| `0x034` | 1 | checksum byte (whole block sums to 0 modulo 256) |

The arrays follow: memory map at `0x038` with 32 **20-byte** packed entries
(`base: u64`, `len: u64`, `kind: u32`), modules at `0x2B8` with 4 **16-byte**
packed entries (`base: u64`, `len: u64`), command line at `0x2F8` with at most
256 bytes (length is authoritative, not NUL-terminated).

Module entry #0 is the page-table blob; module entry #1 is the initrd.

## Debug port `0xE9` protocol

The guest publishes one byte per `out dx, al` (`dx = 0xE9`). This port is not
part of the engine's in-kernel fast path: each write is a policy exit, and the
policy completes it with the reported instruction length.

| Byte(s) | Meaning |
|---|---|
| `G` (`0x47`) | boot-parameter magic `S9VMBP` validated |
| `M` (`0x4D`) | `memory_count > 0` |
| `A` (`0x41`) | RSDP found, `rsdp_gpa` coherent, ACPI 1.0 checksum valid |
| `R` (`0x52`) | initrd module present and starts with a cpio `newc` archive |
| `I` (`0x49`) | the initrd archive walks cleanly (headers, names, data, trailer) |
| `r` (`0x72`) | no initrd module (absent, malformed or not cpio) — non-fatal |
| `K` (`0x4B`) | command line parsed, private GDT, IDT and page tables active |
| `T` (`0x54`) | local APIC timer probe observed a count tick |
| `t` (`0x74`) + code | no coherent local APIC timer — non-fatal |
| `N` (`0x4E`) | initrd `init` entry extracted and queued for the console |
| `n` (`0x6E`) | no initrd `init` entry extracted — non-fatal |
| `S` (`0x53`) | ACPI RSDP -> XSDT/RSDT -> MADT walked and validated |
| `s` (`0x73`) + code | ACPI root table or MADT invalid — non-fatal |
| `C` (`0x43`) | virtio-console accepted and consumed the message |
| `c` (`0x63`) + code | no console, or it did not acknowledge — non-fatal |
| `D` (`0x44`) | virtio-block read sector 0 and the `S9VMDISK` label matches |
| `d` (`0x64`) + code | no block device, or the request/label failed — non-fatal |
| `V` (`0x56`) | local APIC timer interrupt delivered through the private IDT |
| `v` (`0x76`) + code | no timer interrupt observed — non-fatal |
| `X` (`0x58`) | virtio-net transmit queue consumed the Ethernet frame |
| `x` (`0x78`) + code | no network device, or the transmit failed — non-fatal |
| `E` (`0x45`) + vector | CPU exception caught by the private IDT; then halt |
| `F` (`0x46`) + code | failure; the code is the failing step (see below) |
| `P` (`0x50`) | Rust panic; the guest halts afterwards (no code) |

Success sequence: `G`, `M`, `A`, `R`/`r`, `I` (only after `R`), `K`, `T`/`t`,
`N`/`n` (initrd init), `S`/`s` (ACPI tables), `C`/`c` (console),
`D`/`d` (block), `V`/`v` (timer interrupt), `X`/`x` (virtio-net transmit),
then repeated `hlt`.
Failure sequence: `F`, code, then `hlt`.

Failure codes published after `F`:

| Code | Failing step |
|---|---|
| 1 | boot-block magic invalid (not `S9VMBP`) |
| 2 | `memory_count == 0` |
| 3 | `rsdp_gpa` is not `0x000E_0000` |
| 4 | `RSD PTR ` signature not found where the block advertises it |
| 5 | ACPI 1.0 checksum of the RSDP invalid |
| 6 | a fixed-capacity array does not fit its field (count/bounds) |
| 7 | command line out of bounds or not printable ASCII |
| 8 | a private page table is not page aligned |
| 9 | block header inconsistent (version, size or block checksum) |

Diagnostic codes published after a **non-fatal** marker (small binary values,
never an ASCII marker, so the marker stream stays unambiguous):

| Marker | Code | Meaning |
|---|---|---|
| `t` | 1 | local APIC version register absent or incoherent |
| `t` | 2 | the polling timer count never moved |
| `s` | 1..6 | ACPI walker error (`guest_acpi::AcpiError`) |
| `c` | 0 | console not advertised by the boot block |
| `c` | 1..4 | transport probe / feature / queue / `DRIVER_OK` step failed |
| `c` | 5 | message empty or larger than 128 bytes |
| `c` | 6 | the device never consumed the message (used ring unchanged) |
| `d` | 0 | block device not advertised by the boot block |
| `d` | 1 | transport does not report device id 2 |
| `d` | 2 | `VIRTIO_F_VERSION_1` not negotiated |
| `d` | 3 | request queue could not be programmed |
| `d` | 4 | device rejected `DRIVER_OK` |
| `d` | 5 | device never completed the request (used ring unchanged) |
| `d` | 6 | device reported a non-zero request status |
| `d` | 7 | sector 0 does not start with the `S9VMDISK` label |
| `v` | 1 | local APIC version register absent or incoherent |
| `v` | 3 | the in-request register block was not empty before `sti` |
| `v` | 4 | no timer interrupt was delivered (poll budget exhausted) |
| `x` | 0 | network device not advertised by the boot block |
| `x` | 1..4 | transport probe / feature / queue / `DRIVER_OK` step failed |
| `x` | 5 | the device never consumed the descriptor |
| `x` | 6 | the device reported an unexpected used length |

The policy logs each of these as
`[s9vm-vmm] guest failure marker=<marker> code=<n>`, which makes a hardware run
diagnosable without rebuilding the guest.

## What the guest validates

1. **magic and block header**: `u64` at `RDI + 0x000` equals `S9VMBP\0\0`, the
   version/size fields match the frozen layout and the byte checksum of the
   whole 1024-byte block is zero;
2. **memory map**: `u32` at `RDI + 0x014` is non-zero; the packed array bounds
   are checked (32 entries of 20 bytes, modules 4 × 16 bytes, command line
   ≤ 256 bytes, all inside the block), not only the counts;
3. **RSDP**: `u64` at `RDI + 0x020` equals `0x000E_0000`; the legacy window is
   scanned by 16-byte steps for the `RSD PTR ` signature and the first 20
   bytes must sum to `0 mod 256`;
4. **command line**: bounded by `cmdline_len` and validated as printable ASCII
   separated by spaces; the argument count is computed;
5. **private GDT**: three descriptors (null, flat 64-bit code `0x08`, flat data
   `0x10`), filled at boot in **`.bss`**, loaded with `lgdt` and a far return
   that reloads `CS`; `SS`, `DS`, `ES`, `FS` and `GS` are reloaded from the
   data selector. The GDT **must be writable**: loading a descriptor sets its
   *accessed* bit, which is a write to the descriptor entry — a read-only GDT
   makes `lretq`/`mov ss` fault (observed as an EPT violation on the
   descriptor address);
6. **private IDT**: 128 gates; vectors 0..31 have dedicated exception stubs and
   the rest share a spurious stub, except vector `0x20` which has a dedicated
   timer interrupt stub: it saves all 15 general-purpose registers, calls the
   Rust handler (which increments a `TIMER_TICKS` atomic and writes the local
   APIC EOI register), restores the registers and executes `iretq`. The
   exception stubs push their vector and call the common Rust handler, which
   publishes `E` + vector and halts. Interrupts are enabled only for the
   bounded timer-interrupt probe;
7. **private page tables**: 4-level tables in `.bss` (page-aligned), `PML4[0]`
   → `PDPT`, two 2 MiB identity leaves covering `0..4 MiB`, plus 2 MiB leaves
   for the device windows (`0xFEA0_0000` virtio-mmio, `0xFEC0_0000` I/O APIC,
   `0xFEE0_0000` local APIC); `CR3` is switched to them. The policy-provided
   tables are only used for the switch itself;
8. **initrd**: module entry #1 is dereferenced only inside the mapped identity
   window; a cpio `newc` archive walks cleanly (`070701` headers, NUL-terminated
   names, aligned data ranges, at least one entry and the `TRAILER!!!` record)
   and reports `R` then `I`; anything else reports the non-fatal `r`. The
   `init` entry is then **extracted** (bounded, revalidated) and its content is
   appended to the console message, which reports `N` (or non-fatal `n` when
   there is no such entry): this proves the guest reads the staged initrd, not
   just its framing;
9. **local APIC timer**: reads `APIC_ID`/`APIC_VERSION`, checks that the version
   register is coherent, software-enables the APIC, programs a masked one-shot
   count (divide by 1, initial count `2_000`) and polls the read-only
   current count until it moves; a tick reports `T`, an incoherent window
   reports `t`. No interrupt is enabled and no ISR is needed;
10. **virtio-console**: completes the modern virtio-mmio handshake (magic,
    version 2, device id 3, `VIRTIO_F_VERSION_1`, status machine), programs the
    transmit split queue in `.bss`, publishes the greeting through one
    device-readable descriptor, notifies the queue and polls the used ring
    (no interrupt requested). Success reports `C`, any absent/uncooperative
    device reports the non-fatal `c`;
11. **virtio-block**: same transport handshake for device id 2, programs the
    request queue and submits the three-descriptor virtio-block request chain
    (16-byte `IN` header for sector 0, 512-byte device-writable data buffer,
    status byte), then checks the completion status and the `S9VMDISK` label
    the userspace policy provisions with `SYS_VMM_LOAD_DISK`. Success reports
    `D`, a missing/failed device reports the non-fatal `d`;
12. **ACPI discovery**: walks `RSDP -> XSDT (or RSDT) -> tables`, validating
    every table header (signature, declared length inside the mapped firmware
    window, byte checksum) before dereferencing it, and summarises the result
    (`acpi: XSDT <n> tables madt=<0/1> facp=<0/1>`) in the console stream.
    Success reports `S` when the root table and the MADT are valid, otherwise
    the non-fatal `s`;
13. **timer interrupt**: checks the APIC version and that no foreign vector is
    pending, software-enables the APIC, programs the LVT timer as an unmasked
    one-shot with vector `0x20` (divide by 1, initial count 1), executes `sti`
    and polls the read-only current count: each read is one replayed device
    exit that advances the timer model, the expiry raises the vector and the
    kernel injects it because `IF = 1`. The assembly stub runs the Rust handler
    (tick counter + EOI) and `iretq`s back; `cli` closes the probe. Success
    reports `V`, an absent APIC or a foreign/silent timer the non-fatal `v`;
14. **virtio-net transmit**: same transport handshake for device id 1,
    negotiates `VIRTIO_F_VERSION_1` plus `VIRTIO_NET_F_MAC` when offered
    (configuration-space MAC used as the frame destination), programs the
    transmit queue in `.bss`, publishes one device-readable descriptor holding
    the 10-byte zeroed `virtio_net_hdr` plus a 60-byte Ethernet frame,
    requests no interrupt, notifies and polls the used ring, then checks the
    used length. Success reports `X`, a missing/failed device the non-fatal
    `x`.

The engine models the local APIC and virtio device pages as device pages: the
second-level translation intentionally leaves them unmapped, so an access
raises a violation that the kernel device model replays. The guest therefore
maps those windows in its own page tables and drives them through normal MMIO;
if a window is not coherently modeled (for example, backed by plain RAM by a
different policy) it takes the non-fatal `t`/`c`/`d`/`v`/`x`/`s` path without
faulting.

## Build

Toolchain: the repository-pinned nightly with the `x86_64-unknown-none` target.

From the repository root:

```powershell
$env:PATH = "C:\Program Files\NASM;" + $env:PATH
cargo make s9vm-guest-release
```

or directly, from `workspace/guest/s9vm-guest` (the crate's
`.cargo/config.toml` already carries the link flags):

```powershell
cargo build --release --target x86_64-unknown-none --target-dir ../../../target
```

The produced ELF is `target/x86_64-unknown-none/release/s9vm-guest`.

The link options are mandatory:

- `-C relocation-model=static` and `-C link-arg=-no-pie` force an `ET_EXEC`
  (otherwise the target emits `ET_DYN` with `DYNAMIC`/`.dynsym`);
- `-C link-arg=-Ts9vm-guest.ld` sets the `0x100000` load address and `_start`;
- `-C link-arg=--build-id=none` avoids a useless `.note.gnu.build-id` section.

They live in the crate's `.cargo/config.toml` (not in a cargo-make task
`env`): a task-level `RUSTFLAGS` would leak into sibling builds.

## Expected ELF properties

```console
$ readelf -h target/x86_64-unknown-none/release/s9vm-guest
  Type:                              EXEC (Executable file)
  Entry point address:               0x100000

$ readelf -lW target/x86_64-unknown-none/release/s9vm-guest
  LOAD  0x001000 0x0000000000100000 0x0000000000100000 0x0026e5 0x0026e5 R E 0x1000
  LOAD  0x004000 0x0000000000103000 0x0000000000103000 0x00010a 0x00010a R   0x1000
  LOAD  0x005000 0x0000000000104000 0x0000000000104000 0x000010 0x000010 RW  0x1000
  LOAD  0x006000 0x0000000000105000 0x0000000000105000 0x000000 0x008dd0 RW  0x1000
```

Expectations:

- `e_type == ET_EXEC` (2), `e_machine == EM_X86_64`;
- `e_entry` inside `0x0010_0000..0x0011_0000` (currently exactly `0x100000`);
- four `PT_LOAD` segments: `.text` `R E` at `0x100000` (three pages: entry, GDT
  loader, exception/timer stubs and the kernel code), `.rodata` `R` (exception
  stub table) at `0x103000`, a small `.data` `RW` page (GDT) at `0x104000` and
  `.bss` `RW` at `0x105000` (36 KiB: 16 KiB stack, four 4 KiB page tables, the
  2 KiB IDT and the virtio-console/block/network queue buffers); the whole
  loaded footprint is 14 pages (`0x100000..0x10E000`), inside the 4 MiB
  identity window;
- **no page overlap between segments** and `p_vaddr % 4096 == p_offset % 4096`
  for every `PT_LOAD`: the kernel guest loader rejects both violations;
- no `DYNAMIC`/`INTERP` entry (fully self-contained image);
- file size around 28 KiB (symbol table included), loaded memory footprint
  56 KiB.

`_start` is the first byte of the executable segment and `guest_main` follows
in the same page. The code is position-independent inside the image: `_start`
computes its stack RIP-relative and `guest_main` only uses `RDI`, RIP-relative
addresses and the physical addresses of the boot contract.

## Integration (outside this crate)

The policy stages the ELF as `/initfs/s9vm-guest`, reads it, loads it with
`SYS_VMM_LOAD_IMAGE` at `0x0010_0000`, installs the identity page tables
(`CR3 = 0`), publishes the `S9VMBP` block (with the initrd module and the ACPI
RSDP) and enters the vCPU with `RDI` = block GPA. On the serial console the
policy is expected to report `G`, `M`, `A`, `R`/`r`, `K`, `T`/`t`, `N`/`n`,
`S`/`s`, `C`/`c`, `D`/`d`, `V`/`v`, `X`/`x` and the `hlt` exits.

## Limits

- one bounded, one-shot local APIC timer interrupt is exercised; there is no
  periodic timer, no device IRQ handling and interrupts are disabled again
  right after the probe;
- the virtio drivers poll their rings (no interrupt is requested), which is why
  no device ISR is needed;
- no allocator and a single static 16 KiB stack;
- the guest page tables only map the low 4 MiB plus the virtio-mmio, I/O APIC
  and local APIC device windows; every other access faults into the `E`
  handler;
- no return path: `guest_main` ends in a `hlt` loop (the panic handler publishes
  `P` before halting).







