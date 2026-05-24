# Hardware Support

> Last updated: 2026-05-19

## Tested platforms

Strat9-OS boots and runs successfully on:

| Platform | Type | Notes |
|---|---|---|
| **QEMU** | Emulator | Primary dev target, all features validated |
| **VMware Workstation** | Hypervisor | Production-like virtualisation |
| **Lenovo ThinkPad X13** | Laptop (x86_64) | Real hardware validation |

---

## Kernel-resident drivers (Ring 0)

These drivers are compiled into the kernel and have direct hardware access via MMIO/PCI.

### PCI / Bus

| Driver | File | Status | Notes |
|---|---|---|---|
| PCI enumeration | `kernel/src/arch/x86_64/pci/` | ✅ Active | Class/probe, BAR mapping, bus master, MSI |
| PCI client API | `kernel/src/hardware/pci_client.rs` | ✅ Active | Wraps raw PCI for kernel drivers |

### Network (kernel-resident NIC adapters)

| Driver | Hardware | File | Status |
|---|---|---|---|
| e1000 | Intel PRO/1000 (82540EM, 82545EM) | `kernel/src/hardware/nic/e1000_drv.rs` | ✅ Active |
| e1000e | Intel 82574L, I217, I219 | `kernel/src/hardware/nic/e1000e_drv.rs` | ✅ Active |
| igc | Intel I225, I226 (2.5 GbE) | `kernel/src/hardware/nic/igc_drv.rs` | ✅ Active |
| pcnet | AMD AM79C970/972 (PCnet-PCI II) | `kernel/src/hardware/nic/pcnet_drv.rs` | ✅ Active |
| rtl8139 | Realtek RTL8139 | `kernel/src/hardware/nic/rtl8139_drv.rs` | ✅ Active |
| virtio-net | VirtIO Network Device | `kernel/src/hardware/nic/virtio_net.rs` | ✅ Active |
| Net scheme | `/dev/net/` VFS | `kernel/src/hardware/nic/scheme.rs` | ✅ Active |

### Storage

| Driver | Hardware | File | Status |
|---|---|---|---|
| AHCI | SATA AHCI controller | `kernel/src/hardware/storage/ahci.rs` | ✅ Active (wired) |
| NVMe | NVM Express | `kernel/src/hardware/storage/nvme.rs` | ✅ Active (wired) |
| ATA legacy | PIO/IDE (primary/secondary) | `kernel/src/hardware/storage/ata_legacy.rs` | ✅ Active (wired) |
| VirtIO block | VirtIO Block Device | `kernel/src/hardware/storage/virtio_block.rs` | ✅ Active (wired) |

### USB

| Driver | Hardware | File | Status |
|---|---|---|---|
| xHCI | USB 3.0 | `kernel/src/hardware/usb/xhci.rs` | ✅ Active |
| EHCI | USB 2.0 | `kernel/src/hardware/usb/ehci.rs` | ✅ Active |
| UHCI | USB 1.1 | `kernel/src/hardware/usb/uhci.rs` | ✅ Active |
| HID | Keyboard, mouse | `kernel/src/hardware/usb/hid.rs` | ✅ Active |

### Timers

| Driver | Hardware | File | Status |
|---|---|---|---|
| HPET | High Precision Event Timer | `kernel/src/hardware/timer/hpet.rs` | ✅ Active |
| RTC | Real-Time Clock (CMOS) | `kernel/src/hardware/timer/rtc.rs` | ✅ Active |

### Video / Display

| Driver | Hardware | File | Status |
|---|---|---|---|
| Framebuffer | Limine boot protocol | `kernel/src/hardware/video/framebuffer.rs` | ✅ Active |
| VirtIO GPU | VirtIO GPU Device | `kernel/src/hardware/virtio/gpu.rs` | ✅ Active |

### VirtIO core

| Driver | File | Status |
|---|---|---|
| VirtIO common (queues, MMIO) | `kernel/src/hardware/virtio/common.rs` | ✅ Active |
| VirtIO console | `kernel/src/hardware/virtio/console.rs` | ⚪ Compiled, not initialised |
| VirtIO RNG | `kernel/src/hardware/virtio/rng.rs` | ⚪ Compiled, not initialised |

---

## Silo-hosted drivers (Ring 3)

These drivers live in isolated userspace components (Silos) and access hardware indirectly via IPC.

### Bus controllers (ARM SoC / embedded)

All bus drivers are in `workspace/drivers/bus/`. They are probed at silo startup : only those matching the platform hardware will init successfully.

| Driver | Compatible strings | File | Lines | Status |
|---|---|---|---|---|
| **simple-pm-bus** | `simple-bus`, `simple-pm-bus`, `simple-mfd`, `isa`, `arm,amba-bus` | `simple_pm_bus.rs` | 98 | ✅ Always active |
| **vexpress-config** | `vexpress-syscfg` | `vexpress_config.rs` | 225 | ✅ Always active |
| **arm-cci** | `arm,cci-400`, `arm,cci-500`, `arm,cci-550` | `arm_cci.rs` | 178 | ⚪ ARM only |
| **arm-integrator-lm** | `arm,integrator-ap-lm` | `arm_integrator_lm.rs` | 105 | ⚪ ARM only |
| **brcmstb-gisb** | `brcm,bcm7038-gisb-arb`, `brcm,bcm7278-gisb-arb`, `brcm,bcm7400-gisb-arb`, `brcm,bcm74165-gisb-arb`, `brcm,bcm7435-gisb-arb`, `brcm,bcm7445-gisb-arb` | `brcmstb_gisb.rs` | 278 | ⚪ Broadcom STB only |
| **bt1-apb** | `baikal,bt1-apb` | `bt1_apb.rs` | 159 | ⚪ Baikal-T1 only |
| **bt1-axi** | `baikal,bt1-axi` | `bt1_axi.rs` | 131 | ⚪ Baikal-T1 only |
| **da8xx-mstpri** | `ti,da850-mstpri` | `da8xx_mstpri.rs` | 175 | ⚪ TI DA850 only |
| **hisi-lpc** | `hisilicon,hip06-lpc`, `hisilicon,hip07-lpc` | `hisi_lpc.rs` | 194 | ⚪ HiSilicon only |
| **imx-aipstz** | `fsl,imx8mp-aipstz` | `imx_aipstz.rs` | 99 | ⚪ NXP i.MX only |
| **imx-weim** | `fsl,imx1-weim`, `fsl,imx27-weim`, `fsl,imx50-weim`, `fsl,imx51-weim`, `fsl,imx6q-weim` | `imx_weim.rs` | 187 | ⚪ NXP i.MX only |
| **intel-ixp4xx-eb** | `intel,ixp42x-expansion-bus-controller`, `intel,ixp43x-*`, `intel,ixp45x-*`, `intel,ixp46x-*` | `intel_ixp4xx_eb.rs` | 196 | ⚪ Intel IXP4xx only |
| **mips-cdmm** | `mti,mips-cdmm` | `mips_cdmm.rs` | 169 | ⚪ MIPS only |
| **moxtet** | `cznic,moxtet` | `moxtet.rs` | 175 | 🟡 Needs SPI backend |
| **mvebu-mbus** | `marvell,armada370-mbus`, `marvell,armada380-mbus`, `marvell,armadaxp-mbus`, `marvell,dove-mbus`, `marvell,kirkwood-mbus`, `marvell,orion5x-88f5281-mbus` (+3) | `mvebu_mbus.rs` | 260 | ⚪ Marvell MVEBU only |
| **omap-l3-noc** | `ti,omap4-l3-noc`, `ti,omap5-l3-noc`, `ti,dra7-l3-noc`, `ti,am4372-l3-noc` | `omap_l3_noc.rs` | 237 | ⚪ TI OMAP only |
| **omap-l3-smx** | `ti,omap3-l3-smx` | `omap_l3_smx.rs` | 189 | ⚪ TI OMAP3 only |
| **omap-ocp2scp** | `ti,omap-ocp2scp`, `ti,am437x-ocp2scp` | `omap_ocp2scp.rs` | 96 | ⚪ TI OMAP only |
| **qcom-ebi2** | `qcom,msm8660-ebi2`, `qcom,apq8060-ebi2` | `qcom_ebi2.rs` | 187 | ⚪ Qualcomm only |
| **qcom-ssc-block-bus** | `qcom,ssc-block-bus` | `qcom_ssc_block_bus.rs` | 136 | ⚪ Qualcomm only |
| **stm32-etzpc** | `st,stm32-etzpc` | `stm32_etzpc.rs` | 144 | ⚪ STM32 only |
| **stm32-rifsc** | `st,stm32mp25-rifsc`, `st,stm32mp21-rifsc` | `stm32_rifsc.rs` | 225 | ⚪ STM32 only |
| **sun50i-de2** | `allwinner,sun50i-a64-de2` | `sun50i_de2.rs` | 88 | ⚪ Allwinner only |
| **sunxi-rsb** | `allwinner,sun8i-a23-rsb` | `sunxi_rsb.rs` | 260 | ⚪ Allwinner only |
| **tegra-aconnect** | `nvidia,tegra210-aconnect` | `tegra_aconnect.rs` | 106 | ⚪ NVIDIA Tegra only |
| **tegra-gmi** | `nvidia,tegra20-gmi`, `nvidia,tegra30-gmi` | `tegra_gmi.rs` | 199 | ⚪ NVIDIA Tegra only |
| **ti-pwmss** | `ti,am33xx-pwmss` | `ti_pwmss.rs` | 73 | ⚪ TI AM33xx only |
| **ti-sysc** | `ti,sysc-omap2`, `ti,sysc-omap4`, `ti,sysc-omap4-timer`, `ti,sysc-omap4-simple`, `ti,sysc-omap2-timer`, `ti,sysc-omap3430-sr`, `ti,sysc-omap3630-sr`, `ti,sysc-omap4-sr`, `ti,sysc-omap3-sham`, `ti,sysc-omap-aes`, `ti,sysc-mcasp`, `ti,sysc-dra7-mcasp`, `ti,sysc-usb-host-fs`, `ti,sysc-dra7-mcan`, `ti,sysc-pruss` | `ti_sysc.rs` | 288 | ⚪ TI OMAP/DRA7 only |
| **ts-nbus** | `technologic,ts-nbus` | `ts_nbus.rs` | 274 | 🟡 Needs GPIO backend |
| **uniphier-system-bus** | `socionext,uniphier-system-bus` | `uniphier_system_bus.rs` | 162 | ⚪ Socionext UniPhier only |

### Network stack (silo-hosted)

| Component | File | Status |
|---|---|---|
| TCP/IP stack (smoltcp) | `components/strate-net/src/` | ✅ Active |
| DHCP client | `components/netutils/dhcp-client/` | ✅ Active |
| Telnet server | `components/netutils/telnetd/` | ✅ Active |

### Shared NIC libraries (linked into kernel)

| Crate | Path | Purpose |
|---|---|---|
| `net-core` | `drivers/nic/net-core/` | `NetworkDevice` trait, `NetError` |
| `nic-buffers` | `drivers/nic/nic-buffers/` | `DmaAllocator`, `DmaRegion` |
| `nic-queues` | `drivers/nic/nic-queues/` | `RxRing`, `TxRing` abstractions |
| `intel-ethernet` | `drivers/nic/intel-ethernet/` | Register offsets, descriptor types |
| `e1000` | `drivers/nic/e1000/` | E1000/E1000e/I210 hardware init |
| `driver-net-proto` | `drivers/nic/driver-net-proto/` | IPC opcodes (future silo driver use) |

---

## Legend

| Icon | Meaning |
|---|---|
| ✅ Active | Fully wired and functional |
| ⚪ Platform-specific | Compiles but only activates on matching hardware |
| 🟡 Needs work | Partially implemented, requires backend or fix |

---

## Future hardware targets

These are platforms and devices we plan to support:

### Short-term (next milestones)

| Target | Type | Motivation |
|---|---|---|
| **Realtek RTL8168/RTL8111** | NIC | Common on desktop motherboards |
| **Intel I350** | NIC (server) | Datacenter-grade, SR-IOV capable |
| **Bochs VBE / VGA** | Display | Fallback for headless / legacy |
| **AHCI hotplug** | Storage | SATA hot-swap support |
| **USB mass storage** | Storage | USB key / external HDD |

### Medium-term

| Target | Type | Notes |
|---|---|---|
| **ARM64 (QEMU virt)** | Architecture | Port kernel to aarch64 |
| **RISC-V (QEMU virt)** | Architecture | Port kernel to riscv64 |
| **ACPI PCI hotplug** | Bus | Physical PCIe hot-add/remove |
| **Intel IGD / GOP** | Display | Intel integrated graphics |
| **NVMe IO queues** | Storage | Multiple queues for throughput |
| **ARM PL011 UART** | Serial | ARM serial console |
| **DeviceTree (FDT)** | Boot | Match drivers to hardware on ARM |

### Long-term

| Target | Type | Notes |
|---|---|---|
| **Real hardware: RPi 4/5** | ARM board | AArch64 userspace |
| **Real hardware: PinePhone** | ARM phone | Mobile form factor |
| **NVMe fabric** | Storage | RDMA-based NVMe over network |
| **VirtIO-fs** | Storage | Shared filesystem with host |
| **Intel AX210 (WiFi 6E)** | Wireless | Native WiFi |
| **USB 3.0 xHCI (real HW)** | USB | Physical USB controller validation |
