/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Intel Wi-Fi 6 AX201 (CNVi, 802.11ax 2x2) kernel glue.
//!
//! Probes PCI for the QuZ family (`8086:02f0`, `06f0`, `34f0`, `3df0`,
//! `4df0`, `43f0`, `a0f0`), maps BAR0, loads `/initfs/wifi.toml`, then brings
//! the controller up through `iwlwifi-ax201`:
//!
//! 1. PCI bus-master + memory space, identity-mapped MMIO.
//! 2. `apm_init` (MAC clock, DMA), RFH/TFH queue allocation.
//! 3. TLV firmware parse and context-info self-load from
//!    `/initfs/iwlwifi-QuZ-a0-hr-b0-77.ucode`.
//! 4. Wait for `UCODE_ALIVE_NTFY`, then start the station MLME.
//!
//! The firmware blob is not distributed with the repository (Intel licence).
//! Place it in `workspace/assets/firmware/` before building the image; the
//! image script copies it into `/boot/initfs` when present.  Without it the
//! driver logs a warning and leaves the interface unregistered.
//!
//! **Hardware status:** transport, firmware self-load, RX, command and TX
//! data paths are implemented and the interface is registered as `wlan0`.
//! `link_up()` only becomes true after the WPA2 handshake, and all crypto is
//! software CCMP.  The remaining validation work is tracked in the driver
//! README (command sizes, RX descriptor length, regulatory/NVM).

use core::ptr;

use alloc::sync::Arc;

use net_core::{NetError, NetMedia, NetworkDevice};

use iwlwifi_ax201::{
    config::{self, WifiConfig},
    device::WifiDevice,
    regs,
    transport::{Bus, IwlTransport},
};
use nic_buffers::{DmaAllocator, DmaRegion};

use crate::{
    arch::xshim::VirtAddr,
    hardware::{
        nic::common::KernelDma,
        pci_client::{self as pci, Bar},
    },
    memory,
    sync::SpinLock,
};

const CONFIG_PATH: &str = "/initfs/wifi.toml";
const MMIO_WINDOW: u64 = 0x0010_0000;

struct PciBus {
    mmio: u64,
    dma: KernelDma,
}

impl Bus for PciBus {
    fn read32(&self, offset: u32) -> u32 {
        unsafe { ptr::read_volatile((self.mmio + offset as u64) as *const u32) }
    }

    fn write32(&self, offset: u32, value: u32) {
        unsafe { ptr::write_volatile((self.mmio + offset as u64) as *mut u32, value) }
    }

    fn alloc_dma(&self, size: usize) -> Option<DmaRegion> {
        self.dma.alloc_dma(size).ok()
    }

    fn delay_us(&self, us: u32) {
        // The firmware-load path runs before the scheduler can be used for
        // fine-grained sleeps.  Spin on the TSC; the delays are <= 20 ms.
        let start = crate::arch::rdtsc();
        let khz = crate::arch::x86_64::boot_timestamp::tsc_khz().max(1);
        let target = start.saturating_add((us as u64).saturating_mul(khz) / 1000);
        while crate::arch::rdtsc() < target {
            core::hint::spin_loop();
        }
    }
}

fn read_initfs(path: &str) -> Option<&'static [u8]> {
    let stripped = path.strip_prefix("/initfs/").unwrap_or(path);
    let full = alloc::format!("/initfs/{}", stripped);
    crate::vfs::get_initfs_file_bytes(&full)
}

fn parse_config() -> Option<WifiConfig> {
    let bytes = match read_initfs(CONFIG_PATH) {
        Some(b) => b,
        None => {
            log::info!(
                "[iwlwifi] {} not present; Wi-Fi stays disabled",
                CONFIG_PATH
            );
            return None;
        }
    };
    match config::parse_bytes(bytes) {
        Ok(cfg) => {
            if !cfg.enabled {
                log::info!("[iwlwifi] disabled by {}", CONFIG_PATH);
                return None;
            }
            Some(cfg)
        }
        Err(e) => {
            log::error!("[iwlwifi] invalid {}: {}", CONFIG_PATH, e);
            None
        }
    }
}

fn mmio_base(dev: &pci::PciDevice) -> Option<u64> {
    match dev.read_bar(0).or_else(|| dev.read_bar(1))? {
        Bar::Memory32 { addr, .. } => Some(addr as u64),
        Bar::Memory64 { addr, .. } => Some(addr),
        Bar::Io { .. } => None,
    }
}

/// `NetworkDevice` adapter around `WifiDevice<PciBus>`.
struct KernelWifi {
    inner: SpinLock<WifiDevice<PciBus>>,
    mac: [u8; 6],
}

impl NetworkDevice for KernelWifi {
    fn name(&self) -> &str {
        "iwlwifi-ax201"
    }

    fn receive(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        let mut wifi = self.inner.lock();
        wifi.poll();
        wifi.receive_eth(buf).ok_or(NetError::NoPacket)
    }

    fn transmit(&self, buf: &[u8]) -> Result<(), NetError> {
        let mut wifi = self.inner.lock();
        if wifi.transmit_eth(buf) {
            Ok(())
        } else {
            Err(NetError::TxQueueFull)
        }
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn link_up(&self) -> bool {
        self.inner.lock().is_connected()
    }

    fn media(&self) -> NetMedia {
        NetMedia::Ethernet
    }

    fn mtu(&self) -> usize {
        1500
    }

    fn poll(&self) {
        self.inner.lock().poll();
    }

    fn link_speed_mbps(&self) -> u32 {
        if self.link_up() {
            866
        } else {
            0
        }
    }
}

/// Probe and initialise the AX201.  Returns true when the firmware reached
/// the alive state and the interface was registered.
pub fn init() -> bool {
    if !memory::paging::is_initialized() {
        return false;
    }
    let Some(cfg) = parse_config() else {
        return false;
    };
    let Some(firmware) = read_initfs(&cfg.firmware) else {
        log::warn!(
            "[iwlwifi] firmware '{}' missing from initfs; copy the Intel \
             ucode blob to workspace/assets/firmware/ before building",
            cfg.firmware
        );
        return false;
    };

    let candidates = pci::probe_all(pci::ProbeCriteria {
        vendor_id: Some(regs::INTEL_VENDOR),
        device_id: None,
        class_code: Some(pci::class::NETWORK),
        subclass: None,
        prog_if: None,
    });

    for dev in candidates {
        if !regs::AX201_DEVICE_IDS.contains(&dev.device_id) {
            continue;
        }
        log::info!(
            "[iwlwifi] AX201 PCI {:04x}:{:04x} at {:?}",
            dev.vendor_id,
            dev.device_id,
            dev.address
        );
        dev.enable_bus_master();
        dev.enable_memory_space();
        let mut cmd = dev.read_config_u16(pci::config::COMMAND);
        cmd &= !pci::command::INTERRUPT_DISABLE;
        dev.write_config_u16(pci::config::COMMAND, cmd);

        let Some(mmio_phys) = mmio_base(&dev) else {
            log::error!(
                "[iwlwifi] no MMIO BAR on {:04x}:{:04x}",
                dev.vendor_id,
                dev.device_id
            );
            continue;
        };
        memory::paging::ensure_identity_map_range(mmio_phys, MMIO_WINDOW);
        let mmio_virt = memory::phys_to_virt(mmio_phys);
        let mapped = memory::paging::translate(VirtAddr::new(mmio_virt))
            .map(|p| p.as_u64())
            .unwrap_or(0);
        if mapped != mmio_phys {
            log::error!("[iwlwifi] MMIO mapping failed phys={:#x}", mmio_phys);
            continue;
        }

        let sbdf = crate::hardware::iommu::Sbdf::from_pci(
            dev.address.bus,
            dev.address.device,
            dev.address.function,
        );
        let bus = PciBus {
            mmio: mmio_virt,
            dma: KernelDma::for_sbdf(sbdf),
        };
        let transport = IwlTransport::new(bus);
        let mut wifi = WifiDevice::new(transport, cfg.clone(), None);
        match wifi.init(firmware) {
            Ok(()) => {
                log::info!(
                    "[iwlwifi] AX201 firmware alive: api={} ver={:#x} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    wifi.transport.fw_api,
                    wifi.transport.fw_version,
                    wifi.mac()[0],
                    wifi.mac()[1],
                    wifi.mac()[2],
                    wifi.mac()[3],
                    wifi.mac()[4],
                    wifi.mac()[5],
                );
                if let Err(e) = wifi.connect() {
                    log::warn!("[iwlwifi] station connect failed: {:?}", e);
                }
                let mac = wifi.mac();
                let dev = Arc::new(KernelWifi {
                    inner: SpinLock::new(wifi),
                    mac,
                });
                let iface = super::register_device(dev);
                log::info!(
                    "[iwlwifi] registered {} (AX201, 802.11ax 2x2, waiting for WPA2 handshake)",
                    iface
                );
                return true;
            }
            Err(e) => {
                log::error!("[iwlwifi] bring-up failed: {:?}", e);
            }
        }
    }
    false
}
