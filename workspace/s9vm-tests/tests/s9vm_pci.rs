//! L2: s9vm PCI host bridge, BARs, routing and virtio modern transport.

extern crate alloc;

#[path = "../../kernel/src/s9vm/pci.rs"]
#[allow(dead_code)] // The host test exercises a subset of the device-facing API.
mod pci;

use alloc::vec::Vec;
use pci::{
    Bar, BarKind, CONFIG_ADDRESS, CONFIG_ADDRESS_ENABLE, CONFIG_DATA, Capability, ConfigAddress,
    HOST_BRIDGE_DEVICE_ID, HOST_BRIDGE_VENDOR_ID, PciAddress, PciError, PciFunction, PciHostBridge,
    VIRTIO_BAR_SIZE, VIRTIO_MODERN_DEVICE_ID_BASE, VIRTIO_VENDOR_ID, class_code, command,
    common_reg, config as cfg, status, virtio_cfg_type, virtio_device_type, virtio_features,
};

fn bridge() -> PciHostBridge {
    PciHostBridge::new()
}

fn virtio_bridge(device_type: u8) -> (PciHostBridge, PciAddress) {
    let mut bridge = PciHostBridge::new();
    let address = bridge
        .add_virtio(3, device_type)
        .expect("virtio function fits");
    (bridge, address)
}

/// Programs the 64-bit BAR 0 of a virtio function at `base` (32 KiB aligned).
fn program_bar(bridge: &mut PciHostBridge, address: PciAddress, base: u64) {
    assert!(bridge.config_write(address, cfg::BAR0, 4, base as u32));
    assert!(bridge.config_write(address, cfg::BAR1, 4, (base >> 32) as u32));
}

fn generic_function(slot: u8, function: u8) -> PciFunction {
    PciFunction::new(
        PciAddress::bus0(slot, function).expect("valid address"),
        0x1234,
        0x5678,
        0x020000,
    )
}

#[test]
fn config_mechanism_constants_and_cam_roundtrip() {
    assert_eq!(CONFIG_ADDRESS, 0xCF8);
    assert_eq!(CONFIG_DATA, 0xCFC);
    assert_eq!(CONFIG_ADDRESS_ENABLE, 1 << 31);
    let address = PciAddress::bus0(3, 2).unwrap();
    let raw = ConfigAddress::raw(address, 0x18);
    let decoded = ConfigAddress::decode(raw).expect("enabled address decodes");
    assert_eq!(decoded.address, address);
    assert_eq!(decoded.offset, 0x18);
    assert_eq!(decoded.encode(), raw);
}

#[test]
fn cam_requires_the_enable_bit() {
    let raw = ConfigAddress::raw(PciAddress::bus0(1, 0).unwrap(), 0x00);
    assert!(ConfigAddress::decode(raw & !CONFIG_ADDRESS_ENABLE).is_none());
    assert!(ConfigAddress::decode(raw).is_some());
}

#[test]
fn host_bridge_is_enumerable() {
    let bridge = bridge();
    let devices = bridge.enumerate();
    assert_eq!(devices.len(), 1);
    let host = devices[0];
    assert_eq!(host.address, PciAddress::bus0(0, 0).unwrap());
    assert_eq!(host.vendor_id, HOST_BRIDGE_VENDOR_ID);
    assert_eq!(host.device_id, HOST_BRIDGE_DEVICE_ID);
    assert_eq!(host.class_code, class_code::HOST_BRIDGE);
    assert_eq!(host.header_type & 0x7F, 0);
}

#[test]
fn config_read_merges_byte_lanes() {
    let bridge = bridge();
    let host = PciAddress::bus0(0, 0).unwrap();
    assert_eq!(
        bridge.config_read(host, cfg::VENDOR_ID, 4),
        Some(0x1237_8086)
    );
    assert_eq!(bridge.config_read(host, cfg::VENDOR_ID, 2), Some(0x8086));
    assert_eq!(bridge.config_read(host, cfg::DEVICE_ID, 2), Some(0x1237));
    assert_eq!(bridge.config_read(host, cfg::VENDOR_ID, 1), Some(0x86));
    assert_eq!(bridge.config_read(host, cfg::VENDOR_ID + 1, 1), Some(0x80));
}

#[test]
fn config_read_of_absent_device_is_none() {
    let bridge = bridge();
    let absent = PciAddress::bus0(9, 0).unwrap();
    assert_eq!(bridge.config_read(absent, 0, 4), None);
}

#[test]
fn config_out_of_bounds_is_rejected() {
    let mut bridge = bridge();
    let host = PciAddress::bus0(0, 0).unwrap();
    assert_eq!(bridge.config_read(host, 0x100, 4), None);
    assert!(!bridge.config_write(host, 0x100, 4, 0));
}

#[test]
fn vendor_and_device_ids_are_read_only() {
    let mut bridge = bridge();
    let host = PciAddress::bus0(0, 0).unwrap();
    assert!(!bridge.config_write(host, cfg::VENDOR_ID, 2, 0));
    assert_eq!(bridge.config_read(host, cfg::VENDOR_ID, 2), Some(0x8086));
}

#[test]
fn command_register_is_read_write() {
    let mut bridge = bridge();
    let host = PciAddress::bus0(0, 0).unwrap();
    assert!(bridge.config_write(
        host,
        cfg::COMMAND,
        2,
        u32::from(command::MEMORY_SPACE | command::BUS_MASTER)
    ));
    assert_eq!(
        bridge.config_read(host, cfg::COMMAND, 2),
        Some(u32::from(command::MEMORY_SPACE | command::BUS_MASTER))
    );
}

#[test]
fn status_capability_bit_is_not_w1c_cleared() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    assert_ne!(
        bridge.config_read(address, cfg::STATUS, 2).unwrap() & u32::from(status::CAPABILITIES),
        0
    );
    assert!(bridge.config_write(address, cfg::STATUS, 2, 0xFFFF));
    assert_ne!(
        bridge.config_read(address, cfg::STATUS, 2).unwrap() & u32::from(status::CAPABILITIES),
        0
    );
}

#[test]
fn io_config_address_port_round_trips() {
    let mut bridge = bridge();
    let address = PciAddress::bus0(4, 1).unwrap();
    let raw = ConfigAddress::raw(address, 0x20);
    assert!(bridge.io_write(CONFIG_ADDRESS, 4, raw));
    assert_eq!(bridge.io_read(CONFIG_ADDRESS, 4), Some(raw));
    assert_eq!(bridge.config_address(), raw);
}

#[test]
fn io_config_data_reads_the_selected_function() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    let raw = ConfigAddress::raw(address, cfg::VENDOR_ID);
    assert!(bridge.io_write(CONFIG_ADDRESS, 4, raw));
    assert_eq!(
        bridge.io_read(CONFIG_DATA, 4),
        Some(u32::from(VIRTIO_VENDOR_ID) | (u32::from(VIRTIO_MODERN_DEVICE_ID_BASE + 3) << 16))
    );
    assert_eq!(bridge.io_read(CONFIG_DATA, 2), Some(0x1AF4));
    assert_eq!(bridge.io_read(CONFIG_DATA + 2, 2), Some(0x1043));
}

#[test]
fn io_config_data_byte_writes_merge() {
    let mut bridge = bridge();
    let host = PciAddress::bus0(0, 0).unwrap();
    let raw = ConfigAddress::raw(host, cfg::COMMAND);
    assert!(bridge.io_write(CONFIG_ADDRESS, 4, raw));
    assert!(bridge.io_write(CONFIG_DATA, 1, 0x03));
    assert_eq!(bridge.config_read(host, cfg::COMMAND, 2), Some(3));
    assert!(bridge.io_write(CONFIG_DATA + 1, 1, 0x00));
    assert_eq!(bridge.config_read(host, cfg::COMMAND, 2), Some(3));
}

#[test]
fn io_config_data_without_enable_returns_all_ones() {
    let mut bridge = bridge();
    let host = PciAddress::bus0(0, 0).unwrap();
    let raw = ConfigAddress::raw(host, 0) & !CONFIG_ADDRESS_ENABLE;
    assert!(bridge.io_write(CONFIG_ADDRESS, 4, raw));
    assert_eq!(bridge.io_read(CONFIG_DATA, 4), Some(0xFFFF_FFFF));
    assert_eq!(bridge.io_read(CONFIG_DATA + 1, 2), Some(0xFFFF));
}

#[test]
fn io_ports_outside_the_config_window_are_ignored() {
    let mut bridge = bridge();
    assert_eq!(bridge.io_read(0x80, 1), None);
    assert!(!bridge.io_write(0x80, 1, 0));
    assert_eq!(bridge.io_read(CONFIG_DATA + 2, 4), None);
}

#[test]
fn config_on_bus_one_is_absent() {
    let mut bridge = bridge();
    let bus1 = PciAddress::new(1, 0, 0).unwrap();
    assert!(!bus1.is_modelled());
    assert_eq!(bridge.config_read(bus1, 0, 4), None);
    assert!(!bridge.config_write(bus1, 0, 4, 0));
    assert!(bridge.io_write(CONFIG_ADDRESS, 4, ConfigAddress::raw(bus1, 0)));
    assert_eq!(bridge.io_read(CONFIG_DATA, 4), Some(0xFFFF_FFFF));
}

#[test]
fn bar32_probe_returns_the_size_mask() {
    let mut bridge = bridge();
    let address = PciAddress::bus0(2, 0).unwrap();
    let mut function = generic_function(2, 0);
    function
        .add_memory_bar(0, 0x1000, BarKind::Memory32, false)
        .unwrap();
    bridge.add_function(function).unwrap();
    assert!(bridge.config_write(address, cfg::BAR0, 4, 0xFFFF_FFFF));
    assert_eq!(bridge.config_read(address, cfg::BAR0, 4), Some(0xFFFF_F000));
}

#[test]
fn bar32_remap_is_visible_in_the_memory_map() {
    let mut bridge = bridge();
    let address = PciAddress::bus0(2, 0).unwrap();
    let mut function = generic_function(2, 0);
    function
        .add_memory_bar(0, 0x1000, BarKind::Memory32, false)
        .unwrap();
    bridge.add_function(function).unwrap();
    assert!(bridge.config_write(address, cfg::BAR0, 4, 0x0000_2000));
    assert_eq!(bridge.config_read(address, cfg::BAR0, 4), Some(0x0000_2000));
    let window = bridge
        .memory_map()
        .find(0x2000)
        .expect("programmed BAR window");
    assert_eq!(window.base, 0x2000);
    assert_eq!(window.size, 0x1000);
    assert_eq!(window.address, address);
    assert_eq!(window.bar, 0);
}

#[test]
fn bar32_address_is_aligned_down_to_the_size() {
    let mut bridge = bridge();
    let address = PciAddress::bus0(2, 0).unwrap();
    let mut function = generic_function(2, 0);
    function
        .add_memory_bar(0, 0x1000, BarKind::Memory32, false)
        .unwrap();
    bridge.add_function(function).unwrap();
    assert!(bridge.config_write(address, cfg::BAR0, 4, 0x0000_2345));
    assert_eq!(bridge.config_read(address, cfg::BAR0, 4), Some(0x0000_2000));
}

#[test]
fn bar64_probe_reads_low_and_high_masks() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    assert!(bridge.config_write(address, cfg::BAR0, 4, 0xFFFF_FFFF));
    assert_eq!(bridge.config_read(address, cfg::BAR0, 4), Some(0xFFFF_8004));
    assert!(bridge.config_write(address, cfg::BAR1, 4, 0xFFFF_FFFF));
    assert_eq!(bridge.config_read(address, cfg::BAR1, 4), Some(0xFFFF_FFFF));
}

#[test]
fn bar64_remap_above_four_gib() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    program_bar(&mut bridge, address, 0x1_0000_0000);
    assert_eq!(bridge.config_read(address, cfg::BAR0, 4), Some(0x0000_0004));
    assert_eq!(bridge.config_read(address, cfg::BAR1, 4), Some(0x0000_0001));
    let window = bridge
        .memory_map()
        .find(0x1_0000_0000)
        .expect("64-bit BAR window");
    assert_eq!(window.base, 0x1_0000_0000);
    assert_eq!(window.size, VIRTIO_BAR_SIZE);
}

#[test]
fn bar_type_and_prefetchable_bits_are_reported() {
    let bar = Bar::new(0, BarKind::Memory32, 0x1000, true).unwrap();
    assert_eq!(bar.kind(), BarKind::Memory32);
    assert!(bar.prefetchable());
    assert_eq!(bar.low_dword() & 0x8, 0x8);
    let mut bar = bar;
    bar.write_low(0xFFFF_FFFF);
    assert_eq!(bar.low_dword() & 0x8, 0x8);
    assert_eq!(bar.low_dword() & 0x1, 0);
}

#[test]
fn io_bar_probe_program_and_no_memory_window() {
    let mut bridge = bridge();
    let address = PciAddress::bus0(4, 0).unwrap();
    let mut function = generic_function(4, 0);
    function.add_io_bar(0, 16).unwrap();
    bridge.add_function(function).unwrap();
    assert!(bridge.config_write(address, cfg::BAR0, 4, 0xFFFF_FFFF));
    assert_eq!(bridge.config_read(address, cfg::BAR0, 4), Some(0xFFFF_FFF1));
    assert!(bridge.config_write(address, cfg::BAR0, 4, 0x0000_03F8));
    assert_eq!(bridge.config_read(address, cfg::BAR0, 4), Some(0x0000_03F1));
    assert!(bridge.memory_map().find(0x3F0).is_none());
}

#[test]
fn multifunction_header_bit_is_set_for_shared_slots() {
    let mut bridge = bridge();
    bridge
        .add_function(generic_function(5, 0))
        .expect("first function");
    bridge
        .add_function(generic_function(5, 1))
        .expect("second function");
    let first = bridge
        .config_read(PciAddress::bus0(5, 0).unwrap(), cfg::HEADER_TYPE, 1)
        .unwrap();
    let second = bridge
        .config_read(PciAddress::bus0(5, 1).unwrap(), cfg::HEADER_TYPE, 1)
        .unwrap();
    assert_ne!(first & 0x80, 0);
    assert_ne!(second & 0x80, 0);
}

#[test]
fn capability_chain_is_linked_and_bounded() {
    let (bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    let function = bridge.function(address).expect("virtio function");
    let headers = function.capability_headers();
    assert_eq!(headers.len(), 7);
    assert_eq!(headers[0].offset, 0x40);
    assert_eq!(headers[0].id, pci::capability_id::VENDOR);
    assert_eq!(headers[5].id, pci::capability_id::MSI);
    assert_eq!(headers[6].id, pci::capability_id::MSIX);
    assert_eq!(headers[6].next, 0);
}

#[test]
fn virtio_capability_windows_are_consistent() {
    let (bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    let function = bridge.function(address).unwrap();
    let capabilities = function.capabilities();
    assert_eq!(capabilities.len(), 7);
    let mut types = Vec::new();
    for capability in &capabilities {
        if let Capability::Virtio(virtio) = capability {
            types.push(virtio.cfg_type);
            assert_eq!(virtio.bar, 0);
        }
    }
    assert_eq!(
        types,
        alloc::vec![
            virtio_cfg_type::COMMON,
            virtio_cfg_type::NOTIFY,
            virtio_cfg_type::ISR,
            virtio_cfg_type::DEVICE,
            virtio_cfg_type::PCI
        ]
    );
    assert_eq!(
        function
            .virtio_capability(virtio_cfg_type::COMMON)
            .unwrap()
            .mmio_offset,
        pci::virtio_window::COMMON
    );
    assert_eq!(
        function
            .virtio_capability(virtio_cfg_type::NOTIFY)
            .unwrap()
            .length,
        pci::VIRTIO_NOTIFY_SIZE
    );
}

#[test]
fn msi_and_msix_are_discovered_without_enabling() {
    let (bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    let function = bridge.function(address).unwrap();
    let msi = function.msi_capability().expect("MSI advertised");
    let msix = function.msix_capability().expect("MSI-X advertised");
    assert_eq!(msi.vectors, 2);
    assert_eq!(msix.table_size, 3);
    assert_eq!(msix.table_bar, 0);
    assert_eq!(msix.table_offset, pci::MSIX_TABLE_OFFSET);
    assert_eq!(msix.pba_bar, 0);
    assert_eq!(msix.pba_offset, pci::MSIX_PBA_OFFSET);
}

#[test]
fn virtio_device_features_are_advertised() {
    let (bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    let device = bridge.virtio(address).unwrap();
    assert_ne!(
        device.common.device_features() & virtio_features::VERSION_1,
        0
    );
    assert_ne!(
        device.common.device_features() & virtio_features::CONSOLE_SIZE,
        0
    );
    assert_eq!(device.common.num_queues(), 2);
    assert_eq!(device.common.device_status(), 0);
}

#[test]
fn driver_feature_writes_are_validated() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    program_bar(&mut bridge, address, 0x1_0000);
    let base = 0x1_0000;
    assert!(bridge.mmio_write(base + u64::from(common_reg::DRIVER_FEATURE), 4, 1));
    assert_eq!(
        bridge.mmio_read(base + u64::from(common_reg::DRIVER_FEATURE), 4),
        Some(1)
    );
    // The console does not offer bit 2.
    assert!(!bridge.mmio_write(base + u64::from(common_reg::DRIVER_FEATURE), 4, 1 << 2));
    assert_eq!(
        bridge.mmio_read(base + u64::from(common_reg::DRIVER_FEATURE), 4),
        Some(1)
    );
}

#[test]
fn queue_programming_enables_the_queue() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    program_bar(&mut bridge, address, 0x1_0000);
    let base = 0x1_0000;
    assert!(bridge.mmio_write(base + 0x16, 2, 0));
    assert!(bridge.mmio_write(base + 0x18, 2, 8));
    assert!(bridge.mmio_write(base + 0x20, 4, 0x2000));
    assert!(bridge.mmio_write(base + 0x28, 4, 0x3000));
    assert!(bridge.mmio_write(base + 0x30, 4, 0x4000));
    assert!(bridge.mmio_write(base + 0x1C, 2, 1));
    assert_eq!(bridge.mmio_read(base + 0x1C, 2), Some(1));
    assert_eq!(bridge.mmio_read(base + 0x18, 2), Some(8));
    assert_eq!(bridge.mmio_read(base + 0x1E, 2), Some(0));
}

#[test]
fn queue_enable_requires_sizes_and_addresses() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    program_bar(&mut bridge, address, 0x1_0000);
    let base = 0x1_0000;
    assert!(bridge.mmio_write(base + 0x16, 2, 1));
    assert!(bridge.mmio_write(base + 0x18, 2, 8));
    // No addresses programmed yet.
    assert!(!bridge.mmio_write(base + 0x1C, 2, 1));
    assert!(bridge.mmio_write(base + 0x20, 4, 0x5000));
    assert!(bridge.mmio_write(base + 0x28, 4, 0x6000));
    assert!(bridge.mmio_write(base + 0x30, 4, 0x7000));
    assert!(bridge.mmio_write(base + 0x1C, 2, 1));
    assert_eq!(bridge.mmio_read(base + 0x1C, 2), Some(1));
}

#[test]
fn queue_address_alignment_is_enforced() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    program_bar(&mut bridge, address, 0x1_0000);
    let base = 0x1_0000;
    assert!(bridge.mmio_write(base + 0x16, 2, 0));
    assert!(bridge.mmio_write(base + 0x18, 2, 8));
    assert!(bridge.mmio_write(base + 0x20, 4, 0x2001));
    assert!(bridge.mmio_write(base + 0x28, 4, 0x3000));
    assert!(bridge.mmio_write(base + 0x30, 4, 0x4000));
    assert!(!bridge.mmio_write(base + 0x1C, 2, 1));
}

#[test]
fn queue_size_must_be_a_power_of_two() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    program_bar(&mut bridge, address, 0x1_0000);
    let base = 0x1_0000;
    assert!(bridge.mmio_write(base + 0x16, 2, 0));
    assert!(!bridge.mmio_write(base + 0x18, 2, 3));
    assert!(!bridge.mmio_write(base + 0x18, 2, 1024));
    assert!(bridge.mmio_write(base + 0x18, 2, 16));
    assert_eq!(bridge.mmio_read(base + 0x18, 2), Some(16));
}

#[test]
fn queue_selection_out_of_range_is_rejected() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    program_bar(&mut bridge, address, 0x1_0000);
    let base = 0x1_0000;
    assert!(bridge.mmio_write(base + 0x16, 2, 5));
    assert_eq!(bridge.mmio_read(base + 0x18, 2), None);
    assert!(!bridge.mmio_write(base + 0x18, 2, 8));
    // Selecting a valid queue again is always allowed.
    assert!(bridge.mmio_write(base + 0x16, 2, 0));
}

#[test]
fn notify_offsets_and_queue_notifications_are_recorded() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    program_bar(&mut bridge, address, 0x1_0000);
    let base = 0x1_0000;
    for (queue, desc) in [(0u16, 0x2000u32), (1, 0x4000)] {
        assert!(bridge.mmio_write(base + 0x16, 2, u32::from(queue)));
        assert!(bridge.mmio_write(base + 0x18, 2, 8));
        assert!(bridge.mmio_write(base + 0x20, 4, desc));
        assert!(bridge.mmio_write(base + 0x28, 4, desc + 0x1000));
        assert!(bridge.mmio_write(base + 0x30, 4, desc + 0x2000));
        assert!(bridge.mmio_write(base + 0x1C, 2, 1));
    }
    let notify_base = base + u64::from(pci::virtio_window::NOTIFY);
    let off0 = bridge.mmio_read(base + 0x1E, 2).unwrap();
    assert_eq!(off0, 1);
    assert!(bridge.mmio_write(notify_base + u64::from(off0) * 2, 2, 1));
    assert!(bridge.mmio_write(notify_base, 2, 0));
    let device = bridge.virtio_mut(address).unwrap();
    let notifications = device.take_notifications();
    assert_eq!(notifications, alloc::vec![1, 0]);
    assert!(!bridge.mmio_write(notify_base + 0x20, 2, 0));
}

#[test]
fn isr_is_read_to_clear() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    program_bar(&mut bridge, address, 0x1_0000);
    let base = 0x1_0000;
    bridge.virtio_mut(address).unwrap().raise_isr(0x01);
    let isr = base + u64::from(pci::virtio_window::ISR);
    assert_eq!(bridge.mmio_read(isr, 1), Some(1));
    assert_eq!(bridge.mmio_read(isr, 1), Some(0));
    assert!(!bridge.mmio_write(isr, 1, 0x01));
}

#[test]
fn device_specific_config_is_read_only() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    program_bar(&mut bridge, address, 0x1_0000);
    let device_cfg = 0x1_0000 + u64::from(pci::virtio_window::DEVICE_CFG);
    assert_eq!(
        bridge.mmio_read(device_cfg, 4),
        Some(u32::from(pci::CONSOLE_COLUMNS) | (u32::from(pci::CONSOLE_ROWS) << 16))
    );
    assert!(!bridge.mmio_write(device_cfg, 4, 0));
}

#[test]
fn block_device_reports_capacity() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::BLOCK);
    program_bar(&mut bridge, address, 0x1_0000);
    let device_cfg = 0x1_0000 + u64::from(pci::virtio_window::DEVICE_CFG);
    assert_eq!(
        bridge.mmio_read(device_cfg, 4),
        Some(pci::BLOCK_CAPACITY_SECTORS as u32)
    );
}

#[test]
fn pci_configuration_window_exposes_config_space() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    program_bar(&mut bridge, address, 0x1_0000);
    let window = 0x1_0000 + u64::from(pci::virtio_window::PCI_CFG);
    assert_eq!(
        bridge.mmio_read(window, 4),
        Some(u32::from(VIRTIO_VENDOR_ID) | (u32::from(VIRTIO_MODERN_DEVICE_ID_BASE + 3) << 16))
    );
    assert!(!bridge.mmio_write(window, 4, 0));
}

#[test]
fn mmio_out_of_bounds_and_absent_devices_are_rejected() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    program_bar(&mut bridge, address, 0x1_0000);
    assert_eq!(bridge.mmio_read(0x1_0000 + VIRTIO_BAR_SIZE, 4), None);
    assert_eq!(bridge.mmio_read(0x1_7FFE, 4), None);
    assert!(!bridge.mmio_write(0x1_0000 + VIRTIO_BAR_SIZE, 4, 0));
    assert_eq!(bridge.mmio_read(0xDEAD_0000, 4), None);
    assert!(!bridge.mmio_write(0xDEAD_0000, 4, 0));
}

#[test]
fn memory_map_boundaries_are_exclusive() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    program_bar(&mut bridge, address, 0x1_0000);
    assert!(bridge.memory_map().contains(0x1_0000));
    assert!(bridge.memory_map().contains(0x1_0000 + VIRTIO_BAR_SIZE - 1));
    assert!(!bridge.memory_map().contains(0x1_0000 + VIRTIO_BAR_SIZE));
}

#[test]
fn legacy_pirq_rotation_is_programmed() {
    let bridge = bridge();
    let routing = bridge.routing();
    assert_eq!(routing.gsi(0, 1), Some(16));
    assert_eq!(routing.gsi(0, 2), Some(17));
    assert_eq!(routing.gsi(1, 1), Some(17));
    assert_eq!(routing.gsi(1, 4), Some(16));
    assert_eq!(routing.gsi(3, 1), Some(19));
    assert_eq!(routing.gsi(0, 0), None);
}

#[test]
fn interrupt_line_and_pin_are_exposed() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    // Slot 3 INTA rotates to GSI 19 in the default table.
    assert_eq!(bridge.function(address).unwrap().interrupt_pin(), 1);
    assert_eq!(bridge.function(address).unwrap().interrupt_line(), 19);
    bridge.routing_mut().set(3, 1, 42).unwrap();
    assert_eq!(bridge.routing().gsi(3, 1), Some(42));
    // Firmware writes the line into the configuration space.
    assert!(bridge.config_write(address, cfg::INTERRUPT_LINE, 1, 42));
    assert_eq!(bridge.function(address).unwrap().interrupt_line(), 42);
    assert!(!bridge.config_write(address, cfg::INTERRUPT_PIN, 1, 2));
}

#[test]
fn device_status_reset_clears_driver_state() {
    let (mut bridge, address) = virtio_bridge(virtio_device_type::CONSOLE);
    program_bar(&mut bridge, address, 0x1_0000);
    let base = 0x1_0000;
    assert!(bridge.mmio_write(base + 0x08, 4, 1));
    assert!(bridge.mmio_write(base + 0x16, 2, 0));
    assert!(bridge.mmio_write(base + 0x18, 2, 8));
    assert!(bridge.mmio_write(base + 0x20, 4, 0x2000));
    assert!(bridge.mmio_write(base + 0x28, 4, 0x3000));
    assert!(bridge.mmio_write(base + 0x30, 4, 0x4000));
    assert!(bridge.mmio_write(base + 0x1C, 2, 1));
    assert!(bridge.mmio_write(base + 0x14, 1, 0));
    assert_eq!(
        bridge
            .function(address)
            .unwrap()
            .virtio()
            .unwrap()
            .common
            .driver_features(),
        0
    );
    assert_eq!(bridge.mmio_read(base + 0x1C, 2), Some(0));
}

#[test]
fn devices_are_enumerated_in_address_order() {
    let mut bridge = bridge();
    let console = bridge.add_virtio(2, virtio_device_type::CONSOLE).unwrap();
    let net = bridge.add_virtio(1, virtio_device_type::NET).unwrap();
    let devices = bridge.enumerate();
    let addresses: Vec<PciAddress> = devices.iter().map(|device| device.address).collect();
    assert_eq!(
        addresses,
        alloc::vec![PciAddress::bus0(0, 0).unwrap(), net, console]
    );
    let net_info = devices[1];
    assert_eq!(net_info.class_code, class_code::VIRTIO);
    assert_eq!(net_info.device_id, VIRTIO_MODERN_DEVICE_ID_BASE + 1);
}

#[test]
fn duplicate_function_is_rejected() {
    let mut bridge = bridge();
    bridge.add_function(generic_function(6, 0)).unwrap();
    let result = bridge.add_function(generic_function(6, 0));
    assert_eq!(result, Err(PciError::DuplicateFunction));
}
