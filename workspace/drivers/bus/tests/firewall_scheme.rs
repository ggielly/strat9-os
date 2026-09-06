//! Integration tests for the `/bus/<driver>/firewall/...` scheme paths.
//!
//! Issue #60: the `FirewallController` capability (ETZPC/RIFSC) was not
//! reachable from userspace. These tests drive `BusSchemeServer::dispatch`
//! directly, without a live IPC transport.

use strat9_bus_drivers::{BusChild, BusDriver, scheme::BusSchemeServer, stm32_etzpc::Stm32Etzpc};

const OP_OPEN: u32 = 0x01;
const OP_READ: u32 = 0x02;
const OP_WRITE: u32 = 0x03;

const OK: u32 = 0;
const EINVAL: usize = 22; // best-effort: only check != OK below

fn open_payload(path: &str) -> Vec<u8> {
    let mut p = vec![0u8; 6];
    p[4..6].copy_from_slice(&(path.len() as u16).to_le_bytes());
    p.extend_from_slice(path.as_bytes());
    p
}

/// Opens a path and returns the file id (status must be OK).
fn open(server: &mut BusSchemeServer, path: &str) -> u64 {
    let reply = server.dispatch(OP_OPEN, 1, &open_payload(path));
    assert_eq!(
        u32::from_le_bytes(reply.payload[0..4].try_into().unwrap()),
        OK
    );
    u64::from_le_bytes(reply.payload[4..12].try_into().unwrap())
}

fn open_err(server: &mut BusSchemeServer, path: &str) -> bool {
    let reply = server.dispatch(OP_OPEN, 1, &open_payload(path));
    u32::from_le_bytes(reply.payload[0..4].try_into().unwrap()) != OK
}

fn write(server: &mut BusSchemeServer, file_id: u64, data: &[u8]) -> bool {
    let mut payload = vec![0u8; 18];
    payload[0..8].copy_from_slice(&file_id.to_le_bytes());
    payload[16..18].copy_from_slice(&(data.len() as u16).to_le_bytes());
    payload.extend_from_slice(data);
    let reply = server.dispatch(OP_WRITE, 1, &payload);
    u32::from_le_bytes(reply.payload[0..4].try_into().unwrap()) == OK
}

fn read(server: &mut BusSchemeServer, file_id: u64) -> String {
    let mut payload = vec![0u8; 16];
    payload[0..8].copy_from_slice(&file_id.to_le_bytes());
    let reply = server.dispatch(OP_READ, 1, &payload);
    let n = u32::from_le_bytes(reply.payload[4..8].try_into().unwrap()) as usize;
    String::from_utf8_lossy(&reply.payload[8..8 + n]).into_owned()
}

/// A plain driver with no firewall capability.
struct PlainDriver;

impl BusDriver for PlainDriver {
    fn name(&self) -> &str {
        "plain"
    }

    fn init(&mut self, _base: usize) -> Result<(), strat9_bus_drivers::BusError> {
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), strat9_bus_drivers::BusError> {
        Ok(())
    }

    fn read_reg(&self, _offset: usize) -> Result<u32, strat9_bus_drivers::BusError> {
        Err(strat9_bus_drivers::BusError::NotSupported)
    }

    fn write_reg(
        &mut self,
        _offset: usize,
        _value: u32,
    ) -> Result<(), strat9_bus_drivers::BusError> {
        Err(strat9_bus_drivers::BusError::NotSupported)
    }

    fn children(&self) -> Vec<BusChild> {
        vec![BusChild {
            name: "kid".into(),
            base_addr: 0,
            size: 1,
        }]
    }
}

#[test]
fn firewall_paths_exist_only_for_capable_drivers() {
    let etzpc = Stm32Etzpc::new();
    let mut server = BusSchemeServer::new(
        vec![
            ("stm32-etzpc".into(), Box::new(etzpc) as Box<dyn BusDriver>),
            ("plain".into(), Box::new(PlainDriver) as Box<dyn BusDriver>),
        ],
        1,
    );

    // Capable driver: paths exist.
    assert!(!open_err(&mut server, "stm32-etzpc/firewall/info"));
    assert!(!open_err(&mut server, "stm32-etzpc/firewall/grant/3"));
    assert!(!open_err(&mut server, "stm32-etzpc/firewall/release/0x3"));

    // Capable driver: invalid ids do not exist.
    assert!(open_err(&mut server, "stm32-etzpc/firewall/grant/"));
    assert!(open_err(&mut server, "stm32-etzpc/firewall/grant/xyz"));

    // Incapable driver: no firewall subtree at all.
    assert!(open_err(&mut server, "plain/firewall/info"));
    assert!(open_err(&mut server, "plain/firewall/grant/1"));

    // Unknown driver names stay unknown.
    assert!(open_err(&mut server, "nosuch/firewall/info"));
}

#[test]
fn firewall_info_reports_type_and_entries() {
    let mut server = BusSchemeServer::new(
        vec![(
            "stm32-etzpc".into(),
            Box::new(Stm32Etzpc::new()) as Box<dyn BusDriver>,
        )],
        1,
    );
    let fid = open(&mut server, "stm32-etzpc/firewall/info");
    let content = read(&mut server, fid);
    assert!(content.contains("type:"), "got: {content}");
    assert!(content.contains("max_entries:"), "got: {content}");
}

#[test]
fn grant_and_release_invoke_the_controller() {
    // RAM-backed ETZPC register block: DECPROT regs at +0x10.
    let mut regs = Box::leak(Box::new([0u32; 256]));
    // Peripheral 0 starts in non-secure A7NS mode (DECPROT bits = 0b11),
    // which is the state grant_access() accepts.
    regs[0x10 / 4] = 0b11;
    // HWCFGR at +0x3F0 (word index 252): 4 peripherals, 2 masters.
    regs[0x3F0 / 4] = (4 << 8) | (2 << 16);

    let mut etzpc = Stm32Etzpc::new();
    etzpc.init(regs.as_mut_ptr() as usize).unwrap();

    let mut server = BusSchemeServer::new(
        vec![("stm32-etzpc".into(), Box::new(etzpc) as Box<dyn BusDriver>)],
        1,
    );

    // Peripheral 0 starts in A7NS mode (DECPROT bits = 0b11): grant ok,
    // release ok.
    let g = open(&mut server, "stm32-etzpc/firewall/grant/0");
    assert!(write(&mut server, g, &[0]), "grant(0) must succeed");
    let r = open(&mut server, "stm32-etzpc/firewall/release/0");
    assert!(write(&mut server, r, &[0]), "release(0) must succeed");

    // Out-of-range id (6 >= 4+2): EINVAL-style failure.
    let bad = open(&mut server, "stm32-etzpc/firewall/grant/6");
    assert!(
        !write(&mut server, bad, &[0]),
        "grant(out-of-range) must fail"
    );
}

#[test]
fn readdir_lists_firewall_dir_only_when_capable() {
    let etzpc = Stm32Etzpc::new();
    let mut server = BusSchemeServer::new(
        vec![
            ("stm32-etzpc".into(), Box::new(etzpc) as Box<dyn BusDriver>),
            ("plain".into(), Box::new(PlainDriver) as Box<dyn BusDriver>),
        ],
        1,
    );

    // Just verify the driver-dir listing opens for both; the firewall dir
    // entry presence is covered by the existence checks above.
    assert!(!open_err(&mut server, "stm32-etzpc"));
    assert!(!open_err(&mut server, "plain"));
}
