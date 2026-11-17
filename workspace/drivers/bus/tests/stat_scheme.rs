//! `OPCODE_STAT` on the `/bus` scheme: handles report the same
//! directory/file nature that `OPCODE_OPEN` advertised, with sane modes.

use strat9_bus_drivers::{scheme::BusSchemeServer, simple_pm_bus::SimplePmBus, BusDriver};
use strat9_syscall::data::StatReply;

const OPCODE_STAT: u32 = 0x0B;

fn encode_stat_request(ino: u64) -> Vec<u8> {
    ino.to_le_bytes().to_vec()
}

const OP_OPEN: u32 = 0x01;
use strat9_syscall::data::IPC_FILE_FLAG_DIRECTORY;

fn open(server: &mut BusSchemeServer, sender: u64, path: &str) -> (u64, u32) {
    let mut p = vec![0u8; 6];
    p[4..6].copy_from_slice(&(path.len() as u16).to_le_bytes());
    p.extend_from_slice(path.as_bytes());
    let r = server.dispatch(OP_OPEN, sender, &p);
    assert_eq!(u32::from_le_bytes(r.payload[0..4].try_into().unwrap()), 0);
    let id = u64::from_le_bytes(r.payload[4..12].try_into().unwrap());
    let flags = u32::from_le_bytes(r.payload[20..24].try_into().unwrap());
    (id, flags)
}

fn stat(server: &mut BusSchemeServer, sender: u64, id: u64) -> Result<StatReply, u32> {
    let r = server.dispatch(OPCODE_STAT, sender, &encode_stat_request(id));
    let status = u32::from_le_bytes(r.payload[0..4].try_into().unwrap());
    if status != 0 {
        return Err(status);
    }
    Ok(StatReply::parse(&r.payload).unwrap())
}

#[test]
fn stat_matches_open_directory_flag() {
    let mut drivers: Vec<(String, Box<dyn BusDriver>)> = Vec::new();
    let mut d = SimplePmBus::new();
    d.init(0).unwrap();
    drivers.push(("simple-pm-bus".into(), Box::new(d)));
    let mut server = BusSchemeServer::new(drivers, 0);

    for path in ["", "pci", "simple-pm-bus", "simple-pm-bus/status", "pci/count"] {
        let (id, flags) = open(&mut server, 1, path);
        let st = stat(&mut server, 1, id).unwrap_or_else(|e| panic!("stat {path}: {e}"));
        let is_dir = flags & IPC_FILE_FLAG_DIRECTORY != 0;
        assert_eq!(st.mode & 0o170000 == 0o040000, is_dir, "{path}");
        assert_eq!(st.ino, id);
        if is_dir {
            assert_eq!(st.nlink, 2);
        } else {
            assert_eq!(st.mode & 0o170000, 0o100000, "{path}");
        }
    }
}

#[test]
fn stat_rejects_foreign_and_unknown_handles() {
    let mut server = BusSchemeServer::new(Vec::new(), 0);
    let (id, _) = open(&mut server, 1, "");
    assert!(stat(&mut server, 2, id).is_err(), "other sender must not stat");
    assert!(stat(&mut server, 1, 0xdead).is_err());
}

#[test]
fn unknown_opcode_is_enosys() {
    let mut server = BusSchemeServer::new(Vec::new(), 0);
    let r = server.dispatch(0x0C /* RENAME */, 1, &[0u8; 8]);
    assert_eq!(u32::from_le_bytes(r.payload[0..4].try_into().unwrap()), 38);
}
