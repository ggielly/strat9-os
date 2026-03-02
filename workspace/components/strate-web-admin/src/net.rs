use alloc::string::String;
use alloc::vec::Vec;
use strat9_syscall::{call, data::TimeSpec, flag, number};

const EAGAIN: usize = 11;
const MAX_EAGAIN_RETRIES: usize = 50;
const MAX_FILE_READ_BYTES: usize = 128 * 1024;

pub fn sleep_ms(ms: u64) {
    let req = TimeSpec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    };
    let _ = unsafe {
        strat9_syscall::syscall2(number::SYS_NANOSLEEP, &req as *const TimeSpec as usize, 0)
    };
}

pub fn open_listener(port: u16) -> usize {
    let path = alloc::format!("/net/tcp/listen/{}", port);
    loop {
        match call::openat(0, &path, flag::OpenFlags::RDWR.bits() as usize, 0) {
            Ok(fd) => return fd as usize,
            Err(_) => sleep_ms(200),
        }
    }
}

pub fn write_all(fd: usize, data: &[u8]) -> bool {
    let mut off = 0usize;
    while off < data.len() {
        match call::write(fd, &data[off..]) {
            Ok(0) => return false,
            Ok(n) => off += n,
            Err(e) if e.to_errno() == EAGAIN => {
                sleep_ms(1);
                continue;
            }
            Err(_) => return false,
        }
    }
    true
}

pub fn read_file_buf(path: &str, buf: &mut [u8]) -> usize {
    let fd = match call::openat(0, path, flag::OpenFlags::RDONLY.bits() as usize, 0) {
        Ok(fd) => fd as usize,
        Err(_) => return 0,
    };
    let mut total = 0;
    let mut retries = 0;
    loop {
        if total >= buf.len() {
            break;
        }
        match call::read(fd, &mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                retries = 0;
            }
            Err(e) if e.to_errno() == EAGAIN => {
                retries += 1;
                if retries > MAX_EAGAIN_RETRIES {
                    break;
                }
                let _ = call::sched_yield();
                continue;
            }
            Err(_) => break,
        }
    }
    let _ = call::close(fd);
    total
}

pub fn read_file_string(path: &str) -> Vec<u8> {
    let fd = match call::openat(0, path, flag::OpenFlags::RDONLY.bits() as usize, 0) {
        Ok(fd) => fd as usize,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut retries = 0;
    loop {
        if out.len() >= MAX_FILE_READ_BYTES {
            break;
        }
        match call::read(fd, &mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let remain = MAX_FILE_READ_BYTES.saturating_sub(out.len());
                let take = core::cmp::min(n, remain);
                out.extend_from_slice(&chunk[..take]);
                if take < n {
                    break;
                }
                retries = 0;
            }
            Err(e) if e.to_errno() == EAGAIN => {
                retries += 1;
                if retries > MAX_EAGAIN_RETRIES {
                    break;
                }
                let _ = call::sched_yield();
                continue;
            }
            Err(_) => break,
        }
    }
    let _ = call::close(fd);
    out
}

pub fn read_file_text(path: &str) -> String {
    let data = read_file_string(path);
    String::from_utf8(data).unwrap_or_default()
}

pub fn clock_gettime_ns() -> u64 {
    let mut ts = TimeSpec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let _ = call::clock_gettime(1, &mut ts);
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
