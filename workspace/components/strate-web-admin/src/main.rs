#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![recursion_limit = "512"]

extern crate alloc;

mod executor;
mod io;
mod net;
mod routes;
mod sysinfo;

use core::alloc::Layout;
use core::fmt::Write;
use core::panic::PanicInfo;
use strat9_syscall::call;

const LISTEN_PORT: u16 = 8080;
const HTTP_BUF_SIZE: usize = 8192;

alloc_freelist::define_freelist_brk_allocator!(
    pub struct WebAdminAllocator;
    brk = strat9_syscall::call::brk;
    heap_max = 4 * 1024 * 1024;
);

#[global_allocator]
static ALLOCATOR: WebAdminAllocator = WebAdminAllocator;

#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    let mut buf = [0u8; 80];
    let n = {
        let mut w = BufWriter::new(&mut buf);
        let _ = write!(w, "[web-admin] OOM: {} bytes align {}\n", layout.size(), layout.align());
        w.len()
    };
    let _ = call::write(2, &buf[..n]);
    call::exit(12)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let mut buf = [0u8; 256];
    let n = {
        let mut w = BufWriter::new(&mut buf);
        let _ = write!(w, "[web-admin] PANIC: {}\n", info.message());
        w.len()
    };
    let _ = call::write(2, &buf[..n]);
    call::exit(255)
}

struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BufWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn len(&self) -> usize {
        self.pos
    }
}

impl core::fmt::Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let avail = self.buf.len().saturating_sub(self.pos);
        let n = bytes.len().min(avail);
        self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
        self.pos += n;
        Ok(())
    }
}

pub fn log(msg: &str) {
    let _ = call::write(1, msg.as_bytes());
}

static CONFIG: picoserve::Config = picoserve::Config::const_default().close_connection_after_response();

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    log("[web-admin] Strat9 Web Admin starting on port 8080\n");

    let app = routes::build_router();
    let mut conn_count: u64 = 0;

    loop {
        let fd = net::open_listener(LISTEN_PORT);
        conn_count += 1;

        executor::block_on(async {
            let socket = io::TcpSocket::new(fd);
            let timer = io::Strat9Timer;
            let mut http_buf = [0u8; HTTP_BUF_SIZE];

            let server = picoserve::Server::custom(&app, timer, &CONFIG, &mut http_buf);

            match server.serve(socket).await {
                Ok(info) => {
                    let msg = alloc::format!(
                        "[web-admin] conn #{}: {} reqs\n",
                        conn_count,
                        info.handled_requests_count
                    );
                    log(&msg);
                }
                Err(_) => {
                    log("[web-admin] connection error\n");
                }
            }
        });
    }
}
