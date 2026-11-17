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

//! Native display server for strat9-os (jalon 4 of `docs/GUI_AUDIT_2026-11.md`).
//!
//! Binds `/srv/display`, owns the screen exclusively (K5) and serves the
//! `display-core` state machine: clients send `HELLO` on the server port and
//! receive every reply on the event port named in `HELLO.path` (A.1).
//!
//! This binary is the only module that knows `/dev/display` and `DMG2`:
//!
//! - `allocate` maps an anonymous page-aligned region, exports it with
//!   `mem_region_export` and grants it to the client's `HELLO` pid.
//! - `present` copies only the commit's damage rectangles from the client
//!   region into a private anonymous backbuffer (bounded reads, no long-lived
//!   `&[u8]` over client memory), then writes the same rows to the mapped
//!   framebuffer (write-only) and sends one `DMG2` record for display 0.
//!
//! Assumptions of this first slice: XRGB8888 native screen, one surface at
//! `(0, 0)`; the backbuffer is one screen-sized anonymous mapping.
//!
//! ## Resize
//!
//! Protocol v1 has no `CONFIGURE` *request*: `CONFIGURE` is a server event and
//! the only producer would be a backend-driven resize. The server therefore
//! never invents one; a client resizes by creating a new surface, as
//! `display-demo` does. The core exposes `set_configure` for a future
//! backend-driven path.
//!
//! Fixed capacities, no global allocator, no panic on wire input.

#![no_std]
#![no_main]

use core::{fmt::Write as _, panic::PanicInfo, slice};

use display_backend::{encode, encoded_len, SharedPixels};
use display_core::{Backend, PeerId, RegionHandle, Server, SurfaceId, Transport};
use display_protocol::{Body, Header, Opcode, Rect, HEADER_LEN, MAX_RECTS};
use strat9_syscall::{
    call,
    data::{IpcMessage, TimeSpec},
    error::Error,
    number, syscall6,
};

/// Server namespace path (A.1).
const SERVER_PATH: &[u8] = b"/srv/display";
/// Concurrent clients accepted by the adapter's transport table.
const MAX_PEERS: usize = 8;
/// Live pixel regions (A.6: 8 sessions x 16 buffers).
const MAX_REGIONS: usize = 128;
/// Page size for page-aligned region lengths.
const PAGE_SIZE: usize = 4096;
/// Receive budget per loop iteration (A.7: bounded work per turn).
const RECV_BUDGET: usize = 16;
/// Idle sleep, in nanoseconds.
const IDLE_NS: u64 = 2_000_000;
/// Log the counters every this many idle/served iterations (2 ms idle sleep:
/// about 60 s). A shorter period floods the serial line for no new evidence.
const LOG_EVERY: u64 = 30_000;
/// Retries of a transiently full client port.
const SEND_RETRIES: usize = 2;

const PROT_NONE: usize = 0;
const PROT_READ_WRITE: usize = 3;
const MAP_SHARED: usize = 1;
const MAP_PRIVATE: usize = 2;
const MAP_ANONYMOUS: usize = 0x20;

/// A pixel region exported to one client.
#[derive(Clone, Copy)]
struct Region {
    addr: usize,
    len: usize,
    export: usize,
    width: u32,
    height: u32,
    stride: u32,
}

/// The screen this server owns (`fb` is a mapped user address).
struct Screen {
    fb: usize,
    /// Private composited frame (anonymous mmap), sized `stride * height`.
    back: usize,
    back_len: usize,
    width: u32,
    height: u32,
    stride: u32,
    damage_fd: usize,
}

/// `display_core::Backend` over `/dev/display` and `DMG2`.
struct DisplayBackend {
    screen: Screen,
    regions: [Option<Region>; MAX_REGIONS],
}

impl DisplayBackend {
    const fn new(screen: Screen) -> Self {
        Self {
            screen,
            regions: [None; MAX_REGIONS],
        }
    }

    fn region(&self, handle: RegionHandle) -> Option<&Region> {
        self.regions
            .iter()
            .flatten()
            .find(|region| region.export as u64 == handle.raw())
    }
}

impl Backend for DisplayBackend {
    type Error = ();

    fn allocate(
        &mut self,
        width: u32,
        height: u32,
        stride: u32,
        _format: u32,
    ) -> Result<RegionHandle, Self::Error> {
        if width == 0 || height == 0 || stride < width.saturating_mul(4) {
            return Err(());
        }
        let len = (stride as usize).checked_mul(height as usize).ok_or(())?;
        let len = len.checked_add(PAGE_SIZE - 1).ok_or(())? & !(PAGE_SIZE - 1);
        // Guard page before the buffer. The kernel's `reserve_region` merges a
        // new anonymous VMA into a preceding one with identical attributes, so
        // a buffer mapped right after the private backbuffer (or the previous
        // buffer) is folded into that VMA; `mem_region_export(addr)` then fails
        // EINVAL because there is no VMA that starts at `addr`. A one-page
        // PROT_NONE mapping in between gives the buffer a neighbour with
        // different attributes, keeping its own VMA and exportable base.
        let guard = match unsafe {
            syscall6(
                number::SYS_MMAP,
                0,
                PAGE_SIZE,
                PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                0,
                0,
            )
        } {
            Ok(addr) if addr != 0 => Some(addr),
            _ => None,
        };
        let addr = unsafe {
            syscall6(
                number::SYS_MMAP,
                0,
                len,
                PROT_READ_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                0,
                0,
            )
        }
        .map_err(|_| {
            if let Some(guard) = guard {
                let _ = unsafe { call::funmap(guard, PAGE_SIZE) };
            }
            log_text(b"display-server: buffer mmap failed");
            ()
        })?;
        if let Some(guard) = guard {
            let _ = unsafe { call::funmap(guard, PAGE_SIZE) };
        }
        if addr == 0 {
            log_text(b"display-server: buffer mmap null");
            return Err(());
        }
        // The export walk requires every page to have an effective mapping:
        // anonymous mmap is lazy, so fault/zero the whole region first.
        // SAFETY: fresh RW anonymous mapping of `len` bytes owned here.
        unsafe {
            core::ptr::write_bytes(addr as *mut u8, 0, len);
        }
        let export = match call::mem_region_export(addr) {
            Ok(export) => export,
            Err(error) => {
                let _ = call::write(2, b"display-server: export failed: ");
                let _ = call::write(2, error.name().as_bytes());
                let _ = call::write(2, b"\n");
                let _ = unsafe { call::funmap(addr, len) };
                return Err(());
            }
        };
        let slot = match self.regions.iter().position(|slot| slot.is_none()) {
            Some(slot) => slot,
            None => {
                let _ = call::handle_close(export);
                let _ = unsafe { call::funmap(addr, len) };
                return Err(());
            }
        };
        self.regions[slot] = Some(Region {
            addr,
            len,
            export,
            width,
            height,
            stride,
        });
        Ok(RegionHandle::new(export as u64))
    }

    fn free(&mut self, handle: RegionHandle) {
        let Some(slot) = self
            .regions
            .iter()
            .position(|slot| matches!(slot, Some(region) if region.export as u64 == handle.raw()))
        else {
            return;
        };
        if let Some(region) = self.regions[slot].take() {
            let _ = call::handle_close(region.export);
            let _ = unsafe { call::funmap(region.addr, region.len) };
        }
    }

    fn present(
        &mut self,
        _surface: SurfaceId,
        handle: RegionHandle,
        damage: &[Rect],
    ) -> Result<(), Self::Error> {
        let region = match self.region(handle) {
            Some(region) => *region,
            None => {
                log_text(b"display-server: present: region missing");
                return Err(());
            }
        };
        if region.width > self.screen.width || region.height > self.screen.height {
            log(&format_args!(
                "display-server: present: region {}x{} exceeds screen {}x{}",
                region.width, region.height, self.screen.width, self.screen.height
            ));
            return Err(());
        }
        // Bounded view over client shared memory: never borrows it past the
        // copy, and copy_damage validates every rect before writing.
        let source_len = region.stride as usize * region.height as usize;
        let source = unsafe { slice::from_raw_parts(region.addr as *const u8, source_len) };
        let pixels = SharedPixels::new(source, region.width, region.height, region.stride).map_err(
            |error| {
                log(&format_args!(
                    "display-server: present: SharedPixels {:?} addr={:#x} len={} {}x{} stride={}",
                    error, region.addr, source_len, region.width, region.height, region.stride
                ));
                ()
            },
        )?;
        // SAFETY: the backbuffer is a private anonymous mapping of exactly
        // `back_len` bytes owned by this single-threaded server.
        let backbuffer =
            unsafe { slice::from_raw_parts_mut(self.screen.back as *mut u8, self.screen.back_len) };
        pixels
            .copy_damage(damage, backbuffer, self.screen.stride)
            .map_err(|_| {
                log_text(b"display-server: present: copy_damage failed");
                ()
            })?;

        // Write-only copy of the damaged rows to the mapped framebuffer.
        let stride = self.screen.stride as usize;
        for rect in damage {
            let row_bytes = rect.w as usize * 4;
            for row in 0..rect.h as usize {
                let offset = (rect.y as usize + row) * stride + rect.x as usize * 4;
                let end = offset.checked_add(row_bytes).ok_or(())?;
                let src = backbuffer.get(offset..end).ok_or(())?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        src.as_ptr(),
                        (self.screen.fb as *mut u8).add(offset),
                        row_bytes,
                    );
                }
            }
        }

        let mut message = [0u8; 8 + MAX_RECTS * 8];
        if encoded_len(damage.len()).ok_or(())? > message.len() {
            return Err(());
        }
        let len = encode(0, damage, &mut message).map_err(|_| {
            log_text(b"display-server: present: dmg2 encode failed");
            ()
        })?;
        call::write(self.screen.damage_fd, &message[..len]).map_err(|error| {
            let _ = call::write(2, b"display-server: present: damage write failed: ");
            let _ = call::write(2, error.name().as_bytes());
            let _ = call::write(2, b"\n");
            ()
        })?;
        Ok(())
    }
}

/// One client's event port.
struct PeerTransport {
    port: usize,
    /// Set when the port can no longer be written: the peer is gone.
    dead: bool,
}

impl PeerTransport {
    fn close(&mut self) {
        let _ = call::handle_close(self.port);
        self.port = 0;
    }
}

impl Transport for PeerTransport {
    fn send(&mut self, message: &[u8]) {
        if self.dead || message.len() > IpcMessage::PAYLOAD_CAPACITY {
            return;
        }
        if let Ok((header, body)) = Header::decode_message(message) {
            if header.opcode == Opcode::ERROR.value() {
                if let Ok(Body::Error { code, .. }) = Body::decode(header.opcode, header.object_id, body) {
                    let _ = call::write(2, b"display-server: wire ERROR code=");
                    let mut line = Line { buffer: [0; 192], len: 0 };
                    let _ = line.write_fmt(format_args!("{}\n", code));
                    let _ = call::write(2, &line.buffer[..line.len]);
                }
            }
        }
        let mut msg = IpcMessage::new(0);
        msg.payload[..message.len()].copy_from_slice(message);
        for _ in 0..SEND_RETRIES {
            match call::ipc_try_send(self.port, &msg) {
                Ok(_) => return,
                Err(Error::Again | Error::Interrupted) => {
                    let _ = call::sched_yield();
                }
                // BadHandle, closed port, ...: the peer can never answer.
                Err(_) => {
                    self.dead = true;
                    return;
                }
            }
        }
        // Queue stayed full: drop this reply (the client will time out), but
        // keep the session: Jalon 5 owns backpressure.
    }

    fn transfer_region(&mut self, server_region: u64, client_pid: u32) -> Option<u64> {
        match call::handle_grant(server_region as usize, client_pid as usize) {
            Ok(handle) => Some(handle as u64),
            Err(error) => {
                let _ = call::write(2, b"display-server: grant failed: ");
                let _ = call::write(2, error.name().as_bytes());
                let _ = call::write(2, b"\n");
                None
            }
        }
    }
}

/// The core state machine (~54 KiB) lives in `.bss`: the user stack is 64 KiB.
/// Built in place through [`Server::init_at`] so no whole-state temporary is
/// pushed on the stack.
static mut SERVER: core::mem::MaybeUninit<Server<DisplayBackend>> =
    core::mem::MaybeUninit::uninit();

fn main_loop(server_port: usize, display: Screen) -> ! {
    let backend = DisplayBackend::new(display);
    // SAFETY: single-threaded process, initialised once before the loop and
    // never aliased: `server` below is the only reference. `init_at` fills the
    // static in place.
    let server = unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(SERVER);
        Server::init_at(slot, backend)
    };
    let mut peers: [Option<(PeerId, PeerTransport)>; MAX_PEERS] = [const { None }; MAX_PEERS];
    let mut iterations: u64 = 0;
    log_text(b"display-server: loop");

    loop {
        let mut served = 0usize;
        for _ in 0..RECV_BUDGET {
            let mut msg = IpcMessage::new(0);
            match call::ipc_try_recv(server_port, &mut msg) {
                // SYS_IPC_TRY_RECV always returns 0: the payload is the
                // fixed-size IpcMessage, its own header gives the length.
                Ok(_) => {}
                Err(Error::Again | Error::Interrupted) => break,
                Err(_) => break,
            }
            served += 1;

            let Some((opcode, len)) = frame_shape(&msg.payload) else {
                log_text(b"display-server: bad frame");
                continue;
            };
            let peer = PeerId::new(msg.sender);
            let mut slot = peer_slot(&peers, peer);

            if slot.is_none() {
                if opcode != Opcode::HELLO.value() {
                    // A.1: only HELLO may open a session. Ignore silently: a
                    // log line here would let one peer flood the serial line.
                    continue;
                }
                let Some(client_port) = connect_event_port(&msg.payload[HEADER_LEN..len]) else {
                    log_text(b"display-server: HELLO event port connect failed");
                    continue;
                };
                log_text(b"display-server: HELLO accepted");
                slot = peers.iter().position(|entry| entry.is_none());
                let Some(slot) = slot else {
                    // No adapter slot: let the core answer `ERROR QUOTA` on
                    // the event port instead of dropping the HELLO silently.
                    let mut refused = PeerTransport {
                        port: client_port,
                        dead: false,
                    };
                    let _ = server.handle(peer, &msg.payload[..len], &mut refused);
                    refused.close();
                    continue;
                };
                peers[slot] = Some((
                    peer,
                    PeerTransport {
                        port: client_port,
                        dead: false,
                    },
                ));
            }
            let slot = slot.expect("slot set above");
            let transport = &mut peers[slot].as_mut().expect("slot filled").1;
            let _ = server.handle(peer, &msg.payload[..len], transport);
            let dead = transport.dead;
            let gone = dead || server.session_of(peer).is_none();
            if gone && server.session_of(peer).is_some() {
                let _ = server.disconnect(peer);
            }
            if gone {
                let stats = server.core().stats();
                log(&format_args!(
                    "display-server: drop peer dead={} session={} sessions={} surfaces={} buffers={} used_bytes={}",
                    dead,
                    server.session_of(peer).is_some(),
                    stats.sessions,
                    stats.surfaces,
                    stats.buffers,
                    stats.used_bytes
                ));
                if let Some((_, mut transport)) = peers[slot].take() {
                    transport.close();
                }
            }
        }

        // The client mapping dies with its process; freed once per iteration
        // (including after a dead-peer disconnect, which retires regions) so
        // an idle server never keeps them alive.
        while let Some(region) = server.take_retired() {
            server.free_retired(region);
        }

        // Exactly one bump per iteration. With two `wrapping_add(1)` calls the
        // release build eliminated this liveness branch as dead code (the
        // counter only ever took even values and LLVM folded `% 128`), so the
        // dead-peer poll silently never ran. Keep one increment and verify the
        // "peer gone" log survives `--release`.
        iterations = iterations.wrapping_add(1);
        if iterations % 128 == 0 {
            // Liveness: a destroyed client port fails the zero-timeout wait;
            // a live empty port reports WRITABLE.
            for index in 0..MAX_PEERS {
                let Some((peer, port)) = peers[index]
                    .as_ref()
                    .map(|(peer, transport)| (*peer, transport.port))
                else {
                    continue;
                };
                let wait = call::handle_wait_timeout(port, 0);
                if wait.is_err() {
                    log(&format_args!("display-server: peer gone"));
                    let _ = server.disconnect(peer);
                    if let Some((_, mut transport)) = peers[index].take() {
                        transport.close();
                    }
                    let stats = server.core().stats();
                    log(&format_args!(
                        "display-server: peer gone disconnect: sessions={} surfaces={} buffers={} used_bytes={}",
                        stats.sessions, stats.surfaces, stats.buffers, stats.used_bytes
                    ));
                }
            }
        }
        if served == 0 {
            let request = TimeSpec {
                tv_sec: 0,
                tv_nsec: IDLE_NS as i64,
            };
            let mut remaining = TimeSpec::zero();
            let _ = call::nanosleep(&request, &mut remaining);
        }

        if iterations % LOG_EVERY == 0 {
            let stats = server.core().stats();
            log(&format_args!(
                "display-server: sessions={} surfaces={} buffers={} used_bytes={}",
                stats.sessions, stats.surfaces, stats.buffers, stats.used_bytes
            ));
        }
    }
}

/// Opcode and declared frame length of an IPC payload, or `None` when the
/// frame is not a complete `S9DP` message that fits the payload.
fn frame_shape(payload: &[u8]) -> Option<(u16, usize)> {
    if payload.len() < HEADER_LEN {
        return None;
    }
    if u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
        != display_protocol::MAGIC
    {
        return None;
    }
    let len = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]) as usize;
    if len < HEADER_LEN || len > payload.len() {
        return None;
    }
    let opcode = u16::from_le_bytes([payload[8], payload[9]]);
    Some((opcode, len))
}

fn peer_slot(peers: &[Option<(PeerId, PeerTransport)>; MAX_PEERS], peer: PeerId) -> Option<usize> {
    peers
        .iter()
        .position(|entry| matches!(entry, Some((known, _)) if *known == peer))
}

/// Decode `HELLO.path` and connect to the client's event port.
fn connect_event_port(body: &[u8]) -> Option<usize> {
    match Body::decode(Opcode::HELLO.value(), 0, body).ok()? {
        Body::Hello { path, .. } => call::ipc_connect(path).ok(),
        _ => None,
    }
}

/// Read the screen geometry from `/dev/display/info`.
fn read_screen_info() -> Option<(u32, u32, u8, u32, u8, u8, u8)> {
    let fd = call::open("/dev/display/info", 0).ok()?;
    let mut buffer = [0u8; 256];
    let count = call::read(fd, &mut buffer).ok()?;
    let _ = call::close(fd);
    let text = core::str::from_utf8(&buffer[..count]).ok()?;
    let mut width = 800u32;
    let mut height = 600u32;
    let mut bpp = 32u8;
    let mut stride = 0u32;
    let mut red_shift = 16u8;
    let mut green_shift = 8u8;
    let mut blue_shift = 0u8;
    for field in text.split_whitespace() {
        if let Some(value) = field.strip_prefix("width=") {
            width = value.parse().unwrap_or(width);
        } else if let Some(value) = field.strip_prefix("height=") {
            height = value.parse().unwrap_or(height);
        } else if let Some(value) = field.strip_prefix("bpp=") {
            bpp = value.parse().unwrap_or(bpp);
        } else if let Some(value) = field.strip_prefix("stride=") {
            stride = value.parse().unwrap_or(stride);
        } else if let Some(value) = field.strip_prefix("red_shift=") {
            red_shift = value.parse().unwrap_or(red_shift);
        } else if let Some(value) = field.strip_prefix("green_shift=") {
            green_shift = value.parse().unwrap_or(green_shift);
        } else if let Some(value) = field.strip_prefix("blue_shift=") {
            blue_shift = value.parse().unwrap_or(blue_shift);
        }
    }
    if stride == 0 {
        stride = width.saturating_mul(bpp as u32 / 8);
    }
    Some((
        width,
        height,
        bpp,
        stride,
        red_shift,
        green_shift,
        blue_shift,
    ))
}

/// Take exclusive ownership of the screen (K5) and map it `MAP_SHARED`.
fn open_screen() -> Screen {
    let (width, height, bpp, stride, red_shift, green_shift, blue_shift) =
        read_screen_info().unwrap_or((800, 600, 32, 800 * 4, 16, 8, 0));
    if bpp != 32 || (red_shift, green_shift, blue_shift) != (16, 8, 0) {
        log(&format_args!(
            "display-server: unsupported screen bpp={} shifts={}/{}/{}",
            bpp, red_shift, green_shift, blue_shift
        ));
        halt();
    }
    let size = (stride as usize)
        .checked_mul(height as usize)
        .filter(|size| *size != 0)
        .unwrap_or(0);
    if size == 0 {
        log_text(b"display-server: invalid screen geometry");
        halt();
    }
    log(&format_args!(
        "display-server: screen {}x{} bpp={} stride={}",
        width, height, bpp, stride
    ));

    let display_fd = open_exclusive();
    // K5: only the owner may clear.
    match call::open("/dev/display/clear", 2) {
        Ok(fd) => {
            let _ = call::write(fd, b"clear");
            let _ = call::close(fd);
        }
        Err(_) => log_text(b"display-server: clear failed"),
    }
    let damage_fd = match call::open("/dev/display/damage", 2) {
        Ok(fd) => fd,
        Err(_) => {
            log_text(b"display-server: FATAL: /dev/display/damage unavailable");
            halt();
        }
    };
    let fb = match unsafe {
        syscall6(
            number::SYS_MMAP,
            0,
            size,
            PROT_READ_WRITE,
            MAP_SHARED,
            display_fd,
            0,
        )
    } {
        Ok(addr) if addr != 0 => addr,
        _ => {
            log_text(b"display-server: FATAL: framebuffer mmap failed");
            halt();
        }
    };
    // Private composited frame: anonymous, page-aligned, zero-filled. No
    // static BSS (a 1600x1200 screen alone is 7.7 MiB).
    let back = match unsafe {
        syscall6(
            number::SYS_MMAP,
            0,
            size,
            PROT_READ_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            0,
            0,
        )
    } {
        Ok(addr) if addr != 0 => addr,
        _ => {
            log_text(b"display-server: FATAL: backbuffer mmap failed");
            halt();
        }
    };
    log(&format_args!(
        "display-server: framebuffer mapped ({} bytes), backbuffer mapped",
        size
    ));
    Screen {
        fb,
        back,
        back_len: size,
        width,
        height,
        stride,
        damage_fd,
    }
}

/// Open `/dev/display/0.0` for writing, retrying while another owner (or the
/// boot console) still holds it.
fn open_exclusive() -> usize {
    let request = TimeSpec {
        tv_sec: 0,
        tv_nsec: 20_000_000,
    };
    let mut remaining = TimeSpec::zero();
    let mut logged = false;
    loop {
        match call::open("/dev/display/0.0", 2) {
            Ok(fd) => {
                log_text(b"display-server: screen owned (K5)");
                return fd;
            }
            Err(Error::Busy) => {
                if !logged {
                    log_text(b"display-server: /dev/display/0.0 busy, waiting");
                    logged = true;
                }
                let _ = call::nanosleep(&request, &mut remaining);
            }
            Err(_) => {
                log_text(b"display-server: FATAL: cannot open /dev/display/0.0");
                halt();
            }
        }
    }
}

fn halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Fixed-size, allocation-free log line builder.
struct Line {
    buffer: [u8; 192],
    len: usize,
}

impl core::fmt::Write for Line {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let bytes = text.as_bytes();
        let room = self.buffer.len() - self.len;
        let count = room.min(bytes.len());
        self.buffer[self.len..self.len + count].copy_from_slice(&bytes[..count]);
        self.len += count;
        Ok(())
    }
}

fn log_text(text: &[u8]) {
    let _ = call::write(2, text);
    let _ = call::write(2, b"\n");
}

fn log(args: &core::fmt::Arguments<'_>) {
    let mut line = Line {
        buffer: [0; 192],
        len: 0,
    };
    let _ = line.write_fmt(*args);
    let _ = call::write(2, &line.buffer[..line.len]);
    let _ = call::write(2, b"\n");
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log_text(b"display-server: strate-display v0.1.0");
    log(&format_args!(
        "display-server: pid={}",
        call::getpid().unwrap_or(0)
    ));
    let screen = open_screen();
    let server_port = match call::ipc_create_port(0) {
        Ok(port) => port,
        Err(_) => {
            log_text(b"display-server: FATAL: ipc_create_port failed");
            halt();
        }
    };
    if call::ipc_bind_port(server_port, SERVER_PATH).is_err() {
        log_text(b"display-server: FATAL: cannot bind /srv/display");
        halt();
    }
    log_text(b"display-server: bound /srv/display");
    main_loop(server_port, screen)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("display-server", info)
}
