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
//! Binds `/srv/vasistas`, owns the screen exclusively (K5) and serves the
//! `vasistas-core` state machine: clients send `HELLO` on the server port and
//! receive every reply on the event port named in `HELLO.path` (A.1).
//!
//! This binary is the only module that knows `/dev/vasistas` and `DMG2`:
//!
//! - `allocate` maps an anonymous page-aligned region, exports it with
//!   `mem_region_export` and grants it to the client's `HELLO` pid.
//! - `present` copies only the commit's damage rectangles from the client
//!   region into a private anonymous backbuffer at the surface's screen origin
//!   (bounded reads, no long-lived `&[u8]` over client memory), then writes the
//!   same rows to the mapped framebuffer (write-only) and sends one `DMG2`
//!   record for display 0.
//!
//! Assumptions of this slice: XRGB8888 native screen. `vasistas-core` places
//! each session in a fixed tile of the screen (4 columns x 2 rows); each damage
//! rect is surface-local and is translated, clipped to the screen and copied by
//! `present`. The backbuffer is one screen-sized anonymous mapping.
//!
//! ## Resize
//!
//! Protocol v1 has no `CONFIGURE` *request*: `CONFIGURE` is a server event and
//! the only producer would be a backend-driven resize. The server therefore
//! never invents one; a client resizes by creating a new surface, as
//! `vasistas-demo` does. The core exposes `set_configure` for a future
//! backend-driven path.
//!
//! ## Volontairement hors périmètre
//!
//! - `CONFIGURE` n'est **pas déclenchable** : v1 n'a aucune requête de resize,
//!   donc le serveur n'émet jamais cet événement (le client recrée une
//!   surface).
//! - `CLOSE_REQUEST` n'est **pas émis** : il n'existe aucun chemin d'arrêt du
//!   serveur (pas de signal de shutdown dans cette tranche), donc aucun
//!   `CLOSE_REQUEST { reason = SHUTDOWN }` ne peut être produit. Le client
//!   traite `CLOSE_REQUEST` s'il en reçoit un (avenir).
//!
//! Fixed capacities, no global allocator, no panic on wire input.

#![no_std]
#![no_main]

use core::{fmt::Write as _, panic::PanicInfo, slice};

use input_client::{Client as InputClient, Poll};
use input_protocol::{
    NormalizedEvent, INPUT_EVENT_KEY, INPUT_EVENT_POINTER_AXIS, INPUT_EVENT_POINTER_BUTTON,
    INPUT_EVENT_POINTER_MOTION, INPUT_EVENT_TEXT,
};
use vasistas_backend::{clip_to_screen, encode, SharedPixels};
use vasistas_core::{Backend, PeerId, RegionHandle, SessionId, Server, SurfaceId, Transport};
use vasistas_protocol::{
    Body, Header, InputBatch, InputRecord, Opcode, Rect, HEADER_LEN, INPUT_EVENT_FOCUS_GAINED,
    INPUT_EVENT_FOCUS_LOST, INPUT_FLAG_ABSOLUTE, MAX_MESSAGE_BYTES, MAX_RECTS,
};
use strat9_syscall::{
    call,
    data::{IpcMessage, TimeSpec},
    error::Error,
    number, syscall6,
};

/// Server namespace path (A.1).
const SERVER_PATH: &[u8] = b"/srv/vasistas";
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
/// Queued replies per peer before the newest is dropped (Jalon 5).
const PEER_QUEUE_FRAMES: usize = 8;
/// Largest complete wire message, equal to `IpcMessage::PAYLOAD_CAPACITY`.
const MAX_MESSAGE: usize = 1008;
/// Software cursor side, in pixels (hotspot at the top-left corner).
const CURSOR_SIZE: u32 = 16;
/// A.3.1 object id of the single output. A.3.1 reserves object 0 for
/// connection-scoped messages, so the only output is numbered 1.
const DISPLAY_OUTPUT_ID: u64 = 1;
/// RAM kept free for the rest of the system when sizing the pixel budget.
const SYSTEM_RESERVE_BYTES: u64 = 64 * 1024 * 1024;
/// RAM kept free for the rescue console when sizing the pixel budget.
const RESCUE_RESERVE_BYTES: u64 = 32 * 1024 * 1024;
/// Smallest pixel budget offered to the core (A.6).
const MIN_GLOBAL_BUDGET_BYTES: u64 = 8 * 1024 * 1024;

/// Software cursor, one byte per pixel: `0` transparent, `1` black border,
/// `2` white fill. Drawn at the pointer hotspot `(0, 0)`. One 16x16 table per
/// A.3.1 shape: 0 default arrow, 1 text caret, 2 pointer hand.
const CURSOR_SHAPES: [[[u8; 16]; 16]; 3] = [
    // 0: default arrow.
    [
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0],
        [1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0],
        [1, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0],
        [1, 2, 2, 1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 2, 1, 0, 1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 1, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
    ],
    // 1: text caret, thin vertical bar.
    [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ],
    // 2: pointer hand, simple silhouette.
    [
        [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 1, 1, 1, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 1, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 1, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0],
        [0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0],
        [0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0],
        [0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0],
        [0, 1, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 1, 2, 2, 1, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 1, 2, 2, 1, 0, 1, 2, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ],
];

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

/// `vasistas_core::Backend` over `/dev/vasistas` and `DMG2`.
struct DisplayBackend {
    screen: Screen,
    regions: [Option<Region>; MAX_REGIONS],
    /// Pointer hotspot, in screen space. Starts at the screen centre.
    cursor_x: u32,
    cursor_y: u32,
    /// Selected A.3.1 cursor shape (`0..=2`).
    cursor_shape: u32,
    /// Set once the cursor has been painted over the framebuffer.
    cursor_drawn: bool,
}

impl DisplayBackend {
    const fn new(screen: Screen) -> Self {
        Self {
            cursor_x: screen.width / 2,
            cursor_y: screen.height / 2,
            cursor_shape: 0,
            screen,
            regions: [None; MAX_REGIONS],
            cursor_drawn: false,
        }
    }

    fn region(&self, handle: RegionHandle) -> Option<&Region> {
        self.regions
            .iter()
            .flatten()
            .find(|region| region.export as u64 == handle.raw())
    }

    fn cursor_pos(&self) -> (u32, u32) {
        (self.cursor_x, self.cursor_y)
    }

    /// Visible part of a 16x16 cursor at `(x, y)`, clipped to the screen.
    fn cursor_rect(&self, x: u32, y: u32) -> Option<Rect> {
        if x >= self.screen.width || y >= self.screen.height {
            return None;
        }
        let width = (x + CURSOR_SIZE).min(self.screen.width) - x;
        let height = (y + CURSOR_SIZE).min(self.screen.height) - y;
        Some(Rect {
            x: x as i32,
            y: y as i32,
            w: width,
            h: height,
        })
    }

    /// Copy `rect` (screen space) from the cursor-free backbuffer to the
    /// framebuffer. Never reads the framebuffer.
    fn restore_rect(&mut self, rect: Rect) {
        let stride = self.screen.stride as usize;
        let row_bytes = rect.w as usize * 4;
        for row in rect.y as usize..(rect.y as u32 + rect.h) as usize {
            let offset = row * stride + rect.x as usize * 4;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (self.screen.back as *const u8).add(offset),
                    (self.screen.fb as *mut u8).add(offset),
                    row_bytes,
                );
            }
        }
    }

    /// Paint the selected cursor shape over the framebuffer, clipped to `rect`.
    fn paint_cursor(&mut self, x: u32, y: u32, rect: Rect) {
        let stride = self.screen.stride as usize;
        let shape = &CURSOR_SHAPES[self.cursor_shape.min(2) as usize];
        for row in rect.y..(rect.y as u32 + rect.h) as i32 {
            let shape = &shape[(row as u32 - y) as usize];
            for col in rect.x..(rect.x as u32 + rect.w) as i32 {
                let style = shape[(col as u32 - x) as usize];
                if style == 0 {
                    continue;
                }
                let color = if style == 1 { 0x0000_0000u32 } else { 0x00FF_FFFFu32 };
                let offset = row as usize * stride + col as usize * 4;
                unsafe {
                    core::ptr::write_unaligned((self.screen.fb as *mut u32).add(offset / 4), color);
                }
            }
        }
    }

    /// Clamp `(x, y)` to the screen, restore the old cursor, paint the new one
    /// and damage the affected rectangles. Returns the clamped position.
    fn move_cursor(&mut self, x: i32, y: i32) -> (u32, u32) {
        let max_x = self.screen.width.saturating_sub(1).min(i32::MAX as u32) as i32;
        let max_y = self.screen.height.saturating_sub(1).min(i32::MAX as u32) as i32;
        let x = x.clamp(0, max_x) as u32;
        let y = y.clamp(0, max_y) as u32;
        if x == self.cursor_x && y == self.cursor_y && self.cursor_drawn {
            return (x, y);
        }
        let old = if self.cursor_drawn {
            self.cursor_rect(self.cursor_x, self.cursor_y)
        } else {
            None
        };
        if let Some(rect) = old {
            self.restore_rect(rect);
        }
        self.cursor_x = x;
        self.cursor_y = y;
        let mut rects = [Rect::default(); 2];
        let mut count = 0usize;
        if let Some(rect) = old {
            rects[count] = rect;
            count += 1;
        }
        if let Some(rect) = self.cursor_rect(x, y) {
            self.paint_cursor(x, y, rect);
            if count == 0 || rects[0] != rect {
                rects[count] = rect;
                count += 1;
            }
        }
        self.cursor_drawn = true;
        self.send_damage(&rects[..count]);
        (x, y)
    }

    fn send_damage(&mut self, rects: &[Rect]) {
        if rects.is_empty() {
            return;
        }
        let mut message = [0u8; 8 + MAX_RECTS * 8];
        if let Ok(len) = encode(0, rects, &mut message) {
            let _ = call::write(self.screen.damage_fd, &message[..len]);
        }
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
            log_text(b"vasistas: buffer mmap failed");
            ()
        })?;
        if let Some(guard) = guard {
            let _ = unsafe { call::funmap(guard, PAGE_SIZE) };
        }
        if addr == 0 {
            log_text(b"vasistas: buffer mmap null");
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
                let _ = call::write(2, b"vasistas: export failed: ");
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
        origin_x: u32,
        origin_y: u32,
    ) -> Result<(), Self::Error> {
        if damage.len() > MAX_RECTS {
            log_text(b"vasistas: present: too many rects");
            return Err(());
        }
        let region = match self.region(handle) {
            Some(region) => *region,
            None => {
                log_text(b"vasistas: present: region missing");
                return Err(());
            }
        };
        // Bounded view over client shared memory: never borrows it past the
        // copy, and copy_rect_to validates every rect before writing.
        let source_len = region.stride as usize * region.height as usize;
        let source = unsafe { slice::from_raw_parts(region.addr as *const u8, source_len) };
        let pixels = SharedPixels::new(source, region.width, region.height, region.stride).map_err(
            |error| {
                log(&format_args!(
                    "vasistas: present: SharedPixels {:?} addr={:#x} len={} {}x{} stride={}",
                    error, region.addr, source_len, region.width, region.height, region.stride
                ));
                ()
            },
        )?;
        // SAFETY: the backbuffer is a private anonymous mapping of exactly
        // `back_len` bytes owned by this single-threaded server.
        let backbuffer =
            unsafe { slice::from_raw_parts_mut(self.screen.back as *mut u8, self.screen.back_len) };

        // Damage rects are surface-local: translate each one to screen space,
        // clip it to the screen, and copy only the visible part from the client
        // region to its screen position in the private backbuffer. Surfaces
        // larger than their tile therefore only paint the visible part.
        let mut screen_rects = [Rect::default(); MAX_RECTS];
        let mut count = 0usize;
        for rect in damage {
            let Some(screen) = clip_to_screen(
                *rect,
                origin_x,
                origin_y,
                self.screen.width,
                self.screen.height,
            ) else {
                continue;
            };
            let local = Rect {
                x: (screen.x as i64 - origin_x as i64) as i32,
                y: (screen.y as i64 - origin_y as i64) as i32,
                w: screen.w,
                h: screen.h,
            };
            pixels
                .copy_rect_to(
                    local,
                    screen.x as u32,
                    screen.y as u32,
                    backbuffer,
                    self.screen.stride,
                )
                .map_err(|_| {
                    log_text(b"vasistas: present: copy_rect_to failed");
                    ()
                })?;
            screen_rects[count] = screen;
            count += 1;
        }
        if count == 0 {
            // Every rect was clipped away: nothing to show, nothing to ack.
            return Ok(());
        }
        let screen_rects = &screen_rects[..count];

        // Write-only copy of the damaged rows to the mapped framebuffer. All
        // offsets are absolute (already in screen space) and checked in u64.
        let stride = self.screen.stride as usize;
        for rect in screen_rects {
            let x = rect.x as u32 as u64 * 4;
            let y = rect.y as u32 as u64;
            let row_bytes = rect.w as usize * 4;
            for row in 0..rect.h as u64 {
                let offset = (y + row)
                    .checked_mul(stride as u64)
                    .and_then(|offset| offset.checked_add(x))
                    .ok_or(())?;
                let offset = usize::try_from(offset).map_err(|_| ())?;
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

        // Paint the cursor before the damage message: the kernel copies only
        // the damaged rectangles to the scanout, so every painted pixel must
        // be covered. The cursor rectangle joins the damage when the commit's
        // rectangles do not already cover it.
        let cursor = self.cursor_rect(self.cursor_x, self.cursor_y);
        if let Some(rect) = cursor {
            self.paint_cursor(self.cursor_x, self.cursor_y, rect);
            self.cursor_drawn = true;
        }
        let mut damaged = [Rect::default(); MAX_RECTS];
        damaged[..count].copy_from_slice(screen_rects);
        let mut damaged_len = count;
        if let Some(rect) = cursor {
            if !screen_rects.iter().any(|outer| rect_contains(*outer, rect)) {
                if damaged_len < MAX_RECTS {
                    damaged[damaged_len] = rect;
                    damaged_len += 1;
                } else {
                    // Damage is full: widening the last rect only copies more.
                    damaged[damaged_len - 1] = rect_union(damaged[damaged_len - 1], rect);
                }
            }
        }

        let mut message = [0u8; 8 + MAX_RECTS * 8];
        let len = encode(0, &damaged[..damaged_len], &mut message).map_err(|_| {
            log_text(b"vasistas: present: dmg2 encode failed");
            ()
        })?;
        call::write(self.screen.damage_fd, &message[..len]).map_err(|error| {
            let _ = call::write(2, b"vasistas: present: damage write failed: ");
            let _ = call::write(2, error.name().as_bytes());
            let _ = call::write(2, b"\n");
            ()
        })?;
        Ok(())
    }

    fn set_cursor_shape(&mut self, shape: u32) {
        // The protocol decoder only accepts 0..=2; clamp anyway so a future
        // caller can never index `CURSOR_SHAPES` out of bounds.
        let shape = shape.min(2);
        if shape == self.cursor_shape {
            return;
        }
        self.cursor_shape = shape;
        // Repaint immediately when the cursor is already visible: restore the
        // pixels under the old shape, draw the new one, damage the rectangle.
        if !self.cursor_drawn {
            return;
        }
        let Some(rect) = self.cursor_rect(self.cursor_x, self.cursor_y) else {
            return;
        };
        self.restore_rect(rect);
        self.paint_cursor(self.cursor_x, self.cursor_y, rect);
        self.send_damage(&[rect]);
    }
}

/// One client's event port and its bounded reply queue.
///
/// `send` never blocks: frames that do not fit go to the queue and are
/// retried by [`PeerTransport::flush`] once per main-loop iteration. When the
/// queue is full the newest frame is dropped, so a slow client cannot stall
/// the server or grow memory (Jalon 5).
struct PeerTransport {
    port: usize,
    /// Set when the port can no longer be written: the peer is gone.
    dead: bool,
    /// Ring of queued complete messages; `qlen` valid frames from `qhead`.
    queue: [[u8; MAX_MESSAGE]; PEER_QUEUE_FRAMES],
    qlen: usize,
    qhead: usize,
    /// Frames dropped since the peer connected (diagnostic only).
    dropped: u32,
}

impl PeerTransport {
    fn new(port: usize) -> Self {
        Self {
            port,
            dead: false,
            queue: [[0; MAX_MESSAGE]; PEER_QUEUE_FRAMES],
            qlen: 0,
            qhead: 0,
            dropped: 0,
        }
    }

    fn close(&mut self) {
        let _ = call::handle_close(self.port);
        self.port = 0;
    }

    /// Try to hand every queued frame to the port, never blocking.
    ///
    /// Stops at the first transiently full port (the rest stays queued) and
    /// marks the peer dead on any other error.
    fn flush(&mut self) {
        if self.dead {
            return;
        }
        while self.qlen > 0 {
            let mut msg = IpcMessage::new(0);
            {
                let frame = &self.queue[self.qhead];
                let len = u32::from_le_bytes([frame[12], frame[13], frame[14], frame[15]]) as usize;
                if len < HEADER_LEN || len > MAX_MESSAGE {
                    // Only `send` writes the queue, so this cannot happen;
                    // drop the frame instead of wedging the queue.
                    self.qhead = (self.qhead + 1) % PEER_QUEUE_FRAMES;
                    self.qlen -= 1;
                    continue;
                }
                msg.payload[..len].copy_from_slice(&frame[..len]);
            }
            match call::ipc_try_send(self.port, &msg) {
                Ok(_) => {
                    self.qhead = (self.qhead + 1) % PEER_QUEUE_FRAMES;
                    self.qlen -= 1;
                }
                Err(Error::Again | Error::Interrupted) => return,
                // BadHandle, closed port, ...: the peer can never answer.
                Err(_) => {
                    self.dead = true;
                    return;
                }
            }
        }
    }
}

impl Transport for PeerTransport {
    fn send(&mut self, message: &[u8]) {
        if self.dead || message.len() > MAX_MESSAGE {
            return;
        }
        if let Ok((header, body)) = Header::decode_message(message) {
            if header.opcode == Opcode::ERROR.value() {
                if let Ok(Body::Error { code, .. }) = Body::decode(header.opcode, header.object_id, body) {
                    let _ = call::write(2, b"vasistas: wire ERROR code=");
                    let mut line = Line { buffer: [0; 192], len: 0 };
                    let _ = line.write_fmt(format_args!("{}\n", code));
                    let _ = call::write(2, &line.buffer[..line.len]);
                }
            }
        }
        if self.qlen == PEER_QUEUE_FRAMES {
            // Queue full: drop the newest frame and keep draining the rest.
            if self.dropped == 0 {
                log_text(b"vasistas: peer queue full, dropping event");
            }
            self.dropped = self.dropped.saturating_add(1);
        } else {
            let tail = (self.qhead + self.qlen) % PEER_QUEUE_FRAMES;
            self.queue[tail][..message.len()].copy_from_slice(message);
            self.qlen += 1;
        }
        self.flush();
    }

    fn transfer_region(&mut self, server_region: u64, client_pid: u32) -> Option<u64> {
        match call::handle_grant(server_region as usize, client_pid as usize) {
            Ok(handle) => Some(handle as u64),
            Err(error) => {
                let _ = call::write(2, b"vasistas: grant failed: ");
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

/// Peer table, in `.bss` beside [`SERVER`]: each transport owns a 64 KiB reply
/// queue and the user stack is 64 KiB, so it cannot be a local.
static mut PEERS: [Option<(PeerId, PeerTransport)>; MAX_PEERS] = [const { None }; MAX_PEERS];

fn main_loop(server_port: usize, display: Screen) -> ! {
    let back_len = display.back_len;
    let output_width = display.width;
    let output_height = display.height;
    let output_stride = display.stride;
    let backend = DisplayBackend::new(display);
    // SAFETY: single-threaded process, initialised once before the loop and
    // never aliased: `server` below is the only reference. `init_at` fills the
    // static in place.
    let server = unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(SERVER);
        Server::init_at(slot, backend)
    };
    // SAFETY: same single-threaded contract as `SERVER`; `peers` is the only
    // reference to the static and lives for the whole loop.
    let peers: &mut [Option<(PeerId, PeerTransport)>; MAX_PEERS] =
        unsafe { &mut *core::ptr::addr_of_mut!(PEERS) };
    install_global_budget(server, back_len);
    let mut iterations: u64 = 0;
    let mut focused: Option<(SessionId, SurfaceId)> = None;
    // Vasistas is the active display server: it subscribes and takes input
    // focus as soon as it is bound. console-admin is the rescue path when
    // Vasistas is absent, so a missing input service is not fatal here.
    let mut input = match InputClient::open(1) {
        Some(client) => {
            if !client.request_focus() {
                log_text(b"vasistas: input focus request failed");
            }
            log_text(b"vasistas: input subscribed");
            Some(client)
        }
        None => {
            log_text(b"vasistas: input unavailable, display only");
            None
        }
    };
    let mut focus_epoch = input.as_ref().map_or(0, |client| client.focus_epoch());
    log_text(b"vasistas: loop");

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
                log_text(b"vasistas: bad frame");
                continue;
            };
            let peer = PeerId::new(msg.sender);
            let mut slot = peer_slot(peers, peer);
            let mut new_peer = false;

            if slot.is_none() {
                if opcode != Opcode::HELLO.value() {
                    // A.1: only HELLO may open a session. Ignore silently: a
                    // log line here would let one peer flood the serial line.
                    continue;
                }
                let Some(client_port) = connect_event_port(&msg.payload[HEADER_LEN..len]) else {
                    log_text(b"vasistas: HELLO event port connect failed");
                    continue;
                };
                log_text(b"vasistas: HELLO accepted");
                slot = peers.iter().position(|entry| entry.is_none());
                let Some(slot) = slot else {
                    // No adapter slot: let the core answer `ERROR QUOTA` on
                    // the event port instead of dropping the HELLO silently.
                    let mut refused = PeerTransport::new(client_port);
                    let _ = server.handle(peer, &msg.payload[..len], &mut refused);
                    refused.close();
                    continue;
                };
                peers[slot] = Some((peer, PeerTransport::new(client_port)));
                new_peer = true;
            }
            let slot = slot.expect("slot set above");
            let transport = &mut peers[slot].as_mut().expect("slot filled").1;
            let _ = server.handle(peer, &msg.payload[..len], transport);
            // A.3.1 `OUTPUT_INFO`: the adapter knows the output geometry and
            // the peer slot was just created, so announce it exactly once per
            // `HELLO` (object_id is the output, never 0 per A.3.1).
            if new_peer {
                let _ = send_event(
                    transport,
                    Opcode::OUTPUT_INFO,
                    DISPLAY_OUTPUT_ID,
                    &Body::OutputInfo {
                        width: output_width,
                        height: output_height,
                        stride: output_stride,
                        format: vasistas_protocol::FORMAT_XRGB8888,
                        scale: 1,
                    },
                );
            }
            let dead = transport.dead;
            let peer_session = server.session_of(peer);
            if dead || peer_session.is_none() {
                drop_peer(server, peers, &mut focused, slot, dead);
            }
            // A first accepted commit takes input focus while nobody holds it.
            if focused.is_none() && opcode == Opcode::COMMIT.value() {
                if let Some(session) = peer_session {
                    let surface = SurfaceId::from_raw(frame_object(&msg.payload[..len]));
                    if matches!(
                        server.core().surface(session, surface),
                        Ok(surface) if surface.current.is_some()
                    ) {
                        focused = Some((session, surface));
                        send_focus(
                            server,
                            peers,
                            (session, surface),
                            INPUT_EVENT_FOCUS_GAINED,
                            focus_epoch,
                        );
                    }
                }
            }
        }

        // Jalon 5: drain every peer's reply queue once per turn, including
        // peers that sent nothing, so a transiently full port does not strand
        // its queued frames. A port that fails here is dropped like a dead
        // reply path.
        for index in 0..MAX_PEERS {
            let Some(transport) = peers[index].as_mut().map(|(_, transport)| transport) else {
                continue;
            };
            transport.flush();
            if !transport.dead {
                continue;
            }
            drop_peer(server, peers, &mut focused, index, true);
        }

        // The client mapping dies with its process; freed once per iteration
        // (including after a dead-peer disconnect, which retires regions) so
        // an idle server never keeps them alive.
        while let Some(region) = server.take_retired() {
            server.free_retired(region);
        }

        // Input (A.5): at most `RECV_BUDGET` pending batches per turn.
        let mut input_failed = false;
        if let Some(client) = input.as_mut() {
            for _ in 0..RECV_BUDGET {
                match client.poll() {
                    Poll::Empty => break,
                    Poll::Error => {
                        // Malformed payload or failed port: the adapter drops
                        // the input client (the port is lost), so report
                        // SERVICE_CHANGED and release display focus. A batch
                        // dropped by a full peer queue never reaches here and
                        // never invents a reset.
                        send_input_reset(
                            server,
                            peers,
                            &focused,
                            focus_epoch,
                            vasistas_protocol::INPUT_RESET_SERVICE_CHANGED,
                        );
                        focused = None;
                        input_failed = true;
                        break;
                    }
                    Poll::Reset {
                        focus_epoch: epoch,
                        reason,
                    } => {
                        // Keep focus, adopt the new epoch the input server
                        // expects and forward the reset reason.
                        focus_epoch = epoch;
                        send_input_reset(
                            server,
                            peers,
                            &focused,
                            focus_epoch,
                            reset_reason(reason),
                        );
                    }
                    Poll::Batch(batch) => {
                        for record in batch.records() {
                            handle_input(
                                server,
                                peers,
                                &mut focused,
                                focus_epoch,
                                &record.event,
                                record.text,
                            );
                        }
                    }
                }
            }
        }
        if input_failed {
            log_text(b"vasistas: input port error, display only");
            input = None;
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
                    log(&format_args!("vasistas: peer gone"));
                    let peer_session = server.session_of(peer);
                    let _ = server.disconnect(peer);
                    forget_focus(&mut focused, peer_session);
                    if let Some((_, mut transport)) = peers[index].take() {
                        transport.close();
                    }
                    let stats = server.core().stats();
                    log(&format_args!(
                        "vasistas: peer gone disconnect: sessions={} surfaces={} buffers={} used_bytes={}",
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
                "vasistas: sessions={} surfaces={} buffers={} used_bytes={}",
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
        != vasistas_protocol::MAGIC
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

/// Set when `outer` covers every pixel of `inner`.
fn rect_contains(outer: Rect, inner: Rect) -> bool {
    inner.x >= outer.x
        && inner.y >= outer.y
        && (inner.x as i64 + inner.w as i64) <= (outer.x as i64 + outer.w as i64)
        && (inner.y as i64 + inner.h as i64) <= (outer.y as i64 + outer.h as i64)
}

/// Smallest rectangle covering both inputs.
fn rect_union(a: Rect, b: Rect) -> Rect {
    let x0 = a.x.min(b.x) as i64;
    let y0 = a.y.min(b.y) as i64;
    let x1 = (a.x as i64 + a.w as i64).max(b.x as i64 + b.w as i64);
    let y1 = (a.y as i64 + a.h as i64).max(b.y as i64 + b.h as i64);
    Rect {
        x: x0 as i32,
        y: y0 as i32,
        w: (x1 - x0) as u32,
        h: (y1 - y0) as u32,
    }
}

/// `object_id` of a complete frame whose total length is `len`.
fn frame_object(payload: &[u8]) -> u64 {
    if payload.len() < 24 {
        return 0;
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&payload[16..24]);
    u64::from_le_bytes(bytes)
}

/// Drop `focused` when it names `session` (its peer went away).
fn forget_focus(focused: &mut Option<(SessionId, SurfaceId)>, session: Option<SessionId>) {
    if let (Some((focus, _)), Some(session)) = (*focused, session) {
        if focus == session {
            *focused = None;
        }
    }
}

/// Close a peer's session and its transport, then log the counters once.
///
/// `dead` only distinguishes a failed transport from a peer that left cleanly
/// in the log; the session is closed either way.
fn drop_peer(
    server: &mut Server<DisplayBackend>,
    peers: &mut [Option<(PeerId, PeerTransport)>; MAX_PEERS],
    focused: &mut Option<(SessionId, SurfaceId)>,
    index: usize,
    dead: bool,
) {
    let Some(peer) = peers[index].as_ref().map(|(peer, _)| *peer) else {
        return;
    };
    let peer_session = server.session_of(peer);
    if peer_session.is_some() {
        let _ = server.disconnect(peer);
    }
    forget_focus(focused, peer_session);
    let stats = server.core().stats();
    log(&format_args!(
        "vasistas: drop peer dead={} session={} sessions={} surfaces={} buffers={} used_bytes={}",
        dead,
        server.session_of(peer).is_some(),
        stats.sessions,
        stats.surfaces,
        stats.buffers,
        stats.used_bytes
    ));
    if let Some((_, mut transport)) = peers[index].take() {
        transport.close();
    }
}

/// Peer slot serving `session`, if any.
fn peer_index(
    server: &Server<DisplayBackend>,
    peers: &[Option<(PeerId, PeerTransport)>; MAX_PEERS],
    session: SessionId,
) -> Option<usize> {
    (0..MAX_PEERS).find(|&index| {
        peers[index]
            .as_ref()
            .and_then(|(peer, _)| server.session_of(*peer))
            == Some(session)
    })
}

/// Encode one spontaneous event and hand it to a peer transport.
///
/// Returns `false` when the body cannot be encoded, so the caller can ignore a
/// diagnostic failure. `request_id` is always `0` (A.3.1 events).
fn send_event(
    transport: &mut PeerTransport,
    opcode: Opcode,
    object: u64,
    body: &Body<'_>,
) -> bool {
    let mut message = [0u8; MAX_MESSAGE_BYTES as usize];
    let Ok(body_len) = body.encode(&mut message[HEADER_LEN..]) else {
        return false;
    };
    let total = HEADER_LEN + body_len;
    let header = Header {
        opcode: opcode.value(),
        flags: 0,
        message_bytes: total as u32,
        object_id: object,
        request_id: 0,
    };
    if header.encode(&mut message).is_err() {
        return false;
    }
    transport.send(&message[..total]);
    true
}

/// Encode one `INPUT_BATCH` for `object` and hand it to peer `index`.
fn send_batch(
    peers: &mut [Option<(PeerId, PeerTransport)>; MAX_PEERS],
    index: usize,
    object: u64,
    batch: &InputBatch,
) {
    let Some((_, transport)) = peers[index].as_mut() else {
        return;
    };
    let _ = send_event(transport, Opcode::INPUT_BATCH, object, &Body::InputBatch(*batch));
}

/// A.3.1 `INPUT_RESET`: tell the focused surface's client to resynchronise.
///
/// `focus_epoch` is the epoch the client must adopt; `reason` is one of the
/// protocol `INPUT_RESET_*` constants. A dropped input batch never invents a
/// reset: only an explicit input reset or the loss of the input port does.
fn send_input_reset(
    server: &Server<DisplayBackend>,
    peers: &mut [Option<(PeerId, PeerTransport)>; MAX_PEERS],
    focused: &Option<(SessionId, SurfaceId)>,
    focus_epoch: u32,
    reason: u32,
) {
    let Some((session, surface)) = *focused else {
        return;
    };
    if server.core().surface(session, surface).is_err() {
        return;
    }
    let Some(index) = peer_index(server, peers, session) else {
        return;
    };
    let Some((_, transport)) = peers[index].as_mut() else {
        return;
    };
    let _ = send_event(
        transport,
        Opcode::INPUT_RESET,
        surface.raw(),
        &Body::InputReset {
            focus_epoch,
            reason,
        },
    );
}

/// Map an input-protocol `RESET_REASON_*` to the display `INPUT_RESET` reason.
///
/// Both protocols assign `1` to RESYNC and `2` to SERVICE_CHANGED; unknown
/// values fall back to RESYNC, which is the safe "resynchronise" signal.
fn reset_reason(reason: u32) -> u32 {
    match reason {
        input_protocol::RESET_REASON_SERVICE_CHANGED => {
            vasistas_protocol::INPUT_RESET_SERVICE_CHANGED
        }
        _ => vasistas_protocol::INPUT_RESET_RESYNC,
    }
}

/// Forward one record to `surface`'s session, when both still exist.
fn send_input(
    server: &Server<DisplayBackend>,
    peers: &mut [Option<(PeerId, PeerTransport)>; MAX_PEERS],
    session: SessionId,
    surface: SurfaceId,
    record: InputRecord,
    focus_epoch: u32,
) {
    if server.core().surface(session, surface).is_err() {
        return;
    }
    let Some(index) = peer_index(server, peers, session) else {
        return;
    };
    let mut batch = InputBatch::default();
    batch.focus_epoch = focus_epoch;
    batch.count = 1;
    batch.records[0] = record;
    send_batch(peers, index, surface.raw(), &batch);
}

/// Send one synthetic focus record (`FOCUS_GAINED`/`FOCUS_LOST`).
fn send_focus(
    server: &Server<DisplayBackend>,
    peers: &mut [Option<(PeerId, PeerTransport)>; MAX_PEERS],
    target: (SessionId, SurfaceId),
    event_type: u16,
    focus_epoch: u32,
) {
    let mut record = InputRecord::default();
    record.event_type = event_type;
    send_input(server, peers, target.0, target.1, record, focus_epoch);
}

/// One input record: cursor, focus and forwarding.
fn handle_input(
    server: &mut Server<DisplayBackend>,
    peers: &mut [Option<(PeerId, PeerTransport)>; MAX_PEERS],
    focused: &mut Option<(SessionId, SurfaceId)>,
    focus_epoch: u32,
    event: &NormalizedEvent,
    text: [u8; input_protocol::INPUT_TEXT_LEN],
) {
    let record = InputRecord {
        timestamp_ns: event.timestamp_ns,
        sequence: event.sequence,
        device_id: event.device_id,
        event_type: event.event_type,
        code: event.code,
        value: event.value,
        flags: event.flags,
        text,
    };

    match event.event_type {
        INPUT_EVENT_POINTER_MOTION => {
            let (x, y) = if event.flags & INPUT_FLAG_ABSOLUTE != 0 {
                (event.value, event.code as i32)
            } else {
                let (cursor_x, cursor_y) = server.backend().cursor_pos();
                (
                    (cursor_x as i32).saturating_add(event.value),
                    (cursor_y as i32).saturating_add(event.code as i32),
                )
            };
            let (x, y) = server.backend_mut().move_cursor(x, y);
            let Some((session, surface)) = server.core().surface_at(x, y) else {
                return;
            };
            let Ok(origin) = server.core().surface_origin(session, surface) else {
                return;
            };
            let Ok(shape) = server.core().surface(session, surface) else {
                return;
            };
            let (local_x, local_y) = (x - origin.0, y - origin.1);
            if local_x >= shape.width || local_y >= shape.height {
                return;
            }
            let mut record = record;
            record.flags = INPUT_FLAG_ABSOLUTE;
            record.value = local_x as i32;
            record.code = local_y as u16;
            send_input(server, peers, session, surface, record, focus_epoch);
        }
        INPUT_EVENT_POINTER_BUTTON => {
            let (x, y) = server.backend().cursor_pos();
            if let Some(target) = server.core().surface_at(x, y) {
                if *focused != Some(target) {
                    if let Some(old) = *focused {
                        send_focus(server, peers, old, INPUT_EVENT_FOCUS_LOST, focus_epoch);
                    }
                    send_focus(server, peers, target, INPUT_EVENT_FOCUS_GAINED, focus_epoch);
                    *focused = Some(target);
                }
                send_input(server, peers, target.0, target.1, record, focus_epoch);
            }
        }
        INPUT_EVENT_KEY | INPUT_EVENT_TEXT => {
            if let Some((session, surface)) = *focused {
                send_input(server, peers, session, surface, record, focus_epoch);
            }
        }
        INPUT_EVENT_POINTER_AXIS => {
            let (x, y) = server.backend().cursor_pos();
            if let Some((session, surface)) = server.core().surface_at(x, y) {
                send_input(server, peers, session, surface, record, focus_epoch);
            }
        }
        _ => {}
    }
}

/// Decode `HELLO.path` and connect to the client's event port.
fn connect_event_port(body: &[u8]) -> Option<usize> {
    match Body::decode(Opcode::HELLO.value(), 0, body).ok()? {
        Body::Hello { path, .. } => call::ipc_connect(path).ok(),
        _ => None,
    }
}

/// Read the screen geometry from `/dev/vasistas/info`.
fn read_screen_info() -> Option<(u32, u32, u8, u32, u8, u8, u8)> {
    let fd = call::open("/dev/vasistas/info", 0).ok()?;
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

/// Bytes of RAM the kernel reports as available, or `None` when
/// `/proc/meminfo` cannot be read or parsed.
fn mem_available_bytes() -> Option<u64> {
    let fd = call::open("/proc/meminfo", 0).ok()?;
    let mut buffer = [0u8; 512];
    let count = call::read(fd, &mut buffer);
    let _ = call::close(fd);
    let count = count.ok()?.min(buffer.len());
    let text = core::str::from_utf8(&buffer[..count]).ok()?;
    let mut free = None;
    let mut available = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("MemAvailable:") {
            available = available.or_else(|| kilobytes(value));
        } else if let Some(value) = line.strip_prefix("MemFree:") {
            free = free.or_else(|| kilobytes(value));
        }
    }
    available.or(free)
}

/// Bytes of a `/proc/meminfo` value (`"      12345 kB"`).
fn kilobytes(value: &str) -> Option<u64> {
    let kb: u64 = value.split_whitespace().next()?.parse().ok()?;
    Some(kb.saturating_mul(1024))
}

/// Size and install the A.6 global pixel budget from `/proc/meminfo`.
///
/// Keeps a system reserve, the private backbuffer and a rescue reserve out of
/// the budget, and never goes below [`MIN_GLOBAL_BUDGET_BYTES`]. Unavailable
/// or unparsable meminfo leaves the budget disabled (`0`).
fn install_global_budget(server: &mut Server<DisplayBackend>, back_len: usize) {
    let Some(available) = mem_available_bytes() else {
        log_text(b"vasistas: global budget disabled (meminfo unavailable)");
        return;
    };
    let budget = available
        .saturating_sub(SYSTEM_RESERVE_BYTES)
        .saturating_sub(back_len as u64)
        .saturating_sub(RESCUE_RESERVE_BYTES)
        .max(MIN_GLOBAL_BUDGET_BYTES);
    server.set_global_budget(budget as usize);
    log(&format_args!(
        "vasistas: global budget {} bytes (meminfo {})",
        budget, available
    ));
}

/// Take exclusive ownership of the screen (K5) and map it `MAP_SHARED`.
fn open_screen() -> Screen {
    let (width, height, bpp, stride, red_shift, green_shift, blue_shift) =
        read_screen_info().unwrap_or((800, 600, 32, 800 * 4, 16, 8, 0));
    if bpp != 32 || (red_shift, green_shift, blue_shift) != (16, 8, 0) {
        log(&format_args!(
            "vasistas: unsupported screen bpp={} shifts={}/{}/{}",
            bpp, red_shift, green_shift, blue_shift
        ));
        halt();
    }
    let size = (stride as usize)
        .checked_mul(height as usize)
        .filter(|size| *size != 0)
        .unwrap_or(0);
    if size == 0 {
        log_text(b"vasistas: invalid screen geometry");
        halt();
    }
    log(&format_args!(
        "vasistas: screen {}x{} bpp={} stride={}",
        width, height, bpp, stride
    ));

    let display_fd = open_exclusive();
    // K5: only the owner may clear.
    match call::open("/dev/vasistas/clear", 2) {
        Ok(fd) => {
            let _ = call::write(fd, b"clear");
            let _ = call::close(fd);
        }
        Err(_) => log_text(b"vasistas: clear failed"),
    }
    let damage_fd = match call::open("/dev/vasistas/damage", 2) {
        Ok(fd) => fd,
        Err(_) => {
            log_text(b"vasistas: FATAL: /dev/vasistas/damage unavailable");
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
            log_text(b"vasistas: FATAL: framebuffer mmap failed");
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
            log_text(b"vasistas: FATAL: backbuffer mmap failed");
            halt();
        }
    };
    log(&format_args!(
        "vasistas: framebuffer mapped ({} bytes), backbuffer mapped",
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

/// Open `/dev/vasistas/0.0` for writing, retrying while another owner (or the
/// boot console) still holds it.
fn open_exclusive() -> usize {
    let request = TimeSpec {
        tv_sec: 0,
        tv_nsec: 20_000_000,
    };
    let mut remaining = TimeSpec::zero();
    let mut logged = false;
    loop {
        match call::open("/dev/vasistas/0.0", 2) {
            Ok(fd) => {
                log_text(b"vasistas: screen owned (K5)");
                return fd;
            }
            Err(Error::Busy) => {
                if !logged {
                    log_text(b"vasistas: /dev/vasistas/0.0 busy, waiting");
                    logged = true;
                }
                let _ = call::nanosleep(&request, &mut remaining);
            }
            Err(_) => {
                log_text(b"vasistas: FATAL: cannot open /dev/vasistas/0.0");
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
    log_text(b"vasistas: vasistas v0.1.0");
    log(&format_args!(
        "vasistas: pid={}",
        call::getpid().unwrap_or(0)
    ));
    let screen = open_screen();
    let server_port = match call::ipc_create_port(0) {
        Ok(port) => port,
        Err(_) => {
            log_text(b"vasistas: FATAL: ipc_create_port failed");
            halt();
        }
    };
    if call::ipc_bind_port(server_port, SERVER_PATH).is_err() {
        log_text(b"vasistas: FATAL: cannot bind /srv/vasistas");
        halt();
    }
    log_text(b"vasistas: bound /srv/vasistas");
    main_loop(server_port, screen)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("vasistas", info)
}
