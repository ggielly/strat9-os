//! Display VFS scheme : exposes framebuffer as `/dev/display/`.
//!
//! Modeled after Redox OS `vesad` + `driver-graphics` but implemented
//! as a kernel scheme with `GraphicsAdapter` support for multi-display.
//!
//! # Files
//!
//! - `info`              : read-only: adapter info, display list
//! - `0.0`, `0.1`, ...   : read/write: per-display screen (display_id.screen_id)
//! - `damage`            : write-only: present dirty rect or full screen
//! - `clear`             : write-only: clear screen to black
//!
//! # Multi-display
//!
//! ```text
//! /dev/display/
//! ├── info
//! ├── 0.0          ← display 0, screen 0 (primary)
//! ├── 0.1          ← display 0, screen 1 (secondary, if present)
//! ├── damage
//! └── clear
//! ```

use crate::{
    hardware::video::{
        graphics_adapter::{
            get_adapter_for_display, total_display_count, Damage, DisplayScreen, HeapScreen,
            SimpleDisplayAdapter,
        },
        Framebuffer,
    },
    syscall::error::SyscallError,
    vfs::scheme::{
        finalize_pseudo_stat, DirEntry, FileFlags, FileStat, OpenFlags, OpenResult, Scheme,
        DEV_CHAR_FS, DT_CHR, DT_REG,
    },
};
use alloc::{collections::BTreeMap, format, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Once, RwLock};

const MAX_HANDLES: usize = 64;

/// SIMD pixel-ingest ops for the Screen write path (RGB888 wire format ->
/// screen format). Detected once on first use; falls back to scalar
/// implementations when no SIMD extension is available.
fn fb_ops() -> crate::framebuffer::FramebufferOps {
    static OPS: Once<crate::framebuffer::FramebufferOps> = Once::new();
    *OPS.call_once(crate::framebuffer::FramebufferOps::detect)
}

#[derive(Clone, Debug)]
enum Handle {
    Root,
    Info,
    /// Per-display screen: (global_display_id, offscreen buffer).
    Screen(u32, Arc<RwLock<HeapScreen>>),
    Damage,
    Clear,
}

pub struct DisplayScheme {
    handles: RwLock<BTreeMap<u64, Handle>>,
    next: AtomicU64,
    /// Offscreen buffers keyed by display_id.
    screens: RwLock<BTreeMap<u32, Arc<RwLock<HeapScreen>>>>,
}

impl DisplayScheme {
    fn new() -> Self {
        Self {
            handles: RwLock::new(BTreeMap::new()),
            next: AtomicU64::new(1),
            screens: RwLock::new(BTreeMap::new()),
        }
    }

    fn alloc_id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }

    /// Get or create the offscreen buffer for a display.
    fn get_or_create_screen(&self, display_id: u32) -> Arc<RwLock<HeapScreen>> {
        let screens = self.screens.read();
        if let Some(screen) = screens.get(&display_id) {
            return screen.clone();
        }
        drop(screens);

        // Create new screen for this display.
        let (w, h) = get_adapter_for_display(display_id as usize)
            .map(|(a, local_id)| a.display_size(local_id))
            .unwrap_or((800, 600));

        let bpp = Framebuffer::info()
            .map(|i| i.format.bits_per_pixel)
            .unwrap_or(32);

        let screen = Arc::new(RwLock::new(HeapScreen::new(w, h, bpp)));
        self.screens.write().insert(display_id, screen.clone());
        screen
    }

    /// Parse "display_id.screen_id" path to global display_id.
    fn parse_display_path(path: &str) -> Option<u32> {
        let parts: Vec<&str> = path.split('.').collect();
        if parts.len() != 2 {
            return None;
        }
        let display_id: u32 = parts[0].parse().ok()?;
        let _screen_id: u32 = parts[1].parse().ok()?;
        // For now, screen_id is always 0 (single screen per display).
        Some(display_id)
    }
}

impl Scheme for DisplayScheme {
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let path = path.trim_start_matches('/');
        let id = self.alloc_id();

        if self.handles.read().len() >= MAX_HANDLES {
            return Err(SyscallError::OutOfMemory);
        }

        let handle = if path.is_empty() {
            Handle::Root
        } else if path == "info" {
            Handle::Info
        } else if path == "damage" {
            Handle::Damage
        } else if path == "clear" {
            Handle::Clear
        } else if let Some(display_id) = Self::parse_display_path(path) {
            let screen = self.get_or_create_screen(display_id);
            Handle::Screen(display_id, screen)
        } else {
            return Err(SyscallError::NotFound);
        };

        self.handles.write().insert(id, handle.clone());

        let flags = match &handle {
            Handle::Root => FileFlags::DIRECTORY,
            Handle::Info => FileFlags::DEVICE,
            Handle::Screen(..) => FileFlags::DEVICE | FileFlags::CHUNK_WRITE,
            Handle::Damage | Handle::Clear => FileFlags::DEVICE | FileFlags::CHUNK_WRITE,
        };

        Ok(OpenResult {
            file_id: id,
            size: None,
            flags,
        })
    }

    fn read(&self, fid: u64, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        let h = self.handles.read();
        let handle = h.get(&fid).ok_or(SyscallError::BadHandle)?;

        match handle {
            Handle::Root => {
                let total = total_display_count();
                let mut out = format!("displays={}\n", total);
                for i in 0..total {
                    if let Some((adapter, local_id)) = get_adapter_for_display(i) {
                        let (w, h) = adapter.display_size(local_id);
                        out.push_str(&format!("{}.0={}x{}\n", i, w, h));
                    }
                }
                out.push_str("damage\n");
                out.push_str("clear\n");
                let b = out.as_bytes();
                let start = offset as usize;
                if start >= b.len() {
                    return Ok(0);
                }
                let n = core::cmp::min(b.len() - start, buf.len());
                buf[..n].copy_from_slice(&b[start..start + n]);
                Ok(n)
            }
            Handle::Info => {
                let total = total_display_count();
                let mut s = format!("adapter_displays={}\n", total);
                for i in 0..total {
                    if let Some((adapter, local_id)) = get_adapter_for_display(i) {
                        let (w, h) = adapter.display_size(local_id);
                        s.push_str(&format!("display.{}.{}x{}\n", i, w, h));
                    }
                }
                let b = s.as_bytes();
                let start = offset as usize;
                if start >= b.len() {
                    return Ok(0);
                }
                let n = core::cmp::min(b.len() - start, buf.len());
                buf[..n].copy_from_slice(&b[start..start + n]);
                Ok(n)
            }
            Handle::Screen(_display_id, screen) => {
                // Read pixel data from offscreen buffer.
                let scr = screen.read();
                let scr_stride = scr.stride() as usize;
                let start = offset as usize;
                let total = scr_stride * scr.height() as usize;
                if start >= total {
                    return Ok(0);
                }
                let n = core::cmp::min(total - start, buf.len());
                unsafe {
                    core::ptr::copy_nonoverlapping(scr.pixels().add(start), buf.as_mut_ptr(), n);
                }
                Ok(n)
            }
            Handle::Damage | Handle::Clear => Err(SyscallError::PermissionDenied),
        }
    }

    fn write(&self, fid: u64, _offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        let h = self.handles.read();
        let handle = h.get(&fid).ok_or(SyscallError::BadHandle)?;

        match handle {
            Handle::Root | Handle::Info => Err(SyscallError::PermissionDenied),
            Handle::Screen(_display_id, screen) => {
                // Write pixel data to offscreen buffer.
                //
                // Wire format v2:
                //   [x u16le][y u16le][w u16le][r,g,b × w per row, ...]
                // - `w == 0` means "fill to the right edge" (screen_w - x).
                // - Rows advance by exactly w pixels per row while pixel
                //   data remains; a single write can carry h*w pixels.
                // - Pixels are RGB888 and are converted to the screen
                //   format on ingest (SIMD-accelerated for 32bpp screens).
                //
                // Note: the file offset is currently ignored; callers must
                // send complete rectangles starting at their (x, y).
                if buf.len() < 7 {
                    return Err(SyscallError::InvalidArgument);
                }
                let x = u16::from_le_bytes([buf[0], buf[1]]) as usize;
                let y = u16::from_le_bytes([buf[2], buf[3]]) as usize;
                let req_w = u16::from_le_bytes([buf[4], buf[5]]) as usize;
                let pixels = &buf[6..];

                let mut scr = screen.write();
                let bpp = scr.bpp() as usize;
                let bpx = bpp / 8;
                let screen_w = scr.width() as usize;
                let screen_h = scr.height() as usize;
                let stride = scr.stride() as usize;
                let dst = scr.pixels_mut();

                if x >= screen_w || y >= screen_h {
                    return Err(SyscallError::InvalidArgument);
                }
                // Clip the requested width to the right edge (w == 0 => edge).
                let w = if req_w == 0 {
                    screen_w - x
                } else {
                    req_w.min(screen_w - x)
                };
                if w == 0 || pixels.is_empty() {
                    return Ok(buf.len());
                }

                // Per-row ingest. Each row consumes exactly w*bpp/8 target
                // pixels from the stream; the stream ends when exhausted or
                // when the bottom of the screen is reached.
                let src_row_bytes = w * 3; // wire format is always RGB888
                let mut off = 0usize;
                let mut py = y;
                while py < screen_h && off + src_row_bytes <= pixels.len() {
                    let dst_off = py * stride + x * bpx;
                    unsafe {
                        if bpp == 32 {
                            // SIMD RGB888 -> XRGB8888 (pshufb-based, handles
                            // unaligned edges with a scalar tail). Plain
                            // stores: the HeapScreen lives in cached RAM,
                            // volatile would only block vectorization.
                            (fb_ops().convert)(
                                dst.add(dst_off) as *mut u32,
                                pixels.as_ptr().add(off),
                                w,
                            );
                        } else if bpp == 24 {
                            let ptr = dst.add(dst_off);
                            for i in 0..src_row_bytes {
                                *ptr.add(i) = pixels[off + i];
                            }
                        } else {
                            // Unsupported screen bpp: drop silently.
                            return Ok(buf.len());
                        }
                    }
                    off += src_row_bytes;
                    py += 1;
                }
                Ok(buf.len())
            }
            Handle::Damage => {
                // Parse: "present" or "display_id,x,y,w,h" or just "x,y,w,h" for display 0.
                let s = core::str::from_utf8(buf).unwrap_or("").trim();
                if s == "present" || s.is_empty() {
                    // Present all displays.
                    let total = total_display_count();
                    for i in 0..total {
                        if let Some((adapter, local_id)) = get_adapter_for_display(i) {
                            if let Some(screen_arc) = self.screens.read().get(&(i as u32)) {
                                let scr = screen_arc.read();
                                let damage = Damage::full(scr.width(), scr.height());
                                adapter.update_plane(local_id, &*scr, damage);
                            }
                        }
                    }
                } else {
                    let parts: Vec<&str> = s.split(',').collect();
                    let (display_id, x, y, w, h) = if parts.len() == 5 {
                        let did: u32 = parts[0].parse().unwrap_or(0);
                        (
                            did,
                            parts[1].parse().unwrap_or(0),
                            parts[2].parse().unwrap_or(0),
                            parts[3].parse().unwrap_or(0),
                            parts[4].parse().unwrap_or(0),
                        )
                    } else if parts.len() == 4 {
                        (
                            0u32,
                            parts[0].parse().unwrap_or(0),
                            parts[1].parse().unwrap_or(0),
                            parts[2].parse().unwrap_or(0),
                            parts[3].parse().unwrap_or(0),
                        )
                    } else {
                        return Err(SyscallError::InvalidArgument);
                    };
                    if w > 0 && h > 0 {
                        if let Some((adapter, local_id)) =
                            get_adapter_for_display(display_id as usize)
                        {
                            if let Some(screen_arc) = self.screens.read().get(&display_id) {
                                let scr = screen_arc.read();
                                let damage = Damage {
                                    x,
                                    y,
                                    width: w,
                                    height: h,
                                };
                                adapter.update_plane(local_id, &*scr, damage);
                            }
                        }
                    }
                }
                Ok(buf.len())
            }
            Handle::Clear => {
                // Clear all offscreen buffers to black.
                let screens = self.screens.read();
                for (_, screen_arc) in screens.iter() {
                    let mut scr = screen_arc.write();
                    unsafe {
                        core::ptr::write_bytes(
                            scr.pixels_mut(),
                            0,
                            scr.stride() as usize * scr.height() as usize,
                        );
                    }
                }
                // Also clear the onscreen framebuffers.
                let total = total_display_count();
                for i in 0..total {
                    if let Some((adapter, local_id)) = get_adapter_for_display(i) {
                        let fb = adapter.create_framebuffer(
                            adapter.display_size(local_id).0,
                            adapter.display_size(local_id).1,
                        );
                        adapter.update_plane(local_id, &fb, Damage::full(fb.width(), fb.height()));
                    }
                }
                Ok(buf.len())
            }
        }
    }

    fn close(&self, fid: u64) -> Result<(), SyscallError> {
        self.handles.write().remove(&fid);
        Ok(())
    }

    fn stat(&self, fid: u64) -> Result<FileStat, SyscallError> {
        let h = self.handles.read();
        let handle = h.get(&fid).ok_or(SyscallError::BadHandle)?;

        Ok(match handle {
            Handle::Root => finalize_pseudo_stat(
                FileStat {
                    st_ino: 0,
                    st_mode: 0o040555,
                    st_nlink: 2,
                    st_size: 0,
                    ..FileStat::zeroed()
                },
                DEV_CHAR_FS,
                0,
            ),
            Handle::Info => finalize_pseudo_stat(
                FileStat {
                    st_ino: 1,
                    st_mode: 0o0100444,
                    st_nlink: 1,
                    st_size: 256,
                    ..FileStat::zeroed()
                },
                DEV_CHAR_FS,
                1,
            ),
            Handle::Screen(did, _) => finalize_pseudo_stat(
                FileStat {
                    st_ino: 2 + *did as u64,
                    st_mode: 0o0100666,
                    st_nlink: 1,
                    st_size: 0,
                    ..FileStat::zeroed()
                },
                DEV_CHAR_FS,
                2 + *did as u64,
            ),
            Handle::Damage => finalize_pseudo_stat(
                FileStat {
                    st_ino: 0x100,
                    st_mode: 0o0100222,
                    st_nlink: 1,
                    st_size: 0,
                    ..FileStat::zeroed()
                },
                DEV_CHAR_FS,
                0x100,
            ),
            Handle::Clear => finalize_pseudo_stat(
                FileStat {
                    st_ino: 0x101,
                    st_mode: 0o0100222,
                    st_nlink: 1,
                    st_size: 0,
                    ..FileStat::zeroed()
                },
                DEV_CHAR_FS,
                0x101,
            ),
        })
    }

    fn readdir(&self, fid: u64) -> Result<Vec<DirEntry>, SyscallError> {
        let h = self.handles.read();
        if !matches!(h.get(&fid), Some(Handle::Root)) {
            return Err(SyscallError::InvalidArgument);
        }

        let total = total_display_count();
        let mut entries = Vec::new();

        entries.push(DirEntry {
            ino: 1,
            file_type: DT_REG,
            name: String::from("info"),
        });

        for i in 0..total {
            entries.push(DirEntry {
                ino: 2 + i as u64,
                file_type: DT_CHR,
                name: format!("{}.0", i),
            });
        }

        entries.push(DirEntry {
            ino: 0x100,
            file_type: DT_CHR,
            name: String::from("damage"),
        });
        entries.push(DirEntry {
            ino: 0x101,
            file_type: DT_CHR,
            name: String::from("clear"),
        });

        Ok(entries)
    }
}

/// Register the display scheme at `/dev/display/`.
pub fn register_display_scheme() -> Result<(), SyscallError> {
    // Create and register the default adapter from the global framebuffer.
    if let Some(adapter) = SimpleDisplayAdapter::from_framebuffer() {
        graphics_adapter::register_adapter(Arc::new(adapter));
    }

    let scheme = Arc::new(DisplayScheme::new());
    crate::vfs::scheme_router::register_scheme("display", scheme)?;
    crate::vfs::scheme_router::mount_scheme("display", "/dev/display")?;
    log::info!(
        "[display] Scheme at /dev/display/ ({} display(s))",
        total_display_count()
    );
    Ok(())
}

use super::graphics_adapter;
