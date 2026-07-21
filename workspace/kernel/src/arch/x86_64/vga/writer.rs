use super::{
    api::current_ui_scale,
    cursor::{CursorManager, CURSOR_H, CURSOR_PIXELS, CURSOR_W, TEXT_CURSOR_MAX_DIM},
    font::{parse_psf, parse_psf2_unicode_map, FontInfo, FONT_PSF},
    scrollback::{SbCell, ScrollbackBuffer},
    types::*,
};
use crate::framebuffer::{CanvasBuffer, DirtyRectSet, MAX_DIRTY_RECTS};
use alloc::vec::Vec;
use core::{
    fmt,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

pub(crate) static PRESENTED_FRAMES: AtomicU64 = AtomicU64::new(0);
pub(crate) static DOUBLE_BUFFER_MODE: AtomicBool = AtomicBool::new(false);
pub(crate) static VGA_PRESENT_REGION_COUNT: AtomicU64 = AtomicU64::new(0);
pub(crate) static VGA_PRESENT_PIXEL_COUNT: AtomicU64 = AtomicU64::new(0);

/// Core framebuffer terminal writer: owns the VGA text-mode state machine,
/// glyph cache, scrollback ring-buffer, hardware/software cursors, and
/// pixel-level rendering helpers.
const SCROLLBAR_W: usize = 12;

use crate::framebuffer::RgbColor;

#[derive(Clone, Copy)]
pub(crate) struct ClipRect {
    x: usize,
    y: usize,
    w: usize,
    h: usize,
}

// Mouse cursor (X arrow, 12×16) ==================================================================================================================================
const PRESENT_MIN_TICKS: u64 = 16;

// Selection clipboard ==========================================================================================================================================================================
const CLIPBOARD_CAP: usize = 8192;
static CLIPBOARD: spin::Mutex<([u8; CLIPBOARD_CAP], usize)> =
    spin::Mutex::new(([0u8; CLIPBOARD_CAP], 0));

pub struct VgaWriter {
    pub(crate) enabled: bool,
    /// Shared double-buffered framebuffer canvas (None before init).
    pub(crate) canvas: Option<CanvasBuffer>,
    /// Pixel format (pack_rgb/unpack_color helpers).
    pub(crate) fmt: PixelFormat,

    pub(crate) cols: usize,
    pub(crate) rows: usize,
    pub(crate) col: usize,
    pub(crate) row: usize,

    pub(crate) fg: u32,
    pub(crate) bg: u32,

    pub(crate) font: &'static [u8],
    pub(crate) font_info: FontInfo,
    pub(crate) glyph_mask_cache: Vec<u8>,
    pub(crate) unicode_map: Vec<(u32, usize)>,
    pub(crate) status_bar_height: usize,
    pub(crate) clip: ClipRect,

    /// Scrollback ring-buffer.
    pub(crate) sb: ScrollbackBuffer,
    pub(crate) scroll_offset: usize,

    /// Mouse + text cursor manager.
    pub(crate) cursor: CursorManager,

    // Text selection
    pub(crate) sel_active: bool,
    pub(crate) sel_start_row: usize,
    pub(crate) sel_start_col: usize,
    pub(crate) sel_end_row: usize,
    pub(crate) sel_end_col: usize,
    pub(crate) prepared_row_cells: Vec<(usize, u32, u32)>,

    /// When true, `end_viewport_render()` defers present : only marks dirty.
    /// The display server (or explicit `flush_display()`) triggers the actual present.
    pub(crate) console_defer_present: bool,
}

unsafe impl Send for VgaWriter {}

/// Short helpers to access the optional canvas without repeating unwrap.
impl VgaWriter {
    #[inline]
    fn can(&self) -> &CanvasBuffer {
        self.canvas
            .as_ref()
            .expect("VgaWriter canvas not initialized")
    }

    #[inline]
    fn canm(&mut self) -> &mut CanvasBuffer {
        self.canvas
            .as_mut()
            .expect("VgaWriter canvas not initialized")
    }
}

impl VgaWriter {
    /// Maximum capacity of the scrollback ring buffer.
    pub(crate) fn sb_capacity(&self) -> usize {
        self.sb.capacity(self.rows)
    }

    pub(crate) fn sb_row_at(&self, logical_idx: usize) -> Option<&Vec<SbCell>> {
        self.sb.row_at(logical_idx)
    }

    pub(crate) fn sb_push_row(&mut self, row: Vec<SbCell>) {
        let rows = self.rows;
        self.sb.push_row(row, rows);
    }

    pub(crate) fn build_glyph_mask_cache(font: &'static [u8], info: &FontInfo) -> Vec<u8> {
        let glyph_pixels = info.glyph_w.saturating_mul(info.glyph_h);
        let total_pixels = info.glyph_count.saturating_mul(glyph_pixels);
        let mut cache = Vec::with_capacity(total_pixels);
        if glyph_pixels == 0 || info.glyph_count == 0 {
            return cache;
        }

        let row_bytes = info.glyph_w.div_ceil(8);
        for glyph_index in 0..info.glyph_count {
            let start = info.data_offset + glyph_index * info.bytes_per_glyph;
            let end = start.saturating_add(info.bytes_per_glyph);
            if end > font.len() {
                cache.resize(cache.len().saturating_add(glyph_pixels), 0);
                continue;
            }
            let glyph_ptr = font[start..end].as_ptr();
            for gy in 0..info.glyph_h {
                for gx in 0..info.glyph_w {
                    let byte = unsafe { *glyph_ptr.add(gy * row_bytes + gx / 8) };
                    let mask = 0x80u8 >> (gx % 8);
                    cache.push(if (byte & mask) != 0 { 1 } else { 0 });
                }
            }
        }
        cache
    }

    pub(crate) fn glyph_mask_slice(&self, glyph_index: usize) -> Option<&[u8]> {
        let glyph_pixels = self
            .font_info
            .glyph_w
            .saturating_mul(self.font_info.glyph_h);
        if glyph_pixels == 0 {
            return None;
        }
        let start = glyph_index.checked_mul(glyph_pixels)?;
        let end = start.checked_add(glyph_pixels)?;
        self.glyph_mask_cache.get(start..end)
    }

    /// Creates a new instance.
    pub const fn new() -> Self {
        Self {
            enabled: false,
            canvas: None,
            fmt: PixelFormat {
                bpp: 0,
                red_size: 0,
                red_shift: 0,
                green_size: 0,
                green_shift: 0,
                blue_size: 0,
                blue_shift: 0,
            },
            cols: 0,
            rows: 0,
            col: 0,
            row: 0,
            fg: 0,
            bg: 0,
            font: &[],
            font_info: FontInfo {
                glyph_count: 0,
                bytes_per_glyph: 0,
                glyph_w: 8,
                glyph_h: 16,
                data_offset: 0,
                unicode_table_offset: None,
            },
            glyph_mask_cache: Vec::new(),
            unicode_map: Vec::new(),
            status_bar_height: 0,
            clip: ClipRect {
                x: 0,
                y: 0,
                w: 0,
                h: 0,
            },
            sb: ScrollbackBuffer::new(),
            scroll_offset: 0,
            cursor: CursorManager::new(),
            sel_active: false,
            sel_start_row: 0,
            sel_start_col: 0,
            sel_end_row: 0,
            sel_end_col: 0,
            prepared_row_cells: Vec::new(),
            console_defer_present: false,
        }
    }

    /// Performs the configure operation.
    pub(crate) fn configure(
        &mut self,
        fb_addr: *mut u8,
        fb_width: usize,
        fb_height: usize,
        pitch: usize,
        fmt: PixelFormat,
    ) -> bool {
        let Some(font_info) = parse_psf(FONT_PSF) else {
            return false;
        };
        let status_bar_height = font_info.glyph_h;
        let text_height = fb_height.saturating_sub(status_bar_height);
        let cols = fb_width / font_info.glyph_w;
        let rows = text_height / font_info.glyph_h;
        if cols == 0 || rows == 0 {
            return false;
        }
        let (fr, fg, fb) = color_to_rgb(Color::LightGrey);
        let (br, bg, bb) = color_to_rgb(Color::Black);

        self.enabled = true;
        self.canvas = Some(CanvasBuffer {
            addr: fb_addr,
            width: fb_width,
            height: fb_height,
            pitch,
            bpp: fmt.bpp,
            back_buffer: None,
            draw_to_back: false,
            dirty: DirtyRectSet::empty(),
            track_dirty: false,
            present_pending: false,
            last_present_tick: 0,
            ops: crate::framebuffer::FramebufferOps::detect(),
        });
        self.fmt = fmt;
        self.cols = cols;
        self.rows = rows;
        self.col = 0;
        self.row = 0;
        self.fg = fmt.pack_rgb(fr, fg, fb);
        self.bg = fmt.pack_rgb(br, bg, bb);
        self.font = FONT_PSF;
        self.font_info = font_info;
        self.glyph_mask_cache = Self::build_glyph_mask_cache(FONT_PSF, &self.font_info);
        self.unicode_map = parse_psf2_unicode_map(FONT_PSF, &self.font_info);
        self.status_bar_height = status_bar_height;
        self.clip = ClipRect {
            x: 0,
            y: 0,
            w: fb_width,
            h: fb_height,
        };
        self.sb = ScrollbackBuffer::new();
        self.scroll_offset = 0;
        self.cursor = CursorManager::new();
        self.cursor.tc_visible = false;
        self.cursor.tc_col = 0;
        self.cursor.tc_row = 0;
        self.cursor.tc_w = 0;
        self.cursor.tc_h = 0;
        self.cursor.tc_color = 0;
        self.sel_active = false;
        self.prepared_row_cells = Vec::new();
        true
    }

    /// Performs the pack color operation.
    #[inline]
    pub(crate) fn pack_color(&self, color: RgbColor) -> u32 {
        self.fmt.pack_rgb(color.r, color.g, color.b)
    }

    /// Performs the unpack color operation.
    pub(crate) fn unpack_color(&self, value: u32) -> RgbColor {
        /// Performs the unscale operation.
        fn unscale(v: u32, bits: u8) -> u8 {
            if bits == 0 {
                return 0;
            }
            let max = (1u32 << bits) - 1;
            ((v * 255) / max) as u8
        }

        let r = unscale(
            (value >> self.fmt.red_shift) & ((1u32 << self.fmt.red_size) - 1),
            self.fmt.red_size,
        );
        let g = unscale(
            (value >> self.fmt.green_shift) & ((1u32 << self.fmt.green_size) - 1),
            self.fmt.green_size,
        );
        let b = unscale(
            (value >> self.fmt.blue_shift) & ((1u32 << self.fmt.blue_size) - 1),
            self.fmt.blue_size,
        );
        RgbColor::new(r, g, b)
    }

    /// Sets color.
    pub fn set_color(&mut self, fg: Color, bg: Color) {
        self.set_rgb_color(fg.into(), bg.into());
    }

    /// Sets rgb color.
    pub fn set_rgb_color(&mut self, fg: RgbColor, bg: RgbColor) {
        self.fg = self.pack_color(fg);
        self.bg = self.pack_color(bg);
    }

    /// Performs the text colors operation.
    pub fn text_colors(&self) -> (RgbColor, RgbColor) {
        (self.unpack_color(self.fg), self.unpack_color(self.bg))
    }

    /// Performs the width operation.
    pub fn width(&self) -> usize {
        self.can().width
    }

    /// Performs the height operation.
    pub fn height(&self) -> usize {
        self.can().height
    }

    /// Performs the cols operation.
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// Performs the rows operation.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Performs the glyph size operation.
    pub fn glyph_size(&self) -> (usize, usize) {
        (self.font_info.glyph_w, self.font_info.glyph_h)
    }

    /// Sets cursor cell.
    pub fn set_cursor_cell(&mut self, col: usize, row: usize) {
        if !self.enabled || self.cols == 0 || self.rows == 0 {
            return;
        }
        if self.cursor.tc_visible {
            self.text_cursor_erase_hw();
            self.cursor.tc_visible = false;
            self.cursor.tc_dirty = true;
        }
        self.col = core::cmp::min(col, self.cols - 1);
        self.row = core::cmp::min(row, self.rows - 1);
    }

    /// Performs the text area height operation.
    pub(crate) fn text_area_height(&self) -> usize {
        self.can().height.saturating_sub(self.status_bar_height)
    }

    /// Performs the enabled operation.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Performs the framebuffer info operation.
    pub fn framebuffer_info(&self) -> FramebufferInfo {
        FramebufferInfo {
            available: self.enabled,
            width: self.can().width,
            height: self.can().height,
            pitch: self.can().pitch,
            bpp: self.fmt.bpp,
            red_size: self.fmt.red_size,
            red_shift: self.fmt.red_shift,
            green_size: self.fmt.green_size,
            green_shift: self.fmt.green_shift,
            blue_size: self.fmt.blue_size,
            blue_shift: self.fmt.blue_shift,
            text_cols: self.cols,
            text_rows: self.rows,
            glyph_w: self.font_info.glyph_w,
            glyph_h: self.font_info.glyph_h,
            double_buffer_mode: DOUBLE_BUFFER_MODE.load(Ordering::Relaxed),
            double_buffer_enabled: self.can().draw_to_back && self.can().back_buffer.is_some(),
            ui_scale: current_ui_scale(),
        }
    }

    /// Performs the in clip operation.
    #[inline]
    pub(crate) fn in_clip(&self, x: usize, y: usize) -> bool {
        x >= self.clip.x
            && y >= self.clip.y
            && x < self.clip.x.saturating_add(self.clip.w)
            && y < self.clip.y.saturating_add(self.clip.h)
    }

    /// Performs the clipped rect operation.
    pub(crate) fn clipped_rect(
        &self,
        x: usize,
        y: usize,
        width: usize,
        height: usize,
    ) -> Option<(usize, usize, usize, usize)> {
        if width == 0 || height == 0 || !self.enabled {
            return None;
        }
        let src_x2 = core::cmp::min(x.saturating_add(width), self.can().width);
        let src_y2 = core::cmp::min(y.saturating_add(height), self.can().height);
        let clip_x2 = self.clip.x.saturating_add(self.clip.w);
        let clip_y2 = self.clip.y.saturating_add(self.clip.h);

        let sx = core::cmp::max(x, self.clip.x);
        let sy = core::cmp::max(y, self.clip.y);
        let ex = core::cmp::min(src_x2, clip_x2);
        let ey = core::cmp::min(src_y2, clip_y2);
        if ex <= sx || ey <= sy {
            return None;
        }
        Some((sx, sy, ex - sx, ey - sy))
    }

    /// Performs the clear dirty operation.
    pub(crate) fn clear_dirty(&mut self) {
        self.canm().dirty.clear();
    }

    /// Performs the mark dirty rect operation.
    pub(crate) fn mark_dirty_rect(&mut self, x: usize, y: usize, width: usize, height: usize) {
        let canvas = self.can();
        if !canvas.track_dirty || width == 0 || height == 0 || !self.enabled {
            return;
        }
        let fw = canvas.width;
        let fh = canvas.height;
        let src_x2 = core::cmp::min(x.saturating_add(width), fw);
        let src_y2 = core::cmp::min(y.saturating_add(height), fh);
        let clip_x2 = self.clip.x.saturating_add(self.clip.w);
        let clip_y2 = self.clip.y.saturating_add(self.clip.h);
        let sx = core::cmp::max(x, self.clip.x);
        let sy = core::cmp::max(y, self.clip.y);
        let ex = core::cmp::min(src_x2, clip_x2);
        let ey = core::cmp::min(src_y2, clip_y2);
        if ex <= sx || ey <= sy {
            return;
        }
        let _ = canvas;
        self.canm()
            .dirty
            .include(sx as u32, sy as u32, (ex - sx) as u32, (ey - sy) as u32);
    }

    /// Sets clip rect.
    pub fn set_clip_rect(&mut self, x: usize, y: usize, width: usize, height: usize) {
        let x_end = core::cmp::min(x.saturating_add(width), self.can().width);
        let y_end = core::cmp::min(y.saturating_add(height), self.can().height);
        self.clip = ClipRect {
            x,
            y,
            w: x_end.saturating_sub(x),
            h: y_end.saturating_sub(y),
        };
    }

    /// Performs the reset clip rect operation.
    pub fn reset_clip_rect(&mut self) {
        self.clip = ClipRect {
            x: 0,
            y: 0,
            w: self.can().width,
            h: self.can().height,
        };
    }

    /// Performs the draw to back buffer operation.
    pub(crate) fn draw_to_back_buffer(&self) -> bool {
        self.can().draw_to_back && self.can().back_buffer.is_some()
    }

    /// Enables double buffer.
    pub fn enable_double_buffer(&mut self) -> bool {
        if !self.enabled {
            return false;
        }
        if self.can().back_buffer.is_none() {
            let mut buf = Vec::with_capacity(self.can().width.saturating_mul(self.can().height));
            for y in 0..self.can().height {
                for x in 0..self.can().width {
                    buf.push(self.read_hw_pixel_packed(x, y));
                }
            }
            self.canm().back_buffer = Some(buf);
        }
        self.canm().draw_to_back = true;
        self.canm().track_dirty = true;
        self.clear_dirty();
        true
    }

    /// Disables double buffer.
    pub fn disable_double_buffer(&mut self, present: bool) {
        if present {
            self.present();
        }
        self.canm().draw_to_back = false;
        self.canm().track_dirty = false;
        self.clear_dirty();
    }

    /// Performs the present operation.
    pub fn present(&mut self) {
        if !self.enabled {
            return;
        }

        // Rate-limit: skip if not enough time since last present.
        // Debug output calls present() very frequently; the human eye
        // cannot see >60 FPS, and each present() copies the full dirty region.
        let now = crate::process::scheduler::ticks();
        if now.saturating_sub(self.canm().last_present_tick) < PRESENT_MIN_TICKS {
            self.canm().present_pending = true;
            return;
        }

        // Extract all info through can() first to avoid borrow conflicts
        let bpp = self.fmt.bpp;
        let fb_addr = self.can().addr;
        let pitch = self.can().pitch;
        let fb_width = self.can().width;
        let track_dirty = self.can().track_dirty;

        // Early return: nothing dirty to present
        if track_dirty && self.can().dirty.len == 0 {
            return;
        }

        // Copy dirty rects to local array (no borrow on self after this)
        let region_count;
        let mut regions = [ClipRect {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        }; MAX_DIRTY_RECTS];
        if track_dirty {
            region_count = self.can().dirty.len;
            for idx in 0..region_count {
                let r = self.can().dirty.rects[idx];
                if r.is_valid() {
                    regions[idx] = ClipRect {
                        x: r.x0 as usize,
                        y: r.y0 as usize,
                        w: r.width() as usize,
                        h: r.height() as usize,
                    };
                }
            }
        } else {
            region_count = 1;
            regions[0] = ClipRect {
                x: 0,
                y: 0,
                w: fb_width,
                h: self.can().height,
            };
        }

        // Scoped block: get raw ptr to back_buffer then release immutable borrow
        let buf_ptr = {
            let Some(buf) = self.can().back_buffer.as_ref() else {
                return;
            };
            buf.as_ptr()
        };

        // Pixel copy loop using local vars only (no live borrow on self)
        for region_idx in 0..region_count {
            let region = regions[region_idx];
            if region.w == 0 || region.h == 0 {
                continue;
            }

            if bpp == 32 {
                let row_bytes = region.w * 4;
                for y in region.y..(region.y + region.h) {
                    let src = unsafe { buf_ptr.add(y * fb_width + region.x) as *const u8 };
                    let dst_off = y * pitch + region.x * 4;
                    unsafe {
                        core::ptr::copy_nonoverlapping(src, fb_addr.add(dst_off), row_bytes);
                    }
                }
            } else {
                // 24bpp: convert row-by-row to packed bytes, then bulk-copy.
                // Stack buffer avoids heap allocation; falls back to heap
                // for resolutions wider than 4K (3840 px).
                let row_bytes = region.w * 3;
                const MAX_STACK_ROW: usize = 3840 * 3;
                if row_bytes <= MAX_STACK_ROW {
                    let mut row_buf = [0u8; MAX_STACK_ROW];
                    for y in region.y..(region.y + region.h) {
                        let src_row = y * fb_width + region.x;
                        for x in 0..region.w {
                            let packed = unsafe { *buf_ptr.add(src_row + x) };
                            let off = x * 3;
                            row_buf[off] = packed as u8;
                            row_buf[off + 1] = (packed >> 8) as u8;
                            row_buf[off + 2] = (packed >> 16) as u8;
                        }
                        let dst_off = y * pitch + region.x * 3;
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                row_buf.as_ptr(),
                                fb_addr.add(dst_off),
                                row_bytes,
                            );
                        }
                    }
                } else {
                    let mut row_buf = alloc::vec![0u8; row_bytes];
                    for y in region.y..(region.y + region.h) {
                        let src_row = y * fb_width + region.x;
                        for x in 0..region.w {
                            let packed = unsafe { *buf_ptr.add(src_row + x) };
                            let off = x * 3;
                            row_buf[off] = packed as u8;
                            row_buf[off + 1] = (packed >> 8) as u8;
                            row_buf[off + 2] = (packed >> 16) as u8;
                        }
                        let dst_off = y * pitch + region.x * 3;
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                row_buf.as_ptr(),
                                fb_addr.add(dst_off),
                                row_bytes,
                            );
                        }
                    }
                }
            }

            VGA_PRESENT_REGION_COUNT.fetch_add(1, Ordering::Relaxed);
            VGA_PRESENT_PIXEL_COUNT
                .fetch_add(region.w.saturating_mul(region.h) as u64, Ordering::Relaxed);
        }

        PRESENTED_FRAMES.fetch_add(1, Ordering::Relaxed);
        self.clear_dirty();
        self.canm().present_pending = false;
        self.canm().last_present_tick = crate::process::scheduler::ticks();

        if crate::hardware::virtio::gpu::is_available() {
            if let Some(gpu) = crate::hardware::virtio::gpu::get_gpu() {
                gpu.flush_now();
            }
        }

        if self.cursor.mc_visible && self.cursor.mc_dirty {
            self.mc_save_hw();
            self.mc_draw_hw();
        }
        if self.cursor.tc_visible && self.cursor.tc_dirty {
            self.text_cursor_save_hw();
            self.text_cursor_draw_hw();
        }
    }

    pub(crate) fn request_present(&mut self) {
        if !self.draw_to_back_buffer() {
            return;
        }
        self.canm().present_pending = true;
        self.present_if_due(false);
    }

    pub(crate) fn present_if_due(&mut self, force: bool) {
        if !self.canm().present_pending || !self.draw_to_back_buffer() {
            return;
        }
        let now = crate::process::scheduler::ticks();
        if force || now.saturating_sub(self.canm().last_present_tick) >= PRESENT_MIN_TICKS {
            self.present();
        }
    }

    // Mouse cursor ====================

    /// Performs the mc save hw operation.
    /// Uses read_pixel_packed (back-buffer aware) instead of read_hw_pixel_packed.
    pub(crate) fn mc_save_hw(&mut self) {
        let x = self.cursor.mc_x;
        let y = self.cursor.mc_y;
        let fw = self.can().width;
        let fh = self.can().height;
        for cy in 0..CURSOR_H {
            for cx in 0..CURSOR_W {
                let px = x + cx as i32;
                let py = y + cy as i32;
                if px < 0 || py < 0 || px as usize >= fw || py as usize >= fh {
                    self.cursor.mc_save[cy * CURSOR_W + cx] = 0;
                    continue;
                }
                self.cursor.mc_save[cy * CURSOR_W + cx] =
                    self.read_pixel_packed(px as usize, py as usize);
            }
        }
    }

    /// Performs the mc draw hw operation.
    /// Uses put_pixel_raw (back-buffer aware) instead of write_hw_pixel_packed.
    pub(crate) fn mc_draw_hw(&mut self) {
        let x = self.cursor.mc_x;
        let y = self.cursor.mc_y;
        let black = self.pack_color(RgbColor::BLACK);
        let white = self.pack_color(RgbColor::WHITE);
        for cy in 0..CURSOR_H {
            for cx in 0..CURSOR_W {
                let p = CURSOR_PIXELS[cy * CURSOR_W + cx];
                if p == 0 {
                    continue;
                }
                let px = x + cx as i32;
                let py = y + cy as i32;
                if px < 0
                    || py < 0
                    || px as usize >= self.can().width
                    || py as usize >= self.can().height
                {
                    continue;
                }
                let color = if p == 1 { black } else { white };
                self.put_pixel_raw(px as usize, py as usize, color);
            }
        }
    }

    /// Performs the mc erase hw operation.
    /// Uses put_pixel_raw (back-buffer aware) instead of write_hw_pixel_packed.
    pub(crate) fn mc_erase_hw(&mut self) {
        let x = self.cursor.mc_x;
        let y = self.cursor.mc_y;
        for cy in 0..CURSOR_H {
            for cx in 0..CURSOR_W {
                if CURSOR_PIXELS[cy * CURSOR_W + cx] == 0 {
                    continue;
                }
                let px = x + cx as i32;
                let py = y + cy as i32;
                if px < 0
                    || py < 0
                    || px as usize >= self.can().width
                    || py as usize >= self.can().height
                {
                    continue;
                }
                self.put_pixel_raw(
                    px as usize,
                    py as usize,
                    self.cursor.mc_save[cy * CURSOR_W + cx],
                );
            }
        }
    }

    /// Updates mouse cursor.
    pub fn update_mouse_cursor(&mut self, x: i32, y: i32) {
        if !self.enabled {
            return;
        }
        if self.cursor.mc_visible && self.cursor.mc_x == x && self.cursor.mc_y == y {
            self.present_if_due(false);
            return;
        }
        if self.cursor.mc_visible {
            self.mc_erase_hw();
        }
        self.cursor.mc_x = x;
        self.cursor.mc_y = y;
        self.mc_save_hw();
        self.mc_draw_hw();
        self.cursor.mc_visible = true;
        self.present_if_due(false);
    }

    /// Performs the hide mouse cursor operation.
    pub fn hide_mouse_cursor(&mut self) {
        if self.cursor.mc_visible {
            self.mc_erase_hw();
            self.cursor.mc_visible = false;
        }
        self.present_if_due(false);
    }

    pub(crate) fn text_cursor_rect(&self) -> Option<(usize, usize, usize, usize)> {
        if !self.enabled {
            return None;
        }
        let (gw, gh) = self.glyph_size();
        if gw == 0 || gh == 0 {
            return None;
        }
        let x = self.cursor.tc_col.saturating_mul(gw);
        let y = self.cursor.tc_row.saturating_mul(gh);
        if x >= self.can().width || y >= self.can().height {
            return None;
        }
        Some((
            x,
            y,
            gw.min(TEXT_CURSOR_MAX_DIM).min(self.can().width - x),
            gh.min(TEXT_CURSOR_MAX_DIM).min(self.can().height - y),
        ))
    }

    /// Save text cursor pixels. Uses read_pixel_packed (back-buffer aware).
    pub(crate) fn text_cursor_save_hw(&mut self) {
        let Some((x, y, w, h)) = self.text_cursor_rect() else {
            self.cursor.tc_w = 0;
            self.cursor.tc_h = 0;
            return;
        };
        self.cursor.tc_w = w;
        self.cursor.tc_h = h;
        for cy in 0..h {
            for cx in 0..w {
                self.cursor.tc_save[cy * TEXT_CURSOR_MAX_DIM + cx] =
                    self.read_pixel_packed(x + cx, y + cy);
            }
        }
    }

    /// Draw text cursor. Uses put_pixel_raw (back-buffer aware).
    pub(crate) fn text_cursor_draw_hw(&mut self) {
        let Some((x, y, w, h)) = self.text_cursor_rect() else {
            return;
        };
        for cy in 0..h {
            for cx in 0..w {
                self.put_pixel_raw(x + cx, y + cy, self.cursor.tc_color);
            }
        }
    }

    /// Erase text cursor (restore saved pixels). Uses put_pixel_raw (back-buffer aware).
    pub(crate) fn text_cursor_erase_hw(&mut self) {
        let Some((x, y, w, h)) = self.text_cursor_rect() else {
            return;
        };
        let restore_w = w.min(self.cursor.tc_w);
        let restore_h = h.min(self.cursor.tc_h);
        for cy in 0..restore_h {
            for cx in 0..restore_w {
                self.put_pixel_raw(
                    x + cx,
                    y + cy,
                    self.cursor.tc_save[cy * TEXT_CURSOR_MAX_DIM + cx],
                );
            }
        }
    }

    pub(crate) fn draw_text_cursor_overlay(&mut self, color: RgbColor) {
        if !self.enabled {
            return;
        }
        let packed = self.pack_color(color);
        if self.cursor.tc_visible {
            self.text_cursor_erase_hw();
            self.cursor.tc_visible = false;
            self.cursor.tc_dirty = true;
        }
        if packed == self.bg {
            self.present();
            return;
        }
        self.cursor.tc_col = self.col;
        self.cursor.tc_row = self.row;
        self.cursor.tc_color = packed;
        self.text_cursor_save_hw();
        self.text_cursor_draw_hw();
        self.cursor.tc_visible = true;
        // Present immediately so the cursor is always visible after this call.
        // Using present() instead of present_if_due() avoids the race where
        // vgabuf_flush_to_framebuffer presents between draw and next blink.
        self.present();
    }

    /// Performs the hide text cursor operation on the writer.
    pub fn hide_text_cursor(&mut self) {
        if self.cursor.tc_visible {
            self.text_cursor_erase_hw();
            self.cursor.tc_visible = false;
            self.present();
        }
    }

    //  Text selection ==========

    /// Performs the sel normalized operation.
    pub(crate) fn sel_normalized(&self) -> (usize, usize, usize, usize) {
        let (sr, sc, er, ec) = (
            self.sel_start_row,
            self.sel_start_col,
            self.sel_end_row,
            self.sel_end_col,
        );
        if sr < er || (sr == er && sc <= ec) {
            (sr, sc, er, ec)
        } else {
            (er, ec, sr, sc)
        }
    }

    /// Performs the pixel to sb pos operation.
    pub fn pixel_to_sb_pos(&self, px: usize, py: usize) -> Option<(usize, usize)> {
        if !self.enabled {
            return None;
        }
        let gw = self.font_info.glyph_w;
        let gh = self.font_info.glyph_h;
        if gw == 0 || gh == 0 {
            return None;
        }
        let text_h = self.text_area_height();
        let text_w = self.can().width.saturating_sub(SCROLLBAR_W);
        if px >= text_w || py >= text_h {
            return None;
        }
        let vis_row = py / gh;
        let vis_col = px / gw;
        if vis_col >= self.cols {
            return None;
        }
        let total_complete = self.sb.rows.len();
        let has_partial = !self.sb.cur_row.is_empty();
        let total_virtual = total_complete + if has_partial { 1 } else { 0 };
        if total_virtual == 0 {
            return None;
        }
        let view_end = total_virtual.saturating_sub(self.scroll_offset);
        let view_start = view_end.saturating_sub(self.rows);
        let display_len = view_end.saturating_sub(view_start);
        if vis_row >= display_len {
            return None;
        }
        Some((view_start + vis_row, vis_col))
    }

    /// Starts selection.
    pub fn start_selection(&mut self, px: usize, py: usize) {
        if let Some((row, col)) = self.pixel_to_sb_pos(px, py) {
            self.sel_start_row = row;
            self.sel_start_col = col;
            self.sel_end_row = row;
            self.sel_end_col = col;
            self.sel_active = true;
            self.render_viewport_full();
        }
    }

    /// Updates selection.
    pub fn update_selection(&mut self, px: usize, py: usize) {
        if !self.sel_active {
            return;
        }
        if let Some((row, col)) = self.pixel_to_sb_pos(px, py) {
            if row == self.sel_end_row && col == self.sel_end_col {
                return;
            }
            self.sel_end_row = row;
            self.sel_end_col = col;
            self.render_viewport_full();
        }
    }

    /// Performs the end selection operation.
    pub fn end_selection(&mut self) {
        if !self.sel_active {
            return;
        }
        let (start_row, start_col, end_row, end_col) = self.sel_normalized();
        let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        for row in start_row..=end_row {
            let len = if row < self.sb.rows.len() {
                self.sb_row_at(row).map(|r| r.len()).unwrap_or(0)
            } else if row == self.sb.rows.len() {
                self.sb.cur_row.len()
            } else {
                break;
            };
            let c0 = if row == start_row {
                start_col.min(len)
            } else {
                0
            };
            let c1 = if row == end_row {
                end_col.min(len)
            } else {
                len
            };
            for col in c0..c1 {
                let ch = if row < self.sb.rows.len() {
                    self.sb_row_at(row)
                        .and_then(|r| r.get(col))
                        .map(|cell| cell.ch)
                        .unwrap_or(' ')
                } else {
                    self.sb.cur_row[col].ch
                };
                let mut buf = [0u8; 4];
                bytes.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
            if row < end_row {
                bytes.push(b'\n');
            }
        }
        if let Some(mut clip) = CLIPBOARD.try_lock() {
            let n = bytes.len().min(CLIPBOARD_CAP);
            clip.0[..n].copy_from_slice(&bytes[..n]);
            clip.1 = n;
        }
    }

    /// Performs the clear selection operation.
    pub fn clear_selection(&mut self) {
        if self.sel_active {
            self.sel_active = false;
            self.render_viewport_full();
        }
    }

    /// Performs the clear with operation.
    pub fn clear_with(&mut self, color: RgbColor) {
        if !self.enabled {
            return;
        }
        let packed = self.pack_color(color);
        let canvas = self.can();
        let (fw, fh) = (canvas.width, canvas.height);

        if canvas.draw_to_back && canvas.back_buffer.is_some() {
            let _ = canvas;
            if let Some(buf) = self.canm().back_buffer.as_mut() {
                buf.fill(packed);
            }
            self.mark_dirty_rect(0, 0, fw, fh);
            self.col = 0;
            self.row = 0;
            return;
        }

        let _ = canvas;
        // Direct HW path: bulk fill per row.
        if self.fmt.bpp == 32 {
            let canvas = self.can();
            let _row_bytes = fw * 4;
            for y in 0..fh {
                let off = y * canvas.pitch;
                unsafe {
                    let ptr = canvas.addr.add(off) as *mut u32;
                    for x in 0..fw {
                        core::ptr::write_volatile(ptr.add(x), packed);
                    }
                }
            }
        } else {
            for y in 0..fh {
                for x in 0..fw {
                    self.write_hw_pixel_packed(x, y, packed);
                }
            }
        }
        self.col = 0;
        self.row = 0;
    }

    /// Performs the clear operation.
    pub fn clear(&mut self) {
        self.clear_with(self.unpack_color(self.bg));
    }

    /// Performs the pixel offset operation.
    #[inline]
    pub(crate) fn pixel_offset(&self, x: usize, y: usize) -> Option<usize> {
        if x >= self.can().width || y >= self.can().height {
            return None;
        }
        let bytes_pp = self.fmt.bpp as usize / 8;
        let row = y.checked_mul(self.can().pitch)?;
        let col = x.checked_mul(bytes_pp)?;
        row.checked_add(col)
    }

    /// Writes hw pixel packed.
    pub(crate) fn write_hw_pixel_packed(&mut self, x: usize, y: usize, color: u32) {
        let Some(off) = self.pixel_offset(x, y) else {
            return;
        };
        unsafe {
            match self.fmt.bpp {
                32 => {
                    core::ptr::write_volatile(self.can().addr.add(off) as *mut u32, color);
                }
                24 => {
                    core::ptr::write_volatile(self.can().addr.add(off), (color & 0xFF) as u8);
                    core::ptr::write_volatile(
                        self.can().addr.add(off + 1),
                        ((color >> 8) & 0xFF) as u8,
                    );
                    core::ptr::write_volatile(
                        self.can().addr.add(off + 2),
                        ((color >> 16) & 0xFF) as u8,
                    );
                }
                _ => {}
            }
        }
    }

    /// Reads hw pixel packed.
    pub(crate) fn read_hw_pixel_packed(&self, x: usize, y: usize) -> u32 {
        let Some(off) = self.pixel_offset(x, y) else {
            return 0;
        };
        unsafe {
            match self.fmt.bpp {
                32 => core::ptr::read_volatile(self.can().addr.add(off) as *const u32),
                24 => {
                    let b0 = core::ptr::read_volatile(self.can().addr.add(off)) as u32;
                    let b1 = core::ptr::read_volatile(self.can().addr.add(off + 1)) as u32;
                    let b2 = core::ptr::read_volatile(self.can().addr.add(off + 2)) as u32;
                    b0 | (b1 << 8) | (b2 << 16)
                }
                _ => 0,
            }
        }
    }

    /// Reads pixel packed.
    pub(crate) fn read_pixel_packed(&self, x: usize, y: usize) -> u32 {
        if x >= self.can().width || y >= self.can().height {
            return 0;
        }
        if self.draw_to_back_buffer() {
            if let Some(buf) = self.can().back_buffer.as_ref() {
                return buf[y * self.can().width + x];
            }
        }
        self.read_hw_pixel_packed(x, y)
    }

    /// Performs the put pixel raw operation.
    pub(crate) fn put_pixel_raw(&mut self, x: usize, y: usize, color: u32) {
        if !self.enabled {
            return;
        }
        // Fast path : inline canvas bounds + clip check in one go.
        let canvas = self.can();
        let (fw, fh) = (canvas.width, canvas.height);
        if x >= fw || y >= fh || !self.in_clip(x, y) {
            return;
        }
        if canvas.draw_to_back && canvas.back_buffer.is_some() {
            let _ = canvas;
            if let Some(buf) = self.canm().back_buffer.as_mut() {
                buf[y * fw + x] = color;
            }
            self.mark_dirty_rect(x, y, 1, 1);
            return;
        }
        let _ = canvas;
        self.write_hw_pixel_packed(x, y, color);
    }

    /// Performs the draw pixel operation.
    pub fn draw_pixel(&mut self, x: usize, y: usize, color: RgbColor) {
        self.put_pixel_raw(x, y, self.pack_color(color));
    }

    /// Performs the draw pixel alpha operation.
    pub fn draw_pixel_alpha(&mut self, x: usize, y: usize, color: RgbColor, alpha: u8) {
        if !self.enabled
            || alpha == 0
            || x >= self.can().width
            || y >= self.can().height
            || !self.in_clip(x, y)
        {
            return;
        }
        if alpha == 255 {
            self.put_pixel_raw(x, y, self.pack_color(color));
            return;
        }
        let dst = self.unpack_color(self.read_pixel_packed(x, y));
        let inv = (255u16).saturating_sub(alpha as u16);
        let a = alpha as u16;
        let blended = RgbColor::new(
            ((color.r as u16 * a + dst.r as u16 * inv + 127) / 255) as u8,
            ((color.g as u16 * a + dst.g as u16 * inv + 127) / 255) as u8,
            ((color.b as u16 * a + dst.b as u16 * inv + 127) / 255) as u8,
        );
        self.put_pixel_raw(x, y, self.pack_color(blended));
    }

    /// Performs the draw line operation.
    pub fn draw_line(&mut self, x0: isize, y0: isize, x1: isize, y1: isize, color: RgbColor) {
        let mut x = x0;
        let mut y = y0;
        let dx = (x1 - x0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let dy = -(y1 - y0).abs();
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;
        let packed = self.pack_color(color);

        loop {
            if x >= 0 && y >= 0 {
                self.put_pixel_raw(x as usize, y as usize, packed);
            }
            if x == x1 && y == y1 {
                break;
            }
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                x += sx;
            }
            if e2 <= dx {
                err += dx;
                y += sy;
            }
        }
    }

    /// Performs the draw rect operation.
    pub fn draw_rect(&mut self, x: usize, y: usize, width: usize, height: usize, color: RgbColor) {
        if width == 0 || height == 0 {
            return;
        }
        let x2 = x.saturating_add(width - 1);
        let y2 = y.saturating_add(height - 1);
        self.draw_line(x as isize, y as isize, x2 as isize, y as isize, color);
        self.draw_line(x as isize, y as isize, x as isize, y2 as isize, color);
        self.draw_line(x2 as isize, y as isize, x2 as isize, y2 as isize, color);
        self.draw_line(x as isize, y2 as isize, x2 as isize, y2 as isize, color);
    }

    /// Performs the fill rect operation.
    pub fn fill_rect(&mut self, x: usize, y: usize, width: usize, height: usize, color: RgbColor) {
        let Some((sx, sy, sw, sh)) = self.clipped_rect(x, y, width, height) else {
            return;
        };
        let sw = sw.min(self.can().width.saturating_sub(sx));
        let sh = sh.min(self.can().height.saturating_sub(sy));
        if sw == 0 || sh == 0 {
            return;
        }
        let packed = self.pack_color(color);

        if self.draw_to_back_buffer() {
            let fw = self.can().width;
            let wrote = self
                .canm()
                .back_buffer
                .as_mut()
                .map(|buf| {
                    for py in sy..(sy + sh) {
                        let row = py * fw;
                        let start = row + sx;
                        let end = start + sw;
                        buf[start..end].fill(packed);
                    }
                })
                .is_some();
            if wrote {
                self.mark_dirty_rect(sx, sy, sw, sh);
            }
            return;
        }

        if self.fmt.bpp == 32 {
            for py in sy..(sy + sh) {
                let Some(row_off) = py
                    .checked_mul(self.can().pitch)
                    .and_then(|v| v.checked_add(sx * 4))
                else {
                    continue;
                };
                let count = sw;
                unsafe {
                    let ptr = self.can().addr.add(row_off) as *mut u32;
                    for i in 0..count {
                        core::ptr::write_volatile(ptr.add(i), packed);
                    }
                }
            }
            return;
        }

        for py in sy..(sy + sh) {
            for px in sx..(sx + sw) {
                self.write_hw_pixel_packed(px, py, packed);
            }
        }
    }

    /// Performs the fill rect alpha operation.
    pub fn fill_rect_alpha(
        &mut self,
        x: usize,
        y: usize,
        width: usize,
        height: usize,
        color: RgbColor,
        alpha: u8,
    ) {
        if !self.enabled || width == 0 || height == 0 || alpha == 0 {
            return;
        }
        if alpha == 255 {
            self.fill_rect(x, y, width, height, color);
            return;
        }
        let x_end = core::cmp::min(x.saturating_add(width), self.can().width);
        let y_end = core::cmp::min(y.saturating_add(height), self.can().height);
        for py in y..y_end {
            for px in x..x_end {
                self.draw_pixel_alpha(px, py, color, alpha);
            }
        }
    }

    /// Performs the blit rgb operation.
    pub fn blit_rgb(
        &mut self,
        dst_x: usize,
        dst_y: usize,
        src_width: usize,
        src_height: usize,
        pixels: &[RgbColor],
    ) -> bool {
        let len = src_width.saturating_mul(src_height);
        if !self.enabled || src_width == 0 || src_height == 0 || pixels.len() < len {
            return false;
        }
        let x_end = core::cmp::min(dst_x.saturating_add(src_width), self.can().width);
        let y_end = core::cmp::min(dst_y.saturating_add(src_height), self.can().height);
        if x_end <= dst_x || y_end <= dst_y {
            return true;
        }
        let copy_w = x_end - dst_x;
        let copy_h = y_end - dst_y;

        let fmt = self.fmt;
        if self.draw_to_back_buffer() {
            let fb_width = self.can().width;
            let wrote = self
                .canm()
                .back_buffer
                .as_mut()
                .map(|buf| {
                    for row in 0..copy_h {
                        let src_row = row * src_width;
                        let dst_row = (dst_y + row) * fb_width + dst_x;
                        for col in 0..copy_w {
                            buf[dst_row + col] = fmt.pack_rgb(
                                pixels[src_row + col].r,
                                pixels[src_row + col].g,
                                pixels[src_row + col].b,
                            );
                        }
                    }
                })
                .is_some();
            if wrote {
                self.mark_dirty_rect(dst_x, dst_y, copy_w, copy_h);
                return true;
            }
        }

        if fmt.bpp == 32 {
            let mut row_buf = alloc::vec![0u32; copy_w];
            for row in 0..copy_h {
                let src_row = row * src_width;
                for col in 0..copy_w {
                    row_buf[col] = self.pack_color(pixels[src_row + col]);
                }
                if let Some(off) = self.pixel_offset(dst_x, dst_y + row) {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            row_buf.as_ptr(),
                            self.can().addr.add(off) as *mut u32,
                            copy_w,
                        );
                    }
                }
            }
        } else {
            for row in 0..copy_h {
                let src_row = row * src_width;
                for col in 0..copy_w {
                    self.draw_pixel(dst_x + col, dst_y + row, pixels[src_row + col]);
                }
            }
        }
        true
    }

    /// Performs the blit rgb24 operation.
    pub fn blit_rgb24(
        &mut self,
        dst_x: usize,
        dst_y: usize,
        src_width: usize,
        src_height: usize,
        bytes: &[u8],
    ) -> bool {
        let needed = src_width.saturating_mul(src_height).saturating_mul(3);
        if !self.enabled || src_width == 0 || src_height == 0 || bytes.len() < needed {
            return false;
        }
        let x_end = core::cmp::min(dst_x.saturating_add(src_width), self.can().width);
        let y_end = core::cmp::min(dst_y.saturating_add(src_height), self.can().height);
        if x_end <= dst_x || y_end <= dst_y {
            return true;
        }
        let copy_w = x_end - dst_x;
        let copy_h = y_end - dst_y;

        let fmt = self.fmt;
        if self.draw_to_back_buffer() {
            let fb_width = self.can().width;
            let wrote = self
                .canm()
                .back_buffer
                .as_mut()
                .map(|buf| {
                    for row in 0..copy_h {
                        let src_base = row * src_width * 3;
                        let dst_row = (dst_y + row) * fb_width + dst_x;
                        for col in 0..copy_w {
                            let i = src_base + col * 3;
                            buf[dst_row + col] = fmt.pack_rgb(bytes[i], bytes[i + 1], bytes[i + 2]);
                        }
                    }
                })
                .is_some();
            if wrote {
                self.mark_dirty_rect(dst_x, dst_y, copy_w, copy_h);
                return true;
            }
        }

        if fmt.bpp == 32 {
            let mut row_buf = alloc::vec![0u32; copy_w];
            for row in 0..copy_h {
                let src_base = row * src_width * 3;
                for col in 0..copy_w {
                    let i = src_base + col * 3;
                    row_buf[col] =
                        self.pack_color(RgbColor::new(bytes[i], bytes[i + 1], bytes[i + 2]));
                }
                if let Some(off) = self.pixel_offset(dst_x, dst_y + row) {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            row_buf.as_ptr(),
                            self.can().addr.add(off) as *mut u32,
                            copy_w,
                        );
                    }
                }
            }
        } else {
            for row in 0..copy_h {
                for col in 0..copy_w {
                    let i = (row * src_width + col) * 3;
                    let color = RgbColor::new(bytes[i], bytes[i + 1], bytes[i + 2]);
                    self.draw_pixel(dst_x + col, dst_y + row, color);
                }
            }
        }
        true
    }

    /// Performs the blit rgba operation.
    pub fn blit_rgba(
        &mut self,
        dst_x: usize,
        dst_y: usize,
        src_width: usize,
        src_height: usize,
        bytes: &[u8],
        global_alpha: u8,
    ) -> bool {
        let needed = src_width.saturating_mul(src_height).saturating_mul(4);
        if !self.enabled
            || src_width == 0
            || src_height == 0
            || bytes.len() < needed
            || global_alpha == 0
        {
            return false;
        }

        let Some((sx, sy, sw, sh)) = self.clipped_rect(dst_x, dst_y, src_width, src_height) else {
            return true;
        };
        let src_x0 = sx.saturating_sub(dst_x);
        let src_y0 = sy.saturating_sub(dst_y);

        for row in 0..sh {
            let syi = src_y0 + row;
            for col in 0..sw {
                let sxi = src_x0 + col;
                let i = (syi * src_width + sxi) * 4;
                let r = bytes[i];
                let g = bytes[i + 1];
                let b = bytes[i + 2];
                let sa = bytes[i + 3];
                if sa == 0 {
                    continue;
                }
                let a = ((sa as u16 * global_alpha as u16 + 127) / 255) as u8;
                let dx = sx + col;
                let dy = sy + row;
                if a == 255 {
                    self.put_pixel_raw(dx, dy, self.pack_color(RgbColor::new(r, g, b)));
                } else if a != 0 {
                    self.draw_pixel_alpha(dx, dy, RgbColor::new(r, g, b), a);
                }
            }
        }
        true
    }

    /// Performs the blit sprite rgba operation.
    pub fn blit_sprite_rgba(
        &mut self,
        dst_x: usize,
        dst_y: usize,
        sprite: SpriteRgba<'_>,
        global_alpha: u8,
    ) -> bool {
        self.blit_rgba(
            dst_x,
            dst_y,
            sprite.width,
            sprite.height,
            sprite.pixels,
            global_alpha,
        )
    }

    /// Performs the draw text at operation.
    pub fn draw_text_at(
        &mut self,
        pixel_x: usize,
        pixel_y: usize,
        text: &str,
        fg: RgbColor,
        bg: RgbColor,
    ) {
        if !self.enabled {
            return;
        }
        let gw = self.font_info.glyph_w;
        let gh = self.font_info.glyph_h;
        let fg_packed = self.pack_color(fg);
        let bg_packed = self.pack_color(bg);
        let mut cx = pixel_x;
        let cy = pixel_y;
        for ch in text.chars() {
            if ch == '\n' {
                break;
            }
            if cx + gw > self.can().width || cy + gh > self.can().height {
                break;
            }
            self.draw_glyph_at_pixel(cx, cy, ch, fg_packed, bg_packed);
            cx += gw;
        }
    }

    /// Performs the glyph index for char operation.
    pub(crate) fn glyph_index_for_char(&self, ch: char) -> usize {
        if ch.is_ascii() {
            let idx = ch as usize;
            if idx < self.font_info.glyph_count {
                return idx;
            }
        }
        let cp = ch as u32;
        if let Some((_, glyph)) = self.unicode_map.iter().find(|(u, _)| *u == cp) {
            return *glyph;
        }
        if let Some((_, glyph)) = self.unicode_map.iter().find(|(u, _)| *u == ('?' as u32)) {
            return *glyph;
        }
        if ('?' as usize) < self.font_info.glyph_count {
            return '?' as usize;
        }
        0
    }

    /// Performs the draw glyph index at pixel operation.
    pub(crate) fn draw_glyph_index_at_pixel(
        &mut self,
        pixel_x: usize,
        pixel_y: usize,
        glyph_index: usize,
        fg: u32,
        bg: u32,
    ) {
        if !self.enabled {
            return;
        }
        let glyph_index = core::cmp::min(glyph_index, self.font_info.glyph_count.saturating_sub(1));
        let gw = self.font_info.glyph_w;
        let gh = self.font_info.glyph_h;
        let glyph_pixels = gw.saturating_mul(gh);
        let Some(mask) = self.glyph_mask_slice(glyph_index) else {
            return;
        };
        let mask_ptr = mask.as_ptr();

        if self.draw_to_back_buffer()
            && pixel_x + gw <= self.can().width
            && pixel_y + gh <= self.can().height
        {
            let fb_width = self.can().width;
            if let Some(buf) = self.canm().back_buffer.as_mut() {
                for gy in 0..gh {
                    let row_start = (pixel_y + gy) * fb_width + pixel_x;
                    buf[row_start..row_start + gw].fill(bg);
                    for gx in 0..gw {
                        let idx = gy * gw + gx;
                        if idx >= glyph_pixels {
                            continue;
                        }
                        let bit = unsafe { *mask_ptr.add(idx) };
                        if bit != 0 {
                            buf[row_start + gx] = fg;
                        }
                    }
                }
            }
            self.mark_dirty_rect(pixel_x, pixel_y, gw, gh);
        } else {
            if self.fmt.bpp == 32 {
                for gy in 0..gh {
                    if let Some(off) = self.pixel_offset(pixel_x, pixel_y + gy) {
                        let row_ptr = unsafe { self.can().addr.add(off) } as *mut u32;
                        for gx in 0..gw {
                            let idx = gy * gw + gx;
                            let color = if idx < glyph_pixels && unsafe { *mask_ptr.add(idx) } != 0
                            {
                                fg
                            } else {
                                bg
                            };
                            unsafe {
                                core::ptr::write_volatile(row_ptr.add(gx), color);
                            }
                        }
                    }
                }
            } else {
                for gy in 0..gh {
                    for gx in 0..gw {
                        let idx = gy * gw + gx;
                        if idx >= glyph_pixels {
                            continue;
                        }
                        let color = if unsafe { *mask_ptr.add(idx) } != 0 {
                            fg
                        } else {
                            bg
                        };
                        self.put_pixel_raw(pixel_x + gx, pixel_y + gy, color);
                    }
                }
            }
        }
    }

    /// Performs the draw glyph at pixel operation.
    pub(crate) fn draw_glyph_at_pixel(
        &mut self,
        pixel_x: usize,
        pixel_y: usize,
        ch: char,
        fg: u32,
        bg: u32,
    ) {
        let glyph_index = self.glyph_index_for_char(ch);
        self.draw_glyph_index_at_pixel(pixel_x, pixel_y, glyph_index, fg, bg);
    }

    pub(crate) fn fill_text_span_bg(
        &mut self,
        pixel_x: usize,
        pixel_y: usize,
        width: usize,
        height: usize,
        bg: u32,
    ) {
        if self.draw_to_back_buffer()
            && pixel_x + width <= self.can().width
            && pixel_y + height <= self.can().height
        {
            let fb_width = self.can().width;
            if let Some(buf) = self.canm().back_buffer.as_mut() {
                for row in 0..height {
                    let start = (pixel_y + row) * fb_width + pixel_x;
                    let end = start + width;
                    buf[start..end].fill(bg);
                }
            }
            self.mark_dirty_rect(pixel_x, pixel_y, width, height);
            return;
        }

        let gh = height;
        let color = self.unpack_color(bg);
        self.fill_rect(pixel_x, pixel_y, width, gh, color);
    }

    pub(crate) fn clear_text_line_pixels(&mut self, vis_row: usize) {
        let gh = self.font_info.glyph_h;
        let text_w = self.can().width.saturating_sub(SCROLLBAR_W);
        self.fill_text_span_bg(0, vis_row.saturating_mul(gh), text_w, gh, self.bg);
    }

    pub(crate) fn visible_virtual_bounds(&self) -> (usize, usize, usize, usize, bool) {
        let total_complete = self.sb.rows.len();
        let has_partial = !self.sb.cur_row.is_empty();
        let total_virtual = total_complete + if has_partial { 1 } else { 0 };
        let view_end = total_virtual.saturating_sub(self.scroll_offset);
        let view_start = view_end.saturating_sub(self.rows);
        (
            total_complete,
            total_virtual,
            view_start,
            view_end,
            has_partial,
        )
    }

    pub(crate) fn sync_live_cursor_from_view(
        &mut self,
        total_complete: usize,
        view_start: usize,
        view_end: usize,
    ) {
        let display_len = view_end.saturating_sub(view_start);
        self.row = if display_len > 0 { display_len - 1 } else { 0 };
        let last_virt = view_start + display_len.saturating_sub(1);
        let last_len = if last_virt < total_complete {
            self.sb_row_at(last_virt).map(|row| row.len()).unwrap_or(0)
        } else if last_virt == total_complete {
            self.sb.cur_row.len()
        } else {
            0
        };
        self.col = last_len.min(self.cols);
    }

    pub(crate) fn selection_colors_for_cell(
        &self,
        virt_row: usize,
        col: usize,
        fg: u32,
        bg: u32,
    ) -> (u32, u32) {
        if !self.sel_active {
            return (fg, bg);
        }
        let (sel_sr, sel_sc, sel_er, sel_ec) = self.sel_normalized();
        let in_sel = if virt_row < sel_sr || virt_row > sel_er {
            false
        } else if sel_sr == sel_er {
            col >= sel_sc && col < sel_ec
        } else if virt_row == sel_sr {
            col >= sel_sc
        } else if virt_row == sel_er {
            col < sel_ec
        } else {
            true
        };
        if in_sel {
            (
                self.pack_color(RgbColor::WHITE),
                self.pack_color(RgbColor::new(0x26, 0x5F, 0xCC)),
            )
        } else {
            (fg, bg)
        }
    }

    pub(crate) fn render_virtual_row(
        &mut self,
        virt_row: usize,
        vis_row: usize,
        total_complete: usize,
        has_partial: bool,
    ) {
        let glyph_h = self.font_info.glyph_h;
        let glyph_w = self.font_info.glyph_w;
        let py = vis_row.saturating_mul(glyph_h);

        let (row_ptr, row_len) = if virt_row < total_complete {
            let row = match self.sb_row_at(virt_row) {
                Some(row) => row,
                None => return,
            };
            (row.as_ptr(), row.len())
        } else if has_partial && virt_row == total_complete {
            (self.sb.cur_row.as_ptr(), self.sb.cur_row.len())
        } else {
            (core::ptr::null(), 0)
        };

        let cell_count = row_len.min(self.cols);
        let text_w = self.can().width.saturating_sub(SCROLLBAR_W);
        let used_width = cell_count.saturating_mul(glyph_w).min(text_w);

        if self.draw_to_back_buffer() && py + glyph_h <= self.can().height {
            let fb_width = self.can().width;
            let default_bg = self.bg;
            let glyph_pixels = glyph_w.saturating_mul(glyph_h);
            let glyph_cache_ptr = self.glyph_mask_cache.as_ptr();
            self.prepared_row_cells.clear();
            if self.prepared_row_cells.capacity() < cell_count {
                self.prepared_row_cells
                    .reserve(cell_count - self.prepared_row_cells.capacity());
            }
            for col in 0..cell_count {
                let cell = unsafe { &*row_ptr.add(col) };
                let glyph_index = self.glyph_index_for_char(cell.ch);
                let (draw_fg, draw_bg) =
                    self.selection_colors_for_cell(virt_row, col, cell.fg, cell.bg);
                self.prepared_row_cells
                    .push((glyph_index, draw_fg, draw_bg));
            }
            let cells_ptr = self.prepared_row_cells.as_ptr();
            let cells_len = self.prepared_row_cells.len();
            if let Some(buf) = self.canm().back_buffer.as_mut() {
                for gy in 0..glyph_h {
                    let row_start = (py + gy) * fb_width;
                    buf[row_start..row_start + text_w].fill(default_bg);
                }

                for col in 0..cells_len {
                    let (glyph_index, draw_fg, draw_bg) = unsafe { *cells_ptr.add(col) };
                    let px = col.saturating_mul(glyph_w);
                    if draw_bg != default_bg {
                        for gy in 0..glyph_h {
                            let row_start = (py + gy) * fb_width + px;
                            buf[row_start..row_start + glyph_w].fill(draw_bg);
                        }
                    }

                    let glyph_base = glyph_index.saturating_mul(glyph_pixels);
                    for gy in 0..glyph_h {
                        let row_start = (py + gy) * fb_width + px;
                        for gx in 0..glyph_w {
                            let idx = glyph_base + gy * glyph_w + gx;
                            let bit = unsafe { *glyph_cache_ptr.add(idx) };
                            if bit != 0 {
                                buf[row_start + gx] = draw_fg;
                            }
                        }
                    }
                }
            }

            self.mark_dirty_rect(0, py, text_w, glyph_h);
            return;
        }

        for col in 0..cell_count {
            let px = col.saturating_mul(glyph_w);
            let cell = unsafe { &*row_ptr.add(col) };
            let (draw_fg, draw_bg) =
                self.selection_colors_for_cell(virt_row, col, cell.fg, cell.bg);
            self.draw_glyph_at_pixel(px, py, cell.ch, draw_fg, draw_bg);
        }
        if text_w > used_width {
            self.fill_text_span_bg(used_width, py, text_w - used_width, glyph_h, self.bg);
        }
    }

    pub(crate) fn redraw_visible_rows(&mut self, start_vis_row: usize, count: usize) {
        let (total_complete, _, view_start, view_end, has_partial) = self.visible_virtual_bounds();
        let display_len = view_end.saturating_sub(view_start);
        let end_vis_row = start_vis_row.saturating_add(count).min(self.rows);
        for vis_row in start_vis_row..end_vis_row {
            if vis_row < display_len {
                self.render_virtual_row(view_start + vis_row, vis_row, total_complete, has_partial);
            } else {
                self.clear_text_line_pixels(vis_row);
            }
        }
    }

    pub(crate) fn ensure_back_buffer_for_viewport(&mut self) {
        let canvas = self.can();
        if canvas.back_buffer.is_none() {
            let total = canvas.width.saturating_mul(canvas.height);
            if total > 0 {
                let mut buf = alloc::vec![0u32; total];
                // Sync back buffer from hardware so content written directly
                // (e.g. status bar during boot) survives present().
                if self.enabled && !canvas.addr.is_null() {
                    if self.fmt.bpp == 32 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                canvas.addr as *const u8,
                                buf.as_mut_ptr() as *mut u8,
                                total * 4,
                            );
                        }
                    } else {
                        for y in 0..canvas.height {
                            for x in 0..canvas.width {
                                buf[y * canvas.width + x] = self.read_hw_pixel_packed(x, y);
                            }
                        }
                    }
                }
                let _ = canvas;
                self.canm().back_buffer = Some(buf);
            }
        }
    }

    pub(crate) fn begin_viewport_render(&mut self) -> (bool, bool) {
        self.ensure_back_buffer_for_viewport();
        let canvas = self.can();
        let prev_draw_to_back = canvas.draw_to_back;
        let prev_track_dirty = canvas.track_dirty;
        let has_back = canvas.back_buffer.is_some();
        let _ = canvas;
        if has_back {
            let canvas = self.canm();
            canvas.draw_to_back = true;
            canvas.track_dirty = true;
            canvas.dirty.clear();
        }
        (prev_draw_to_back, prev_track_dirty)
    }

    pub(crate) fn end_viewport_render(&mut self, prev_draw_to_back: bool, prev_track_dirty: bool) {
        let has_back = self.can().back_buffer.is_some();
        if has_back {
            if !self.console_defer_present {
                self.request_present();
                let now = crate::process::scheduler::ticks();
                let force_present = self.canm().last_present_tick == 0 || now == 0;
                self.present_if_due(force_present);
            }
            let canvas = self.canm();
            canvas.draw_to_back = prev_draw_to_back;
            canvas.track_dirty = prev_track_dirty;
            if !prev_track_dirty {
                canvas.dirty.clear();
            }
        }
    }

    pub(crate) fn finalize_live_view_state(&mut self) {
        let (total_complete, _, view_start, view_end, _) = self.visible_virtual_bounds();
        if self.scroll_offset == 0 {
            self.sync_live_cursor_from_view(total_complete, view_start, view_end);
        }
    }

    pub(crate) fn render_viewport_full(&mut self) {
        let (prev_draw_to_back, prev_track_dirty) = self.begin_viewport_render();
        let text_h = self.text_area_height();
        let text_w = self.can().width.saturating_sub(SCROLLBAR_W);
        self.fill_rect(0, 0, text_w, text_h, self.unpack_color(self.bg));
        self.redraw_visible_rows(0, self.rows);
        self.finalize_live_view_state();
        self.draw_scrollbar_inner();
        self.end_viewport_render(prev_draw_to_back, prev_track_dirty);
    }

    pub(crate) fn refresh_viewport_decorations(&mut self) {
        let (prev_draw_to_back, prev_track_dirty) = self.begin_viewport_render();
        self.finalize_live_view_state();
        self.draw_scrollbar_inner();
        self.end_viewport_render(prev_draw_to_back, prev_track_dirty);
    }

    pub(crate) fn set_scroll_offset_and_render(&mut self, new_offset: usize) {
        let old_offset = self.scroll_offset;
        self.scroll_offset = new_offset;
        if !self.redraw_from_scrollback_incremental(old_offset) {
            self.redraw_from_scrollback();
        }
    }

    pub(crate) fn move_text_view_pixels_up(&mut self, pixels: usize) {
        if pixels == 0 {
            return;
        }
        let text_h = self.text_area_height();
        let text_w = self.can().width.saturating_sub(SCROLLBAR_W);
        if pixels >= text_h {
            self.fill_rect(0, 0, text_w, text_h, self.unpack_color(self.bg));
            return;
        }
        let move_rows = text_h - pixels;
        if self.draw_to_back_buffer() {
            let row_width = self.can().width;
            if let Some(buf) = self.canm().back_buffer.as_mut() {
                buf.copy_within(pixels * row_width..text_h * row_width, 0);
            }
            self.mark_dirty_rect(0, 0, row_width, text_h);
        } else {
            unsafe {
                core::ptr::copy(
                    self.can().addr.add(pixels * self.can().pitch),
                    self.can().addr,
                    move_rows * self.can().pitch,
                );
            }
        }
        self.fill_rect(0, move_rows, text_w, pixels, self.unpack_color(self.bg));
    }

    pub(crate) fn move_text_view_pixels_down(&mut self, pixels: usize) {
        if pixels == 0 {
            return;
        }
        let text_h = self.text_area_height();
        let text_w = self.can().width.saturating_sub(SCROLLBAR_W);
        if pixels >= text_h {
            self.fill_rect(0, 0, text_w, text_h, self.unpack_color(self.bg));
            return;
        }
        let move_rows = text_h - pixels;
        if self.draw_to_back_buffer() {
            let row_width = self.can().width;
            if let Some(buf) = self.canm().back_buffer.as_mut() {
                buf.copy_within(0..move_rows * row_width, pixels * row_width);
            }
            self.mark_dirty_rect(0, 0, row_width, text_h);
        } else {
            unsafe {
                core::ptr::copy(
                    self.can().addr,
                    self.can().addr.add(pixels * self.can().pitch),
                    move_rows * self.can().pitch,
                );
            }
        }
        self.fill_rect(0, 0, text_w, pixels, self.unpack_color(self.bg));
    }

    /// Performs the layout text lines operation.
    pub(crate) fn layout_text_lines(
        &self,
        text: &str,
        wrap: bool,
        max_cols: Option<usize>,
    ) -> Vec<Vec<char>> {
        let mut lines: Vec<Vec<char>> = Vec::new();
        let mut current: Vec<char> = Vec::new();
        let wrap_cols = max_cols.filter(|&c| c > 0);

        for ch in text.chars() {
            if ch == '\n' {
                lines.push(current);
                current = Vec::new();
                continue;
            }

            if wrap {
                if let Some(cols) = wrap_cols {
                    if current.len() >= cols {
                        lines.push(current);
                        current = Vec::new();
                    }
                }
            }

            current.push(ch);
        }

        lines.push(current);
        lines
    }

    /// Performs the measure text operation.
    pub fn measure_text(&self, text: &str, max_width: Option<usize>, wrap: bool) -> TextMetrics {
        if !self.enabled {
            return TextMetrics {
                width: 0,
                height: 0,
                lines: 0,
            };
        }
        let gw = self.font_info.glyph_w;
        let gh = self.font_info.glyph_h;
        let max_cols = max_width.map(|w| core::cmp::max(1, w / gw));
        let lines = self.layout_text_lines(text, wrap, max_cols);

        let mut max_line_cols = 0usize;
        for line in &lines {
            max_line_cols = core::cmp::max(max_line_cols, line.len());
        }

        TextMetrics {
            width: max_line_cols * gw,
            height: lines.len() * gh,
            lines: lines.len(),
        }
    }

    /// Performs the draw text operation.
    pub fn draw_text(
        &mut self,
        pixel_x: usize,
        pixel_y: usize,
        text: &str,
        opts: TextOptions,
    ) -> TextMetrics {
        if !self.enabled {
            return TextMetrics {
                width: 0,
                height: 0,
                lines: 0,
            };
        }

        let gw = self.font_info.glyph_w;
        let gh = self.font_info.glyph_h;
        let max_cols = opts.max_width.map(|w| core::cmp::max(1, w / gw));
        let lines = self.layout_text_lines(text, opts.wrap, max_cols);
        let region_w = opts.max_width.unwrap_or_else(|| {
            let mut max_line_cols = 0usize;
            for line in &lines {
                max_line_cols = core::cmp::max(max_line_cols, line.len());
            }
            max_line_cols * gw
        });

        let fg = self.pack_color(opts.fg);
        let bg = self.pack_color(opts.bg);
        let mut max_line_px = 0usize;

        for (line_idx, line) in lines.iter().enumerate() {
            let line_px = line.len() * gw;
            max_line_px = core::cmp::max(max_line_px, line_px);
            let x = match opts.align {
                TextAlign::Left => pixel_x,
                TextAlign::Center => pixel_x.saturating_add(region_w.saturating_sub(line_px) / 2),
                TextAlign::Right => pixel_x.saturating_add(region_w.saturating_sub(line_px)),
            };
            let y = pixel_y + line_idx * gh;

            for (col, ch) in line.iter().enumerate() {
                self.draw_glyph_at_pixel(x + col * gw, y, *ch, fg, bg);
            }
        }

        TextMetrics {
            width: max_line_px,
            height: lines.len() * gh,
            lines: lines.len(),
        }
    }

    /// Performs the draw strata stack operation.
    pub fn draw_strata_stack(
        &mut self,
        origin_x: usize,
        origin_y: usize,
        layer_w: usize,
        layer_h: usize,
    ) {
        if !self.enabled || layer_w == 0 || layer_h == 0 {
            return;
        }

        // Simple "strata" stack: each layer is slightly shifted and tinted.
        let palette = [
            RgbColor::new(0x24, 0x3B, 0x55),
            RgbColor::new(0x2B, 0x54, 0x77),
            RgbColor::new(0x2F, 0x74, 0x93),
            RgbColor::new(0x3A, 0x93, 0xA8),
            RgbColor::new(0x5F, 0xB1, 0xA1),
            RgbColor::new(0xA4, 0xCC, 0x94),
        ];

        let dx = 6usize;
        let dy = 5usize;
        for (i, color) in palette.iter().enumerate() {
            let x = origin_x.saturating_add(i * dx);
            let y = origin_y.saturating_add(i * dy);
            let w = layer_w.saturating_sub(i * dx);
            let h = layer_h.saturating_sub(i * dy);
            if w < 8 || h < 8 {
                break;
            }

            self.fill_rect(x, y, w, h, *color);
            self.draw_rect(x, y, w, h, RgbColor::new(0x10, 0x16, 0x20));
        }
    }

    /// Performs the draw glyph operation.
    pub(crate) fn draw_glyph(&mut self, cx: usize, cy: usize, ch: char) {
        let glyph_index = self.glyph_index_for_char(ch);
        self.draw_glyph_index_at_pixel(
            cx * self.font_info.glyph_w,
            cy * self.font_info.glyph_h,
            glyph_index,
            self.fg,
            self.bg,
        );
    }

    /// Performs the clear row operation.
    pub(crate) fn clear_row(&mut self, row: usize) {
        if !self.enabled {
            return;
        }
        self.clear_text_line_pixels(row);
    }

    /// Performs the scroll operation.
    pub(crate) fn scroll(&mut self) {
        if !self.enabled {
            return;
        }
        let dy = self.font_info.glyph_h;
        let text_h = self.text_area_height();
        if dy >= text_h {
            self.clear();
            return;
        }
        self.move_text_view_pixels_up(dy);
        self.row = self.rows - 1;
    }

    /// Writes char.
    pub(crate) fn write_char(&mut self, c: char) {
        if !self.enabled {
            return;
        }
        let c = normalize_console_char(c);

        // Mirror into scrollback (always, even when scrolled back) ========================================
        self.sb_mirror_char(c);
        // If the user is viewing history, suppress live rendering.
        if self.scroll_offset > 0 {
            return;
        }
        // ==============================

        match c {
            '\n' => {
                self.col = 0;
                self.row += 1;
            }
            '\r' => self.col = 0,
            '\t' => self.col = (self.col + 4) & !3,
            '\u{8}' => {
                if self.col > 0 {
                    self.col -= 1;
                    self.draw_glyph(self.col, self.row, ' ');
                }
            }
            '\0' => {}
            ch => {
                self.draw_glyph(self.col, self.row, ch);
                self.col += 1;
            }
        }

        if self.col >= self.cols {
            self.col = 0;
            self.row += 1;
        }

        if self.row >= self.rows {
            self.scroll();
        }
    }

    /// Writes bytes (render only : does NOT present or draw scrollbar).
    /// Call `flush_display()` after a batch of writes to present.
    pub(crate) fn write_bytes(&mut self, s: &str) {
        self.begin_viewport_render();
        // Skip basic ANSI escape sequences to avoid rendering control garbage.
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b == 0x1B {
                // ESC : skip CSI sequences: ESC [ ... final_byte
                if i + 1 < bytes.len() && bytes[i + 1] == b'[' {
                    i += 2;
                    while i < bytes.len() {
                        let c = bytes[i];
                        i += 1;
                        if c >= b'@' && c <= b'~' {
                            break;
                        }
                    }
                } else {
                    i += 1;
                }
                continue;
            }
            // Safe: ASCII bytes 0x20..=0x7E are valid single-char UTF-8.
            let ch = b as char;
            self.write_char(ch);
            i += 1;
        }
    }

    /// Flush: draw scrollbar + present to screen.
    /// Call after a batch of `write_bytes()` calls to display everything at once.
    /// NOTE: write_bytes() already called begin_viewport_render(), so we must NOT
    /// call it again here : that would clear the dirty rects before present().
    pub(crate) fn flush_display(&mut self) {
        self.draw_scrollbar_inner();
        // Force back-buffer mode and dirty tracking for the present cycle.
        // We do NOT restore prev_draw/prev_track because the caller
        // (write_bytes) expects dirty rects to survive into the next write.
        self.canm().draw_to_back = true;
        self.canm().track_dirty = true;
        self.end_viewport_render(true, true);
    }

    // =============================================================
    // Scrollback buffer + scrollbar
    // =============================================================

    /// Mirror a normalized character into the scrollback model.
    /// Called by `write_char` before any live rendering.
    /// Mirror a typed character into the scrollback buffer.
    pub(crate) fn sb_mirror_char(&mut self, c: char) {
        let cols = self.cols;
        let fg = self.fg;
        let bg = self.bg;
        let rows = self.rows;
        self.sb.mirror_char(c, cols, fg, bg, rows);
    }

    /// Keep the scrollback buffer within MAX_SCROLLBACK + rows.
    #[inline]
    pub(crate) fn sb_trim(&mut self) {
        let rows = self.rows;
        self.sb.trim(rows);
    }

    /// Draw (or refresh) the scrollbar strip on the right edge of the text area.
    pub(crate) fn draw_scrollbar_inner(&mut self) {
        if !self.enabled || self.can().width == 0 {
            return;
        }
        let text_h = self.text_area_height();
        if text_h == 0 {
            return;
        }
        let sb_x = self.can().width.saturating_sub(SCROLLBAR_W);
        let sb_w = SCROLLBAR_W;
        let total = self.sb.rows.len() + 1; // +1 accounts for current partial row
        let track_color = self.unpack_color(self.fmt.pack_rgb(0x22, 0x28, 0x38));
        let thumb_color = self.unpack_color(self.fmt.pack_rgb(0x58, 0x72, 0xA0));
        let thumb_hi_color = self.unpack_color(self.fmt.pack_rgb(0x80, 0xA0, 0xC8));

        if total <= self.rows {
            // Not enough content to scroll: full-height thumb with border.
            self.fill_rect(sb_x, 0, sb_w, text_h, track_color);
            if sb_w > 2 && text_h > 2 {
                self.fill_rect(sb_x + 1, 1, sb_w - 2, text_h - 2, thumb_hi_color);
            }
            return;
        }

        let max_offset = total.saturating_sub(self.rows);
        let thumb_h = ((text_h * self.rows) / total).max(6);
        let avail = text_h.saturating_sub(thumb_h);
        // offset 0 = thumb at bottom; max_offset = thumb at top
        let thumb_y = if self.scroll_offset == 0 || avail == 0 {
            avail // = text_h - thumb_h (bottom)
        } else {
            avail - (avail * self.scroll_offset / max_offset)
        };

        // Draw track background
        self.fill_rect(sb_x, 0, sb_w, text_h, track_color);
        // Draw thumb
        if thumb_h > 0 && thumb_h < text_h {
            self.fill_rect(sb_x, thumb_y, sb_w, thumb_h, thumb_color);
        }
    }

    /// Redraw the entire text area from the scrollback buffer.
    /// Called when scroll_offset changes.
    pub(crate) fn redraw_from_scrollback(&mut self) {
        if !self.enabled {
            return;
        }
        self.render_viewport_full();
    }

    pub(crate) fn redraw_from_scrollback_incremental(&mut self, old_offset: usize) -> bool {
        if !self.enabled || self.rows == 0 {
            return false;
        }
        let diff = old_offset.abs_diff(self.scroll_offset);
        if diff == 0 || diff >= self.rows {
            return false;
        }
        let pixel_delta = diff.saturating_mul(self.font_info.glyph_h);
        if pixel_delta == 0 {
            return false;
        }

        let (prev_draw_to_back, prev_track_dirty) = self.begin_viewport_render();

        if self.scroll_offset > old_offset {
            self.move_text_view_pixels_down(pixel_delta);
            self.redraw_visible_rows(0, diff);
        } else {
            self.move_text_view_pixels_up(pixel_delta);
            self.redraw_visible_rows(self.rows.saturating_sub(diff), diff);
        }

        self.finalize_live_view_state();
        self.draw_scrollbar_inner();
        self.end_viewport_render(prev_draw_to_back, prev_track_dirty);
        true
    }

    /// Scroll the view up (backward in history) by `lines` lines.
    pub fn scroll_view_up(&mut self, lines: usize) {
        if !self.enabled {
            return;
        }
        let total = self.sb.rows.len() + 1;
        let max_off = total.saturating_sub(self.rows);
        self.set_scroll_offset_and_render((self.scroll_offset + lines).min(max_off));
    }

    /// Scroll the view down (forward, toward live) by `lines` lines.
    pub fn scroll_view_down(&mut self, lines: usize) {
        if !self.enabled {
            return;
        }
        self.set_scroll_offset_and_render(self.scroll_offset.saturating_sub(lines));
    }

    /// Immediately return to the live (bottom) view.
    pub fn scroll_to_live(&mut self) {
        if self.scroll_offset == 0 {
            return;
        }
        self.set_scroll_offset_and_render(0);
    }

    /// Handle a click at pixel `(px_x, px_y)` : if it falls in the scrollbar,
    /// jump the view to the corresponding scroll position.
    pub fn scrollbar_click(&mut self, px_x: usize, px_y: usize) {
        if !self.enabled {
            return;
        }
        let sb_x = self.can().width.saturating_sub(SCROLLBAR_W);
        if px_x < sb_x {
            return;
        }
        let text_h = self.text_area_height();
        if text_h <= 1 {
            return;
        }
        let total = self.sb.rows.len() + 1;
        let max_off = total.saturating_sub(self.rows);
        if max_off == 0 {
            return;
        }
        // py = 0 → top = oldest = max_offset; py = text_h - 1 → bottom = 0
        let py = px_y.min(text_h - 1);
        let offset = max_off * (text_h - 1 - py) / (text_h - 1);
        self.set_scroll_offset_and_render(offset.min(max_off));
    }

    /// Drag the scrollbar thumb to vertical pixel `px_y`.
    ///
    /// Unlike `scrollbar_click`, this only depends on Y and is intended for
    /// click-and-drag interactions where the pointer may slightly leave the
    /// scrollbar strip horizontally.
    pub fn scrollbar_drag_to(&mut self, px_y: usize) {
        if !self.enabled {
            return;
        }
        let text_h = self.text_area_height();
        if text_h <= 1 {
            return;
        }
        let total = self.sb.rows.len() + 1;
        let max_off = total.saturating_sub(self.rows);
        if max_off == 0 {
            return;
        }
        // py = 0 -> top = oldest = max_offset; py = text_h - 1 -> bottom = 0
        let py = px_y.min(text_h - 1);
        let offset = max_off * (text_h - 1 - py) / (text_h - 1);
        self.set_scroll_offset_and_render(offset.min(max_off));
    }

    /// Returns `true` if the pixel coordinates fall within the scrollbar strip.
    pub fn scrollbar_hit_test(&self, px_x: usize, px_y: usize) -> bool {
        if !self.enabled {
            return false;
        }
        let sb_x = self.can().width.saturating_sub(SCROLLBAR_W);
        px_x >= sb_x && px_y < self.text_area_height()
    }
}

/// Performs the normalize console char operation.
fn normalize_console_char(ch: char) -> char {
    match ch {
        '\n' | '\r' | '\t' | '\u{8}' => ch,
        c if c.is_control() => '\0',
        // Graceful fallback when font lacks box-drawing coverage.
        '\u{2500}' | '\u{2501}' | '\u{2504}' | '\u{2505}' | '\u{2013}' | '\u{2014}' => '-',
        '\u{2502}' | '\u{2503}' => '|',
        '\u{250c}' | '\u{2510}' | '\u{2514}' | '\u{2518}' | '\u{251c}' | '\u{2524}'
        | '\u{252c}' | '\u{2534}' | '\u{253c}' => '+',
        '\u{00a0}' => ' ',
        _ => ch,
    }
}

impl fmt::Write for VgaWriter {
    /// Writes str.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.enabled {
            self.write_bytes(s);
        } else {
            crate::arch::x86_64::serial::_print(format_args!("{}", s));
        }
        Ok(())
    }
}
