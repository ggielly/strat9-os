//! Public VGA API surface : free functions, the global `VGA_WRITER`, and the
//! `vga_print!` / `vga_println!` macros that the rest of the kernel uses to
//! talk to the framebuffer console.

use super::{
    debug_overlay::vga_debug_init,
    panic_screen::init_panic_fb_globals,
    status_line::draw_boot_status_line,
    types::*,
    writer::{
        VgaWriter, DOUBLE_BUFFER_MODE, PRESENTED_FRAMES, VGA_PRESENT_PIXEL_COUNT,
        VGA_PRESENT_REGION_COUNT,
    },
};
use core::{
    fmt,
    sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
};
use spin::Mutex;

pub(crate) static VGA_AVAILABLE: AtomicBool = AtomicBool::new(false);
pub(crate) static FPS_LAST_TICK: AtomicU64 = AtomicU64::new(0);
pub(crate) static FPS_LAST_FRAME_COUNT: AtomicU64 = AtomicU64::new(0);
static FPS_ESTIMATE: AtomicU64 = AtomicU64::new(0);
const FPS_REFRESH_PERIOD_TICKS: u64 = 100; // 100Hz timer => 1s
pub(crate) static UI_SCALE: AtomicU8 = AtomicU8::new(1);
const CLIPBOARD_CAP: usize = 8192;
static CLIPBOARD: Mutex<([u8; CLIPBOARD_CAP], usize)> = Mutex::new(([0u8; CLIPBOARD_CAP], 0));

pub static VGA_WRITER: Mutex<VgaWriter> = Mutex::new(VgaWriter::new());

/// Returns whether available.
#[inline]
pub fn is_available() -> bool {
    VGA_AVAILABLE.load(Ordering::Relaxed)
}

/// Performs the with writer operation.
///
/// Cursor management is deferred to `present()` to avoid +/-1280 pixel ops per call.
pub fn with_writer<R>(f: impl FnOnce(&mut VgaWriter) -> R) -> Option<R> {
    if !is_available() {
        return None;
    }
    let mut writer = VGA_WRITER.lock();
    let res = f(&mut writer);
    Some(res)
}

/// Performs the try with writer operation.
///
/// Cursor management is deferred to `present()` to avoid ~1280 pixel ops per call.
pub fn try_with_writer<R>(f: impl FnOnce(&mut VgaWriter) -> R) -> Option<R> {
    if !is_available() {
        return None;
    }
    let mut writer = VGA_WRITER.try_lock()?;
    let res = f(&mut writer);
    Some(res)
}

/// Writes raw console text to the framebuffer console in a single writer batch.
pub fn write_text(text: &str) {
    if !is_available() {
        crate::arch::x86_64::serial::_print(format_args!("{}", text));
        return;
    }
    let _ = with_writer(|w| {
        w.write_bytes(text);
    });
}

/// Writes one console character to the framebuffer console.
pub fn write_char(ch: char) {
    if !is_available() {
        crate::arch::x86_64::serial::_print(format_args!("{}", ch));
        return;
    }
    let mut buf = [0u8; 4];
    write_text(ch.encode_utf8(&mut buf));
}

/// Performs the current fps operation.
pub(crate) fn current_fps(tick: u64) -> u64 {
    let last_tick = FPS_LAST_TICK.load(Ordering::Relaxed);
    let frames = PRESENTED_FRAMES.load(Ordering::Relaxed);

    if last_tick == 0 {
        let _ = FPS_LAST_TICK.compare_exchange(0, tick, Ordering::Relaxed, Ordering::Relaxed);
        let _ =
            FPS_LAST_FRAME_COUNT.compare_exchange(0, frames, Ordering::Relaxed, Ordering::Relaxed);
        return FPS_ESTIMATE.load(Ordering::Relaxed);
    }

    let dt = tick.saturating_sub(last_tick);
    if dt >= FPS_REFRESH_PERIOD_TICKS
        && FPS_LAST_TICK
            .compare_exchange(last_tick, tick, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        let last_frames = FPS_LAST_FRAME_COUNT.swap(frames, Ordering::Relaxed);
        let df = frames.saturating_sub(last_frames);
        let fps = if dt == 0 {
            0
        } else {
            df.saturating_mul(100) / dt
        };
        FPS_ESTIMATE.store(fps, Ordering::Relaxed);
    }

    FPS_ESTIMATE.load(Ordering::Relaxed)
}

/// Performs the current ui scale operation.
pub(crate) fn current_ui_scale() -> UiScale {
    match UI_SCALE.load(Ordering::Relaxed) {
        1 => UiScale::Compact,
        3 => UiScale::Large,
        _ => UiScale::Normal,
    }
}

/// Performs the ui scale operation.
pub fn ui_scale() -> UiScale {
    current_ui_scale()
}

/// Sets ui scale.
pub fn set_ui_scale(scale: UiScale) {
    UI_SCALE.store(scale as u8, Ordering::Relaxed);
}

/// Performs the ui scale px operation.
pub fn ui_scale_px(base: usize) -> usize {
    let factor = current_ui_scale().factor();
    let denom = UiScale::Normal.factor();
    base.saturating_mul(factor) / denom
}

/// Performs the init operation.
#[allow(clippy::too_many_arguments)]
pub fn init(
    fb_addr: u64,
    fb_width: u32,
    fb_height: u32,
    pitch: u32,
    bpp: u16,
    red_size: u8,
    red_shift: u8,
    green_size: u8,
    green_shift: u8,
    blue_size: u8,
    blue_shift: u8,
) {
    if fb_addr == 0 || fb_width == 0 || fb_height == 0 || pitch == 0 {
        VGA_AVAILABLE.store(false, Ordering::Relaxed);
        log::info!("Framebuffer console unavailable (no framebuffer)");
        return;
    }

    if bpp != 24 && bpp != 32 {
        VGA_AVAILABLE.store(false, Ordering::Relaxed);
        log::info!("Framebuffer console unavailable (unsupported bpp={})", bpp);
        return;
    }

    let fmt = PixelFormat {
        bpp,
        red_size,
        red_shift,
        green_size,
        green_shift,
        blue_size,
        blue_shift,
    };

    // Ensure fb_addr is a virtual address in the HHDM.
    // If it's already higher-half (>= HHDM), use it as-is.
    // Otherwise, convert it via phys_to_virt.
    //
    // This fix works on VMWare Workstation
    //
    let hhdm = crate::memory::hhdm_offset();
    let fb_virt = if hhdm != 0 && fb_addr < hhdm {
        crate::memory::phys_to_virt(fb_addr)
    } else {
        fb_addr
    };

    let mut writer = VGA_WRITER.lock();
    if writer.configure(
        fb_virt as *mut u8,
        fb_width as usize,
        fb_height as usize,
        pitch as usize,
        fmt,
    ) {
        writer.set_color(Color::LightCyan, Color::Black);
        writer.clear_with(RgbColor::new(0x12, 0x16, 0x1E));
        // Decorative background mark for Strat9 identity.
        let deco_w = (writer.width() / 3).clamp(120, 300);
        let deco_h = (writer.height() / 4).clamp(90, 220);
        let deco_x = writer.width().saturating_sub(deco_w + 24);
        let deco_y = 24;
        writer.draw_strata_stack(deco_x, deco_y, deco_w, deco_h);
        writer.set_rgb_color(
            RgbColor::new(0xA7, 0xD8, 0xD8),
            RgbColor::new(0x12, 0x16, 0x1E),
        );
        writer.write_bytes("Strat9-OS v0.1.0\n");
        writer.set_rgb_color(
            RgbColor::new(0xE2, 0xE8, 0xF0),
            RgbColor::new(0x12, 0x16, 0x1E),
        );
        VGA_AVAILABLE.store(true, Ordering::Relaxed);
        // Initialise panic-screen raw framebuffer globals so the panic
        // handler can draw directly without locking VGA_WRITER.
        init_panic_fb_globals(
            fb_virt,
            fb_width as usize,
            fb_height as usize,
            pitch as usize,
            bpp,
            red_shift,
            green_shift,
            blue_shift,
        );
        // Initialise the live VGA debug writer geometry.
        vga_debug_init(fb_width as usize, fb_height as usize);
        log::info!(
            "Framebuffer console enabled: {}x{} {}bpp pitch={}",
            fb_width,
            fb_height,
            bpp,
            pitch
        );
        drop(writer);
        draw_boot_status_line(UiTheme::OCEAN_STATUS);
    } else {
        writer.enabled = false;
        VGA_AVAILABLE.store(false, Ordering::Relaxed);
        log::info!("Framebuffer console unavailable (font parse/init failed)");
    }
}

// vga_print! / vga_println! macros are defined in mod.rs

/// Performs the print operation.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    if is_available() {
        let _ = with_writer(|w| {
            w.write_fmt(args).ok();
        });
        return;
    }
    crate::arch::x86_64::serial::_print(args);
}

/// Performs the width operation.
pub fn width() -> usize {
    if !is_available() {
        return 0;
    }
    VGA_WRITER.lock().width()
}

/// Performs the height operation.
pub fn height() -> usize {
    if !is_available() {
        return 0;
    }
    VGA_WRITER.lock().height()
}

/// Performs the screen size operation.
pub fn screen_size() -> (usize, usize) {
    (width(), height())
}

/// Performs the ui layout screen operation.
pub fn ui_layout_screen() -> UiDockLayout {
    UiDockLayout::from_screen()
}

/// Performs the glyph size operation.
pub fn glyph_size() -> (usize, usize) {
    if !is_available() {
        return (0, 0);
    }
    VGA_WRITER.lock().glyph_size()
}

/// Performs the text cols operation.
pub fn text_cols() -> usize {
    if !is_available() {
        return 0;
    }
    VGA_WRITER.lock().cols()
}

/// Performs the text rows operation.
pub fn text_rows() -> usize {
    if !is_available() {
        return 0;
    }
    VGA_WRITER.lock().rows()
}

/// Returns text cursor.
pub fn get_text_cursor() -> (usize, usize) {
    if !is_available() {
        return (0, 0);
    }
    let writer = VGA_WRITER.lock();
    (writer.col, writer.row)
}

/// Sets text cursor.
pub fn set_text_cursor(col: usize, row: usize) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().set_cursor_cell(col, row);
}

/// Performs the double buffer mode operation.
pub fn double_buffer_mode() -> bool {
    DOUBLE_BUFFER_MODE.load(Ordering::Relaxed)
}

/// Sets double buffer mode.
pub fn set_double_buffer_mode(enabled: bool) {
    DOUBLE_BUFFER_MODE.store(enabled, Ordering::Relaxed);
}

/// Performs the draw text cursor operation.
pub fn draw_text_cursor(color: RgbColor) {
    if !is_available() {
        return;
    }
    let mut writer = VGA_WRITER.lock();
    writer.draw_text_cursor_overlay(color);
}

/// Performs the hide text cursor operation.
pub fn hide_text_cursor() {
    if !is_available() {
        return;
    }
    let mut writer = VGA_WRITER.lock();
    writer.hide_text_cursor();
}

/// Performs the framebuffer info operation.
pub fn framebuffer_info() -> FramebufferInfo {
    if !is_available() {
        return FramebufferInfo {
            available: false,
            width: 0,
            height: 0,
            pitch: 0,
            bpp: 0,
            red_size: 0,
            red_shift: 0,
            green_size: 0,
            green_shift: 0,
            blue_size: 0,
            blue_shift: 0,
            text_cols: 0,
            text_rows: 0,
            glyph_w: 0,
            glyph_h: 0,
            double_buffer_mode: false,
            double_buffer_enabled: false,
            ui_scale: UiScale::Normal,
        };
    }
    VGA_WRITER.lock().framebuffer_info()
}

/// Returns lightweight render metrics for profiling.
pub fn render_stats() -> RenderStats {
    RenderStats {
        presented_frames: PRESENTED_FRAMES.load(Ordering::Relaxed),
        estimated_fps: FPS_ESTIMATE.load(Ordering::Relaxed),
        present_region_count: VGA_PRESENT_REGION_COUNT.load(Ordering::Relaxed),
        present_pixel_count: VGA_PRESENT_PIXEL_COUNT.load(Ordering::Relaxed),
    }
}

/// Sets text color.
pub fn set_text_color(fg: RgbColor, bg: RgbColor) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().set_rgb_color(fg, bg);
}

/// Sets clip rect.
pub fn set_clip_rect(x: usize, y: usize, width: usize, height: usize) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().set_clip_rect(x, y, width, height);
}

/// Performs the reset clip rect operation.
pub fn reset_clip_rect() {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().reset_clip_rect();
}

/// Performs the begin frame operation.
pub fn begin_frame() -> bool {
    if !is_available() {
        return false;
    }
    if !double_buffer_mode() {
        return false;
    }
    VGA_WRITER.lock().enable_double_buffer()
}

/// Performs the end frame operation.
pub fn end_frame() {
    if !is_available() {
        return;
    }
    let mut writer = VGA_WRITER.lock();
    writer.present();
    writer.disable_double_buffer(false);
}

/// Performs the present operation.
pub fn present() {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().present();
}

/// Performs the draw pixel operation.
pub fn draw_pixel(x: usize, y: usize, color: RgbColor) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().draw_pixel(x, y, color);
}

/// Performs the draw pixel alpha operation.
pub fn draw_pixel_alpha(x: usize, y: usize, color: RgbColor, alpha: u8) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().draw_pixel_alpha(x, y, color, alpha);
}

/// Performs the draw line operation.
pub fn draw_line(x0: isize, y0: isize, x1: isize, y1: isize, color: RgbColor) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().draw_line(x0, y0, x1, y1, color);
}

/// Performs the draw rect operation.
pub fn draw_rect(x: usize, y: usize, width: usize, height: usize, color: RgbColor) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().draw_rect(x, y, width, height, color);
}

/// Performs the fill rect operation.
pub fn fill_rect(x: usize, y: usize, width: usize, height: usize, color: RgbColor) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().fill_rect(x, y, width, height, color);
}

/// Performs the fill rect alpha operation.
pub fn fill_rect_alpha(
    x: usize,
    y: usize,
    width: usize,
    height: usize,
    color: RgbColor,
    alpha: u8,
) {
    if !is_available() {
        return;
    }
    VGA_WRITER
        .lock()
        .fill_rect_alpha(x, y, width, height, color, alpha);
}

/// Performs the blit rgb operation.
pub fn blit_rgb(
    dst_x: usize,
    dst_y: usize,
    src_width: usize,
    src_height: usize,
    pixels: &[RgbColor],
) -> bool {
    if !is_available() {
        return false;
    }
    VGA_WRITER
        .lock()
        .blit_rgb(dst_x, dst_y, src_width, src_height, pixels)
}

/// Performs the blit rgb24 operation.
pub fn blit_rgb24(
    dst_x: usize,
    dst_y: usize,
    src_width: usize,
    src_height: usize,
    bytes: &[u8],
) -> bool {
    if !is_available() {
        return false;
    }
    VGA_WRITER
        .lock()
        .blit_rgb24(dst_x, dst_y, src_width, src_height, bytes)
}

/// Performs the blit rgba operation.
pub fn blit_rgba(
    dst_x: usize,
    dst_y: usize,
    src_width: usize,
    src_height: usize,
    bytes: &[u8],
    global_alpha: u8,
) -> bool {
    if !is_available() {
        return false;
    }
    VGA_WRITER
        .lock()
        .blit_rgba(dst_x, dst_y, src_width, src_height, bytes, global_alpha)
}

/// Performs the blit sprite rgba operation.
pub fn blit_sprite_rgba(
    dst_x: usize,
    dst_y: usize,
    sprite: SpriteRgba<'_>,
    global_alpha: u8,
) -> bool {
    if !is_available() {
        return false;
    }
    VGA_WRITER
        .lock()
        .blit_sprite_rgba(dst_x, dst_y, sprite, global_alpha)
}

/// Performs the draw text at operation.
pub fn draw_text_at(pixel_x: usize, pixel_y: usize, text: &str, fg: RgbColor, bg: RgbColor) {
    if !is_available() {
        return;
    }
    VGA_WRITER
        .lock()
        .draw_text_at(pixel_x, pixel_y, text, fg, bg);
}

/// Performs the draw text operation.
pub fn draw_text(pixel_x: usize, pixel_y: usize, text: &str, opts: TextOptions) -> TextMetrics {
    if !is_available() {
        return TextMetrics {
            width: 0,
            height: 0,
            lines: 0,
        };
    }
    VGA_WRITER.lock().draw_text(pixel_x, pixel_y, text, opts)
}

/// Performs the measure text operation.
pub fn measure_text(text: &str, max_width: Option<usize>, wrap: bool) -> TextMetrics {
    if !is_available() {
        return TextMetrics {
            width: 0,
            height: 0,
            lines: 0,
        };
    }
    VGA_WRITER.lock().measure_text(text, max_width, wrap)
}

/// Performs the ui clear operation.
pub fn ui_clear(theme: UiTheme) {
    let _ = with_writer(|w| w.clear_with(theme.background));
}

/// Performs the ui draw panel operation.
pub fn ui_draw_panel(
    x: usize,
    y: usize,
    width: usize,
    height: usize,
    title: &str,
    body: &str,
    theme: UiTheme,
) {
    let _ = with_writer(|w| {
        if width < 8 || height < 8 {
            return;
        }
        let (gw, gh) = w.glyph_size();
        w.fill_rect(x, y, width, height, theme.panel_bg);
        w.draw_rect(x, y, width, height, theme.panel_border);

        let title_h = gh + 6;
        w.fill_rect(
            x.saturating_add(1),
            y.saturating_add(1),
            width.saturating_sub(2),
            title_h,
            theme.accent,
        );
        let title_opts = TextOptions {
            fg: theme.text,
            bg: theme.accent,
            align: TextAlign::Left,
            wrap: false,
            max_width: Some(width.saturating_sub(10)),
        };
        w.draw_text(x.saturating_add(6), y.saturating_add(3), title, title_opts);

        let body_opts = TextOptions {
            fg: theme.text,
            bg: theme.panel_bg,
            align: TextAlign::Left,
            wrap: true,
            max_width: Some(width.saturating_sub(10)),
        };
        w.draw_text(
            x.saturating_add(6),
            y.saturating_add(title_h + 4),
            body,
            body_opts,
        );

        // Visual separator.
        w.fill_rect(
            x.saturating_add(1),
            y.saturating_add(title_h + 1),
            width.saturating_sub(2),
            1,
            theme.panel_border,
        );
        // Keep an implicit reference to glyph width to avoid dead code warning for gw in tiny fonts.
        let _ = gw;
    });
}

/// Performs the ui draw panel widget operation.
pub fn ui_draw_panel_widget(panel: &UiPanel<'_>) {
    ui_draw_panel(
        panel.rect.x,
        panel.rect.y,
        panel.rect.w,
        panel.rect.h,
        panel.title,
        panel.body,
        panel.theme,
    );
}

/// Performs the ui draw label operation.
pub fn ui_draw_label(label: &UiLabel<'_>) {
    let _ = with_writer(|w| {
        w.draw_text(
            label.rect.x,
            label.rect.y,
            label.text,
            TextOptions {
                fg: label.fg,
                bg: label.bg,
                align: label.align,
                wrap: false,
                max_width: Some(label.rect.w),
            },
        );
    });
}

/// Performs the ui draw progress bar operation.
pub fn ui_draw_progress_bar(bar: UiProgressBar) {
    let _ = with_writer(|w| {
        if bar.rect.w < 3 || bar.rect.h < 3 {
            return;
        }
        let value = core::cmp::min(bar.value, 100) as usize;
        w.fill_rect(bar.rect.x, bar.rect.y, bar.rect.w, bar.rect.h, bar.bg);
        w.draw_rect(bar.rect.x, bar.rect.y, bar.rect.w, bar.rect.h, bar.border);
        let inner_w = bar.rect.w.saturating_sub(2);
        let fill_w = inner_w.saturating_mul(value) / 100;
        if fill_w > 0 {
            w.fill_rect(
                bar.rect.x + 1,
                bar.rect.y + 1,
                fill_w,
                bar.rect.h.saturating_sub(2),
                bar.fg,
            );
        }
    });
}

/// Performs the ui draw table operation.
pub fn ui_draw_table(table: &UiTable) {
    let _ = with_writer(|w| {
        if table.rect.w < 8 || table.rect.h < 8 {
            return;
        }
        let (_gw, gh) = w.glyph_size();
        if gh == 0 {
            return;
        }

        w.fill_rect(
            table.rect.x,
            table.rect.y,
            table.rect.w,
            table.rect.h,
            table.theme.panel_bg,
        );
        w.draw_rect(
            table.rect.x,
            table.rect.y,
            table.rect.w,
            table.rect.h,
            table.theme.panel_border,
        );

        let cols = core::cmp::max(1, table.headers.len());
        let col_w = table.rect.w / cols;
        let header_h = gh + 2;
        w.fill_rect(
            table.rect.x + 1,
            table.rect.y + 1,
            table.rect.w.saturating_sub(2),
            header_h,
            table.theme.accent,
        );

        for (i, h) in table.headers.iter().enumerate() {
            let x = table.rect.x + i * col_w + 2;
            w.draw_text(
                x,
                table.rect.y + 1,
                h,
                TextOptions {
                    fg: table.theme.text,
                    bg: table.theme.accent,
                    align: TextAlign::Left,
                    wrap: false,
                    max_width: Some(col_w.saturating_sub(4)),
                },
            );
        }

        let mut y = table.rect.y + header_h + 2;
        for row in &table.rows {
            if y + gh > table.rect.y + table.rect.h {
                break;
            }
            for c in 0..cols {
                if c >= row.len() {
                    continue;
                }
                let x = table.rect.x + c * col_w + 2;
                w.draw_text(
                    x,
                    y,
                    &row[c],
                    TextOptions {
                        fg: table.theme.text,
                        bg: table.theme.panel_bg,
                        align: TextAlign::Left,
                        wrap: false,
                        max_width: Some(col_w.saturating_sub(4)),
                    },
                );
            }
            y += gh;
        }
    });
}

/// Performs the draw strata stack operation.
pub fn draw_strata_stack(origin_x: usize, origin_y: usize, layer_w: usize, layer_h: usize) {
    if !is_available() {
        return;
    }
    VGA_WRITER
        .lock()
        .draw_strata_stack(origin_x, origin_y, layer_w, layer_h);
}
//  Scrollback / scrollbar public API ==================================================================================================================================

/// Scroll the console view up (backward in history) by `lines` lines.
pub fn scroll_view_up(lines: usize) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().scroll_view_up(lines);
}

/// Scroll the console view down (forward, toward live output) by `lines` lines.
pub fn scroll_view_down(lines: usize) {
    if !is_available() {
        return;
    }
    VGA_WRITER.lock().scroll_view_down(lines);
}

/// Return immediately to the live (bottom) view.
pub fn scroll_to_live() {
    if !is_available() {
        return;
    }
    let _ = try_with_writer(|w| {
        w.scroll_to_live();
    });
}

/// Handle a click at framebuffer pixel `(px_x, px_y)`.
/// If the click lands on the scrollbar, jump the view accordingly.
pub fn scrollbar_click(px_x: usize, px_y: usize) {
    if !is_available() {
        return;
    }
    let _ = try_with_writer(|w| {
        w.scrollbar_click(px_x, px_y);
    });
}

/// Drag the scrollbar to a given Y pixel coordinate.
pub fn scrollbar_drag_to(px_y: usize) {
    if !is_available() {
        return;
    }
    let _ = try_with_writer(|w| {
        w.scrollbar_drag_to(px_y);
    });
}

/// Returns `true` if `(px_x, px_y)` falls within the scrollbar strip.
pub fn scrollbar_hit_test(px_x: usize, px_y: usize) -> bool {
    if !is_available() {
        return false;
    }
    try_with_writer(|w| w.scrollbar_hit_test(px_x, px_y)).unwrap_or(false)
}

/// Updates mouse cursor.
pub fn update_mouse_cursor(x: i32, y: i32) {
    if !is_available() {
        return;
    }
    let _ = try_with_writer(|w| {
        w.update_mouse_cursor(x, y);
    });
}

/// Performs the hide mouse cursor operation.
pub fn hide_mouse_cursor() {
    if !is_available() {
        return;
    }
    let _ = try_with_writer(|w| {
        w.hide_mouse_cursor();
    });
}

/// Starts selection.
pub fn start_selection(px: usize, py: usize) {
    if !is_available() {
        return;
    }
    let _ = try_with_writer(|w| {
        w.start_selection(px, py);
    });
}

/// Updates selection.
pub fn update_selection(px: usize, py: usize) {
    if !is_available() {
        return;
    }
    let _ = try_with_writer(|w| {
        w.update_selection(px, py);
    });
}

/// Performs the end selection operation.
pub fn end_selection() {
    if !is_available() {
        return;
    }
    let _ = try_with_writer(|w| {
        w.end_selection();
    });
}

/// Performs the clear selection operation.
pub fn clear_selection() {
    if !is_available() {
        return;
    }
    let _ = try_with_writer(|w| {
        w.clear_selection();
    });
}

/// Returns clipboard text.
pub fn get_clipboard_text(buf: &mut [u8]) -> usize {
    if let Some(clip) = CLIPBOARD.try_lock() {
        let n = clip.1.min(buf.len());
        buf[..n].copy_from_slice(&clip.0[..n]);
        n
    } else {
        0
    }
}
