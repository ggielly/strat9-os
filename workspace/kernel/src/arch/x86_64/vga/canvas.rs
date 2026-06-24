//! Canvas convenience drawing API : a thin wrapper around VgaWriter for drawing primitives.

use super::{
    api::*,
    status_line::{draw_system_status_line, ui_draw_status_bar},
    types::*,
};

pub struct Canvas {
    fg: RgbColor,
    bg: RgbColor,
}

impl Default for Canvas {
    /// Builds a default instance.
    fn default() -> Self {
        Self {
            fg: RgbColor::LIGHT_GREY,
            bg: RgbColor::BLACK,
        }
    }
}

impl Canvas {
    /// Creates a new instance.
    pub const fn new(fg: RgbColor, bg: RgbColor) -> Self {
        Self { fg, bg }
    }

    /// Sets fg.
    pub fn set_fg(&mut self, fg: RgbColor) {
        self.fg = fg;
    }

    /// Sets bg.
    pub fn set_bg(&mut self, bg: RgbColor) {
        self.bg = bg;
    }

    /// Sets colors.
    pub fn set_colors(&mut self, fg: RgbColor, bg: RgbColor) {
        self.fg = fg;
        self.bg = bg;
    }

    /// Sets clip rect.
    pub fn set_clip_rect(&self, x: usize, y: usize, w: usize, h: usize) {
        set_clip_rect(x, y, w, h);
    }

    /// Performs the reset clip rect operation.
    pub fn reset_clip_rect(&self) {
        reset_clip_rect();
    }

    /// Performs the clear operation.
    pub fn clear(&self) {
        fill_rect(0, 0, width(), height(), self.bg);
    }

    /// Performs the pixel operation.
    pub fn pixel(&self, x: usize, y: usize) {
        draw_pixel(x, y, self.fg);
    }

    /// Performs the line operation.
    pub fn line(&self, x0: isize, y0: isize, x1: isize, y1: isize) {
        draw_line(x0, y0, x1, y1, self.fg);
    }

    /// Performs the rect operation.
    pub fn rect(&self, x: usize, y: usize, w: usize, h: usize) {
        draw_rect(x, y, w, h, self.fg);
    }

    /// Performs the fill rect operation.
    pub fn fill_rect(&self, x: usize, y: usize, w: usize, h: usize) {
        fill_rect(x, y, w, h, self.fg);
    }

    /// Performs the fill rect alpha operation.
    pub fn fill_rect_alpha(&self, x: usize, y: usize, w: usize, h: usize, alpha: u8) {
        fill_rect_alpha(x, y, w, h, self.fg, alpha);
    }

    /// Performs the text operation.
    pub fn text(&self, x: usize, y: usize, text: &str) {
        draw_text_at(x, y, text, self.fg, self.bg);
    }

    /// Performs the text opts operation.
    pub fn text_opts(
        &self,
        x: usize,
        y: usize,
        text: &str,
        align: TextAlign,
        wrap: bool,
        max_width: Option<usize>,
    ) -> TextMetrics {
        draw_text(
            x,
            y,
            text,
            TextOptions {
                fg: self.fg,
                bg: self.bg,
                align,
                wrap,
                max_width,
            },
        )
    }

    /// Performs the measure text operation.
    pub fn measure_text(&self, text: &str, max_width: Option<usize>, wrap: bool) -> TextMetrics {
        measure_text(text, max_width, wrap)
    }

    /// Performs the blit rgb operation.
    pub fn blit_rgb(&self, x: usize, y: usize, w: usize, h: usize, pixels: &[RgbColor]) -> bool {
        blit_rgb(x, y, w, h, pixels)
    }

    /// Performs the blit rgb24 operation.
    pub fn blit_rgb24(&self, x: usize, y: usize, w: usize, h: usize, bytes: &[u8]) -> bool {
        blit_rgb24(x, y, w, h, bytes)
    }

    /// Performs the blit rgba operation.
    pub fn blit_rgba(
        &self,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        bytes: &[u8],
        global_alpha: u8,
    ) -> bool {
        blit_rgba(x, y, w, h, bytes, global_alpha)
    }

    /// Performs the blit sprite rgba operation.
    pub fn blit_sprite_rgba(
        &self,
        x: usize,
        y: usize,
        sprite: SpriteRgba<'_>,
        global_alpha: u8,
    ) -> bool {
        blit_sprite_rgba(x, y, sprite, global_alpha)
    }

    /// Performs the begin frame operation.
    pub fn begin_frame(&self) -> bool {
        begin_frame()
    }

    /// Performs the end frame operation.
    pub fn end_frame(&self) {
        end_frame();
    }

    /// Performs the ui clear operation.
    pub fn ui_clear(&self, theme: UiTheme) {
        ui_clear(theme);
    }

    /// Performs the ui panel operation.
    pub fn ui_panel(
        &self,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        title: &str,
        body: &str,
        theme: UiTheme,
    ) {
        ui_draw_panel(x, y, w, h, title, body, theme);
    }

    /// Performs the ui status bar operation.
    pub fn ui_status_bar(&self, left: &str, right: &str, theme: UiTheme) {
        ui_draw_status_bar(left, right, theme);
    }

    /// Performs the system status line operation.
    pub fn system_status_line(&self, theme: UiTheme) {
        draw_system_status_line(theme);
    }

    /// Performs the layout screen operation.
    pub fn layout_screen(&self) -> UiDockLayout {
        UiDockLayout::from_screen()
    }

    /// Performs the ui label operation.
    pub fn ui_label(&self, label: &UiLabel<'_>) {
        ui_draw_label(label);
    }

    /// Performs the ui progress bar operation.
    pub fn ui_progress_bar(&self, bar: UiProgressBar) {
        ui_draw_progress_bar(bar);
    }

    /// Performs the ui table operation.
    pub fn ui_table(&self, table: &UiTable) {
        ui_draw_table(table);
    }
}
