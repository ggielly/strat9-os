//! Graphics console commands
use crate::{
    arch::x86_64::vga::{self, RgbColor, TextAlign, TextOptions, UiTheme},
    shell::ShellError,
    shell_println,
};
use alloc::{string::String, vec, vec::Vec};
use core::f32::consts::PI;

fn sin_approx(x: f32) -> f32 {
    let x2 = x * x;
    x * (1.0 + x2 * (-0.166_666_67 + x2 * (0.008_333_334 - x2 * 0.000_198_412_7)))
}

fn cos_approx(x: f32) -> f32 {
    let x2 = x * x;
    1.0 + x2 * (-0.5 + x2 * (0.041_666_668 - x2 * 0.001_388_888_9))
}

fn norm_angle(a: f32) -> f32 {
    let two_pi = 2.0 * PI;
    let mut r = a % two_pi;
    if r > PI {
        r -= two_pi;
    } else if r < -PI {
        r += two_pi;
    }
    r
}

/// Graphics console commands
pub fn cmd_gfx(args: &[String]) -> Result<(), ShellError> {
    /// Performs the print gfx help operation.
    fn print_gfx_help() {
        shell_println!("Usage: gfx <subcommand>");
        shell_println!("  help                 Show this help");
        shell_println!("  info                 Show framebuffer/text console info");
        shell_println!("  mode on|off          Enable/disable double-buffer mode");
        shell_println!("  ui compact|normal|large");
        shell_println!("                       Set UI scaling preset");
        shell_println!("  test                 Draw graphics validation screen");
        shell_println!("  test3d               Spinning 3D torus (SIMD framebuffer test)");
    }

    if args.is_empty() {
        print_gfx_help();
        return Ok(());
    }
    match args[0].as_str() {
        "help" => {
            print_gfx_help();
            Ok(())
        }
        "info" => {
            let info = vga::framebuffer_info();
            if !info.available {
                shell_println!("Graphics console: unavailable");
                return Ok(());
            }

            shell_println!("Graphics console:");
            shell_println!(
                "  Framebuffer: {}x{} {}bpp pitch={}",
                info.width,
                info.height,
                info.bpp,
                info.pitch
            );
            shell_println!(
                "  RGB masks: R({}:{}) G({}:{}) B({}:{})",
                info.red_size,
                info.red_shift,
                info.green_size,
                info.green_shift,
                info.blue_size,
                info.blue_shift
            );
            shell_println!(
                "  Text grid: {}x{} (glyph={}x{})",
                info.text_cols,
                info.text_rows,
                info.glyph_w,
                info.glyph_h
            );
            shell_println!(
                "  Double buffer mode: {}",
                if info.double_buffer_mode { "on" } else { "off" }
            );
            shell_println!(
                "  Double buffer active: {}",
                if info.double_buffer_enabled {
                    "yes"
                } else {
                    "no"
                }
            );
            let scale = match info.ui_scale {
                vga::UiScale::Compact => "compact",
                vga::UiScale::Normal => "normal",
                vga::UiScale::Large => "large",
            };
            shell_println!("  UI scale: {}", scale);
            Ok(())
        }
        "mode" => {
            if args.len() < 2 {
                print_gfx_help();
                return Ok(());
            }
            match args[1].as_str() {
                "on" => {
                    vga::set_double_buffer_mode(true);
                    shell_println!("gfx: double-buffer mode enabled");
                }
                "off" => {
                    vga::set_double_buffer_mode(false);
                    shell_println!("gfx: double-buffer mode disabled");
                }
                _ => print_gfx_help(),
            }
            Ok(())
        }
        "ui" => {
            if args.len() < 2 {
                print_gfx_help();
                return Ok(());
            }
            let scale = match args[1].as_str() {
                "compact" => vga::UiScale::Compact,
                "normal" => vga::UiScale::Normal,
                "large" => vga::UiScale::Large,
                _ => {
                    print_gfx_help();
                    return Ok(());
                }
            };
            vga::set_ui_scale(scale);
            shell_println!("gfx: ui scale updated");
            Ok(())
        }
        "test" => cmd_gfx_test(),
        "test3d" => cmd_gfx_test3d(),
        "demo" => cmd_gfx_demo(args),
        _ => {
            print_gfx_help();
            Ok(())
        }
    }
}

/// Performs the cmd gfx test operation.
pub fn cmd_gfx_test() -> Result<(), ShellError> {
    if !vga::is_available() {
        shell_println!("gfx-test: framebuffer console unavailable");
        return Ok(());
    }

    let (w, h) = vga::screen_size();
    let canvas = vga::Canvas::new(
        RgbColor::new(0xE2, 0xE8, 0xF0),
        RgbColor::new(0x12, 0x16, 0x1E),
    );
    canvas.begin_frame();
    canvas.clear();

    for y in (0..h).step_by(40) {
        vga::draw_line(
            0,
            y as isize,
            w.saturating_sub(1) as isize,
            y as isize,
            RgbColor::new(0x22, 0x2E, 0x3A),
        );
    }
    for x in (0..w).step_by(40) {
        vga::draw_line(
            x as isize,
            0,
            x as isize,
            h.saturating_sub(1) as isize,
            RgbColor::new(0x22, 0x2E, 0x3A),
        );
    }

    let bw = w.saturating_sub(120).min(560);
    let bh = h.saturating_sub(220).min(240);
    let bx = 60;
    let by = 80;
    vga::fill_rect(bx, by, bw, bh, RgbColor::new(0x1A, 0x22, 0x2C));
    vga::draw_rect(bx, by, bw, bh, RgbColor::new(0x4F, 0xB3, 0xB3));
    vga::fill_rect_alpha(
        bx + 24,
        by + 24,
        bw.saturating_sub(48),
        bh.saturating_sub(48),
        RgbColor::new(0x7E, 0xC1, 0xFF),
        96,
    );
    vga::set_clip_rect(
        bx + 12,
        by + 12,
        bw.saturating_sub(24),
        bh.saturating_sub(24),
    );
    vga::fill_rect(bx, by, bw, bh, RgbColor::new(0x1B, 0x4D, 0x8A));
    vga::reset_clip_rect();

    vga::draw_text(
        bx + 18,
        by + 16,
        "GFX TEST: alpha / clip / text",
        TextOptions {
            fg: RgbColor::new(0xF5, 0xFA, 0xFF),
            bg: RgbColor::new(0x1A, 0x22, 0x2C),
            align: TextAlign::Left,
            wrap: false,
            max_width: Some(bw.saturating_sub(36)),
        },
    );

    canvas.system_status_line(UiTheme::OCEAN_STATUS);
    canvas.end_frame();
    vga::set_text_cursor(0, vga::text_rows().saturating_sub(2));
    shell_println!("gfx-test: rendered");
    Ok(())
}

/// Spinning 3D torus (donut) :test SIMD framebuffer in real conditions
pub fn cmd_gfx_test3d() -> Result<(), ShellError> {
    if !vga::is_available() {
        shell_println!("gfx-test3d: framebuffer console unavailable");
        return Ok(());
    }

    use crate::shell::is_interrupted;
    use core::f32::consts::PI;

    let (w, h) = vga::screen_size();
    let cx = w as f32 / 2.0;
    let cy = h as f32 / 2.0;
    let scale = (w.min(h) as f32) * 0.28;

    let canvas = vga::Canvas::new(
        RgbColor::new(0xE2, 0xE8, 0xF0),
        RgbColor::new(0x0A, 0x0E, 0x14),
    );
    vga::set_double_buffer_mode(true);

    // Paramètres du tore
    const R1: f32 = 2.00; // radius of the central circle
    const R2: f32 = 0.80; // radius of the tube
    const THETA_N: usize = 50; // subdivisions around the tube
    const PHI_N: usize = 100; // subdivisions around the torus
    const DOT_SIZE: usize = 2; // size of a point on the screen

    let theta_step = 2.0 * PI / THETA_N as f32;
    let phi_step = 2.0 * PI / PHI_N as f32;

    // Cyclic palette (blue => cyan => green => yellow => red)
    const PALETTE: [RgbColor; 16] = [
        RgbColor::new(0x10, 0x48, 0xA0), // deep blue
        RgbColor::new(0x18, 0x60, 0xB0),
        RgbColor::new(0x20, 0x7A, 0xC0),
        RgbColor::new(0x30, 0x94, 0xD0),
        RgbColor::new(0x40, 0xAE, 0xD0), // blue-cyan
        RgbColor::new(0x50, 0xC8, 0xC0),
        RgbColor::new(0x60, 0xD8, 0xA0), // green-cyan
        RgbColor::new(0x80, 0xE0, 0x80), // light green
        RgbColor::new(0xA0, 0xE0, 0x60),
        RgbColor::new(0xC0, 0xD0, 0x50), // yellow-green
        RgbColor::new(0xD0, 0xB0, 0x40), // yellow
        RgbColor::new(0xE0, 0x90, 0x30), // orange
        RgbColor::new(0xE0, 0x70, 0x30),
        RgbColor::new(0xE0, 0x50, 0x30), // red-orange
        RgbColor::new(0xC0, 0x30, 0x30), // red
        RgbColor::new(0x90, 0x20, 0x30), // dark red
    ];

    shell_println!("gfx-test3d: spinning donut — press Ctrl+C to quit");

    let mut frame: u64 = 0;
    loop {
        if is_interrupted() {
            shell_println!("gfx-test3d: stopped");
            break;
        }

        canvas.begin_frame();
        canvas.clear();

        let rot_a = frame as f32 * 0.020; // rotation around X axis
        let rot_b = frame as f32 * 0.015; // rotation around Z axis
        let sa = sin_approx(norm_angle(rot_a));
        let ca = cos_approx(norm_angle(rot_a));
        let sb = sin_approx(norm_angle(rot_b));
        let cb = cos_approx(norm_angle(rot_b));

        let mut ti = 0;
        while ti < THETA_N {
            let theta = ti as f32 * theta_step;
            let st = sin_approx(norm_angle(theta));
            let ct = cos_approx(norm_angle(theta));

            let mut pi = 0;
            while pi < PHI_N {
                let phi = pi as f32 * phi_step;
                let sp = sin_approx(norm_angle(phi));
                let cp = cos_approx(norm_angle(phi));

                // 3D position on the torus (local coordinate system)
                let x = (R1 + R2 * ct) * cp;
                let y = (R1 + R2 * ct) * sp;
                let z = R2 * st;

                // Rotation around X axis
                let x1 = x;
                let y1 = y * ca - z * sa;
                let z1 = y * sa + z * ca;

                // Rotation around Z axis
                let x2 = x1 * cb - y1 * sb;
                let y2 = x1 * sb + y1 * cb;
                let z2 = z1;

                // Surface normal (pointing outward from the tube)
                let nx = ct * cp;
                let ny = ct * sp;
                let nz = st;
                // Apply rotations to the normal
                let nx1 = nx;
                let ny1 = ny * ca - nz * sa;
                let nz1 = ny * sa + nz * ca;
                let nx2 = nx1 * cb - ny1 * sb;
                let ny2 = nx1 * sb + ny1 * cb;
                let nz2 = nz1;

                // Luminosity (fixed light direction)
                let lum = nx2 * 0.3 + ny2 * 0.5 + nz2 * 0.8;
                // Project only points whose normal is facing the light
                if lum > 0.0 {
                    // Perspective
                    let dist = 6.0;
                    let inv_z = dist / (z2 + 3.0 + dist);
                    let sx = (cx + x2 * scale * inv_z) as isize;
                    let sy = (cy - y2 * scale * inv_z) as isize;

                    let idx = (lum * 15.0) as usize;
                    let color = PALETTE[idx.min(15)];

                    for dy in 0..DOT_SIZE {
                        for dx in 0..DOT_SIZE {
                            let px = sx + dx as isize;
                            let py = sy + dy as isize;
                            if px >= 0 && py >= 0 && px < w as isize && py < h as isize {
                                vga::draw_pixel(px as usize, py as usize, color);
                            }
                        }
                    }
                }

                pi += 1;
            }
            ti += 1;
        }

        canvas.system_status_line(UiTheme::OCEAN_STATUS);
        canvas.end_frame();

        frame += 1;
    }

    vga::set_double_buffer_mode(false);
    vga::set_text_cursor(0, vga::text_rows().saturating_sub(2));
    Ok(())
}

/// Performs the cmd gfx demo operation.
pub fn cmd_gfx_demo(_args: &[String]) -> Result<(), ShellError> {
    use vga::{
        DockEdge, TerminalWidget, UiDockLayout, UiLabel, UiPanel, UiProgressBar, UiRect, UiTable,
    };

    if !vga::is_available() {
        shell_println!("gfx-demo: framebuffer console unavailable");
        return Ok(());
    }

    let mut layout = UiDockLayout::from_screen();
    let top = layout.dock(DockEdge::Top, vga::ui_scale_px(56));
    let bottom = layout.dock(DockEdge::Bottom, vga::ui_scale_px(120));
    let left = layout.dock(DockEdge::Left, vga::ui_scale_px(360));
    let _center = layout.remaining();

    let theme = UiTheme::SLATE;
    let canvas = vga::Canvas::new(theme.text, theme.background);
    canvas.begin_frame();
    canvas.ui_clear(theme);

    vga::ui_draw_panel_widget(&UiPanel {
        rect: top,
        title: "Strat9 Graphics Console",
        body: "Dock layout + widgets + terminal demo",
        theme,
    });

    canvas.ui_label(&UiLabel {
        rect: UiRect::new(
            top.x + vga::ui_scale_px(8),
            top.y + vga::ui_scale_px(30),
            top.w.saturating_sub(vga::ui_scale_px(16)),
            vga::ui_scale_px(24),
        ),
        text: "layout: top + bottom + left + center",
        fg: RgbColor::new(0xD0, 0xE4, 0xFF),
        bg: theme.panel_bg,
        align: TextAlign::Left,
    });

    canvas.ui_panel(
        left.x,
        left.y,
        left.w,
        left.h,
        "System",
        "Progress bars and data table",
        theme,
    );

    canvas.ui_progress_bar(UiProgressBar {
        rect: UiRect::new(
            left.x + vga::ui_scale_px(12),
            left.y + vga::ui_scale_px(46),
            left.w.saturating_sub(vga::ui_scale_px(24)),
            vga::ui_scale_px(16),
        ),
        value: 72,
        fg: RgbColor::new(0x58, 0xD6, 0xA3),
        bg: RgbColor::new(0x12, 0x16, 0x1E),
        border: theme.panel_border,
    });

    let headers = vec![
        String::from("Metric"),
        String::from("Value"),
        String::from("Status"),
    ];
    let rows: Vec<Vec<String>> = vec![
        vec![String::from("CPU"), String::from("72%"), String::from("ok")],
        vec![
            String::from("Memory"),
            String::from("43%"),
            String::from("ok"),
        ],
    ];
    canvas.ui_table(&UiTable {
        rect: UiRect::new(
            left.x + vga::ui_scale_px(12),
            left.y + vga::ui_scale_px(96),
            left.w.saturating_sub(vga::ui_scale_px(24)),
            left.h.saturating_sub(vga::ui_scale_px(108)),
        ),
        headers,
        rows,
        theme,
    });

    let mut term = TerminalWidget::new(bottom, 64);
    term.title = String::from("Kernel Terminal");
    term.push_ansi_line("\u{1b}[36m[boot]\u{1b}[0m ui widgets initialized");
    term.draw();

    canvas.system_status_line(UiTheme::OCEAN_STATUS);
    canvas.end_frame();
    let row = vga::text_rows().saturating_sub(2);
    vga::set_text_cursor(0, row);
    Ok(())
}
