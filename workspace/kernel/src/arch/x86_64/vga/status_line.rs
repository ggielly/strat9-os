use alloc::{format, string::String};
use core::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};
use spin::Mutex;

use super::{
    current_fps, is_available, with_writer, TextAlign, TextOptions, UiTheme, VgaWriter, VGA_WRITER,
};

static STATUS_LAST_REFRESH_TICK: AtomicU64 = AtomicU64::new(0);
const STATUS_REFRESH_PERIOD_TICKS: u64 = 100; // 100Hz timer => 1s
static STATUS_LAST_IP_REFRESH_TICK: AtomicU64 = AtomicU64::new(0);
const STATUS_IP_REFRESH_PERIOD_TICKS: u64 = 3_000; // 100Hz timer => 30s

#[derive(Debug, Clone)]
struct StatusLineInfo {
    hostname: String,
    ip: String,
}

static STATUS_LINE_INFO: Mutex<Option<StatusLineInfo>> = Mutex::new(None);

const STATUS_NET_INFO_DEFAULT: &str = "n/a | n/a";
const STATUS_HOSTNAME_BUF_CAP: usize = 64;
const STATUS_NET_BUF_CAP: usize = 96;
const STATUS_LEFT_TEXT_CAP: usize = 128;
const STATUS_RIGHT_TEXT_CAP: usize = 320;
const STATUS_BAR_LEFT_MIN_COLS: usize = 8;
const STATUS_BAR_GAP_COLS: usize = 2;

/// Performs the status line info operation.
fn status_line_info() -> StatusLineInfo {
    let mut guard = STATUS_LINE_INFO.lock();
    if guard.is_none() {
        *guard = Some(StatusLineInfo {
            hostname: String::from("strat9"),
            ip: String::from(STATUS_NET_INFO_DEFAULT),
        });
    }
    guard.as_ref().cloned().unwrap_or(StatusLineInfo {
        hostname: String::from("strat9"),
        ip: String::from(STATUS_NET_INFO_DEFAULT),
    })
}

/// Stack-only string buffer to avoid heap allocation in the status-line path.
struct StackStr<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> StackStr<N> {
    /// Creates a new instance.
    const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn char_len(&self) -> usize {
        self.as_str().chars().count()
    }

    fn push_str(&mut self, s: &str) {
        let _ = core::fmt::Write::write_str(self, s);
    }

    fn push_char(&mut self, ch: char) {
        let mut buf = [0u8; 4];
        self.push_str(ch.encode_utf8(&mut buf));
    }

    /// Returns this as str.
    fn as_str(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
}

impl<const N: usize> core::fmt::Write for StackStr<N> {
    /// Writes str.
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let avail = N - self.len;
        let n = bytes.len().min(avail);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        Ok(())
    }
}

impl<const N: usize> core::fmt::Display for StackStr<N> {
    /// Performs the fmt operation.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

struct StatusLineRender {
    left: StackStr<STATUS_LEFT_TEXT_CAP>,
    right: StackStr<STATUS_RIGHT_TEXT_CAP>,
}

impl StatusLineRender {
    fn new(hostname: &str, ip: &str, tick: u64) -> Self {
        use core::fmt::Write;

        let total_secs = tick / 100;
        let h = total_secs / 3600;
        let m = (total_secs % 3600) / 60;
        let s = total_secs % 60;
        let fps = current_fps(tick);
        let mem = format_mem_usage_stack();

        let mut left = StackStr::<STATUS_LEFT_TEXT_CAP>::new();
        let _ = write!(left, " {} ", hostname);

        let mut right = StackStr::<STATUS_RIGHT_TEXT_CAP>::new();
        let _ = write!(
            right,
            "ip:{}  ver:{}  up:{:02}:{:02}:{:02}  ticks:{}  fps:{}  load:n/a  mem:{} ",
            ip,
            env!("CARGO_PKG_VERSION"),
            h,
            m,
            s,
            tick,
            fps,
            mem.as_str()
        );

        Self { left, right }
    }
}

fn fit_status_bar_text<const N: usize>(text: &str, max_cols: usize) -> StackStr<N> {
    let mut out = StackStr::<N>::new();
    if max_cols == 0 {
        return out;
    }

    let total_cols = text.chars().count();
    if total_cols <= max_cols {
        out.push_str(text);
        return out;
    }

    if max_cols <= 3 {
        for _ in 0..max_cols {
            out.push_char('.');
        }
        return out;
    }

    for ch in text.chars().take(max_cols - 3) {
        out.push_char(ch);
    }
    out.push_str("...");
    out
}

/// Performs the draw status bar inner operation.
fn draw_status_bar_inner(w: &mut VgaWriter, left: &str, right: &str, theme: UiTheme) {
    let saved_clip = w.clip;
    w.reset_clip_rect();

    let (gw, gh) = w.glyph_size();
    if gh == 0 || gw == 0 {
        w.clip = saved_clip;
        return;
    }

    let total_cols = w.width() / gw;
    if total_cols == 0 {
        w.clip = saved_clip;
        return;
    }

    let bar_h = gh;
    let y = w.height().saturating_sub(bar_h);
    w.fill_rect(0, y, w.width(), bar_h, theme.status_bg);

    let available_cols = total_cols.saturating_sub(STATUS_BAR_GAP_COLS);
    let left_cols = left.chars().count();
    let right_cols = right.chars().count();

    let right_budget_cols = if left_cols.saturating_add(right_cols) > available_cols {
        available_cols.saturating_sub(core::cmp::min(left_cols, STATUS_BAR_LEFT_MIN_COLS))
    } else {
        right_cols
    };
    let fitted_right = fit_status_bar_text::<STATUS_RIGHT_TEXT_CAP>(right, right_budget_cols);
    let fitted_right_cols = fitted_right.char_len();
    let left_budget_cols = available_cols.saturating_sub(fitted_right_cols);
    let fitted_left = fit_status_bar_text::<STATUS_LEFT_TEXT_CAP>(left, left_budget_cols);

    let left_width = fitted_left.char_len().saturating_mul(gw);
    let right_width = fitted_right.char_len().saturating_mul(gw);

    if !fitted_left.is_empty() {
        let left_opts = TextOptions {
            fg: theme.status_text,
            bg: theme.status_bg,
            align: TextAlign::Left,
            wrap: false,
            max_width: Some(left_width),
        };
        w.draw_text(0, y, fitted_left.as_str(), left_opts);
    }

    if !fitted_right.is_empty() {
        let right_opts = TextOptions {
            fg: theme.status_text,
            bg: theme.status_bg,
            align: TextAlign::Right,
            wrap: false,
            max_width: Some(right_width),
        };
        let right_x = w.width().saturating_sub(right_width);
        w.draw_text(right_x, y, fitted_right.as_str(), right_opts);
    }
    w.clip = saved_clip;
}

/// Performs the ui draw status bar operation.
pub fn ui_draw_status_bar(left: &str, right: &str, theme: UiTheme) {
    let _ = with_writer(|w| {
        draw_status_bar_inner(w, left, right, theme);
    });
}

/// Sets status hostname.
pub fn set_status_hostname(hostname: &str) {
    let mut guard = STATUS_LINE_INFO.lock();
    if guard.is_none() {
        *guard = Some(StatusLineInfo {
            hostname: String::new(),
            ip: String::from(STATUS_NET_INFO_DEFAULT),
        });
    }
    if let Some(info) = guard.as_mut() {
        info.hostname.clear();
        info.hostname.push_str(hostname);
    }
}

/// Sets status ip.
pub fn set_status_ip(ip: &str) {
    let mut guard = STATUS_LINE_INFO.lock();
    if guard.is_none() {
        *guard = Some(StatusLineInfo {
            hostname: String::from("strat9"),
            ip: String::new(),
        });
    }
    if let Some(info) = guard.as_mut() {
        info.ip.clear();
        info.ip.push_str(ip);
    }
}

/// Performs the draw system status line operation.
pub fn draw_system_status_line(theme: UiTheme) {
    let info = status_line_info();
    let tick = crate::process::scheduler::ticks();
    let render = StatusLineRender::new(&info.hostname, &info.ip, tick);
    ui_draw_status_bar(render.left.as_str(), render.right.as_str(), theme);
}

/// Performs the draw boot status line operation.
pub(super) fn draw_boot_status_line(theme: UiTheme) {
    let _ = with_writer(|w| {
        draw_status_bar_inner(
            w,
            " strat9 ",
            "ip:n/a | n/a  ver:boot  up:00:00:00  ticks:0  load:n/a  mem:n/a ",
            theme,
        );
    });
}

fn read_status_net_value(paths: &[&str], invalid_values: &[&str]) -> Option<String> {
    for path in paths {
        let fd = match crate::vfs::open(path, crate::vfs::OpenFlags::READ) {
            Ok(fd) => fd,
            Err(_) => continue,
        };
        let mut buf = [0u8; 96];
        let read_res = crate::vfs::read(fd, &mut buf);
        let _ = crate::vfs::close(fd);
        let n = match read_res {
            Ok(n) => n,
            Err(_) => continue,
        };
        if n == 0 {
            continue;
        }
        let Ok(text) = core::str::from_utf8(&buf[..n]) else {
            continue;
        };
        let mut value = text.trim();
        if let Some(slash) = value.find('/') {
            value = &value[..slash];
        }
        if value.is_empty() || invalid_values.iter().any(|invalid| value == *invalid) {
            continue;
        }
        return Some(String::from(value));
    }
    None
}

/// Performs the refresh status ip from net scheme operation.
fn refresh_status_ip_from_net_scheme() {
    let tick = crate::process::scheduler::ticks();
    let last = STATUS_LAST_IP_REFRESH_TICK.load(Ordering::Relaxed);
    if tick.saturating_sub(last) < STATUS_IP_REFRESH_PERIOD_TICKS {
        return;
    }
    if STATUS_LAST_IP_REFRESH_TICK
        .compare_exchange(last, tick, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    let ipv4 = read_status_net_value(&["/net/address", "/net/ip"], &["0.0.0.0", "169.254.0.0"])
        .unwrap_or_else(|| String::from("n/a"));
    let ipv6 = read_status_net_value(&["/net/ip6/address", "/net/ip6"], &["::"])
        .unwrap_or_else(|| String::from("n/a"));
    let display = format!("{} | {}", ipv4, ipv6);
    set_status_ip(&display);
}

fn try_status_line_snapshot() -> Option<(
    StackStr<STATUS_HOSTNAME_BUF_CAP>,
    StackStr<STATUS_NET_BUF_CAP>,
)> {
    let guard = STATUS_LINE_INFO.try_lock()?;
    let (hostname, ip) = if let Some(info) = guard.as_ref() {
        (info.hostname.as_str(), info.ip.as_str())
    } else {
        ("strat9", STATUS_NET_INFO_DEFAULT)
    };

    let mut hostname_buf = StackStr::<STATUS_HOSTNAME_BUF_CAP>::new();
    hostname_buf.push_str(hostname);

    let mut ip_buf = StackStr::<STATUS_NET_BUF_CAP>::new();
    ip_buf.push_str(ip);

    Some((hostname_buf, ip_buf))
}

/// Performs the maybe refresh system status line operation.
pub fn maybe_refresh_system_status_line(theme: UiTheme) {
    if !is_available() {
        return;
    }

    let tick = crate::process::scheduler::ticks();
    let last = STATUS_LAST_REFRESH_TICK.load(Ordering::Relaxed);
    if tick.saturating_sub(last) < STATUS_REFRESH_PERIOD_TICKS {
        return;
    }
    if STATUS_LAST_REFRESH_TICK
        .compare_exchange(last, tick, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    refresh_status_ip_from_net_scheme();

    let Some((hostname, ip)) = try_status_line_snapshot() else {
        return;
    };

    let render = StatusLineRender::new(hostname.as_str(), ip.as_str(), tick);

    if let Some(mut writer) = VGA_WRITER.try_lock() {
        draw_status_bar_inner(
            &mut writer,
            render.left.as_str(),
            render.right.as_str(),
            theme,
        );
    }
}

fn format_mem_usage_stack() -> StackStr<32> {
    use core::fmt::Write;

    let lock = crate::memory::buddy::get_allocator();
    let Some(guard) = lock.try_lock() else {
        let mut buf = StackStr::<32>::new();
        buf.push_str("n/a");
        return buf;
    };
    let Some(alloc) = guard.as_ref() else {
        let mut buf = StackStr::<32>::new();
        buf.push_str("n/a");
        return buf;
    };

    let (total_pages, allocated_pages) = alloc.page_totals();
    let page_size = 4096usize;
    let total = total_pages.saturating_mul(page_size);
    let used = allocated_pages.saturating_mul(page_size);
    let free = total.saturating_sub(used);

    let mut buf = StackStr::<32>::new();
    let _ = write!(
        buf,
        "{}/{}",
        format_size_stack(free),
        format_size_stack(total)
    );
    buf
}

/// Performs the format size stack operation.
fn format_size_stack(bytes: usize) -> StackStr<16> {
    use core::fmt::Write;
    const KB: usize = 1024;
    const MB: usize = 1024 * KB;
    const GB: usize = 1024 * MB;
    let mut buf = StackStr::<16>::new();
    if bytes >= GB {
        let _ = write!(buf, "{}G", bytes / GB);
    } else if bytes >= MB {
        let _ = write!(buf, "{}M", bytes / MB);
    } else if bytes >= KB {
        let _ = write!(buf, "{}K", bytes / KB);
    } else {
        let _ = write!(buf, "{}B", bytes);
    }
    buf
}

/// Performs the status line task main operation.
pub extern "C" fn status_line_task_main() -> ! {
    let mut last_tick = 0u64;
    let mut diag_counter = 0u64;
    loop {
        let tick = crate::process::scheduler::ticks();
        if tick != last_tick {
            last_tick = tick;
            maybe_refresh_system_status_line(UiTheme::OCEAN_STATUS);
        }
        diag_counter += 1;
        if diag_counter % 5000 == 0 {
            crate::serial_println!(
                "[status-line] heartbeat tick={} vga={}",
                tick,
                is_available()
            );
        }
        crate::process::yield_task();
    }
}
