use alloc::string::String;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use picoserve::extract::FromRequestParts;
use picoserve::request::RequestParts;
use picoserve::response::Response;
use picoserve::routing::{get, parse_path_segment, post};

use crate::{net, sysinfo};
const ADMIN_TOKEN_PATH: &str = "/initfs/web-admin.token";
const KILL_RATE_LIMIT_WINDOW_NS: u64 = 10_000_000_000;
const KILL_RATE_LIMIT_MAX_PER_WINDOW: u32 = 8;
static KILL_WINDOW_START_NS: AtomicU64 = AtomicU64::new(0);
static KILL_WINDOW_COUNT: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// Content types for picoserve responses
// ---------------------------------------------------------------------------

pub struct HtmlContent(pub &'static str);

impl picoserve::response::Content for HtmlContent {
    /// Implements content type.
    fn content_type(&self) -> &'static str {
        "text/html; charset=utf-8"
    }
    /// Implements content length.
    fn content_length(&self) -> usize {
        self.0.len()
    }
    async fn write_content<W: picoserve::io::Write>(self, mut writer: W) -> Result<(), W::Error> {
        writer.write_all(self.0.as_bytes()).await
    }
}

pub struct JsonContent(pub String);

impl picoserve::response::Content for JsonContent {
    /// Implements content type.
    fn content_type(&self) -> &'static str {
        "application/json"
    }
    /// Implements content length.
    fn content_length(&self) -> usize {
        self.0.len()
    }
    async fn write_content<W: picoserve::io::Write>(self, mut writer: W) -> Result<(), W::Error> {
        writer.write_all(self.0.as_bytes()).await
    }
}

// ---------------------------------------------------------------------------
// Helper: JSON response with CORS
// ---------------------------------------------------------------------------

/// Implements json ok.
fn json_ok(
    body: String,
) -> Response<impl picoserve::response::HeadersIter, impl picoserve::response::Body> {
    Response::ok(JsonContent(body)).with_header("Access-Control-Allow-Origin", "*")
}

/// Implements json admin.
fn json_admin(
    body: String,
) -> Response<impl picoserve::response::HeadersIter, impl picoserve::response::Body> {
    Response::ok(JsonContent(body))
}

/// Implements admin token.
fn admin_token() -> String {
    let token = net::read_file_text(ADMIN_TOKEN_PATH);
    let trimmed = token.trim();
    String::from(trimmed)
}

/// Implements allow kill now.
fn allow_kill_now() -> bool {
    let now = net::clock_gettime_ns();
    let start = KILL_WINDOW_START_NS.load(Ordering::Relaxed);
    if now.saturating_sub(start) > KILL_RATE_LIMIT_WINDOW_NS {
        KILL_WINDOW_START_NS.store(now, Ordering::Relaxed);
        KILL_WINDOW_COUNT.store(0, Ordering::Relaxed);
    }
    let prev = KILL_WINDOW_COUNT.fetch_add(1, Ordering::Relaxed);
    prev < KILL_RATE_LIMIT_MAX_PER_WINDOW
}

struct AdminAuth;

impl<'r, State> FromRequestParts<'r, State> for AdminAuth {
    type Rejection = String;

    /// Builds a value from request parts.
    async fn from_request_parts(
        _state: &'r State,
        request_parts: &RequestParts<'r>,
    ) -> Result<Self, Self::Rejection> {
        let expected = admin_token();
        if expected.is_empty() {
            return Err(String::from(
                r#"{"killed":false,"error":"admin token not configured"}"#,
            ));
        }
        let provided = request_parts
            .headers()
            .get("authorization")
            .and_then(|v| v.as_str().ok())
            .unwrap_or("");
        let ok = if let Some(bearer) = provided.strip_prefix("Bearer ") {
            bearer == expected
        } else {
            provided == expected
        };
        if ok {
            Ok(Self)
        } else {
            Err(String::from(
                r#"{"killed":false,"error":"unauthorized"}"#,
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// Implements index.
async fn index() -> Response<impl picoserve::response::HeadersIter, impl picoserve::response::Body>
{
    Response::ok(HtmlContent(DASHBOARD_HTML))
}

/// Implements api health.
async fn api_health(
) -> Response<impl picoserve::response::HeadersIter, impl picoserve::response::Body> {
    json_ok(sysinfo::json_health())
}

/// Implements api uptime.
async fn api_uptime(
) -> Response<impl picoserve::response::HeadersIter, impl picoserve::response::Body> {
    json_ok(sysinfo::json_uptime())
}

/// Implements api version.
async fn api_version(
) -> Response<impl picoserve::response::HeadersIter, impl picoserve::response::Body> {
    json_ok(sysinfo::json_version())
}

/// Implements api cpuinfo.
async fn api_cpuinfo(
) -> Response<impl picoserve::response::HeadersIter, impl picoserve::response::Body> {
    json_ok(sysinfo::json_cpuinfo())
}

/// Implements api meminfo.
async fn api_meminfo(
) -> Response<impl picoserve::response::HeadersIter, impl picoserve::response::Body> {
    json_ok(sysinfo::json_meminfo())
}

/// Implements api silos.
async fn api_silos(
) -> Response<impl picoserve::response::HeadersIter, impl picoserve::response::Body> {
    json_ok(sysinfo::json_silos())
}

/// Implements api processes.
async fn api_processes(
) -> Response<impl picoserve::response::HeadersIter, impl picoserve::response::Body> {
    json_ok(sysinfo::json_processes())
}

/// Implements api network.
async fn api_network(
) -> Response<impl picoserve::response::HeadersIter, impl picoserve::response::Body> {
    json_ok(sysinfo::json_network())
}

/// Implements api routes.
async fn api_routes(
) -> Response<impl picoserve::response::HeadersIter, impl picoserve::response::Body> {
    json_ok(sysinfo::json_routes())
}

/// Implements api all.
async fn api_all(
) -> Response<impl picoserve::response::HeadersIter, impl picoserve::response::Body> {
    json_ok(sysinfo::json_all())
}

/// Implements api kill.
async fn api_kill(
    pid: u32,
    _auth: AdminAuth,
) -> Response<impl picoserve::response::HeadersIter, impl picoserve::response::Body> {
    if !allow_kill_now() {
        return json_admin(String::from(
            r#"{"killed":false,"error":"rate limit"}"#,
        ));
    }
    json_admin(sysinfo::json_kill_result(pid))
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Implements build router.
pub fn build_router() -> picoserve::Router<impl picoserve::routing::PathRouter> {
    picoserve::Router::new()
        .route("/", get(index))
        .route("/api/health", get(api_health))
        .route("/api/uptime", get(api_uptime))
        .route("/api/version", get(api_version))
        .route("/api/cpuinfo", get(api_cpuinfo))
        .route("/api/meminfo", get(api_meminfo))
        .route("/api/silos", get(api_silos))
        .route("/api/processes", get(api_processes))
        .route("/api/network", get(api_network))
        .route("/api/routes", get(api_routes))
        .route("/api/all", get(api_all))
        .route(
            ("/api/kill", parse_path_segment::<u32>()),
            post(|pid, auth| async move { api_kill(pid, auth).await }),
        )
}

// ---------------------------------------------------------------------------
// Embedded HTML dashboard
// ---------------------------------------------------------------------------

const DASHBOARD_HTML: &str = include_str!("../assets/dashboard.html");
