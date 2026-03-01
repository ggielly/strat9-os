#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::{
    format,
    string::String,
    vec::Vec,
};
use base64::Engine;
use core::{
    alloc::Layout,
    panic::PanicInfo,
};
use libssh_strat9::{
    Server,
    SessionPump,
};
use ssh_core::{
    AuthProvider, CoreDirective, ExecSessionProvider, ExecSessionWiring, HostKeyProvider, SshCore,
    SshCoreError, Transport,
};
use strat9_syscall::{
    call,
    error,
    flag,
};

const GLOBAL_AUTH_PATHS: [&str; 2] = ["/initfs/etc/ssh/authorized_keys", "/initfs/authorized_keys"];
const USER_AUTH_DIR: &str = "/initfs/etc/ssh/authorized_keys.d";
const ALLOWED_COMMANDS_PATH: &str = "/initfs/etc/ssh/allowed_commands";
const LISTEN_PORT_PATH: &str = "/initfs/etc/ssh/listen_port";
const MAX_AUTH_TRIES_PATH: &str = "/initfs/etc/ssh/max_auth_tries";
const DENY_ROOT_LOGIN_PATH: &str = "/initfs/etc/ssh/deny_root_login";
const LOG_PATH: &str = "/var/log/sshd.log";
const MAX_AUTH_KEYS: usize = 4096;

alloc_freelist::define_freelist_brk_allocator!(
    pub struct SshdAllocator;
    brk = strat9_syscall::call::brk;
    heap_max = 16 * 1024 * 1024;
);

#[global_allocator]
static ALLOCATOR: SshdAllocator = SshdAllocator;

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    let _ = call::write(2, b"[sshd] OOM\n");
    call::exit(12)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = call::write(2, b"[sshd] panic\n");
    call::exit(255)
}

fn open_log_fd() -> Option<usize> {
    let flags = (flag::OpenFlags::WRONLY | flag::OpenFlags::CREATE | flag::OpenFlags::APPEND).bits() as usize;
    call::openat(0, LOG_PATH, flags, 0).ok()
}

fn log_with_fd(log_fd: Option<usize>, msg: &str) {
    if let Some(fd) = log_fd {
        let _ = call::write(fd, msg.as_bytes());
    }
    let _ = call::write(1, msg.as_bytes());
}

fn read_file(path: &str) -> Option<Vec<u8>> {
    let fd = call::openat(0, path, flag::OpenFlags::RDONLY.bits() as usize, 0).ok()?;
    let mut out = Vec::new();
    let mut chunk = [0u8; 1024];

    loop {
        match call::read(fd, &mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(_) => {
                let _ = call::close(fd);
                return None;
            }
        }
    }

    let _ = call::close(fd);
    Some(out)
}

fn parse_u32_ascii(data: &[u8]) -> Option<u32> {
    let s = core::str::from_utf8(data).ok()?.trim();
    if s.is_empty() {
        return None;
    }
    let mut out: u32 = 0;
    for &b in s.as_bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        out = out.checked_mul(10)?;
        out = out.checked_add((b - b'0') as u32)?;
    }
    Some(out)
}

fn load_bool_flag(path: &str, default: bool) -> bool {
    let Some(data) = read_file(path) else {
        return default;
    };
    let Ok(s) = core::str::from_utf8(&data) else {
        return default;
    };
    let v = s.trim();
    if v.eq_ignore_ascii_case("1")
        || v.eq_ignore_ascii_case("true")
        || v.eq_ignore_ascii_case("yes")
        || v.eq_ignore_ascii_case("on")
    {
        return true;
    }
    if v.eq_ignore_ascii_case("0")
        || v.eq_ignore_ascii_case("false")
        || v.eq_ignore_ascii_case("no")
        || v.eq_ignore_ascii_case("off")
    {
        return false;
    }
    default
}

fn load_listen_port() -> u16 {
    let Some(data) = read_file(LISTEN_PORT_PATH) else {
        return 22;
    };
    let Some(port) = parse_u32_ascii(&data) else {
        return 22;
    };
    if (1..=65535).contains(&port) {
        port as u16
    } else {
        22
    }
}

fn load_max_auth_tries() -> usize {
    let Some(data) = read_file(MAX_AUTH_TRIES_PATH) else {
        return 6;
    };
    let Some(v) = parse_u32_ascii(&data) else {
        return 6;
    };
    let v = v.clamp(1, 32);
    v as usize
}

fn open_listener(path: &str, log_fd: Option<usize>) -> usize {
    let flags = flag::OpenFlags::RDWR.bits() as usize;
    loop {
        match call::openat(0, path, flags, 0) {
            Ok(fd) => return fd,
            Err(_) => {
                log_with_fd(log_fd, "[sshd] waiting for /net tcp listener\n");
                let _ = call::sched_yield();
            }
        }
    }
}

struct NetTransport {
    fd: usize,
    connected: bool,
    saw_zero_read: bool,
}

impl NetTransport {
    fn new(fd: usize) -> Self {
        Self {
            fd,
            connected: false,
            saw_zero_read: false,
        }
    }

    fn close(&mut self) {
        let _ = call::close(self.fd);
    }

    fn saw_zero_read(&mut self) -> bool {
        let v = self.saw_zero_read;
        self.saw_zero_read = false;
        v
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

impl Transport for NetTransport {
    fn recv(&mut self, out: &mut [u8]) -> ssh_core::Result<usize> {
        match call::read(self.fd, out) {
            Ok(0) => {
                self.saw_zero_read = true;
                Ok(0)
            }
            Ok(n) => {
                self.connected = true;
                self.saw_zero_read = false;
                Ok(n)
            }
            Err(error::Error::Again) | Err(error::Error::Interrupted) => Ok(0),
            Err(_) => Err(SshCoreError::Backend),
        }
    }

    fn send(&mut self, data: &[u8]) -> ssh_core::Result<usize> {
        let mut off = 0usize;
        while off < data.len() {
            match call::write(self.fd, &data[off..]) {
                Ok(0) => return Err(SshCoreError::Backend),
                Ok(n) => off += n,
                Err(error::Error::Again) | Err(error::Error::Interrupted) => {
                    let _ = call::sched_yield();
                }
                Err(_) => return Err(SshCoreError::Backend),
            }
        }
        Ok(off)
    }
}

struct FixedHostKey {
    key: &'static [u8],
}

impl HostKeyProvider for FixedHostKey {
    fn host_public_key(&self) -> &[u8] {
        self.key
    }

    fn sign_exchange_hash(&mut self, exchange_hash: &[u8], out: &mut [u8]) -> ssh_core::Result<usize> {
        if out.is_empty() {
            return Err(SshCoreError::BufferTooSmall);
        }
        let mut acc: u8 = 0;
        for b in exchange_hash {
            acc ^= *b;
        }
        let n = out.len().min(32);
        for (i, b) in out[..n].iter_mut().enumerate() {
            *b = acc ^ (i as u8);
        }
        Ok(n)
    }
}

struct AuthorizedKey {
    algo: Vec<u8>,
    key_blob: Vec<u8>,
}

struct PublicKeyAuth {
    global_paths: &'static [&'static str],
    user_dir: &'static str,
    deny_root_login: bool,
    global_keys: Vec<AuthorizedKey>,
    global_fingerprint: u64,
}

impl PublicKeyAuth {
    fn from_paths(global_paths: &'static [&'static str], user_dir: &'static str, deny_root_login: bool) -> Self {
        let mut auth = Self {
            global_paths,
            user_dir,
            deny_root_login,
            global_keys: Vec::new(),
            global_fingerprint: 0,
        };
        auth.reload_global();
        auth
    }

    fn reload_global(&mut self) -> bool {
        let keys = Self::load_keys_from_paths(self.global_paths);
        let fp = Self::keys_fingerprint(&keys);
        if fp != self.global_fingerprint || keys.len() != self.global_keys.len() {
            self.global_keys = keys;
            self.global_fingerprint = fp;
            return true;
        }
        false
    }

    fn load_keys_from_paths(paths: &[&str]) -> Vec<AuthorizedKey> {
        let mut keys = Vec::new();

        for path in paths {
            if let Some(data) = read_file(path) {
                Self::parse_authorized_keys(&data, &mut keys);
                if !keys.is_empty() {
                    break;
                }
            }
        }

        keys
    }

    fn load_user_keys(&self, username: &[u8]) -> Vec<AuthorizedKey> {
        let Some(user) = Self::sanitize_username(username) else {
            return Vec::new();
        };

        let mut path = String::from(self.user_dir);
        if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str(&user);

        let Some(data) = read_file(&path) else {
            return Vec::new();
        };

        let mut keys = Vec::new();
        Self::parse_authorized_keys(&data, &mut keys);
        keys
    }

    fn sanitize_username(username: &[u8]) -> Option<String> {
        if username.is_empty() || username.len() > 64 {
            return None;
        }

        let mut out = String::with_capacity(username.len());
        for &b in username {
            let ok = matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' | b'.');
            if !ok {
                return None;
            }
            out.push(b as char);
        }

        Some(out)
    }

    fn parse_authorized_keys(data: &[u8], out: &mut Vec<AuthorizedKey>) {
        let Ok(text) = core::str::from_utf8(data) else {
            return;
        };

        for raw in text.lines() {
            if out.len() >= MAX_AUTH_KEYS {
                break;
            }

            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() < 2 {
                continue;
            }

            let Some(algo_idx) = Self::find_algo_index(&tokens) else {
                continue;
            };
            if algo_idx + 1 >= tokens.len() {
                continue;
            }

            let algo = tokens[algo_idx];
            let blob_b64 = tokens[algo_idx + 1];

            let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(blob_b64.as_bytes()) else {
                continue;
            };

            out.push(AuthorizedKey {
                algo: algo.as_bytes().to_vec(),
                key_blob: blob,
            });
        }
    }

    fn find_algo_index(tokens: &[&str]) -> Option<usize> {
        let mut i = 0;
        while i < tokens.len() {
            if Self::looks_like_algo(tokens[i]) {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn looks_like_algo(token: &str) -> bool {
        token.starts_with("ssh-")
            || token.starts_with("ecdsa-")
            || token.starts_with("sk-")
            || token == "rsa-sha2-256"
            || token == "rsa-sha2-512"
    }

    fn matches(keys: &[AuthorizedKey], algorithm: &[u8], public_key: &[u8]) -> bool {
        for key in keys {
            if key.algo.as_slice() == algorithm && key.key_blob.as_slice() == public_key {
                return true;
            }
        }
        false
    }

    fn keys_fingerprint(keys: &[AuthorizedKey]) -> u64 {
        let mut hash = 0xcbf29ce484222325u64;
        for key in keys {
            for b in key.algo.iter().chain(key.key_blob.iter()) {
                hash ^= *b as u64;
                hash = hash.wrapping_mul(0x100000001b3);
            }
            hash ^= 0xff;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }
}

impl AuthProvider for PublicKeyAuth {
    fn authorize_public_key(
        &mut self,
        username: &[u8],
        algorithm: &[u8],
        public_key: &[u8],
        _signed_data: &[u8],
        _signature: &[u8],
    ) -> ssh_core::Result<bool> {
        if self.deny_root_login && username == b"root" {
            return Ok(false);
        }

        if Self::matches(&self.global_keys, algorithm, public_key) {
            return Ok(true);
        }

        let user_keys = self.load_user_keys(username);
        if Self::matches(&user_keys, algorithm, public_key) {
            return Ok(true);
        }

        Ok(false)
    }
}

struct ExecPolicy {
    path: &'static str,
    allowlist: Vec<String>,
    fingerprint: u64,
}

impl ExecPolicy {
    fn new(path: &'static str) -> Self {
        let mut policy = Self {
            path,
            allowlist: Vec::new(),
            fingerprint: 0,
        };
        let _ = policy.reload();
        policy
    }

    fn reload(&mut self) -> bool {
        let mut allowlist = Vec::new();

        if let Some(data) = read_file(self.path) {
            if let Ok(text) = core::str::from_utf8(&data) {
                for raw in text.lines() {
                    let line = raw.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if line.starts_with("/initfs/bin/") {
                        allowlist.push(String::from(line));
                    }
                }
            }
        }

        let fp = Self::fingerprint(&allowlist);
        if fp != self.fingerprint || allowlist.len() != self.allowlist.len() {
            self.allowlist = allowlist;
            self.fingerprint = fp;
            return true;
        }
        false
    }

    fn fingerprint(items: &[String]) -> u64 {
        let mut hash = 0xcbf29ce484222325u64;
        for item in items {
            for b in item.as_bytes() {
                hash ^= *b as u64;
                hash = hash.wrapping_mul(0x100000001b3);
            }
            hash ^= 0xff;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }

    fn is_allowed(&self, path: &str) -> bool {
        if self.allowlist.is_empty() {
            return true;
        }
        self.allowlist.iter().any(|p| p == path)
    }
}

struct ExecProc {
    session_id: u32,
    pid: usize,
}

struct ExecPlan {
    path: String,
    args: Vec<String>,
}

struct ExecBridge {
    session_seq: u32,
    procs: Vec<ExecProc>,
    policy: ExecPolicy,
    log_fd: Option<usize>,
}

impl ExecBridge {
    fn new(policy_path: &'static str, log_fd: Option<usize>) -> Self {
        Self {
            session_seq: 1,
            procs: Vec::new(),
            policy: ExecPolicy::new(policy_path),
            log_fd,
        }
    }

    fn reload_policy(&mut self) -> bool {
        self.policy.reload()
    }

    fn terminate_all(&mut self) {
        while let Some(proc) = self.procs.pop() {
            let _ = call::kill(proc.pid as isize, 15);
            let mut status = 0;
            let _ = call::waitpid(proc.pid as isize, Some(&mut status), 0);
        }
    }

    fn is_safe_exec_byte(b: u8) -> bool {
        matches!(
            b,
            b'a'..=b'z'
                | b'A'..=b'Z'
                | b'0'..=b'9'
                | b'/'
                | b'.'
                | b'-'
                | b'_'
                | b':'
                | b'='
                | b'+'
                | b'@'
        )
    }

    fn parse_exec_plan(&self, command: &[u8]) -> ssh_core::Result<ExecPlan> {
        let text = core::str::from_utf8(command).map_err(|_| SshCoreError::Unsupported)?;
        let trimmed = text.trim();

        let mut args: Vec<String> = Vec::new();

        if trimmed.is_empty() {
            args.push(String::from("/initfs/bin/sh"));
        } else {
            for token in trimmed.split_whitespace() {
                if token.is_empty() {
                    continue;
                }
                for b in token.as_bytes() {
                    if !Self::is_safe_exec_byte(*b) {
                        return Err(SshCoreError::Unsupported);
                    }
                }
                args.push(String::from(token));
                if args.len() > 32 {
                    return Err(SshCoreError::Unsupported);
                }
            }
            if args.is_empty() {
                args.push(String::from("/initfs/bin/sh"));
            }
        }

        let path = args[0].clone();
        if !path.starts_with("/initfs/bin/") || !self.policy.is_allowed(&path) {
            return Err(SshCoreError::Unsupported);
        }

        Ok(ExecPlan { path, args })
    }

    fn reap_exited(&mut self) {
        loop {
            match call::waitpid(-1, None, call::WNOHANG) {
                Ok(0) => break,
                Ok(pid) => self.drop_pid(pid),
                Err(error::Error::NoChildren) | Err(error::Error::Again) => break,
                Err(error::Error::Interrupted) => continue,
                Err(_) => break,
            }
        }
    }

    fn drop_pid(&mut self, pid: usize) {
        if let Some(idx) = self.procs.iter().position(|p| p.pid == pid) {
            self.procs.swap_remove(idx);
        }
    }
}

impl ExecSessionProvider for ExecBridge {
    fn spawn_exec(&mut self, _username: &[u8], command: &[u8]) -> ssh_core::Result<ExecSessionWiring> {
        let plan = self.parse_exec_plan(command)?;

        let pid = call::fork().map_err(|_| SshCoreError::Backend)?;

        if pid == 0 {
            let _ = call::setpgid(0, 0);

            let mut path_c = plan.path.as_bytes().to_vec();
            path_c.push(0);

            let mut argv_bytes: Vec<Vec<u8>> = Vec::with_capacity(plan.args.len());
            for arg in plan.args {
                let mut v = arg.into_bytes();
                v.push(0);
                argv_bytes.push(v);
            }

            let mut argv: Vec<usize> = Vec::with_capacity(argv_bytes.len() + 1);
            for arg in &argv_bytes {
                argv.push(arg.as_ptr() as usize);
            }
            argv.push(0);

            let envp = [0usize];

            // SAFETY: path_c, argv and envp point to valid process-local buffers during execve.
            let _ = unsafe { call::execve(path_c.as_slice(), argv.as_ptr() as usize, envp.as_ptr() as usize) };
            call::exit(127);
        }

        let session_id = self.session_seq;
        self.session_seq = self.session_seq.wrapping_add(1);
        self.procs.push(ExecProc { session_id, pid });

        log_with_fd(self.log_fd, "[sshd] exec session started\n");

        Ok(ExecSessionWiring {
            session_id,
            stdin_ring: 0,
            stdout_ring: 0,
            stderr_ring: 0,
        })
    }

    fn close_exec(&mut self, wiring: &ExecSessionWiring) -> ssh_core::Result<()> {
        let Some(idx) = self.procs.iter().position(|p| p.session_id == wiring.session_id) else {
            return Ok(());
        };

        let proc = self.procs.swap_remove(idx);
        let _ = call::kill(proc.pid as isize, 15);
        let mut status = 0;
        let _ = call::waitpid(proc.pid as isize, Some(&mut status), 0);

        log_with_fd(self.log_fd, "[sshd] exec session closed\n");
        Ok(())
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let log_fd = open_log_fd();
    let listen_port = load_listen_port();
    let deny_root_login = load_bool_flag(DENY_ROOT_LOGIN_PATH, true);
    let max_auth_tries = load_max_auth_tries();
    let listen_path = format!("/net/tcp/listen/{listen_port}");

    log_with_fd(
        log_fd,
        "[sshd] started (network scheme + pubkey auth + policy reload + child reap)\n",
    );

    loop {
        let fd = open_listener(&listen_path, log_fd);

        let backend = ssh_core::default_backend();
        let auth = PublicKeyAuth::from_paths(&GLOBAL_AUTH_PATHS, USER_AUTH_DIR, deny_root_login);
        let host = FixedHostKey {
            key: b"strat9-sshd-host-key",
        };
        let exec = ExecBridge::new(ALLOWED_COMMANDS_PATH, log_fd);

        let core = SshCore::new(backend, auth, host, exec);
        let mut server = Server::new(core);
        let mut pump = SessionPump::new(NetTransport::new(fd));
        let mut rx_buf = [0u8; 4096];
        let mut tick = 0usize;
        let mut auth_rejects = 0usize;

        'session: loop {
            let directives = match pump.pump_once(&mut server, &mut rx_buf) {
                Ok(directives) => directives,
                Err(_) => break 'session,
            };

            if directives.is_empty() {
                let transport = pump.transport_mut();
                if transport.saw_zero_read() && transport.is_connected() {
                    break 'session;
                }
                let _ = call::sched_yield();
            }

            let mut force_close = false;
            for directive in &directives {
                match directive {
                    CoreDirective::AuthAccepted { username } => {
                        auth_rejects = 0;
                        let user = core::str::from_utf8(username).unwrap_or("<invalid>");
                        let line = format!("[sshd] auth accepted user={user}\n");
                        log_with_fd(log_fd, &line);
                    }
                    CoreDirective::AuthRejected => {
                        auth_rejects = auth_rejects.saturating_add(1);
                        log_with_fd(log_fd, "[sshd] auth rejected\n");
                        if auth_rejects >= max_auth_tries {
                            log_with_fd(log_fd, "[sshd] max auth retries reached\n");
                            force_close = true;
                        }
                    }
                    CoreDirective::ExecStarted { .. } => {
                        log_with_fd(log_fd, "[sshd] exec started\n");
                    }
                    CoreDirective::CloseConnection => {
                        force_close = true;
                    }
                    CoreDirective::SendPacket(_) | CoreDirective::StdinData { .. } => {}
                }
            }

            {
                let core = server.core_mut();
                if (tick & 0x7ff) == 0 {
                    if core.auth_mut().reload_global() {
                        log_with_fd(log_fd, "[sshd] authorized_keys reloaded\n");
                    }
                    if core.sessions_mut().reload_policy() {
                        log_with_fd(log_fd, "[sshd] command policy reloaded\n");
                    }
                }
                core.sessions_mut().reap_exited();
            }

            if force_close {
                break 'session;
            }

            tick = tick.wrapping_add(1);
            let _ = call::sched_yield();
        }

        {
            let core = server.core_mut();
            core.sessions_mut().terminate_all();
        }
        pump.transport_mut().close();
        let _ = call::sched_yield();
    }
}
