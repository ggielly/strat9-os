#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

pub type Result<T> = core::result::Result<T, SshCoreError>;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SshCoreError {
    InvalidPacket,
    InvalidState,
    AuthDenied,
    Backend,
    BufferTooSmall,
    Unsupported,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ConnectionState {
    BannerExchange,
    KeyExchange,
    Authentication,
    SessionOpen,
    ExecRunning,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ChannelStream {
    Stdin,
    Stdout,
    Stderr,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ExecSessionWiring {
    pub session_id: u32,
    pub stdin_ring: u32,
    pub stdout_ring: u32,
    pub stderr_ring: u32,
}

pub trait Transport {
    fn recv(&mut self, out: &mut [u8]) -> Result<usize>;
    fn send(&mut self, data: &[u8]) -> Result<usize>;
}

pub trait HostKeyProvider {
    fn host_public_key(&self) -> &[u8];
    fn sign_exchange_hash(&mut self, exchange_hash: &[u8], out: &mut [u8]) -> Result<usize>;
}

pub trait AuthProvider {
    fn authorize_public_key(
        &mut self,
        username: &[u8],
        algorithm: &[u8],
        public_key: &[u8],
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<bool>;
}

pub trait ExecSessionProvider {
    fn spawn_exec(&mut self, username: &[u8], command: &[u8]) -> Result<ExecSessionWiring>;
    fn close_exec(&mut self, wiring: &ExecSessionWiring) -> Result<()>;
}

pub enum ParsedPacket<'a> {
    ClientBanner(&'a [u8]),
    KexInit(&'a [u8]),
    UserAuthPublicKey {
        username: &'a [u8],
        algorithm: &'a [u8],
        public_key: &'a [u8],
        signed_data: &'a [u8],
        signature: &'a [u8],
    },
    ChannelOpenSession {
        channel_id: u32,
    },
    ChannelExec {
        channel_id: u32,
        command: &'a [u8],
    },
    ChannelData {
        channel_id: u32,
        stream: ChannelStream,
        data: &'a [u8],
    },
    ChannelEof {
        channel_id: u32,
    },
    Disconnect,
}

pub trait SshBackend {
    fn parse_packet<'a>(&mut self, packet: &'a [u8]) -> Result<ParsedPacket<'a>>;
    fn make_server_banner(&mut self) -> Result<Vec<u8>>;
    fn make_kex_reply(&mut self, client_kex: &[u8], host_keys: &mut dyn HostKeyProvider) -> Result<Vec<u8>>;
    fn make_auth_reply(&mut self, accepted: bool) -> Result<Vec<u8>>;
    fn make_exec_reply(&mut self, channel_id: u32, accepted: bool) -> Result<Vec<u8>>;
    fn make_disconnect(&mut self) -> Result<Vec<u8>>;
}

pub enum CoreDirective {
    SendPacket(Vec<u8>),
    AuthAccepted { username: Vec<u8> },
    AuthRejected,
    ExecStarted {
        channel_id: u32,
        wiring: ExecSessionWiring,
    },
    StdinData {
        channel_id: u32,
        data: Vec<u8>,
    },
    CloseConnection,
}

pub struct SshCore<B, A, H, S>
where
    B: SshBackend,
    A: AuthProvider,
    H: HostKeyProvider,
    S: ExecSessionProvider,
{
    backend: B,
    auth: A,
    host_keys: H,
    sessions: S,
    state: ConnectionState,
    active_channel: Option<u32>,
    active_user: Option<Vec<u8>>,
    active_exec: Option<ExecSessionWiring>,
}

impl<B, A, H, S> SshCore<B, A, H, S>
where
    B: SshBackend,
    A: AuthProvider,
    H: HostKeyProvider,
    S: ExecSessionProvider,
{
    pub fn new(backend: B, auth: A, host_keys: H, sessions: S) -> Self {
        Self {
            backend,
            auth,
            host_keys,
            sessions,
            state: ConnectionState::BannerExchange,
            active_channel: None,
            active_user: None,
            active_exec: None,
        }
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn auth_mut(&mut self) -> &mut A {
        &mut self.auth
    }

    pub fn sessions_mut(&mut self) -> &mut S {
        &mut self.sessions
    }

    pub fn ingest_packet(&mut self, packet: &[u8]) -> Result<Vec<CoreDirective>> {
        let event = self.backend.parse_packet(packet)?;
        self.handle_event(event)
    }

    fn handle_event(&mut self, event: ParsedPacket<'_>) -> Result<Vec<CoreDirective>> {
        let mut out = Vec::new();

        match event {
            ParsedPacket::ClientBanner(_banner) => {
                if self.state != ConnectionState::BannerExchange {
                    return Err(SshCoreError::InvalidState);
                }
                self.state = ConnectionState::KeyExchange;
                out.push(CoreDirective::SendPacket(self.backend.make_server_banner()?));
            }
            ParsedPacket::KexInit(client_kex) => {
                if self.state != ConnectionState::KeyExchange {
                    return Err(SshCoreError::InvalidState);
                }
                self.state = ConnectionState::Authentication;
                out.push(CoreDirective::SendPacket(
                    self.backend.make_kex_reply(client_kex, &mut self.host_keys)?,
                ));
            }
            ParsedPacket::UserAuthPublicKey {
                username,
                algorithm,
                public_key,
                signed_data,
                signature,
            } => {
                if self.state != ConnectionState::Authentication {
                    return Err(SshCoreError::InvalidState);
                }

                let accepted = self.auth.authorize_public_key(
                    username,
                    algorithm,
                    public_key,
                    signed_data,
                    signature,
                )?;

                out.push(CoreDirective::SendPacket(self.backend.make_auth_reply(accepted)?));

                if accepted {
                    self.active_user = Some(username.to_vec());
                    self.state = ConnectionState::SessionOpen;
                    out.push(CoreDirective::AuthAccepted {
                        username: username.to_vec(),
                    });
                } else {
                    out.push(CoreDirective::AuthRejected);
                }
            }
            ParsedPacket::ChannelOpenSession { channel_id } => {
                if self.state != ConnectionState::SessionOpen {
                    return Err(SshCoreError::InvalidState);
                }
                self.active_channel = Some(channel_id);
            }
            ParsedPacket::ChannelExec {
                channel_id,
                command,
            } => {
                if self.state != ConnectionState::SessionOpen {
                    return Err(SshCoreError::InvalidState);
                }
                if self.active_channel != Some(channel_id) {
                    return Err(SshCoreError::InvalidState);
                }
                let user = self
                    .active_user
                    .as_ref()
                    .ok_or(SshCoreError::InvalidState)?;

                let wiring = self.sessions.spawn_exec(user, command)?;
                self.active_exec = Some(wiring);
                self.state = ConnectionState::ExecRunning;

                out.push(CoreDirective::SendPacket(
                    self.backend.make_exec_reply(channel_id, true)?,
                ));
                out.push(CoreDirective::ExecStarted { channel_id, wiring });
            }
            ParsedPacket::ChannelData {
                channel_id,
                stream,
                data,
            } => {
                if self.state != ConnectionState::ExecRunning {
                    return Err(SshCoreError::InvalidState);
                }
                if self.active_channel != Some(channel_id) {
                    return Err(SshCoreError::InvalidState);
                }
                if stream == ChannelStream::Stdin {
                    out.push(CoreDirective::StdinData {
                        channel_id,
                        data: data.to_vec(),
                    });
                }
            }
            ParsedPacket::ChannelEof { channel_id } => {
                if self.active_channel != Some(channel_id) {
                    return Err(SshCoreError::InvalidState);
                }
                if let Some(wiring) = self.active_exec.take() {
                    self.sessions.close_exec(&wiring)?;
                }
                self.state = ConnectionState::Closing;
                out.push(CoreDirective::SendPacket(self.backend.make_disconnect()?));
                out.push(CoreDirective::CloseConnection);
                self.state = ConnectionState::Closed;
            }
            ParsedPacket::Disconnect => {
                if let Some(wiring) = self.active_exec.take() {
                    self.sessions.close_exec(&wiring)?;
                }
                self.state = ConnectionState::Closed;
                out.push(CoreDirective::CloseConnection);
            }
        }

        Ok(out)
    }
}

#[derive(Default)]
pub struct MinimalBackend;

impl MinimalBackend {
    fn read_u16_be(input: &[u8], off: usize) -> Result<u16> {
        if off + 2 > input.len() {
            return Err(SshCoreError::InvalidPacket);
        }
        Ok(u16::from_be_bytes([input[off], input[off + 1]]))
    }

    fn read_u32_be(input: &[u8], off: usize) -> Result<u32> {
        if off + 4 > input.len() {
            return Err(SshCoreError::InvalidPacket);
        }
        Ok(u32::from_be_bytes([
            input[off],
            input[off + 1],
            input[off + 2],
            input[off + 3],
        ]))
    }
}

impl SshBackend for MinimalBackend {
    fn parse_packet<'a>(&mut self, packet: &'a [u8]) -> Result<ParsedPacket<'a>> {
        if packet.is_empty() {
            return Err(SshCoreError::InvalidPacket);
        }

        match packet[0] {
            0x01 => Ok(ParsedPacket::ClientBanner(&packet[1..])),
            0x02 => Ok(ParsedPacket::KexInit(&packet[1..])),
            0x03 => {
                if packet.len() < 3 {
                    return Err(SshCoreError::InvalidPacket);
                }

                let mut off = 1;
                let user_len = packet[off] as usize;
                off += 1;
                if off + user_len > packet.len() {
                    return Err(SshCoreError::InvalidPacket);
                }
                let username = &packet[off..off + user_len];
                off += user_len;

                if off >= packet.len() {
                    return Err(SshCoreError::InvalidPacket);
                }
                let algo_len = packet[off] as usize;
                off += 1;
                if off + algo_len > packet.len() {
                    return Err(SshCoreError::InvalidPacket);
                }
                let algorithm = &packet[off..off + algo_len];
                off += algo_len;

                let key_len = Self::read_u16_be(packet, off)? as usize;
                off += 2;
                if off + key_len > packet.len() {
                    return Err(SshCoreError::InvalidPacket);
                }
                let public_key = &packet[off..off + key_len];
                off += key_len;

                let sig_len = Self::read_u16_be(packet, off)? as usize;
                off += 2;
                if off + sig_len > packet.len() {
                    return Err(SshCoreError::InvalidPacket);
                }
                let signature = &packet[off..off + sig_len];

                Ok(ParsedPacket::UserAuthPublicKey {
                    username,
                    algorithm,
                    public_key,
                    signed_data: packet,
                    signature,
                })
            }
            0x04 => Ok(ParsedPacket::ChannelOpenSession {
                channel_id: Self::read_u32_be(packet, 1)?,
            }),
            0x05 => {
                let channel_id = Self::read_u32_be(packet, 1)?;
                let cmd_len = Self::read_u16_be(packet, 5)? as usize;
                if 7 + cmd_len > packet.len() {
                    return Err(SshCoreError::InvalidPacket);
                }
                Ok(ParsedPacket::ChannelExec {
                    channel_id,
                    command: &packet[7..7 + cmd_len],
                })
            }
            0x06 => {
                let channel_id = Self::read_u32_be(packet, 1)?;
                let data_len = Self::read_u16_be(packet, 5)? as usize;
                if 7 + data_len > packet.len() {
                    return Err(SshCoreError::InvalidPacket);
                }
                Ok(ParsedPacket::ChannelData {
                    channel_id,
                    stream: ChannelStream::Stdin,
                    data: &packet[7..7 + data_len],
                })
            }
            0x07 => Ok(ParsedPacket::ChannelEof {
                channel_id: Self::read_u32_be(packet, 1)?,
            }),
            0x08 => Ok(ParsedPacket::Disconnect),
            _ => Err(SshCoreError::Unsupported),
        }
    }

    fn make_server_banner(&mut self) -> Result<Vec<u8>> {
        Ok(b"\x81SSH-2.0-Strat9\n".to_vec())
    }

    fn make_kex_reply(&mut self, client_kex: &[u8], host_keys: &mut dyn HostKeyProvider) -> Result<Vec<u8>> {
        let mut sig = [0u8; 128];
        let sig_len = host_keys.sign_exchange_hash(client_kex, &mut sig)?;
        let host_key = host_keys.host_public_key();

        let mut out = Vec::with_capacity(1 + 2 + host_key.len() + 2 + sig_len);
        out.push(0x82);
        out.extend_from_slice(&(host_key.len() as u16).to_be_bytes());
        out.extend_from_slice(host_key);
        out.extend_from_slice(&(sig_len as u16).to_be_bytes());
        out.extend_from_slice(&sig[..sig_len]);
        Ok(out)
    }

    fn make_auth_reply(&mut self, accepted: bool) -> Result<Vec<u8>> {
        Ok(vec![0x83, u8::from(accepted)])
    }

    fn make_exec_reply(&mut self, channel_id: u32, accepted: bool) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(6);
        out.push(0x84);
        out.extend_from_slice(&channel_id.to_be_bytes());
        out.push(u8::from(accepted));
        Ok(out)
    }

    fn make_disconnect(&mut self) -> Result<Vec<u8>> {
        Ok(vec![0x85])
    }
}

#[cfg(feature = "backend-zssh")]
pub struct ZsshBackend {
    fallback: MinimalBackend,
}

#[cfg(feature = "backend-zssh")]
impl Default for ZsshBackend {
    fn default() -> Self {
        use zssh as _;
        Self {
            fallback: MinimalBackend,
        }
    }
}

#[cfg(feature = "backend-zssh")]
impl SshBackend for ZsshBackend {
    fn parse_packet<'a>(&mut self, packet: &'a [u8]) -> Result<ParsedPacket<'a>> {
        self.fallback.parse_packet(packet)
    }

    fn make_server_banner(&mut self) -> Result<Vec<u8>> {
        self.fallback.make_server_banner()
    }

    fn make_kex_reply(&mut self, client_kex: &[u8], host_keys: &mut dyn HostKeyProvider) -> Result<Vec<u8>> {
        self.fallback.make_kex_reply(client_kex, host_keys)
    }

    fn make_auth_reply(&mut self, accepted: bool) -> Result<Vec<u8>> {
        self.fallback.make_auth_reply(accepted)
    }

    fn make_exec_reply(&mut self, channel_id: u32, accepted: bool) -> Result<Vec<u8>> {
        self.fallback.make_exec_reply(channel_id, accepted)
    }

    fn make_disconnect(&mut self) -> Result<Vec<u8>> {
        self.fallback.make_disconnect()
    }
}

#[cfg(feature = "backend-zssh")]
pub type DefaultBackend = ZsshBackend;

#[cfg(not(feature = "backend-zssh"))]
pub type DefaultBackend = MinimalBackend;

pub fn default_backend() -> DefaultBackend {
    Default::default()
}
