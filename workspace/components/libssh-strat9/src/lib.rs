#![no_std]

extern crate alloc;

use alloc::vec::Vec;

pub use ssh_core::{
    AuthProvider, ChannelStream, ConnectionState, CoreDirective, ExecSessionProvider, ExecSessionWiring,
    HostKeyProvider, ParsedPacket, Result, SshBackend, SshCore, SshCoreError, Transport,
};

pub struct Server<B, A, H, S>
where
    B: SshBackend,
    A: AuthProvider,
    H: HostKeyProvider,
    S: ExecSessionProvider,
{
    core: SshCore<B, A, H, S>,
}

impl<B, A, H, S> Server<B, A, H, S>
where
    B: SshBackend,
    A: AuthProvider,
    H: HostKeyProvider,
    S: ExecSessionProvider,
{
    pub fn new(core: SshCore<B, A, H, S>) -> Self {
        Self { core }
    }

    pub fn state(&self) -> ConnectionState {
        self.core.state()
    }

    pub fn ingest_packet(&mut self, packet: &[u8]) -> Result<Vec<CoreDirective>> {
        self.core.ingest_packet(packet)
    }

    pub fn core_mut(&mut self) -> &mut SshCore<B, A, H, S> {
        &mut self.core
    }
}

pub struct SessionPump<T>
where
    T: Transport,
{
    transport: T,
}

impl<T> SessionPump<T>
where
    T: Transport,
{
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn pump_once<B, A, H, S>(
        &mut self,
        server: &mut Server<B, A, H, S>,
        rx_buf: &mut [u8],
    ) -> Result<Vec<CoreDirective>>
    where
        B: SshBackend,
        A: AuthProvider,
        H: HostKeyProvider,
        S: ExecSessionProvider,
    {
        let n = self.transport.recv(rx_buf)?;
        if n == 0 {
            return Ok(Vec::new());
        }

        let directives = server.ingest_packet(&rx_buf[..n])?;
        for directive in directives.iter() {
            if let CoreDirective::SendPacket(pkt) = directive {
                let _ = self.transport.send(pkt)?;
            }
        }

        Ok(directives)
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}
