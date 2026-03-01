use core::future::Future;
use strat9_syscall::call;

const EAGAIN: usize = 11;

pub struct Strat9Runtime;

// ---------------------------------------------------------------------------
// Error type compatible with embedded-io
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct IoError(pub usize);

impl core::fmt::Display for IoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IoError({})", self.0)
    }
}

impl core::error::Error for IoError {}

impl embedded_io_async::Error for IoError {
    fn kind(&self) -> embedded_io_async::ErrorKind {
        embedded_io_async::ErrorKind::Other
    }
}

// ---------------------------------------------------------------------------
// Read / Write halves operating on a raw fd
// ---------------------------------------------------------------------------

pub struct TcpReadHalf {
    fd: usize,
}

pub struct TcpWriteHalf {
    fd: usize,
}

impl embedded_io_async::ErrorType for TcpReadHalf {
    type Error = IoError;
}

impl embedded_io_async::ErrorType for TcpWriteHalf {
    type Error = IoError;
}

impl embedded_io_async::Read for TcpReadHalf {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        loop {
            match call::read(self.fd, buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.to_errno() == EAGAIN => {
                    let _ = call::sched_yield();
                    continue;
                }
                Err(e) => return Err(IoError(e.to_errno())),
            }
        }
    }
}

impl embedded_io_async::Write for TcpWriteHalf {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, IoError> {
        loop {
            match call::write(self.fd, buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.to_errno() == EAGAIN => {
                    let _ = call::sched_yield();
                    continue;
                }
                Err(e) => return Err(IoError(e.to_errno())),
            }
        }
    }

    async fn flush(&mut self) -> Result<(), IoError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Socket adapter for picoserve
// ---------------------------------------------------------------------------

pub struct TcpSocket {
    fd: usize,
}

impl TcpSocket {
    pub fn new(fd: usize) -> Self {
        Self { fd }
    }
}

impl picoserve::io::Socket<Strat9Runtime> for TcpSocket {
    type Error = IoError;
    type ReadHalf<'a> = TcpReadHalf;
    type WriteHalf<'a> = TcpWriteHalf;

    fn split(&mut self) -> (TcpReadHalf, TcpWriteHalf) {
        (TcpReadHalf { fd: self.fd }, TcpWriteHalf { fd: self.fd })
    }

    async fn abort<T: picoserve::time::Timer<Strat9Runtime>>(
        self,
        _timeouts: &picoserve::Timeouts,
        _timer: &mut T,
    ) -> Result<(), picoserve::Error<IoError>> {
        let _ = call::close(self.fd);
        Ok(())
    }

    async fn shutdown<T: picoserve::time::Timer<Strat9Runtime>>(
        self,
        _timeouts: &picoserve::Timeouts,
        _timer: &mut T,
    ) -> Result<(), picoserve::Error<IoError>> {
        let _ = call::close(self.fd);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Timer adapter for picoserve
// ---------------------------------------------------------------------------

pub struct Strat9Timer;

impl picoserve::time::Timer<Strat9Runtime> for Strat9Timer {
    async fn delay(&self, duration: picoserve::time::Duration) {
        crate::net::sleep_ms(duration.as_millis());
    }

    async fn run_with_timeout<F: Future>(
        &self,
        _duration: picoserve::time::Duration,
        future: F,
    ) -> Result<F::Output, picoserve::time::TimeoutError> {
        Ok(future.await)
    }
}

