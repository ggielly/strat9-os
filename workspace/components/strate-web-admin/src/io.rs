use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use strat9_syscall::call;

const EAGAIN: usize = 11;

pub struct Strat9Runtime;

/// Implements noop raw waker.
fn noop_raw_waker() -> RawWaker {
    /// Implements noop.
    fn noop(_: *const ()) {}
    /// Implements clone.
    fn clone(_: *const ()) -> RawWaker {
        noop_raw_waker()
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    RawWaker::new(core::ptr::null(), &VTABLE)
}

// ---------------------------------------------------------------------------
// Error type compatible with embedded-io
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct IoError(pub usize);

impl core::fmt::Display for IoError {
    /// Implements fmt.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IoError({})", self.0)
    }
}

impl core::error::Error for IoError {}

impl embedded_io_async::Error for IoError {
    /// Implements kind.
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
    /// Implements read.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        let mut eagain_spins = 0usize;
        loop {
            match call::read(self.fd, buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.to_errno() == EAGAIN => {
                    eagain_spins = eagain_spins.saturating_add(1);
                    if eagain_spins % 32 == 0 {
                        crate::net::sleep_ms(1);
                    }
                    let _ = call::sched_yield();
                    continue;
                }
                Err(e) => return Err(IoError(e.to_errno())),
            }
        }
    }
}

impl embedded_io_async::Write for TcpWriteHalf {
    /// Implements write.
    async fn write(&mut self, buf: &[u8]) -> Result<usize, IoError> {
        let mut eagain_spins = 0usize;
        loop {
            match call::write(self.fd, buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.to_errno() == EAGAIN => {
                    eagain_spins = eagain_spins.saturating_add(1);
                    if eagain_spins % 32 == 0 {
                        crate::net::sleep_ms(1);
                    }
                    let _ = call::sched_yield();
                    continue;
                }
                Err(e) => return Err(IoError(e.to_errno())),
            }
        }
    }

    /// Implements flush.
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
    /// Creates a new instance.
    pub fn new(fd: usize) -> Self {
        Self { fd }
    }
}

impl picoserve::io::Socket<Strat9Runtime> for TcpSocket {
    type Error = IoError;
    type ReadHalf<'a> = TcpReadHalf;
    type WriteHalf<'a> = TcpWriteHalf;

    /// Implements split.
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
    /// Implements delay.
    async fn delay(&self, duration: picoserve::time::Duration) {
        crate::net::sleep_ms(duration.as_millis());
    }

    async fn run_with_timeout<F: Future>(
        &self,
        duration: picoserve::time::Duration,
        future: F,
    ) -> Result<F::Output, picoserve::time::TimeoutError> {
        let timeout_ns = duration.as_millis().saturating_mul(1_000_000);
        let start = crate::net::clock_gettime_ns();
        let deadline = start.saturating_add(timeout_ns);
        let mut fut = pin!(future);

        // SAFETY: no-op raw waker is valid for manual cooperative polling.
        let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
        let mut cx = Context::from_waker(&waker);

        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return Ok(v),
                Poll::Pending => {
                    if crate::net::clock_gettime_ns() >= deadline {
                        return Err(picoserve::time::TimeoutError);
                    }
                    let _ = call::sched_yield();
                }
            }
        }
    }
}
