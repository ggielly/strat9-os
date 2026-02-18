use core::fmt;

// Error codes
pub const ENOENT: usize = 2;
pub const EIO: usize = 5;
pub const EBADF: usize = 9;
pub const EINVAL: usize = 22;
pub const ENOTSUP: usize = 52;
pub const ENOTTY: usize = 25;
pub const EFAULT: usize = 14;
pub const EAGAIN: usize = 11;
pub const ENOSPC: usize = 28;
pub const EPIPE: usize = 32;

#[derive(Debug)]
pub enum Error {
    NotFound,
    Io,
    BadFileDescriptor,
    Invalid,
    NotSupported,
    NotATty,
    Fault,
    Again,
    NoSpace,
    Pipe,
}

impl Error {
    pub fn from_errno(errno: usize) -> Self {
        match errno {
            ENOENT => Error::NotFound,
            EIO => Error::Io,
            EBADF => Error::BadFileDescriptor,
            EINVAL => Error::Invalid,
            ENOTSUP => Error::NotSupported,
            ENOTTY => Error::NotATty,
            EFAULT => Error::Fault,
            EAGAIN => Error::Again,
            ENOSPC => Error::NoSpace,
            EPIPE => Error::Pipe,
            _ => Error::Io,
        }
    }

    pub fn to_errno(&self) -> usize {
        match self {
            Error::NotFound => ENOENT,
            Error::Io => EIO,
            Error::BadFileDescriptor => EBADF,
            Error::Invalid => EINVAL,
            Error::NotSupported => ENOTSUP,
            Error::NotATty => ENOTTY,
            Error::Fault => EFAULT,
            Error::Again => EAGAIN,
            Error::NoSpace => ENOSPC,
            Error::Pipe => EPIPE,
        }
    }

    pub fn demux(ret: usize) -> core::result::Result<usize, Error> {
        if ret > -4096isize as usize {
            Err(Error::from_errno(ret))
        } else {
            Ok(ret)
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotFound => write!(f, "No such file or directory"),
            Error::Io => write!(f, "Input/output error"),
            Error::BadFileDescriptor => write!(f, "Bad file descriptor"),
            Error::Invalid => write!(f, "Invalid argument"),
            Error::NotSupported => write!(f, "Not supported"),
            Error::NotATty => write!(f, "Not a typewriter"),
            Error::Fault => write!(f, "Bad address"),
            Error::Again => write!(f, "Resource temporarily unavailable"),
            Error::NoSpace => write!(f, "No space left on device"),
            Error::Pipe => write!(f, "Broken pipe"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

// Result type alias
pub type Result<T> = core::result::Result<T, Error>;
