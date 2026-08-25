pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub mod facade;

#[cfg(target_arch = "x86_64")]
pub use facade::*;
