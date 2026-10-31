#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod cmd;
pub mod config;
pub mod crypto;
pub mod device;
pub mod dot11;
pub mod fw;
pub mod mlme;
pub mod regs;
pub mod transport;
pub mod wpa2;

pub const DRIVER_NAME: &str = "iwlwifi-ax201";
