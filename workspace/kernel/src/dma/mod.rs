//! DMA (Direct Memory Access) safety abstractions.
//!
//! Provides `DmaBuffer` for pinning physical memory during DMA transfers
//! and `DmaDirection` for compile-time direction enforcement.
//!
//! Inspired by Asterinas OSTD `ostd/src/mm/dma/`.

pub mod buffer;
pub mod bounce;
pub mod direction;
pub mod mapper;

pub use bounce::DmaBounce;
pub use buffer::{DmaBuffer, DmaConstraint, DmaError};
pub use mapper::DmaMapper;
pub use direction::{DmaBidirectional, DmaDirection, DmaFromDevice, DmaToDevice};
