//! DMA (Direct Memory Access) safety abstractions.
//!
//! Provides `DmaBuffer` for pinning physical memory during DMA transfers
//! and `DmaDirection` for compile-time direction enforcement.
//!
//! Inspired by Asterinas OSTD `ostd/src/mm/dma/`.

pub mod buffer;
pub mod direction;

pub use buffer::DmaBuffer;
pub use direction::{DmaBidirectional, DmaDirection, DmaFromDevice, DmaToDevice};
