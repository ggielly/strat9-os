use core::fmt::Debug;

/// Compile-time direction constraint for DMA buffers.
///
/// Implemented by three marker types:
/// - [`DmaToDevice`] : write-only from the CPU perspective
/// - [`DmaFromDevice`] : read-only from the CPU perspective
/// - [`DmaBidirectional`] : full read/write
///
/// The associated constants are checked at compile time via
/// `const { assert!(D::CAN_READ) }` blocks, preventing e.g.
/// reading from a write-only buffer at zero runtime cost.
pub trait DmaDirection: Debug + sealed::Sealed {
    /// Whether the CPU may read data transferred from the device.
    const CAN_READ: bool;
    /// Whether the CPU may write data to be transferred to the device.
    const CAN_WRITE: bool;
}

mod sealed {
    pub trait Sealed {}
}

/// Write-only: CPU writes data, device reads it.
#[derive(Debug, Clone, Copy)]
pub struct DmaToDevice;

impl sealed::Sealed for DmaToDevice {}
impl DmaDirection for DmaToDevice {
    const CAN_READ: bool = false;
    const CAN_WRITE: bool = true;
}

/// Read-only: device writes data, CPU reads it.
#[derive(Debug, Clone, Copy)]
pub struct DmaFromDevice;

impl sealed::Sealed for DmaFromDevice {}
impl DmaDirection for DmaFromDevice {
    const CAN_READ: bool = true;
    const CAN_WRITE: bool = false;
}

/// Full read/write in both directions.
#[derive(Debug, Clone, Copy)]
pub struct DmaBidirectional;

impl sealed::Sealed for DmaBidirectional {}
impl DmaDirection for DmaBidirectional {
    const CAN_READ: bool = true;
    const CAN_WRITE: bool = true;
}
