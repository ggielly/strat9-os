//! Architecture-neutral IOMMU backend interface.
//!
//! The hardware-specific programming (root/context tables, invalidation,
//! fault registers) lives behind [`Backend`].  The generic layer only decides
//! which backend is authoritative and whether it may be activated.
//!
//! P0 ships the discovery skeleton: the x86_64 backend reports what the DMAR
//! describes but keeps [`Backend::is_ready`] false until the actual table
//! programming has been validated.  Consequently
//! `hardware::iommu::activate()` still returns `false` and no device is ever
//! silently placed behind an untested translation unit.

use crate::hardware::iommu::DomainId;

/// Errors returned by an IOMMU backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IommuError {
    /// No unit is described by the firmware.
    NotPresent,
    /// The backend exists but has not been validated.
    NotReady,
    /// A feature is not implemented by this backend.
    Unsupported,
    /// The hardware refused a programming step.
    Hardware,
    /// The domain id is not known to the hardware layer.
    InvalidDomain,
}

/// Summary produced by firmware discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Discovery {
    /// True when a DMAR (or IVRS for AMD) table was found.
    pub present: bool,
    /// True when the backend may be activated.
    pub ready: bool,
    /// Short backend name for logs.
    pub backend: &'static str,
    /// Number of remapping hardware units.
    pub units: u32,
    /// Number of reserved memory regions.
    pub rmrrs: u32,
    /// Number of ATS-capable root-port structures.
    pub atsrs: u32,
    /// Host address width, in bits.
    pub host_address_width: u8,
    /// Interrupt remapping is advertised.
    pub intr_remap: bool,
    /// Firmware asked the OS to keep x2APIC disabled.
    pub x2apic_opt_out: bool,
}

impl Discovery {
    /// Result when no IOMMU exists.
    pub const fn absent() -> Self {
        Self {
            present: false,
            ready: false,
            backend: "none",
            units: 0,
            rmrrs: 0,
            atsrs: 0,
            host_address_width: 0,
            intr_remap: false,
            x2apic_opt_out: false,
        }
    }
}

/// A hardware translation backend.
pub trait Backend: Send + Sync {
    /// Stable backend name (`"vt-d"`, `"amd-vi"`, `"none"`).
    fn name(&self) -> &'static str;

    /// True only when the backend has been validated end to end.
    fn is_ready(&self) -> bool;

    /// Program translation for every registered domain and enable it.
    fn activate(&self) -> Result<(), IommuError>;

    /// Flush cached translations for one domain.
    fn invalidate_domain(&self, domain: DomainId);

    /// True when interrupt remapping can be used.
    fn interrupt_remapping(&self) -> bool {
        false
    }
}

/// Backend used when no IOMMU exists (or none is usable).
pub struct NoIommu;

impl Backend for NoIommu {
    fn name(&self) -> &'static str {
        "none"
    }

    fn is_ready(&self) -> bool {
        false
    }

    fn activate(&self) -> Result<(), IommuError> {
        Err(IommuError::NotPresent)
    }

    fn invalidate_domain(&self, _domain: DomainId) {}
}

static NO_IOMMU: NoIommu = NoIommu;

/// Discover the platform IOMMU and cache the result.
///
/// Safe to call more than once; the second call re-parses the firmware tables.
pub fn init() -> Discovery {
    #[cfg(target_arch = "x86_64")]
    {
        return super::x86_64::iommu::init();
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Discovery::absent()
    }
}

/// Return the discovery summary recorded by [`init`].
pub fn discovery() -> Discovery {
    #[cfg(target_arch = "x86_64")]
    {
        return super::x86_64::iommu::discovery();
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Discovery::absent()
    }
}

/// Return the authoritative backend.
///
/// Falls back to [`NoIommu`] whenever the architecture has no usable backend.
pub fn backend() -> &'static dyn Backend {
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(backend) = super::x86_64::iommu::backend() {
            return backend;
        }
    }
    &NO_IOMMU
}

/// True when a backend is present and validated for activation.
pub fn is_available() -> bool {
    backend().is_ready()
}

/// Try to activate translation through the authoritative backend.
pub fn activate() -> Result<(), IommuError> {
    backend().activate()
}
