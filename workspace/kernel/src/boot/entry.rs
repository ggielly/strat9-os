pub use strat9_abi::boot::{KernelArgs, MemoryKind, MemoryRegion};

#[cfg(target_arch = "riscv64")]
pub use crate::arch::riscv64::boot::{
    DtbError, RiscvBootInfo, RiscvMemoryRegion, RiscvMemoryRegionKind, MAX_DTB_MEMORY_REGIONS,
};
