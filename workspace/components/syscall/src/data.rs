pub use strat9_abi::data::*;

// VFS scheme protocol opcodes: wire-contract constants shared by every
// scheme server. Single source of truth lives in the ABI.
pub use strat9_abi::ipc_payload::{
    OPCODE_CLOSE, OPCODE_OPEN, OPCODE_READ, OPCODE_READDIR, OPCODE_WRITE,
};
