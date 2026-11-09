/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

pub use strat9_abi::data::*;

// VFS scheme protocol opcodes and typed request structs: wire-contract
// constants shared by every scheme server. Single source of truth lives in
// the ABI.
pub use strat9_abi::ipc_payload::{
    OpenRequest, WriteRequest, OPCODE_CLOSE, OPCODE_OPEN, OPCODE_READ, OPCODE_READDIR, OPCODE_WRITE,
};
