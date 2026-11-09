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

use core::arch::asm;

const SBI_EXTENSION_LEGACY_TIMER: usize = 0x01;
const SBI_EXTENSION_TIME: usize = 0x5449_4d45;
const SBI_SET_TIMER: usize = 0x00;

fn call(extension: usize, function: usize, arg0: usize, arg1: usize) -> (usize, usize) {
    let mut error = arg0;
    let mut value = arg1;
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") value,
            inlateout("a1") error,
            in("a7") extension,
            in("a6") function,
            options(nostack)
        );
    }
    (value, error)
}

pub fn set_timer(value: u64) -> Result<(), usize> {
    let (_, error) = call(SBI_EXTENSION_LEGACY_TIMER, SBI_SET_TIMER, value as usize, 0);
    if error == 0 {
        return Ok(());
    }
    let (_, modern_error) = call(SBI_EXTENSION_TIME, SBI_SET_TIMER, value as usize, 0);
    if modern_error == 0 {
        Ok(())
    } else {
        Err(error)
    }
}
