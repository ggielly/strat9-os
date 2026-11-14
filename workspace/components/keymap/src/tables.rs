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

//! Scancode set 1 -> ASCII lookup tables (non-ASCII keys are handled in `lib.rs`).

/// French AZERTY scancode set 1 -> ASCII mapping (lowercase)
pub(crate) static AZERTY_NORMAL: [u8; 128] = {
    let mut t = [0u8; 128];
    t[0x01] = 0x1B;
    t[0x02] = b'&';
    t[0x03] = 0; // é: see french_special()
    t[0x04] = b'"';
    t[0x05] = b'\'';
    t[0x06] = b'(';
    t[0x07] = b'-';
    t[0x08] = 0; // è: see french_special()
    t[0x09] = b'_';
    t[0x0A] = 0; // ç: see french_special()
    t[0x0B] = 0; // à: see french_special()
    t[0x0C] = b')';
    t[0x0D] = b'=';
    t[0x0E] = 0x08;
    t[0x0F] = b'\t';
    t[0x10] = b'a';
    t[0x11] = b'z';
    t[0x12] = b'e';
    t[0x13] = b'r';
    t[0x14] = b't';
    t[0x15] = b'y';
    t[0x16] = b'u';
    t[0x17] = b'i';
    t[0x18] = b'o';
    t[0x19] = b'p';
    t[0x1A] = 0; // dead circumflex
    t[0x1B] = b'$';
    t[0x1C] = b'\n';
    t[0x1E] = b'q';
    t[0x1F] = b's';
    t[0x20] = b'd';
    t[0x21] = b'f';
    t[0x22] = b'g';
    t[0x23] = b'h';
    t[0x24] = b'j';
    t[0x25] = b'k';
    t[0x26] = b'l';
    t[0x27] = b'm';
    t[0x28] = 0; // ù: see french_special()
    t[0x29] = 0;
    t[0x2A] = 0x00;
    t[0x2B] = b'*';
    t[0x2C] = b'w';
    t[0x2D] = b'x';
    t[0x2E] = b'c';
    t[0x2F] = b'v';
    t[0x30] = b'b';
    t[0x31] = b'n';
    t[0x32] = b',';
    t[0x33] = b';';
    t[0x34] = b':';
    t[0x35] = b'!';
    t[0x36] = 0x00;
    t[0x37] = b'*';
    t[0x38] = 0x00;
    t[0x39] = b' ';
    t[0x3A] = 0x00;
    t[0x56] = b'<';
    t[0x47] = b'7';
    t[0x48] = b'8';
    t[0x49] = b'9';
    t[0x4A] = b'-';
    t[0x4B] = b'4';
    t[0x4C] = b'5';
    t[0x4D] = b'6';
    t[0x4E] = b'+';
    t[0x4F] = b'1';
    t[0x50] = b'2';
    t[0x51] = b'3';
    t[0x52] = b'0';
    t[0x53] = b'.';
    t
};

/// French AZERTY shifted scancode -> ASCII mapping
pub(crate) static AZERTY_SHIFT: [u8; 128] = {
    let mut t = [0u8; 128];
    t[0x01] = 0x1B;
    t[0x02] = b'1';
    t[0x03] = b'2';
    t[0x04] = b'3';
    t[0x05] = b'4';
    t[0x06] = b'5';
    t[0x07] = b'6';
    t[0x08] = b'7';
    t[0x09] = b'8';
    t[0x0A] = b'9';
    t[0x0B] = b'0';
    t[0x0C] = 0; // non-ASCII: see french_special()
    t[0x0D] = b'+';
    t[0x0E] = 0x08;
    t[0x0F] = b'\t';
    t[0x10] = b'A';
    t[0x11] = b'Z';
    t[0x12] = b'E';
    t[0x13] = b'R';
    t[0x14] = b'T';
    t[0x15] = b'Y';
    t[0x16] = b'U';
    t[0x17] = b'I';
    t[0x18] = b'O';
    t[0x19] = b'P';
    t[0x1A] = 0; // non-ASCII: see french_special()
    t[0x1B] = 0; // non-ASCII: see french_special()
    t[0x1C] = b'\n';
    t[0x1E] = b'Q';
    t[0x1F] = b'S';
    t[0x20] = b'D';
    t[0x21] = b'F';
    t[0x22] = b'G';
    t[0x23] = b'H';
    t[0x24] = b'J';
    t[0x25] = b'K';
    t[0x26] = b'L';
    t[0x27] = b'M';
    t[0x28] = b'%';
    t[0x29] = 0;
    t[0x2B] = 0; // non-ASCII: see french_special()
    t[0x2C] = b'W';
    t[0x2D] = b'X';
    t[0x2E] = b'C';
    t[0x2F] = b'V';
    t[0x30] = b'B';
    t[0x31] = b'N';
    t[0x32] = b'?';
    t[0x33] = b'.';
    t[0x34] = b'/';
    t[0x35] = 0; // non-ASCII: see french_special()
    t[0x36] = 0x00;
    t[0x37] = b'*';
    t[0x38] = 0x00;
    t[0x39] = b' ';
    t[0x3A] = 0x00;
    t[0x56] = b'>';
    t[0x47] = b'7';
    t[0x48] = b'8';
    t[0x49] = b'9';
    t[0x4A] = b'-';
    t[0x4B] = b'4';
    t[0x4C] = b'5';
    t[0x4D] = b'6';
    t[0x4E] = b'+';
    t[0x4F] = b'1';
    t[0x50] = b'2';
    t[0x51] = b'3';
    t[0x52] = b'0';
    t[0x53] = b'.';
    t
};

/// US QWERTY scancode set 1 -> ASCII mapping (lowercase)
pub(crate) static QWERTY_NORMAL: [u8; 128] = {
    let mut t = [0u8; 128];
    t[0x01] = 0x1B;
    t[0x02] = b'1';
    t[0x03] = b'2';
    t[0x04] = b'3';
    t[0x05] = b'4';
    t[0x06] = b'5';
    t[0x07] = b'6';
    t[0x08] = b'7';
    t[0x09] = b'8';
    t[0x0A] = b'9';
    t[0x0B] = b'0';
    t[0x0C] = b'-';
    t[0x0D] = b'=';
    t[0x0E] = 0x08;
    t[0x0F] = b'\t';
    t[0x10] = b'q';
    t[0x11] = b'w';
    t[0x12] = b'e';
    t[0x13] = b'r';
    t[0x14] = b't';
    t[0x15] = b'y';
    t[0x16] = b'u';
    t[0x17] = b'i';
    t[0x18] = b'o';
    t[0x19] = b'p';
    t[0x1A] = b'[';
    t[0x1B] = b']';
    t[0x1C] = b'\n';
    t[0x1E] = b'a';
    t[0x1F] = b's';
    t[0x20] = b'd';
    t[0x21] = b'f';
    t[0x22] = b'g';
    t[0x23] = b'h';
    t[0x24] = b'j';
    t[0x25] = b'k';
    t[0x26] = b'l';
    t[0x27] = b';';
    t[0x28] = b'\'';
    t[0x29] = b'`';
    t[0x2A] = 0x00;
    t[0x2B] = b'\\';
    t[0x2C] = b'z';
    t[0x2D] = b'x';
    t[0x2E] = b'c';
    t[0x2F] = b'v';
    t[0x30] = b'b';
    t[0x31] = b'n';
    t[0x32] = b'm';
    t[0x33] = b',';
    t[0x34] = b'.';
    t[0x35] = b'/';
    t[0x36] = 0x00;
    t[0x37] = b'*';
    t[0x38] = 0x00;
    t[0x39] = b' ';
    t[0x3A] = 0x00;
    t[0x47] = b'7';
    t[0x48] = b'8';
    t[0x49] = b'9';
    t[0x4A] = b'-';
    t[0x4B] = b'4';
    t[0x4C] = b'5';
    t[0x4D] = b'6';
    t[0x4E] = b'+';
    t[0x4F] = b'1';
    t[0x50] = b'2';
    t[0x51] = b'3';
    t[0x52] = b'0';
    t[0x53] = b'.';
    t
};

/// US QWERTY shifted scancode -> ASCII mapping
pub(crate) static QWERTY_SHIFT: [u8; 128] = {
    let mut t = [0u8; 128];
    t[0x01] = 0x1B;
    t[0x02] = b'!';
    t[0x03] = b'@';
    t[0x04] = b'#';
    t[0x05] = b'$';
    t[0x06] = b'%';
    t[0x07] = b'^';
    t[0x08] = b'&';
    t[0x09] = b'*';
    t[0x0A] = b'(';
    t[0x0B] = b')';
    t[0x0C] = b'_';
    t[0x0D] = b'+';
    t[0x0E] = 0x08;
    t[0x0F] = b'\t';
    t[0x10] = b'Q';
    t[0x11] = b'W';
    t[0x12] = b'E';
    t[0x13] = b'R';
    t[0x14] = b'T';
    t[0x15] = b'Y';
    t[0x16] = b'U';
    t[0x17] = b'I';
    t[0x18] = b'O';
    t[0x19] = b'P';
    t[0x1A] = b'{';
    t[0x1B] = b'}';
    t[0x1C] = b'\n';
    t[0x1E] = b'A';
    t[0x1F] = b'S';
    t[0x20] = b'D';
    t[0x21] = b'F';
    t[0x22] = b'G';
    t[0x23] = b'H';
    t[0x24] = b'J';
    t[0x25] = b'K';
    t[0x26] = b'L';
    t[0x27] = b':';
    t[0x28] = b'"';
    t[0x29] = b'~';
    t[0x2B] = b'|';
    t[0x2C] = b'Z';
    t[0x2D] = b'X';
    t[0x2E] = b'C';
    t[0x2F] = b'V';
    t[0x30] = b'B';
    t[0x31] = b'N';
    t[0x32] = b'M';
    t[0x33] = b'<';
    t[0x34] = b'>';
    t[0x35] = b'?';
    t[0x36] = 0x00;
    t[0x37] = b'*';
    t[0x38] = 0x00;
    t[0x39] = b' ';
    t[0x3A] = 0x00;
    t[0x47] = b'7';
    t[0x48] = b'8';
    t[0x49] = b'9';
    t[0x4A] = b'-';
    t[0x4B] = b'4';
    t[0x4C] = b'5';
    t[0x4D] = b'6';
    t[0x4E] = b'+';
    t[0x4F] = b'1';
    t[0x50] = b'2';
    t[0x51] = b'3';
    t[0x52] = b'0';
    t[0x53] = b'.';
    t
};
