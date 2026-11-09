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

use super::*;

/// Crypto key management command.
///
/// Usage: `crypto keys` - list trusted keys
///        `crypto info` - show crypto subsystem status
pub fn cmd_crypto(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: crypto <keys|info>");
        shell_println!("  crypto keys  - list trusted signing keys");
        shell_println!("  crypto info  - show crypto subsystem status");
        return Err(ShellError::InvalidArguments);
    }

    match args[0].as_str() {
        "keys" => cmd_crypto_keys(),
        "info" => cmd_crypto_info(),
        _ => {
            shell_println!("Usage: crypto <keys|info>");
            Err(ShellError::InvalidArguments)
        }
    }
}

/// List all registered trusted signing keys.
fn cmd_crypto_keys() -> Result<(), ShellError> {
    let count = crate::crypto::trusted_key_count();
    shell_println!("Trusted signing keys: {}", count);
    shell_println!("");

    if count == 0 {
        shell_println!("  (no keys registered)");
        return Ok(());
    }

    shell_println!(
        "  {:<12} {:<40} {}",
        "Key ID",
        "Public Key (first 8 bytes)",
        "Label"
    );
    shell_println!(
        "  {:<12} {:<40} {}",
        "------",
        "---------------------------",
        "-----"
    );

    // We can't iterate directly, but we know the dev key
    if crate::crypto::is_key_trusted(b"STRAT9D1") {
        shell_println!(
            "  {:<12} {:<40} {}",
            "STRAT9D1",
            "d75a980182b10c73...",
            "strat9-dev"
        );
    }

    Ok(())
}

/// Show crypto subsystem status.
fn cmd_crypto_info() -> Result<(), ShellError> {
    shell_println!("Crypto Subsystem");
    shell_println!("  Algorithm:      Ed25519 (EC25519)");
    shell_println!("  Hash:           SHA-512 (internal to Ed25519)");
    shell_println!(
        "  Key Store:      {} trusted key(s)",
        crate::crypto::trusted_key_count()
    );
    shell_println!("  Verification:   Ed25519 signature verification");
    shell_println!("  Module Format:  CMOD with Ed25519 signatures");
    shell_println!("");
    shell_println!("  Module signing workflow:");
    shell_println!(
        "    1. Generate keypair:  ed25519-keygen > key.priv && ed25519-keygen -x > key.pub"
    );
    shell_println!("    2. Sign module:       openssl pkeyutl -sign -inkey key.priv -in module.cmod -out sig.bin");
    shell_println!("    3. Embed signature:   Place signature in CMOD header (offset 91)");
    shell_println!("    4. Register key:      Add public key to kernel trusted key store");
    Ok(())
}
