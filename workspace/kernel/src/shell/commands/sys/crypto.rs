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
    let keys = crate::crypto::list_trusted_keys();
    shell_println!("Trusted signing keys: {}", keys.len());
    shell_println!("");

    if keys.is_empty() {
        shell_println!("  (no keys registered)");
        return Ok(());
    }

    shell_println!("  {:<12} {}", "Key ID", "Label");
    shell_println!("  {:<12} {}", "------", "-----");

    for k in &keys {
        let id_str = core::str::from_utf8(&k.id).unwrap_or("<binary>");
        shell_println!("  {:<12} {}", id_str, k.label);
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
    shell_println!("    1. Generate keypair:");
    shell_println!("         openssl genpkey -algorithm Ed25519 -out key.priv");
    shell_println!("         openssl pkey -in key.priv -pubout -out key.pub");
    shell_println!("    2. Sign the code+data sections of your module");
    shell_println!("    3. Place signature in CMOD header 'signature' field");
    shell_println!("    4. Place key ID in CMOD header 'key_id' field");
    shell_println!("    5. Register the public key in the kernel trusted key store");
    Ok(())
}
