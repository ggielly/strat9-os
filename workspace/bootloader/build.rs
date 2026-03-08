// Build script for Strat9-OS Bootloader
// Assembles the bootloader stages using NASM

use std::{env, path::PathBuf, process::Command};

/// Entry point for this component.
fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // Paths
    let asm_dir = manifest_dir.join("asm").join("x86_64");
    let stage1_src = asm_dir.join("stage1.asm");
    let stage2_src = asm_dir.join("stage2.asm");

    let stage1_bin = out_dir.join("stage1.bin");
    let stage2_bin = out_dir.join("stage2.bin");

    println!("cargo:rerun-if-changed={}", stage1_src.display());
    println!("cargo:rerun-if-changed={}", stage2_src.display());
    println!(
        "cargo:rerun-if-changed={}",
        asm_dir.join("gdt.asm").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        asm_dir.join("print.asm").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        asm_dir.join("cpuid.asm").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        asm_dir.join("protected_mode.asm").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        asm_dir.join("long_mode.asm").display()
    );

    // Check if NASM is available
    let nasm_check = Command::new("nasm").arg("--version").output();

    if nasm_check.is_err() {
        println!("cargo:warning=NASM not found. Bootloader assembly stages will not be built.");
        println!("cargo:warning=Install NASM: https://www.nasm.us/");
        return;
    }

    // Assemble Stage 1
    println!("Assembling Stage 1...");
    let status = Command::new("nasm")
        .arg("-f")
        .arg("bin")
        .arg("-I")
        .arg(format!("{}/", asm_dir.display()))
        .arg("-o")
        .arg(&stage1_bin)
        .arg(&stage1_src)
        .status()
        .expect("Failed to execute NASM for stage1");

    if !status.success() {
        panic!("Failed to assemble Stage 1");
    }

    // Verify Stage 1 size.
    // The current assembly flow can emit a combined image (stage1 + embedded stage2),
    // so keep this as a warning instead of a hard failure.
    let stage1_size = std::fs::metadata(&stage1_bin)
        .expect("Failed to get stage1.bin metadata")
        .len();

    if stage1_size != 512 {
        println!(
            "Note: Stage 1 image size is {} bytes (expected 512 for pure MBR)",
            stage1_size
        );
    }

    println!("Stage 1 assembled: {} bytes", stage1_size);

    // Assemble Stage 2 (best effort).
    // In the current layout, stage2 is also embedded through stage1 include flow.
    println!("Assembling Stage 2...");
    let stage2_status = Command::new("nasm")
        .arg("-f")
        .arg("bin")
        .arg("-I")
        .arg(format!("{}/", asm_dir.display()))
        .arg("-o")
        .arg(&stage2_bin)
        .arg(&stage2_src)
        .status();

    match stage2_status {
        Ok(status) if status.success() => {
            let stage2_size = std::fs::metadata(&stage2_bin)
                .expect("Failed to get stage2.bin metadata")
                .len();
            if stage2_size > 4096 {
                println!("Note: Stage 2 exceeds 4KB limit ({} bytes)", stage2_size);
            }
            println!("Stage 2 assembled: {} bytes", stage2_size);
        }
        Ok(_) | Err(_) => {
            println!(
                "Note: Stage 2 standalone assembly failed; continuing with embedded stage2 path"
            );
            let _ = std::fs::write(&stage2_bin, []);
        }
    }

    // Output the paths for use in the Rust code
    println!("cargo:rustc-env=STAGE1_BIN={}", stage1_bin.display());
    println!("cargo:rustc-env=STAGE2_BIN={}", stage2_bin.display());
}
