use std::env;

/// Entry point for this component.
fn main() {
    // Get the kernel directory and add it to linker search path
    let manifest_dir = match env::var("CARGO_MANIFEST_DIR") {
        Ok(v) => v,
        Err(e) => {
            println!("cargo:warning=kernel build.rs: CARGO_MANIFEST_DIR missing: {e}");
            return;
        }
    };
    println!("cargo:rustc-link-search={manifest_dir}");

    // Re-run build script if linker script changes
    println!("cargo:rerun-if-changed=linker.ld");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_arch == "x86_64" {
        let asm_dir = format!("{manifest_dir}/src/framebuffer/x86/asm");

        println!("cargo:rerun-if-changed=src/framebuffer/x86/asm/fill_avx2.asm");
        println!("cargo:rerun-if-changed=src/framebuffer/x86/asm/blit_avx2.asm");
        println!("cargo:rerun-if-changed=src/framebuffer/x86/asm/x86inc.asm");

        // Use nasm-rs to assemble the x86inc.asm-based NASM files (dav1d style)
        // Output format: elf64 for ELF (Linux), win64 for PE (Windows)
        let out_format = if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
            "win64"
        } else {
            "elf64"
        };

        let mut assembly = nasm_rs::Build::new();
        // nasm-rs otherwise selects MSVC's lib.exe from the HOST platform,
        // which cannot archive the ELF objects of x86_64-unknown-none.
        assembly.archiver_is_msvc(
            env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default() == "msvc",
        );
        for file in [
                &format!("{asm_dir}/fill_avx2.asm"),
                &format!("{asm_dir}/blit_avx2.asm"),
            ] {
            assembly.file(file);
        }
        for flag in [
                &format!("-I{asm_dir}/"),
                &format!("-f{out_format}"),
                "-DARCH_X86_64=1",
                "-g",
                "-F",
                "dwarf",
            ] {
            assembly.flag(flag);
        }
        assembly.compile("libframebuffer_asm.a")
            .expect("NASM assembly of framebuffer routines failed");

        println!("cargo:rustc-link-lib=static=framebuffer_asm");
    }
}
