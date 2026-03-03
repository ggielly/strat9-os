use std::env;

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
    println!("cargo:rerun-if-changed=linker-limine.ld");
}
