use std::env;

fn main() {
    // Get the kernel directory and add it to linker search path
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search={}", manifest_dir);

    // Re-run build script if linker script changes
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=linker-limine.ld");
}
