fn main() {
    // bpf-linker path is resolved and injected by net-guardia/build.rs
    // via CARGO_TARGET_BPFEB_UNKNOWN_NONE_LINKER env var.
    // This build.rs only needs to exist for cargo to run it.
    if let Ok(linker) = which::which("bpf-linker") {
        println!("cargo:rerun-if-changed={}", linker.display());
    }
}
