fn main() {
    if let Ok(linker) = which::which("bpf-linker") {
        println!("cargo:rerun-if-changed={}", linker.display());
    }
}
