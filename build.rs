fn main() {
    // Trigger rebuild when Cargo.toml changes (for version detection)
    println!("cargo:rerun-if-changed=Cargo.toml");
}
