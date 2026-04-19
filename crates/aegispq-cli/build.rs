fn main() {
    // On Windows, the default main-thread stack (1 MiB) is not large enough
    // for the hybrid PQ key material + Argon2 working memory used during
    // identity creation and decryption. Bump to 8 MiB to match other
    // platforms.
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        println!("cargo:rustc-link-arg-bin=aegispq=/STACK:8388608");
    }
}
