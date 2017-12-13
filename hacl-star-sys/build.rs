extern crate cc;

use std::path::Path;
use std::process::Command;

fn main() {
    if !Path::new("hacl-star/.git").exists() {
        let _ = Command::new("git").args(&["submodule", "update", "--init"]).status();
    }

    // TODO: -DKRML_NOUNIT128 on 64-bit MSVC and all 32-bit systems

    cc::Build::new()
        .flag_if_supported("-std=c11")
        .file("hacl-star/snapshots/hacl-c/kremlib.c")
        .file("hacl-star/snapshots/hacl-c/FStar.c")
        .file("hacl-star/snapshots/hacl-c/Hacl_Policies.c")
        .file("hacl-star/snapshots/hacl-c/AEAD_Poly1305_64.c")
        .file("hacl-star/snapshots/hacl-c/Hacl_Chacha20.c")
        .file("hacl-star/snapshots/hacl-c/Hacl_Chacha20Poly1305.c")
        .file("hacl-star/snapshots/hacl-c/Hacl_Curve25519.c")
        .file("hacl-star/snapshots/hacl-c/Hacl_Ed25519.c")
        .file("hacl-star/snapshots/hacl-c/Hacl_Poly1305_64.c")
        .file("hacl-star/snapshots/hacl-c/Hacl_SHA2_256.c")
        .file("hacl-star/snapshots/hacl-c/Hacl_SHA2_384.c")
        .file("hacl-star/snapshots/hacl-c/Hacl_SHA2_512.c")
        .file("hacl-star/snapshots/hacl-c/Hacl_HMAC_SHA2_256.c")
        .file("hacl-star/snapshots/hacl-c/Hacl_Salsa20.c")
        .file("hacl-star/snapshots/hacl-c/NaCl.c")
        .compile("hacl");

    println!("cargo:rustc-link-lib=static=hacl");
}
