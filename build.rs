// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Build script for rustflexstack.
//!
//! When the `cv2x` feature is enabled, the `cc` crate compiles
//! `cv2x_ffi/cv2x_wrapper.cpp` into a static library and links it
//! together with `libtelux_cv2x.so` and `libtelux_common.so` (dynamic).
//!
//! Set `TELUX_INCLUDE_DIR` to point to the Telux SDK headers.
//! Set `TELUX_LIB_DIR` if the `.so` files are not on the default library
//! search path.

fn main() {
    #[cfg(feature = "cv2x")]
    {
        let mut build = cc::Build::new();
        build
            .cpp(true)
            .file("cv2x_ffi/cv2x_wrapper.cpp")
            .include("cv2x_ffi") // picks up cv2x_wrapper.h
            .flag("-std=c++14");

        // Telux SDK headers
        if let Ok(inc_dir) = std::env::var("TELUX_INCLUDE_DIR") {
            build.include(&inc_dir);
        }

        build.compile("cv2x_wrapper_cpp");

        // If .so files live in a non-standard directory
        if let Ok(lib_dir) = std::env::var("TELUX_LIB_DIR") {
            println!("cargo:rustc-link-search=native={}", lib_dir);
            println!("cargo:rustc-link-arg=-Wl,-rpath-link,{}", lib_dir);
        }

        // Telux SDK shared libraries
        println!("cargo:rustc-link-lib=dylib=telux_cv2x");
        println!("cargo:rustc-link-lib=dylib=telux_common");

        // C++ standard library
        println!("cargo:rustc-link-lib=dylib=stdc++");

        println!("cargo:rerun-if-env-changed=TELUX_LIB_DIR");
        println!("cargo:rerun-if-env-changed=TELUX_INCLUDE_DIR");
        println!("cargo:rerun-if-changed=cv2x_ffi/cv2x_wrapper.cpp");
        println!("cargo:rerun-if-changed=cv2x_ffi/cv2x_wrapper.h");
    }
}
