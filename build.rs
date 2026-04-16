// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Build script for rustflexstack.
//!
//! When the `cv2x` feature is enabled, the `cc` crate compiles
//! `cv2x_ffi/cv2x_wrapper.cpp` into a static library and links it
//! together with `telux_cv2x` and `telux_common` (dynamic).
//!
//! Set `TELUX_INCLUDE_DIR` to point to the telux header root if they
//! are not under `/usr/include`.  Set `TELUX_LIB_DIR` if the `.so`
//! files are not on the default library search path.

fn main() {
    #[cfg(feature = "cv2x")]
    {
        let telux_include = std::env::var("TELUX_INCLUDE_DIR")
            .unwrap_or_else(|_| "/usr/include".to_string());

        cc::Build::new()
            .cpp(true)
            .std("c++11")
            .file("cv2x_ffi/cv2x_wrapper.cpp")
            .include("cv2x_ffi")
            .include(&telux_include)
            .compile("cv2x_wrapper_c");

        // If telux .so files live in a non-standard directory
        if let Ok(lib_dir) = std::env::var("TELUX_LIB_DIR") {
            println!("cargo:rustc-link-search=native={}", lib_dir);
            // Cross-linking: tell the linker where to find DSOs that
            // libtelux_cv2x.so pulls in transitively (libtelux_qmi,
            // libqmi_common_so, libglib-2.0, …).  These are not needed
            // on the build host but must be resolvable during the
            // cross-link step.
            println!("cargo:rustc-link-arg=-Wl,-rpath-link,{}", lib_dir);
        }

        println!("cargo:rustc-link-lib=dylib=telux_cv2x");
        println!("cargo:rustc-link-lib=dylib=telux_common");
        println!("cargo:rustc-link-lib=dylib=telux_qmi");
        println!("cargo:rustc-link-lib=dylib=qmi_common_so");
        println!("cargo:rustc-link-lib=dylib=qmi_cci");
        println!("cargo:rustc-link-lib=dylib=glib-2.0");
        println!("cargo:rustc-link-lib=dylib=pcre");
        println!("cargo:rustc-link-lib=dylib=dsutils");
        println!("cargo:rustc-link-lib=dylib=dsi_netctrl");

        println!("cargo:rerun-if-env-changed=TELUX_INCLUDE_DIR");
        println!("cargo:rerun-if-env-changed=TELUX_LIB_DIR");
        println!("cargo:rerun-if-changed=cv2x_ffi/cv2x_wrapper.cpp");
        println!("cargo:rerun-if-changed=cv2x_ffi/cv2x_wrapper.h");
    }
}
