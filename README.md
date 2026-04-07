# FlexStack(R) Community Edition — Rust

<img src="https://raw.githubusercontent.com/Fundacio-i2CAT/FlexStack/refs/heads/master/doc/img/i2cat_logo.png" alt="i2CAT Logo" width="200"/>

![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)
![License](https://img.shields.io/badge/license-AGPL--3.0-blue)

# Short description

FlexStack(R) is a software library implementing the ETSI C-ITS protocol stack. Its aim is to facilitate and accelerate the development and integration of software applications on vehicles, vulnerable road users (VRU), and roadside infrastructure that requires the exchange of V2X messages (compliant with ETSI standards) with other actors of the V2X ecosystem.

This repository contains the **Rust implementation** of the FlexStack library, providing a high-performance, memory-safe ETSI C-ITS GeoNetworking (EN 302 636-4-1) and BTP (EN 302 636-5-1) protocol stack. It supports CAM, DENM, and VAM message encoding/decoding and transmission.

# Documentation

Extensive documentation is available at [https://flexstack.eu](https://flexstack.eu).

Library API documentation can be generated locally by running:

```
cargo doc --open
```

# Pre-requisites

## Supported Operating Systems

This library can run on any system that supports Rust 1.75 or higher, including Linux, macOS, and Windows. Raw link-layer access (via `pnet`) may require elevated privileges or specific capabilities (e.g. `CAP_NET_RAW`) on Linux.

Cross-compilation for embedded or non-x86 targets (e.g. `aarch64-unknown-linux-gnu`) is fully supported.

## Dependencies

All dependencies are managed by Cargo and declared in `Cargo.toml`:

| Crate | Version | Purpose |
|-------|---------|---------|
| `pnet` | 0.34 | Raw link-layer packet I/O |
| `rand` | 0.8 | Random number generation |
| `libc` | 0.2 | POSIX system bindings |
| `rasn` | 0.26 | ASN.1 encoding/decoding (for CAM, DENM, VAM) |
| `sha2` | 0.10 | SHA-256 hashing (certificate digests) |
| `p256` | 0.13 | ECDSA P-256 signing and verification |
| `ecdsa` | 0.16 | ECDSA algorithm traits and operations |
| `elliptic-curve` | 0.13 | Elliptic-curve primitives (SEC1 encoding) |

## Build tools

Requires a stable Rust toolchain. Install via [rustup](https://rustup.rs):

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

To build the library:

```
cargo build --release
```

To build and run examples:

```
cargo run --example cam_sender_receiver
cargo run --example denm_sender_receiver
cargo run --example vam_sender_receiver
```

### Secured examples

The secured examples require an ECDSA certificate chain. Generate it first,
then run two instances (one per Authorization Ticket):

```
cargo run --example generate_certificate_chain

# Terminal 1:
sudo cargo run --example secured_cam_sender_receiver -- --at 1
# Terminal 2:
sudo cargo run --example secured_cam_sender_receiver -- --at 2
```

The same pattern applies to the secured VAM example:

```
# Terminal 1:
sudo cargo run --example secured_vam_sender_receiver -- --at 1
# Terminal 2:
sudo cargo run --example secured_vam_sender_receiver -- --at 2
```

### Cross-compilation for aarch64

1. Add the target:
   ```
   rustup target add aarch64-unknown-linux-gnu
   ```
2. Install the cross-linker (Debian/Ubuntu):
   ```
   sudo apt install gcc-aarch64-linux-gnu
   ```
3. Configure the linker in `.cargo/config.toml`:
   ```toml
   [target.aarch64-unknown-linux-gnu]
   linker = "aarch64-linux-gnu-gcc"
   ```
4. Build:
   ```
   cargo build --release --target aarch64-unknown-linux-gnu
   ```

Alternatively, use [`cross`](https://github.com/cross-rs/cross) for a Docker-based, zero-configuration cross-compilation:

```
cargo install cross
cross build --release --target aarch64-unknown-linux-gnu
```

## Known Limitations

- Raw link-layer reception and transmission (via `pnet`) requires `CAP_NET_RAW` privileges or running as root on Linux.
- The ASN.1 codec (`rasn`) may not support all ETSI C-ITS optional extensions. Messages have been tested for interoperability with existing commercial implementations.

# Installation

Add the library to your `Cargo.toml`:

```toml
[dependencies]
rustflexstack = { git = "https://github.com/Fundacio-i2CAT/rustflexstack" }
```

## Developers

- Jordi Marias-i-Parella (jordi.marias@i2cat.net)
- Daniel Ulied Guevara (daniel.ulied@i2cat.net)
- Adrià Pons Serra (adria.pons@i2cat.net)
- Marc Codina Bartumeus (marc.codina@i2cat.net)
- Lluc Feixa Morancho (lluc.feixa@i2cat.net)

# Source

This code has been developed within the following research and innovation projects:

- **CARAMEL** (Grant Agreement No. 833611) – Funded under the Horizon 2020 programme, focusing on cybersecurity for connected and autonomous vehicles.
- **PLEDGER** (Grant Agreement No. 871536) – A Horizon 2020 project aimed at edge computing solutions to improve performance and security.
- **CODECO** (Grant Agreement No. 101092696) – A Horizon Europe initiative addressing cooperative and connected mobility.
- **SAVE-V2X** (Grant Agreement No. ACE05322000044) – Focused on V2X communication for vulnerable road user safety, and funded by ACCIO.
- **PoDIUM** (Grant Agreement No. 101069547) – Funded under the Horizon 2021 programme, this project focuses on accelerating the implementation of connected, cooperative and automated mobility technology.
- **SPRINGTIME** (PID2023-146378NB-I00) funded by the Spanish government (MCIU/AEI/10.13039/501100011033/FEDER/UE), this project focuses in techniques to get IP-based interconnection on multiple environments.
- **ONOFRE-3** (PID2020-112675RB-C43) funded by the Spanish government (MCIN/ AEI /10.13039/501100011033), this project focuses on the adaptation of network and compute resources from the cloud to the far-edge.

# Copyright

This code has been developed by Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT).

FlexStack is a registered trademark of i2CAT. Unauthorized use is strictly prohibited.

i2CAT is a **non-profit research and innovation centre that** promotes mission-driven knowledge to solve business challenges, co-create solutions with a transformative impact, empower citizens through open and participative digital social innovation with territorial capillarity, and promote pioneering and strategic initiatives. i2CAT **aims to transfer** research project results to private companies in order to create social and economic impact via the out-licensing of intellectual property and the creation of spin-offs. Find more information of i2CAT projects and IP rights at https://i2cat.net/tech-transfer/

# License

This code is licensed under the terms of the AGPL. Information about the license can be located at https://www.gnu.org/licenses/agpl-3.0.html.

Please, refer to FlexStack Community Edition (Rust) as a dependence of your works.

If you find that this license doesn't fit with your requirements regarding the use, distribution or redistribution of our code for your specific work, please, don't hesitate to contact the intellectual property managers in i2CAT at the following address: techtransfer@i2cat.net. Also, in the following page you'll find more information about the current commercialization status or other licensees: Under Development.

# Attributions

Attributions of Third Party Components of this work:

- `pnet` Version 0.34.0 - Imported Rust crate - https://github.com/libpnet/libpnet - MIT / Apache-2.0 license
- `rand` Version 0.8 - Imported Rust crate - https://github.com/rust-random/rand - MIT / Apache-2.0 license
- `libc` Version 0.2 - Imported Rust crate - https://github.com/rust-lang/libc - MIT / Apache-2.0 license
- `rasn` Version 0.26 - Imported Rust crate - https://github.com/XAMPPRocky/rasn - MIT license
- `sha2` Version 0.10 - Imported Rust crate - https://github.com/RustCrypto/hashes - MIT / Apache-2.0 license
- `p256` Version 0.13 - Imported Rust crate - https://github.com/RustCrypto/elliptic-curves - MIT / Apache-2.0 license
- `ecdsa` Version 0.16 - Imported Rust crate - https://github.com/RustCrypto/signatures - MIT / Apache-2.0 license
- `elliptic-curve` Version 0.13 - Imported Rust crate - https://github.com/RustCrypto/traits - MIT / Apache-2.0 license


