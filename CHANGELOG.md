# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.6] - 2026-11-11

### Added
- **Decentralized Congestion Control (DCC)**:
  - Implemented `DccEntity` running periodic channel evaluations (§6.1.3).
  - Added Channel Busy Ratio (CBR) measurement providers (`Nl80211SurveyCbr`, `SharedCbr`, `cbr_from_samples`).
  - Integrated `T_GenCam_DCC` into `CooperativeAwarenessBasicService` to dynamically throttle CAM transmission frequency under channel congestion.
- **Universal CLI Installer**:
  - Added `install_v2x_flexstack_cli.sh` for one-line installation (`curl`/`wget`) across Linux x86_64, generic AArch64, and Cohda MK6/MK6C hardware.
  - Automatic hardware detection, dynamic linker inspection (`libtelux_cv2x.so`), and fallback offline lab mirror support.
- **CI / Release Automation**:
  - Configured `release.yml` to automatically upload `install_v2x_flexstack_cli.sh` as a release asset.
  - Fixed hardcoded release version tags in CI archive tables using dynamic GitHub ref names.

### Changed
- **Qualcomm Telematics C-V2X Multi-Firmware Compatibility**:
  - Added compile-time feature detection in `build.rs` and `cv2x_ffi/cv2x_wrapper.cpp` supporting Firmware 20 (`Cv2xFactoryImpl`), Firmware 19 (`Cv2xFactory`), and legacy MDM9150/MK6C SDKs.
  - Prevents runtime `undefined symbol` dynamic linker failures across varying Cohda firmware versions.

---

## [0.3.5] - 2026-11-03

### Added
- Canonical ETSI TS 103 097 v1.4.1 certificate format support and parser refinements.
- PKI enrollment compatibility (ETSI TS 102 941).
- Per-release documentation under `docs/releases/v0.3.5.md`.

---

## [0.3.4] - 2026-10-28

### Added
- CA Basic Service and Security full compliance.
- Python DCC reference synchronization and verification.

---

## [0.3.1] - 2026-04-23

### Changed
- Improved release workflow and binary portability using static `musl` toolchain.

---

## [0.3.0] - 2026-04-20

### Added
- C-V2X (PC5 Mode 4) radio support for Cohda Wireless MK6 devices.
- Live GPS tracking support via `gpsd`.
- Security Layer: IEEE 1609.2 / ETSI TS 103 097 signing and verification services.

