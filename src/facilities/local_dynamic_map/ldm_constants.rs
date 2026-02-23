// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! LDM constants — ITS-AID values, epoch offset and spatial helpers.
//!
//! Mirrors the constant definitions spread across
//! `flexstack/facilities/local_dynamic_map/` in the Python reference.
//!
//! # Haversine fix
//! The Python reference implementation computed spatial distances using raw
//! ETSI integer values (tenths-of-microdegrees) without unit conversion,
//! producing meaningless metre-scale thresholds that were actually in the
//! ~1e7 range.  The `haversine_m` function here converts both coordinates to
//! degrees first, then applies the standard Haversine formula over the WGS-84
//! sphere, giving correct distances in metres.

/// ITS-S application identifiers (ETSI TS 102 965).
pub const ITS_AID_DENM: u32 = 1;
pub const ITS_AID_CAM:  u32 = 2;
pub const ITS_AID_POI:  u32 = 3;
pub const ITS_AID_SAEM: u32 = 4;
pub const ITS_AID_EEBL: u32 = 5;
pub const ITS_AID_IVI:  u32 = 6;
pub const ITS_AID_TLC:  u32 = 7;
pub const ITS_AID_GPC:  u32 = 9;
pub const ITS_AID_GNSS: u32 = 10;
pub const ITS_AID_TPG:  u32 = 11;
pub const ITS_AID_CRL:  u32 = 12;
pub const ITS_AID_CRT:  u32 = 13;
pub const ITS_AID_SRM:  u32 = 14;
pub const ITS_AID_SSM:  u32 = 15;
pub const ITS_AID_VAM:  u32 = 16;
pub const ITS_AID_IMZM: u32 = 17;
pub const ITS_AID_PAM:  u32 = 21;

/// Milliseconds between UNIX epoch (1970-01-01) and the ITS epoch (2004-01-01).
/// Used to convert `std::time::SystemTime` to ITS milliseconds.
///
/// 2004-01-01T00:00:00 UTC in Unix ms = 1_072_915_200_000
pub const ITS_EPOCH_MS: u64 = 1_072_915_200_000;

/// Earth mean radius in metres (WGS-84 approximation used for Haversine).
pub const EARTH_RADIUS_M: f64 = 6_371_000.0;

/// Maximum altitude difference (in cm) between an LDM record and the local
/// station before the record is considered out-of-area for GC purposes.
/// (Python reference had `15`, which was in incorrect units.)
pub const MAINTENANCE_MAX_ALT_DIFF_CM: i32 = 1500;

/// Convert an ETSI timestamp (milliseconds since ITS epoch) to milliseconds
/// since UNIX epoch.
#[inline]
pub fn its_ms_to_unix_ms(its_ms: u64) -> u64 {
    its_ms + ITS_EPOCH_MS
}

/// Return the current time as milliseconds since the ITS epoch (2004-01-01).
/// Panics on platforms where `SystemTime::now()` is before the UNIX epoch
/// (should never happen in practice).
pub fn now_its_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_millis() as u64;
    unix_ms.saturating_sub(ITS_EPOCH_MS)
}

/// Compute the great-circle distance in metres between two positions given as
/// ETSI integer coordinates (tenths of microdegrees, i.e. × 10⁻⁷ degrees).
///
/// This correctly handles the unit conversion that the Python reference
/// implementation omitted, fixing the spatial filtering bug.
///
/// # Arguments
/// * `lat1_etsi`, `lon1_etsi` — first point (ETSI × 1e7 format)
/// * `lat2_etsi`, `lon2_etsi` — second point (ETSI × 1e7 format)
///
/// # Returns
/// Great-circle distance in metres.
pub fn haversine_m(lat1_etsi: i32, lon1_etsi: i32, lat2_etsi: i32, lon2_etsi: i32) -> f64 {
    // Convert ETSI integer to degrees, then to radians.
    let lat1 = (lat1_etsi as f64 * 1e-7).to_radians();
    let lat2 = (lat2_etsi as f64 * 1e-7).to_radians();
    let dlat = lat2 - lat1;
    let dlon = ((lon2_etsi - lon1_etsi) as f64 * 1e-7).to_radians();

    let a = (dlat / 2.0).sin().powi(2)
        + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();

    EARTH_RADIUS_M * c
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two identical positions → 0 m.
    #[test]
    fn haversine_same_point() {
        let d = haversine_m(415520000, 21340000, 415520000, 21340000);
        assert!(d.abs() < 1e-6, "same point should be 0 m, got {d}");
    }

    /// ~111 km per degree of latitude at the equator.
    #[test]
    fn haversine_one_degree_lat() {
        // 0°N,0°E → 1°N,0°E  ≈ 111 195 m
        let d = haversine_m(0, 0, 10_000_000, 0);
        assert!((d - 111_195.0).abs() < 200.0, "expected ~111 km, got {d}");
    }
}
