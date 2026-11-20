// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Certificate validity restrictions (IEEE Std 1609.2-2016, clauses
//! 5.2.3.2.2, 6.4.8 and 6.4.17, as profiled by ETSI TS 103 097 V2.2.1).
//!
//! - time: the validityPeriod of a certificate (start + duration);
//! - region: the circular, rectangular or polygonal region of a certificate;
//!   a certificate without region inherits the region of its issuer;
//! - permissions: the appPermissions entry (PSID and SSP) of a certificate.
//!
//! Identified regions (clauses 6.4.22 to 6.4.26) name countries (UN M.49
//! codes; 65535 is the EU-27 in ETSI TS 103 097 clause 6), regions and
//! subregions. The stack ships no border data: the application registers the
//! geometry of the identifiers it recognises ([`register_identified_region`]),
//! and the PICS conformance claim is the list of registered identifiers
//! (TS 103 097 clause 5). An identifier without geometry cannot be evaluated
//! (`None`).
//!
//! Mirrors `flexstack/security/validity.py`.

use crate::security::certificate::Certificate;
use crate::security::security_asn::ieee1609_dot2::ToBeSignedCertificate;
use crate::security::security_asn::ieee1609_dot2_base_types::{
    Duration, GeographicRegion, IdentifiedRegion, ServiceSpecificPermissions, TwoDLocation,
};
use std::collections::BTreeMap;
use std::sync::RwLock;

const EARTH_RADIUS_M: f64 = 6_371_000.0;
const TENTH_MICRODEGREE: f64 = 1e-7;
/// ETSI TS 103 097 clause 6: UnCountryId 65535 is the European Union
/// "27 countries as of 31 January 2020".
pub const EU27_COUNTRY_ID: u16 = 65535;

/// An identified region: a country, a region of a country
/// (CountryAndRegions) or a subregion of a region (RegionAndSubregions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegionKey {
    pub country: u16,
    pub region: Option<u8>,
    pub subregion: Option<u16>,
}

impl RegionKey {
    pub fn country(country: u16) -> Self {
        Self {
            country,
            region: None,
            subregion: None,
        }
    }
    pub fn region(country: u16, region: u8) -> Self {
        Self {
            country,
            region: Some(region),
            subregion: None,
        }
    }
    pub fn subregion(country: u16, region: u8, subregion: u16) -> Self {
        Self {
            country,
            region: Some(region),
            subregion: Some(subregion),
        }
    }
    /// The enclosing identifiers, closest first (region, then country).
    fn parents(&self) -> Vec<RegionKey> {
        match (self.region, self.subregion) {
            (Some(r), Some(_)) => vec![Self::region(self.country, r), Self::country(self.country)],
            (Some(_), None) => vec![Self::country(self.country)],
            _ => vec![],
        }
    }
}

/// Polygons of (latitude, longitude) vertices in degrees.
type Polygons = Vec<Vec<(f64, f64)>>;

static IDENTIFIED_REGIONS: RwLock<BTreeMap<RegionKey, Polygons>> = RwLock::new(BTreeMap::new());

/// Register the borders of an identified region so that certificates
/// restricted to it can be evaluated. `polygons` is a list of polygons
/// (several for territories with islands), each a list of (latitude,
/// longitude) vertices in 1/10 µdeg.
pub fn register_identified_region(key: RegionKey, polygons: &[Vec<(i32, i32)>]) {
    let geometry = polygons
        .iter()
        .map(|polygon| {
            polygon
                .iter()
                .map(|(lat, lon)| {
                    (
                        *lat as f64 * TENTH_MICRODEGREE,
                        *lon as f64 * TENTH_MICRODEGREE,
                    )
                })
                .collect()
        })
        .collect();
    IDENTIFIED_REGIONS
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, geometry);
}

/// Forget the geometry of an identified region (no-op if unknown).
pub fn unregister_identified_region(key: RegionKey) {
    IDENTIFIED_REGIONS
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&key);
}

/// Identifiers the stack can evaluate (the PICS list of recognised values).
pub fn recognized_identified_regions() -> Vec<RegionKey> {
    IDENTIFIED_REGIONS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .copied()
        .collect()
}

/// (start, end) of the validityPeriod in TAI microseconds since 2004.
pub fn validity_window_us(tbs: &ToBeSignedCertificate) -> (u64, u64) {
    let period = &tbs.validity_period;
    let start_us = period.start.0 .0 as u64 * 1_000_000;
    let duration_us: u64 = match &period.duration {
        Duration::microseconds(v) => v.0 as u64,
        Duration::milliseconds(v) => v.0 as u64 * 1_000,
        Duration::seconds(v) => v.0 as u64 * 1_000_000,
        Duration::minutes(v) => v.0 as u64 * 60_000_000,
        Duration::hours(v) => v.0 as u64 * 3_600_000_000,
        Duration::sixtyHours(v) => v.0 as u64 * 216_000_000_000,
        Duration::years(v) => v.0 as u64 * 31_556_952_000_000,
    };
    (start_us, start_us + duration_us)
}

/// True when `time_us` (Time64, TAI µs since 2004) lies in the validity
/// period of the certificate and of every issuer in its chain.
pub fn valid_at(certificate: &Certificate, time_us: u64) -> bool {
    let mut current = Some(certificate);
    while let Some(cert) = current {
        let (start, end) = validity_window_us(cert.tbs());
        if time_us < start || time_us > end {
            return false;
        }
        current = cert.issuer.as_deref();
    }
    true
}

/// Region of the certificate, or of the closest issuer that has one.
pub fn effective_region(certificate: &Certificate) -> Option<&GeographicRegion> {
    let mut current = Some(certificate);
    while let Some(cert) = current {
        if let Some(region) = &cert.tbs().region {
            return Some(region);
        }
        current = cert.issuer.as_deref();
    }
    None
}

fn deg(location: &TwoDLocation) -> (f64, f64) {
    (
        location.latitude.0 .0 as f64 * TENTH_MICRODEGREE,
        location.longitude.0 .0 as f64 * TENTH_MICRODEGREE,
    )
}

/// Great-circle distance (haversine) in metres between two points in degrees.
fn distance_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let (dp, dl) = (p2 - p1, (lon2 - lon1).to_radians());
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_M * a.sqrt().min(1.0).asin()
}

/// Ray casting in the (longitude, latitude) plane over (lat, lon) vertices in
/// degrees; the border counts as inside.
fn in_polygon(vertices: &[(f64, f64)], lat: f64, lon: f64) -> bool {
    let mut inside = false;
    for i in 0..vertices.len() {
        let (lat_i, lon_i) = vertices[i];
        let (lat_j, lon_j) = vertices[(i + vertices.len() - 1) % vertices.len()];
        if (lat_i > lat) != (lat_j > lat) {
            let cross = lon_i + (lat - lat_i) * (lon_j - lon_i) / (lat_j - lat_i);
            if lon == cross {
                return true;
            }
            if lon < cross {
                inside = !inside;
            }
        } else if lat_i == lat && lat_j == lat && lon_i.min(lon_j) <= lon && lon <= lon_i.max(lon_j)
        {
            return true;
        }
    }
    inside
}

/// Whether the position lies in a registered identifier. When the identifier
/// itself is not registered, a registered enclosing one (the region of a
/// subregion, the country of a region) can still show that the position is
/// outside; otherwise `None`.
fn key_contains(
    regions: &BTreeMap<RegionKey, Polygons>,
    key: &RegionKey,
    lat: f64,
    lon: f64,
) -> Option<bool> {
    let inside = |polygons: &Polygons| polygons.iter().any(|p| in_polygon(p, lat, lon));
    if let Some(polygons) = regions.get(key) {
        return Some(inside(polygons));
    }
    for parent in key.parents() {
        if let Some(polygons) = regions.get(&parent) {
            if !inside(polygons) {
                return Some(false);
            }
        }
    }
    None
}

/// Identifiers named by one IdentifiedRegion (clauses 6.4.22 to 6.4.26);
/// `None` for an empty list (not evaluable).
fn identified_keys(entry: &IdentifiedRegion) -> Option<Vec<RegionKey>> {
    let keys: Vec<RegionKey> = match entry {
        IdentifiedRegion::countryOnly(c) => vec![RegionKey::country(c.0 .0)],
        IdentifiedRegion::countryAndRegions(cr) => cr
            .regions
            .0
            .iter()
            .map(|r| RegionKey::region(cr.country_only.0 .0, r.0))
            .collect(),
        IdentifiedRegion::countryAndSubregions(cs) => cs
            .region_and_subregions
            .0
            .iter()
            .flat_map(|item| {
                item.subregions.0.iter().map(move |sub| {
                    RegionKey::subregion(cs.country_only.0 .0, item.region.0, sub.0)
                })
            })
            .collect(),
    };
    (!keys.is_empty()).then_some(keys)
}

/// SequenceOfIdentifiedRegion: inside when any recognised identifier contains
/// the position (IEEE 1609.2 allows unrecognised values when the recognised
/// ones establish validity); outside when every identifier is recognised and
/// none contains it; otherwise `None`.
pub fn identified_region_contains(
    entries: &[IdentifiedRegion],
    lat: f64,
    lon: f64,
) -> Option<bool> {
    let regions = IDENTIFIED_REGIONS.read().unwrap_or_else(|e| e.into_inner());
    let mut unknown = false;
    for entry in entries {
        let Some(keys) = identified_keys(entry) else {
            unknown = true;
            continue;
        };
        for key in keys {
            match key_contains(&regions, &key, lat, lon) {
                Some(true) => return Some(true),
                Some(false) => {}
                None => unknown = true,
            }
        }
    }
    if unknown {
        None
    } else {
        Some(false)
    }
}

/// Whether a position (1/10 µdeg) lies inside a GeographicRegion. `Some(true)`
/// for no region (no restriction); `None` when the region cannot be
/// evaluated (identifiedRegion without registered geometry).
pub fn region_contains(
    region: Option<&GeographicRegion>,
    latitude: i32,
    longitude: i32,
) -> Option<bool> {
    let Some(region) = region else {
        return Some(true);
    };
    let (lat, lon) = (
        latitude as f64 * TENTH_MICRODEGREE,
        longitude as f64 * TENTH_MICRODEGREE,
    );
    match region {
        GeographicRegion::circularRegion(circle) => {
            let (c_lat, c_lon) = deg(&circle.center);
            Some(distance_m(c_lat, c_lon, lat, lon) <= circle.radius.0 as f64)
        }
        GeographicRegion::rectangularRegion(rects) => Some(rects.0.iter().any(|rect| {
            let (north, west) = deg(&rect.north_west);
            let (south, east) = deg(&rect.south_east);
            south <= lat && lat <= north && west <= lon && lon <= east
        })),
        GeographicRegion::polygonalRegion(polygon) => {
            let vertices: Vec<(f64, f64)> = polygon.0.iter().map(deg).collect();
            Some(in_polygon(&vertices, lat, lon))
        }
        GeographicRegion::identifiedRegion(entries) => {
            identified_region_contains(&entries.0, lat, lon)
        }
    }
}

/// Region consistency (IEEE 1609.2 clause 5.2.3.2.2): the position lies in
/// the effective region of the certificate chain. A region that cannot be
/// evaluated is not treated as a violation.
pub fn location_permitted(certificate: &Certificate, latitude: i32, longitude: i32) -> bool {
    region_contains(effective_region(certificate), latitude, longitude) != Some(false)
}

/// (permitted, SSP) for `psid` in the appPermissions of a certificate. The SSP
/// is the BitmapSsp or opaque octets, or `None` when the entry has no SSP.
pub fn app_permission(tbs: &ToBeSignedCertificate, psid: u64) -> (bool, Option<Vec<u8>>) {
    let Some(permissions) = &tbs.app_permissions else {
        return (false, None);
    };
    for entry in &permissions.0 {
        if u64::try_from(&entry.psid.0).ok() == Some(psid) {
            let ssp = entry.ssp.as_ref().map(|ssp| match ssp {
                ServiceSpecificPermissions::opaque(o) => o.to_vec(),
                ServiceSpecificPermissions::bitmapSsp(b) => b.0.to_vec(),
            });
            return (true, ssp);
        }
    }
    (false, None)
}

/// True when the BitmapSsp of an AT grants every permission bit requested
/// (octets after the SSP version octet). Without requested bits any SSP
/// covers the request.
pub fn ssp_covers(at_ssp: Option<&[u8]>, requested: &[u8]) -> bool {
    let wanted = requested.get(1..).unwrap_or(&[]);
    let have = at_ssp.and_then(|s| s.get(1..)).unwrap_or(&[]);
    wanted
        .iter()
        .enumerate()
        .all(|(i, bits)| *bits == 0 || (i < have.len() && bits & !have[i] == 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::security_asn::ieee1609_dot2_base_types::{
        CircularRegion, CountryAndRegions, CountryAndSubregions, Latitude, Longitude,
        NinetyDegreeInt, OneEightyDegreeInt, PolygonalRegion, RectangularRegion,
        RegionAndSubregions, SequenceOfIdentifiedRegion, SequenceOfRectangularRegion,
        SequenceOfRegionAndSubregions, SequenceOfUint16, SequenceOfUint8, Uint16, Uint8,
        UnCountryId,
    };

    fn point(lat: i32, lon: i32) -> TwoDLocation {
        TwoDLocation::new(
            Latitude(NinetyDegreeInt(lat)),
            Longitude(OneEightyDegreeInt(lon)),
        )
    }

    #[test]
    fn circular_region() {
        let region = GeographicRegion::circularRegion(CircularRegion::new(
            point(415520000, 21340000),
            Uint16(5000),
        ));
        assert_eq!(
            region_contains(Some(&region), 415520000, 21340000),
            Some(true)
        );
        assert_eq!(
            region_contains(Some(&region), 425520000, 21340000),
            Some(false)
        );
        assert_eq!(region_contains(None, 0, 0), Some(true));
    }

    #[test]
    fn rectangular_region() {
        let rect = RectangularRegion::new(point(420000000, 20000000), point(410000000, 30000000));
        let region = GeographicRegion::rectangularRegion(SequenceOfRectangularRegion(vec![rect]));
        assert_eq!(
            region_contains(Some(&region), 415000000, 25000000),
            Some(true)
        );
        assert_eq!(
            region_contains(Some(&region), 400000000, 25000000),
            Some(false)
        );
    }

    #[test]
    fn polygonal_region_with_8_points() {
        // Octagon around (41.5, 2.5) - IEEE 1609.2 clause 6.4.17: at least 8 points
        let pts = [
            (420000000, 24000000),
            (420000000, 26000000),
            (418000000, 28000000),
            (412000000, 28000000),
            (410000000, 26000000),
            (410000000, 24000000),
            (412000000, 22000000),
            (418000000, 22000000),
        ];
        let region = GeographicRegion::polygonalRegion(PolygonalRegion(
            pts.iter().map(|(a, b)| point(*a, *b)).collect(),
        ));
        assert_eq!(
            region_contains(Some(&region), 415000000, 25000000),
            Some(true)
        );
        assert_eq!(
            region_contains(Some(&region), 419500000, 22100000),
            Some(false)
        );
    }

    fn boxed(south: i32, west: i32, north: i32, east: i32) -> Vec<(i32, i32)> {
        vec![(south, west), (north, west), (north, east), (south, east)]
    }

    fn identified(entries: Vec<IdentifiedRegion>) -> GeographicRegion {
        GeographicRegion::identifiedRegion(SequenceOfIdentifiedRegion(entries))
    }

    fn country(code: u16) -> IdentifiedRegion {
        IdentifiedRegion::countryOnly(UnCountryId(Uint16(code)))
    }

    // Synthetic geometry and identifiers; each test uses its own country codes
    // because the registry is shared by the tests running in parallel.

    #[test]
    fn identified_region_without_geometry_cannot_be_evaluated() {
        let region = identified(vec![country(9000)]);
        assert_eq!(region_contains(Some(&region), 0, 0), None);
    }

    #[test]
    fn identified_region_country() {
        let key = RegionKey::country(9001);
        register_identified_region(key, &[boxed(410000000, 15000000, 420000000, 28000000)]);
        assert!(recognized_identified_regions().contains(&key));
        let region = identified(vec![country(9001)]);
        assert_eq!(
            region_contains(Some(&region), 415520000, 21340000),
            Some(true)
        );
        assert_eq!(
            region_contains(Some(&region), 425520000, 21340000),
            Some(false)
        );
        unregister_identified_region(key);
        assert_eq!(region_contains(Some(&region), 415520000, 21340000), None);
    }

    /// IEEE 1609.2 clause 6.4.17: identifiedRegion with 8 entries, one of
    /// them containing the position.
    #[test]
    fn identified_region_with_8_entries() {
        for i in 0..8u16 {
            let lat = 340000000 + i as i32 * 15000000;
            register_identified_region(
                RegionKey::country(9100 + i),
                &[boxed(lat, 0, lat + 10000000, 30000000)],
            );
        }
        let region = identified((0..8).map(|i| country(9100 + i)).collect());
        // Boxes 34.0-35.0 N, 35.5-36.5 N, ...: 41.55 N lies in the 6th (41.5-42.5 N)
        assert_eq!(
            region_contains(Some(&region), 415520000, 21340000),
            Some(true)
        );
        assert_eq!(
            region_contains(Some(&region), 412000000, 21340000),
            Some(false)
        );
    }

    #[test]
    fn identified_regions_and_subregions() {
        register_identified_region(
            RegionKey::country(9200),
            &[boxed(400000000, 0, 430000000, 40000000)],
        );
        register_identified_region(
            RegionKey::region(9200, 3),
            &[boxed(410000000, 15000000, 420000000, 28000000)],
        );
        let regions = identified(vec![IdentifiedRegion::countryAndRegions(
            CountryAndRegions::new(UnCountryId(Uint16(9200)), SequenceOfUint8(vec![Uint8(3)])),
        )]);
        assert_eq!(
            region_contains(Some(&regions), 415520000, 21340000),
            Some(true)
        );
        assert_eq!(
            region_contains(Some(&regions), 425520000, 21340000),
            Some(false)
        );
        let subregions = identified(vec![IdentifiedRegion::countryAndSubregions(
            CountryAndSubregions::new(
                UnCountryId(Uint16(9200)),
                SequenceOfRegionAndSubregions(vec![RegionAndSubregions::new(
                    Uint8(3),
                    SequenceOfUint16(vec![Uint16(7)]),
                )]),
            ),
        )]);
        // Subregion 7 has no geometry: inside region 3 it cannot be decided,
        // outside region 3 (or the country) it is outside.
        assert_eq!(
            region_contains(Some(&subregions), 415520000, 21340000),
            None
        );
        assert_eq!(
            region_contains(Some(&subregions), 425520000, 21340000),
            Some(false)
        );
        assert_eq!(
            region_contains(Some(&subregions), 500000000, 21340000),
            Some(false)
        );
        register_identified_region(
            RegionKey::subregion(9200, 3, 7),
            &[boxed(415000000, 21000000, 416000000, 22000000)],
        );
        assert_eq!(
            region_contains(Some(&subregions), 415520000, 21340000),
            Some(true)
        );
        assert_eq!(
            region_contains(Some(&subregions), 418000000, 21340000),
            Some(false)
        );
    }

    /// IEEE 1609.2 clause 6.4.24: unrecognised values are allowed when the
    /// recognised ones establish that the position is inside.
    #[test]
    fn identified_region_with_unrecognised_entries() {
        register_identified_region(
            RegionKey::country(9301),
            &[boxed(410000000, 15000000, 420000000, 28000000)],
        );
        let region = identified(vec![country(9300), country(9301)]);
        assert_eq!(
            region_contains(Some(&region), 415520000, 21340000),
            Some(true)
        );
        assert_eq!(region_contains(Some(&region), 425520000, 21340000), None);
    }

    #[test]
    fn ssp_coverage() {
        let at = [2u8, 0x02, 0x00];
        assert!(ssp_covers(Some(&at), &[0, 0x02]));
        assert!(!ssp_covers(Some(&at), &[0, 0x01]));
        assert!(!ssp_covers(Some(&at), &[0, 0, 0, 0x80]));
        assert!(ssp_covers(Some(&at), &[0]));
        assert!(ssp_covers(None, &[]));
        assert!(!ssp_covers(None, &[0, 0x01]));
    }
}
