// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Security conformance tests: one test per Test Purpose of ETSI TS 103 096-2
//! V2.1.1, against ETSI TS 103 097 V2.2.1 and IEEE Std 1609.2.
//!
//! Each test is named after its TP and quotes the TP identifier, so that a
//! search for the identifier finds it. A TP with a permutation table (`_XX`)
//! is one test looping over the permutations; TP_SEC_ITSS_SND_CAM_23_BV and
//! TP_SEC_ITSS_SND_CAM_24_BV, which TS 103 096-2 defines twice, are one test
//! each covering both definitions.
//!
//! The tests drive complete stations: the CA basic service, the DEN service
//! and the GeoNetworking Beacon on BTP on a secured GeoNetworking router,
//! sharing one virtual clock (GeoNetworking timers, CA generation, DEN
//! timestamps and the sign service: generationTime, certificate timers, AT
//! validity). Frames are captured at the link layer and decoded from the
//! wire. On the receiving side the test system is another complete station;
//! a message it sends with a deliberate fault is re-signed, so that the fault
//! is the only reason for a discard, and every discard is followed by a valid
//! message that is accepted.
//!
//! Mirrors `tests/flexstack/security/test_sec_conformance.py`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rasn::prelude::{FixedBitString, FixedOctetString, Integer};
use sha2::{Digest, Sha256, Sha384};

use crate::btp::router::{BTPRouterHandle, Router as BtpRouter};
use crate::btp::service_access_point::{BTPDataIndication, BTPDataRequest};
use crate::facilities::ca_basic_service::cam_ssp::tests::vehicle;
use crate::facilities::ca_basic_service::CooperativeAwarenessBasicService;
use crate::facilities::decentralized_environmental_notification_service::conformance::request;
use crate::facilities::decentralized_environmental_notification_service::denm_coder::DenmCoder;
use crate::facilities::decentralized_environmental_notification_service::denm_reception::process_indication;
use crate::facilities::decentralized_environmental_notification_service::denm_transmission::VehicleData as DenVehicleData;
use crate::facilities::decentralized_environmental_notification_service::{
    DecentralizedEnvironmentalNotificationService, DenConfig,
};
use crate::facilities::location_service::GpsFix;
use crate::geonet::basic_header::{BasicHeader, BasicNH};
use crate::geonet::common_header::CommonHeader;
use crate::geonet::gn_address::{GNAddress, M, MID, ST};
use crate::geonet::mib::{GnSecurity, Mib};
use crate::geonet::position_vector::Tst;
use crate::geonet::router::Router as GnRouter;
use crate::geonet::service_access_point::{CommonNH, GNDataIndication, GNDataRequest, HeaderType};
use crate::security::certificate::{
    decode_ieee1609_dot2_data, encode_certificate, encode_ieee1609_dot2_data, encode_tbs_data,
    Certificate, OwnCertificate,
};
use crate::security::certificate_library::CertificateLibrary;
use crate::security::ecdsa_backend::{EcdsaBackend, KeyAlgorithm};
use crate::security::etsi_ts103097_module::EtsiTs103097Certificate;
use crate::security::ieee1609_dot2::{
    Certificate as AsnCertificate, CertificateId, EndEntityType, HeaderInfo, Ieee1609Dot2Content,
    Ieee1609Dot2Data, IssuerIdentifier, MissingCrlIdentifier, PsidGroupPermissions,
    SequenceOfPsidGroupPermissions, SignedData, SignerIdentifier, SubjectPermissions,
    ToBeSignedCertificate, VerificationKeyIndicator,
};
use crate::security::ieee1609_dot2_base_types::{
    BasePublicEncryptionKey, BitmapSsp, CircularRegion, CrlSeries, Duration as AsnDuration,
    EccP256CurvePoint, EccP384CurvePoint, EcdsaP384Signature, Elevation, EncryptionKey,
    GeographicRegion, HashAlgorithm, HashedId3, IdentifiedRegion, Latitude, Longitude,
    NinetyDegreeInt, OneEightyDegreeInt, PolygonalRegion, Psid, PsidSsp, PsidSspRange,
    PublicVerificationKey, RectangularRegion, SequenceOfHashedId3, SequenceOfIdentifiedRegion,
    SequenceOfPsidSsp, SequenceOfPsidSspRange, SequenceOfRectangularRegion,
    ServiceSpecificPermissions, Signature as Ieee1609Signature, SymmetricEncryptionKey,
    ThreeDLocation, Time32, Time64, TwoDLocation, Uint16, Uint32, Uint64, UnCountryId,
    ValidityPeriod,
};
use crate::security::sign_service::SignService;
use crate::security::time_service::{unix_ms_to_its_ms, ELAPSED_SECONDS, ITS_EPOCH};
use crate::security::validity::{
    app_permission, location_permitted, register_identified_region, validity_window_us, RegionKey,
};
use crate::security::verify_service::security_checks::ca_tbs;

const AID_CAM: u64 = 36;
const AID_DENM: u64 = 37;
const AID_GNMGMT: u64 = 141;
const INSIDE: (i32, i32) = (415_520_000, 21_340_000);
const IUT_ID: u32 = 0x1001;
pub(crate) const TS_ID: u32 = 0x2002;
const ONE_S_US: u64 = 1_000_000;
pub(crate) const FLUSH_AID: u64 = 0xFFFF_FFF0;

// ─── Permissions, regions, certificates ─────────────────────────────────────

/// CAM SSP, DENM SSP (every cause code) and GN-MGMT.
pub(crate) fn app_permissions() -> Vec<(u64, Option<Vec<u8>>)> {
    vec![
        (AID_CAM, Some(vec![2, 0x02, 0x00])),
        (AID_DENM, Some(vec![2, 0xFF, 0xFF, 0xFF, 0xFF])),
        (AID_GNMGMT, None),
    ]
}

pub(crate) fn psid_ssps(permissions: &[(u64, Option<Vec<u8>>)]) -> SequenceOfPsidSsp {
    SequenceOfPsidSsp(
        permissions
            .iter()
            .map(|(psid, ssp)| {
                PsidSsp::new(
                    Psid(Integer::from(*psid)),
                    ssp.as_ref().map(|s| {
                        ServiceSpecificPermissions::bitmapSsp(BitmapSsp(s.clone().into()))
                    }),
                )
            })
            .collect(),
    )
}

fn point(lat: i32, lon: i32) -> TwoDLocation {
    TwoDLocation::new(
        Latitude(NinetyDegreeInt(lat)),
        Longitude(OneEightyDegreeInt(lon)),
    )
}

fn rectangles(boxes: &[(i32, i32, i32, i32)]) -> GeographicRegion {
    GeographicRegion::rectangularRegion(SequenceOfRectangularRegion(
        boxes
            .iter()
            .map(|&(north, west, south, east)| {
                RectangularRegion::new(point(north, west), point(south, east))
            })
            .collect(),
    ))
}

fn identified(countries: impl Iterator<Item = u16>) -> GeographicRegion {
    register_identified_regions();
    GeographicRegion::identifiedRegion(SequenceOfIdentifiedRegion(
        countries
            .map(|c| IdentifiedRegion::countryOnly(UnCountryId(Uint16(c))))
            .collect(),
    ))
}

/// Synthetic geometry for UnCountryId 9600..9607 (the 6th contains INSIDE);
/// registered once for the whole process (tests run in parallel).
fn register_identified_regions() {
    for i in 0..8u16 {
        let south = 340_000_000 + i as i32 * 15_000_000;
        let north = south + 10_000_000;
        register_identified_region(
            RegionKey::country(9600 + i),
            &[vec![
                (south, 0),
                (north, 0),
                (north, 30_000_000),
                (south, 30_000_000),
            ]],
        );
    }
}

/// Region restrictions (TS 103 096-2 certificates B, C, D, E and the 8-entry
/// variants), all around INSIDE.
fn circle() -> GeographicRegion {
    GeographicRegion::circularRegion(CircularRegion::new(point(INSIDE.0, INSIDE.1), Uint16(5000)))
}
fn rectangle() -> GeographicRegion {
    rectangles(&[(416_000_000, 20_340_000, 415_000_000, 22_340_000)])
}
fn rectangles_8() -> GeographicRegion {
    let boxes: Vec<_> = (0..8)
        .map(|i| {
            let west = 5_340_000 + i * 3_000_000;
            (416_000_000, west, 415_000_000, west + 2_000_000)
        })
        .collect();
    rectangles(&boxes)
}
fn polygon_8() -> GeographicRegion {
    GeographicRegion::polygonalRegion(PolygonalRegion(
        [
            (1_000_000, -400_000),
            (1_000_000, 400_000),
            (400_000, 1_000_000),
            (-400_000, 1_000_000),
            (-1_000_000, 400_000),
            (-1_000_000, -400_000),
            (-400_000, -1_000_000),
            (400_000, -1_000_000),
        ]
        .iter()
        .map(|(a, b)| point(INSIDE.0 + a, INSIDE.1 + b))
        .collect(),
    ))
}
fn far_rectangle() -> GeographicRegion {
    rectangles(&[(400_000_000, 20_340_000, 390_000_000, 22_340_000)]) // 39.0-40.0 N
}
fn regions() -> Vec<(&'static str, GeographicRegion)> {
    vec![
        ("B", circle()),
        ("C", rectangle()),
        ("D", polygon_8()),
        ("E", identified(9605..9606)),
    ]
}

fn its_now_s() -> i64 {
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    unix - ITS_EPOCH as i64 + ELAPSED_SECONDS as i64
}

fn validity(start_offset_s: i64, duration: AsnDuration) -> ValidityPeriod {
    ValidityPeriod::new(
        Time32(Uint32((its_now_s() + start_offset_s) as u32)),
        duration,
    )
}

/// CERT_IUT_A_AT / CERT_TS_A_AT contents: valid for an hour from a minute ago.
pub(crate) fn at_tbs() -> ToBeSignedCertificate {
    let mut tbs = ca_tbs();
    tbs.cert_issue_permissions = None;
    tbs.app_permissions = Some(psid_ssps(&app_permissions()));
    tbs.validity_period = validity(-60, AsnDuration::hours(Uint16(1)));
    tbs
}

fn with_region(mut tbs: ToBeSignedCertificate, region: GeographicRegion) -> ToBeSignedCertificate {
    tbs.region = Some(region);
    tbs
}

fn with_app(
    mut tbs: ToBeSignedCertificate,
    permissions: &[(u64, Option<Vec<u8>>)],
) -> ToBeSignedCertificate {
    tbs.app_permissions = Some(psid_ssps(permissions));
    tbs
}

fn curve_of(variant: &str) -> (KeyAlgorithm, bool) {
    match variant {
        "A" => (KeyAlgorithm::NistP256, true),
        "AN" => (KeyAlgorithm::NistP256, false),
        "B" => (KeyAlgorithm::BrainpoolP256r1, true),
        "BN" => (KeyAlgorithm::BrainpoolP256r1, false),
        "C" => (KeyAlgorithm::BrainpoolP384r1, true),
        _ => (KeyAlgorithm::BrainpoolP384r1, false),
    }
}

fn is_384(algorithm: KeyAlgorithm) -> bool {
    matches!(
        algorithm,
        KeyAlgorithm::BrainpoolP384r1 | KeyAlgorithm::NistP384
    )
}

fn key_matches(key: &PublicVerificationKey, algorithm: KeyAlgorithm) -> bool {
    matches!(
        (key, algorithm),
        (
            PublicVerificationKey::ecdsaNistP256(_),
            KeyAlgorithm::NistP256
        ) | (
            PublicVerificationKey::ecdsaBrainpoolP256r1(_),
            KeyAlgorithm::BrainpoolP256r1
        ) | (
            PublicVerificationKey::ecdsaBrainpoolP384r1(_),
            KeyAlgorithm::BrainpoolP384r1
        ) | (
            PublicVerificationKey::ecdsaNistP384(_),
            KeyAlgorithm::NistP384
        )
    )
}

fn signature_matches(signature: &Ieee1609Signature, algorithm: KeyAlgorithm) -> bool {
    matches!(
        (signature, algorithm),
        (
            Ieee1609Signature::ecdsaNistP256Signature(_),
            KeyAlgorithm::NistP256
        ) | (
            Ieee1609Signature::ecdsaBrainpoolP256r1Signature(_),
            KeyAlgorithm::BrainpoolP256r1
        ) | (
            Ieee1609Signature::ecdsaBrainpoolP384r1Signature(_),
            KeyAlgorithm::BrainpoolP384r1
        ) | (
            Ieee1609Signature::ecdsaNistP384Signature(_),
            KeyAlgorithm::NistP384
        )
    )
}

/// The rSig choice of an ECDSA signature: "x-only", "compressed-y-0", ...
fn r_choice(signature: &Ieee1609Signature) -> &'static str {
    let p256 = |r: &EccP256CurvePoint| match r {
        EccP256CurvePoint::x_only(_) => "x-only",
        EccP256CurvePoint::compressed_y_0(_) => "compressed-y-0",
        EccP256CurvePoint::compressed_y_1(_) => "compressed-y-1",
        _ => "other",
    };
    let p384 = |r: &EccP384CurvePoint| match r {
        EccP384CurvePoint::x_only(_) => "x-only",
        EccP384CurvePoint::compressed_y_0(_) => "compressed-y-0",
        EccP384CurvePoint::compressed_y_1(_) => "compressed-y-1",
        _ => "other",
    };
    match signature {
        Ieee1609Signature::ecdsaNistP256Signature(s)
        | Ieee1609Signature::ecdsaBrainpoolP256r1Signature(s) => p256(&s.r_sig),
        Ieee1609Signature::ecdsaBrainpoolP384r1Signature(s)
        | Ieee1609Signature::ecdsaNistP384Signature(s) => p384(&s.r_sig),
        _ => "other",
    }
}

fn point_choice_p256(p: &EccP256CurvePoint) -> &'static str {
    match p {
        EccP256CurvePoint::compressed_y_0(_) | EccP256CurvePoint::compressed_y_1(_) => "compressed",
        EccP256CurvePoint::uncompressedP256(_) => "uncompressed",
        _ => "other",
    }
}

fn point_choice(key: &PublicVerificationKey) -> &'static str {
    match key {
        PublicVerificationKey::ecdsaNistP256(p)
        | PublicVerificationKey::ecdsaBrainpoolP256r1(p) => point_choice_p256(p),
        PublicVerificationKey::ecdsaBrainpoolP384r1(p)
        | PublicVerificationKey::ecdsaNistP384(p) => match p {
            EccP384CurvePoint::compressed_y_0(_) | EccP384CurvePoint::compressed_y_1(_) => {
                "compressed"
            }
            EccP384CurvePoint::uncompressedP384(_) => "uncompressed",
            _ => "other",
        },
        _ => "other",
    }
}

// ─── Clock and PKI ──────────────────────────────────────────────────────────

/// Virtual clock of a test: `ms` after a real UTC instant taken at start.
#[derive(Clone)]
pub(crate) struct Clock {
    pub(crate) base_ms: u64,
    pub(crate) offset: Arc<AtomicU64>,
}

impl Clock {
    pub(crate) fn new() -> Clock {
        Clock {
            base_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            offset: Arc::new(AtomicU64::new(0)),
        }
    }
    pub(crate) fn ms(&self) -> u64 {
        self.offset.load(Ordering::SeqCst)
    }
    pub(crate) fn set(&self, ms: u64) {
        self.offset.store(ms, Ordering::SeqCst);
    }
    pub(crate) fn unix_ms(&self) -> u64 {
        self.base_ms + self.ms()
    }
    pub(crate) fn its_ms(&self) -> u64 {
        unix_ms_to_its_ms(self.unix_ms())
    }
    pub(crate) fn its_us(&self) -> u64 {
        self.its_ms() * 1000
    }
}

/// Root CA and AAs; ATs on demand. Every station trusts `roots` and `aas`.
pub(crate) struct Pki {
    pub(crate) backend: EcdsaBackend,
    pub(crate) root: OwnCertificate,
    pub(crate) aa: OwnCertificate,
    pub(crate) roots: Vec<Certificate>,
    pub(crate) aas: Vec<Certificate>,
}

impl Pki {
    pub(crate) fn new() -> Pki {
        Pki::on(KeyAlgorithm::NistP256)
    }

    pub(crate) fn on(algorithm: KeyAlgorithm) -> Pki {
        Pki::chain(algorithm, ca_tbs(), ca_tbs())
    }

    pub(crate) fn chain(
        algorithm: KeyAlgorithm,
        root: ToBeSignedCertificate,
        aa: ToBeSignedCertificate,
    ) -> Pki {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed_with(&mut backend, root, algorithm);
        let aa = OwnCertificate::initialize_issued_with(&mut backend, aa, &root, algorithm);
        Pki {
            roots: vec![root.cert.clone()],
            aas: vec![aa.cert.clone()],
            backend,
            root,
            aa,
        }
    }

    pub(crate) fn new_aa(
        &mut self,
        algorithm: KeyAlgorithm,
        trusted: bool,
        tbs: ToBeSignedCertificate,
    ) -> OwnCertificate {
        let aa =
            OwnCertificate::initialize_issued_with(&mut self.backend, tbs, &self.root, algorithm);
        if trusted {
            self.aas.push(aa.cert.clone());
        }
        aa
    }

    pub(crate) fn at(&mut self) -> OwnCertificate {
        self.at_with(None, KeyAlgorithm::NistP256, true, at_tbs())
    }

    pub(crate) fn at_tbs(&mut self, tbs: ToBeSignedCertificate) -> OwnCertificate {
        self.at_with(None, KeyAlgorithm::NistP256, true, tbs)
    }

    pub(crate) fn at_with(
        &mut self,
        aa: Option<&OwnCertificate>,
        algorithm: KeyAlgorithm,
        compressed: bool,
        tbs: ToBeSignedCertificate,
    ) -> OwnCertificate {
        let issuer = aa.unwrap_or(&self.aa).clone();
        OwnCertificate::initialize_issued_key(
            &mut self.backend,
            tbs,
            &issuer,
            algorithm,
            compressed,
        )
    }

    fn implicit_at(&mut self) -> OwnCertificate {
        let aa = self.aa.clone();
        aa.issue_implicit_certificate(&mut self.backend, at_tbs())
    }
}

// ─── Frames ─────────────────────────────────────────────────────────────────

/// A secured GeoNetworking packet, decoded from the wire.
pub(crate) struct Secured {
    pub(crate) raw: Vec<u8>,
    pub(crate) protocol_version: u8,
    pub(crate) data: Ieee1609Dot2Data,
    pub(crate) sd: SignedData,
    pub(crate) inner: Ieee1609Dot2Data,
    pub(crate) common: CommonHeader,
}

impl Secured {
    fn decode(raw: &[u8]) -> Secured {
        let basic = BasicHeader::decode(raw[0..4].try_into().unwrap());
        assert!(
            matches!(basic.nh, BasicNH::SecuredPacket),
            "not a secured packet"
        );
        let data = decode_ieee1609_dot2_data(&raw[4..]);
        let Ieee1609Dot2Content::signedData(sd) = data.content.clone() else {
            panic!("not signedData")
        };
        let inner = sd.tbs_data.payload.data.clone().expect("payload data");
        let plain = Secured::plain_of(&inner);
        Secured {
            raw: raw.to_vec(),
            protocol_version: raw[4], // COER Uint8, first octet
            common: CommonHeader::decode(plain[0..8].try_into().unwrap()),
            data,
            sd,
            inner,
        }
    }

    fn plain_of(inner: &Ieee1609Dot2Data) -> Vec<u8> {
        match &inner.content {
            Ieee1609Dot2Content::unsecuredData(o) => o.0.to_vec(),
            _ => panic!("payload is not unsecuredData"),
        }
    }

    fn plain(&self) -> Vec<u8> {
        Secured::plain_of(&self.inner)
    }

    fn header(&self) -> &HeaderInfo {
        &self.sd.tbs_data.header_info
    }

    fn generation_time(&self) -> u64 {
        self.header()
            .generation_time
            .as_ref()
            .expect("generationTime")
            .0
             .0
    }

    fn signed_with_certificate(&self) -> bool {
        matches!(self.sd.signer, SignerIdentifier::certificate(_))
    }

    fn digest(&self) -> Option<[u8; 8]> {
        match &self.sd.signer {
            SignerIdentifier::digest(h) => Some(h.0.as_ref().try_into().unwrap()),
            _ => None,
        }
    }

    /// The signer certificate (signer choice `certificate`).
    fn certificate(&self) -> &AsnCertificate {
        match &self.sd.signer {
            SignerIdentifier::certificate(seq) => &seq.0[0],
            _ => panic!("signer is not a certificate"),
        }
    }

    fn certificate_count(&self) -> usize {
        match &self.sd.signer {
            SignerIdentifier::certificate(seq) => seq.0.len(),
            _ => 0,
        }
    }

    fn tbs(&self) -> &ToBeSignedCertificate {
        &self.certificate().0.to_be_signed
    }

    fn key(&self) -> &PublicVerificationKey {
        match &self.tbs().verify_key_indicator {
            VerificationKeyIndicator::verificationKey(k) => k,
            _ => panic!("no verification key"),
        }
    }

    fn inline_requests(&self) -> Vec<[u8; 3]> {
        self.header()
            .inline_p2pcd_request
            .as_ref()
            .map(|s| {
                s.0.iter()
                    .map(|h| h.0.as_ref().try_into().unwrap())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn location(&self) -> (i32, i32) {
        let l = self
            .header()
            .generation_location
            .as_ref()
            .expect("generationLocation");
        (l.latitude.0 .0, l.longitude.0 .0)
    }
}

fn h3(certificate: &Certificate) -> [u8; 3] {
    let h = certificate.as_hashedid8();
    [h[5], h[6], h[7]]
}

fn compress_p256(p: &mut EccP256CurvePoint) {
    if let EccP256CurvePoint::uncompressedP256(u) = p {
        let x = u.x.clone();
        *p = if u.y.as_ref()[31] % 2 == 0 {
            EccP256CurvePoint::compressed_y_0(x)
        } else {
            EccP256CurvePoint::compressed_y_1(x)
        };
    }
}

fn compress_p384(p: &mut EccP384CurvePoint) {
    if let EccP384CurvePoint::uncompressedP384(u) = p {
        let x = u.x.clone();
        *p = if u.y.as_ref()[47] % 2 == 0 {
            EccP384CurvePoint::compressed_y_0(x)
        } else {
            EccP384CurvePoint::compressed_y_1(x)
        };
    }
}

/// COER of the canonical certificate (IEEE 1609.2 clause 6.4.3), computed
/// here: every point of toBeSigned (verification key or reconstruction value,
/// encryption key) in compressed form and the r of the ECDSA signature in
/// x-only form.
fn canonical_bytes(certificate: &AsnCertificate) -> Vec<u8> {
    let mut base = certificate.0.clone();
    match &mut base.to_be_signed.verify_key_indicator {
        VerificationKeyIndicator::verificationKey(
            PublicVerificationKey::ecdsaNistP256(p)
            | PublicVerificationKey::ecdsaBrainpoolP256r1(p),
        )
        | VerificationKeyIndicator::reconstructionValue(p) => compress_p256(p),
        VerificationKeyIndicator::verificationKey(
            PublicVerificationKey::ecdsaBrainpoolP384r1(p)
            | PublicVerificationKey::ecdsaNistP384(p),
        ) => compress_p384(p),
        _ => {}
    }
    if let Some(key) = &mut base.to_be_signed.encryption_key {
        let (BasePublicEncryptionKey::eciesNistP256(p)
        | BasePublicEncryptionKey::eciesBrainpoolP256r1(p)
        | BasePublicEncryptionKey::ecencSm2(p)) = &mut key.public_key;
        compress_p256(p);
    }
    match &mut base.signature {
        Some(
            Ieee1609Signature::ecdsaNistP256Signature(s)
            | Ieee1609Signature::ecdsaBrainpoolP256r1Signature(s),
        ) => {
            if let EccP256CurvePoint::compressed_y_0(x) | EccP256CurvePoint::compressed_y_1(x) =
                &s.r_sig
            {
                s.r_sig = EccP256CurvePoint::x_only(x.clone());
            }
        }
        Some(
            Ieee1609Signature::ecdsaBrainpoolP384r1Signature(s)
            | Ieee1609Signature::ecdsaNistP384Signature(s),
        ) => {
            if let EccP384CurvePoint::compressed_y_0(x) | EccP384CurvePoint::compressed_y_1(x) =
                &s.r_sig
            {
                s.r_sig = EccP384CurvePoint::x_only(x.clone());
            }
        }
        _ => {}
    }
    encode_certificate(&EtsiTs103097Certificate(AsnCertificate(base)))
}

fn hash(data: &[u8], sha384: bool) -> Vec<u8> {
    if sha384 {
        Sha384::digest(data).to_vec()
    } else {
        Sha256::digest(data).to_vec()
    }
}

/// HashedId8: last 8 octets of the hash of the canonical certificate.
fn digest_of(certificate: &AsnCertificate, sha384: bool) -> [u8; 8] {
    let h = hash(&canonical_bytes(certificate), sha384);
    h[h.len() - 8..].try_into().unwrap()
}

fn key_is_384(key: &PublicVerificationKey) -> bool {
    matches!(
        key,
        PublicVerificationKey::ecdsaBrainpoolP384r1(_) | PublicVerificationKey::ecdsaNistP384(_)
    )
}

/// IEEE 1609.2 clause 5.3.1, computed here: the signature over
/// Hash(Hash(tbsData) || Hash(signer certificate)) verifies with `key`.
fn verifies(
    frame: &Secured,
    signer: &AsnCertificate,
    key: &PublicVerificationKey,
    backend: &EcdsaBackend,
) -> bool {
    let sha384 = key_is_384(key);
    let data = [
        hash(&encode_tbs_data(&frame.sd.tbs_data), sha384),
        hash(&canonical_bytes(signer), sha384),
    ]
    .concat();
    backend.verify_with_pk(&data, &frame.sd.signature, key)
}

/// `raw` with `mutate` applied to its SignedData, signed again by `at`
/// (unless `sign` is false); `version` patches the outer protocolVersion octet.
pub(crate) fn resign(
    raw: &[u8],
    at: &OwnCertificate,
    backend: &EcdsaBackend,
    mutate: impl FnOnce(&mut SignedData),
    sign: bool,
    version: Option<u8>,
) -> Vec<u8> {
    let mut data = decode_ieee1609_dot2_data(&raw[4..]);
    let Ieee1609Dot2Content::signedData(sd) = &mut data.content else {
        panic!("not signedData")
    };
    mutate(sd);
    if sign {
        sd.signature = at.sign_message(backend, &encode_tbs_data(&sd.tbs_data));
    }
    let mut encoded = encode_ieee1609_dot2_data(&data);
    if let Some(v) = version {
        encoded[0] = v;
    }
    [raw[..4].to_vec(), encoded].concat()
}

fn no_mutation(_: &mut SignedData) {}

// ─── Stations ───────────────────────────────────────────────────────────────

/// Options of a station.
pub(crate) struct Options {
    pub(crate) n: u8,
    pub(crate) station_id: u32,
    pub(crate) position: (i32, i32),
    pub(crate) beacon: bool,
    pub(crate) aas: Option<Vec<Certificate>>,
    pub(crate) known_ats: Vec<Certificate>,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            n: 1,
            station_id: IUT_ID,
            position: INSIDE,
            beacon: false,
            aas: None,
            known_ats: vec![],
        }
    }
}

/// A complete ITS-S: CA basic service and DEN service on BTP on a secured
/// GeoNetworking router, its own ATs and the trust anchors of the PKI. The
/// link layer is captured with the virtual time.
pub(crate) struct Station {
    pub(crate) clock: Clock,
    pub(crate) gn: GnRouter,
    pub(crate) ll_rx: Receiver<Vec<u8>>,
    pub(crate) gn_btp_rx: Receiver<GNDataIndication>,
    pub(crate) btp: BTPRouterHandle,
    pub(crate) btp_gn_rx: Receiver<GNDataRequest>,
    pub(crate) cam_port_rx: Receiver<BTPDataIndication>,
    pub(crate) denm_port_rx: Receiver<BTPDataIndication>,
    pub(crate) ca: CooperativeAwarenessBasicService,
    pub(crate) den: DecentralizedEnvironmentalNotificationService,
    pub(crate) den_coder: DenmCoder,
    pub(crate) fix: GpsFix,
    pub(crate) log: Vec<(u64, Vec<u8>)>,
    pub(crate) ats: Vec<OwnCertificate>,
    pub(crate) cams: usize,
    pub(crate) denms: usize,
    /// CTL / CRL ports (2014, 2015) open to unsecured packets, when opened.
    pub(crate) trust_list_rx: Option<Receiver<BTPDataIndication>>,
    /// Payloads received on the CTL / CRL ports.
    pub(crate) trust_lists: Vec<Vec<u8>>,
}

impl Station {
    pub(crate) fn new(
        clock: &Clock,
        pki: &Pki,
        ats: Vec<OwnCertificate>,
        options: Options,
    ) -> Station {
        let aas = options.aas.unwrap_or_else(|| pki.aas.clone());
        let library = CertificateLibrary::new(&pki.backend, pki.roots.clone(), aas.clone(), vec![]);
        let c = clock.clone();
        let mut sign = SignService::new(pki.backend.clone(), library)
            .with_clock(Arc::new(move || c.unix_ms() as f64 / 1000.0));
        for at in &ats {
            sign.add_own_certificate(at.clone());
        }
        let verify_library =
            CertificateLibrary::new(&pki.backend, pki.roots.clone(), aas, options.known_ats);
        let mut mib = Mib::new();
        mib.itsGnLocalGnAddr = GNAddress::new(
            M::GnUnicast,
            ST::Unknown,
            MID::new([2, 0, 0, 0, 0, options.n]),
        );
        mib.itsGnSecurity = GnSecurity::Enabled;
        mib.itsGnBeaconServiceRetransmitTimer = if options.beacon { 3000 } else { 0 };
        let (ll_tx, ll_rx) = mpsc::channel();
        let (gn_btp_tx, gn_btp_rx) = mpsc::channel();
        let mut gn = GnRouter::new(
            mib,
            ll_tx,
            gn_btp_tx,
            Some(sign),
            Some(pki.backend.clone()),
            Some(verify_library),
        );
        let c = clock.clone();
        gn.set_clock(Box::new(move || c.ms()));
        gn.ego_position_vector.latitude = options.position.0 as u32;
        gn.ego_position_vector.longitude = options.position.1 as u32;
        gn.ego_position_vector.pai = true;
        gn.ego_position_vector.tst = Tst::set_in_normal_timestamp_milliseconds(clock.unix_ms());
        let (btp, btp_gn_rx) = BtpRouter::spawn(mib);
        let mut vd = vehicle(0, None);
        vd.station_id = options.station_id;
        let (ca, _cam_rx) = CooperativeAwarenessBasicService::new(btp.clone(), vd, None);
        let c = clock.clone();
        let (den, _denm_rx) = DecentralizedEnvironmentalNotificationService::with_config(
            btp.clone(),
            DenVehicleData {
                station_id: options.station_id,
                station_type: 5,
            },
            DenConfig {
                no_scheduler: true,
                clock: Some(Arc::new(move || c.its_ms())),
                ..Default::default()
            },
        );
        den.set_ego_position(options.position.0, options.position.1);
        // Replace the ports of the reception threads: received CAMs and DENMs
        // are processed synchronously by `deliver`.
        let (cam_port_tx, cam_port_rx) = mpsc::channel();
        btp.register_port(2001, cam_port_tx);
        let (denm_port_tx, denm_port_rx) = mpsc::channel();
        btp.register_port(2002, denm_port_tx);
        ca.cam_transmission_management.start();
        Station {
            clock: clock.clone(),
            gn,
            ll_rx,
            gn_btp_rx,
            btp,
            btp_gn_rx,
            cam_port_rx,
            denm_port_rx,
            ca,
            den,
            den_coder: DenmCoder::new(),
            fix: GpsFix {
                latitude: options.position.0 as f64 / 1e7,
                longitude: options.position.1 as f64 / 1e7,
                altitude_m: 100.0,
                speed_mps: 5.0,
                heading_deg: 90.0,
                pai: true,
                fix_time_ms: None,
            },
            log: vec![],
            ats,
            cams: 0,
            denms: 0,
            trust_list_rx: None,
            trust_lists: vec![],
        }
    }

    /// Open the CTL and CRL broadcast ports (2014, 2015) to unsecured packets;
    /// what they receive is collected in `trust_lists`.
    pub(crate) fn open_trust_list_ports(&mut self) {
        let (tx, rx) = mpsc::channel();
        self.btp.register_port_accepting_unsecured(2014, tx.clone());
        self.btp.register_port_accepting_unsecured(2015, tx);
        self.trust_list_rx = Some(rx);
    }

    /// Pass the requests queued in BTP to GN and collect the frames sent.
    pub(crate) fn flush_btp(&mut self) {
        self.btp.send_btp_data_request(BTPDataRequest {
            btp_type: CommonNH::BtpB,
            its_aid: FLUSH_AID,
            ..BTPDataRequest::new()
        });
        loop {
            let request = self
                .btp_gn_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("BTP flush");
            if request.its_aid == FLUSH_AID {
                break;
            }
            self.gn.gn_data_request(request);
        }
        let _ = self.drain();
    }

    fn drain(&mut self) -> Option<Secured> {
        let before = self.log.len();
        let now = self.clock.ms();
        while let Ok(raw) = self.ll_rx.try_recv() {
            self.log.push((now, raw));
        }
        // the last secured frame sent (unsecured CTL / CRL broadcasts are only logged)
        let last = &self.log.last()?.1;
        (self.log.len() > before && last[0] & 0x0F == 2).then(|| Secured::decode(last))
    }

    /// CA generation check at `at_ms` after a heading change of 10 degrees
    /// (TS 103 900 clause 6.1.3), i.e. a CAM is due; the frame sent, if any.
    pub(crate) fn cam(&mut self, at_ms: u64) -> Option<Secured> {
        self.clock.set(at_ms);
        self.fix.heading_deg = (self.fix.heading_deg + 10.0) % 360.0;
        self.ca.location_service_callback(self.fix);
        self.ca
            .cam_transmission_management
            .evaluate_and_maybe_send(self.clock.unix_ms())?;
        let request = self
            .btp_gn_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("BTP request for the CAM");
        self.gn.gn_data_request(request);
        self.drain()
    }

    pub(crate) fn cam_sent(&mut self, at_ms: u64) -> Secured {
        self.cam(at_ms).expect("a CAM is sent")
    }

    /// CAMs requested every 100 ms (more than one per second).
    fn cams_every_100_ms(&mut self, start_ms: u64, until_ms: u64) -> Vec<Secured> {
        (start_ms..=until_ms)
            .step_by(100)
            .map(|t| self.cam_sent(t))
            .collect()
    }

    /// A CAM signed with the certificate (as after a request of the certificate).
    pub(crate) fn certificate_cam(&mut self, at_ms: u64) -> Secured {
        self.gn
            .sign_service_mut()
            .expect("secured")
            .cam_state_mut()
            .requested_own_certificate = true;
        self.cam_sent(at_ms)
    }

    /// DENM triggered by the application (TS 103 831 clause 6.1.2); the frame sent, if any.
    fn denm(&mut self, at_ms: u64) -> Option<Secured> {
        self.clock.set(at_ms);
        let _ = self.den.trigger(&request(2, 0));
        self.btp.send_btp_data_request(BTPDataRequest {
            btp_type: CommonNH::BtpB,
            its_aid: FLUSH_AID,
            ..BTPDataRequest::new()
        });
        loop {
            let request = self
                .btp_gn_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("BTP flush");
            if request.its_aid == FLUSH_AID {
                break;
            }
            self.gn.gn_data_request(request);
        }
        self.drain()
    }

    fn denm_sent(&mut self, at_ms: u64) -> Secured {
        self.denm(at_ms).expect("a DENM is sent")
    }

    /// Advance to the Beacon timer and fire it; the Beacon sent, if any.
    fn beacon(&mut self) -> Option<Secured> {
        let deadline = self.gn.next_deadline().expect("Beacon timer");
        self.clock.set(deadline);
        self.gn.tick(deadline);
        self.drain()
    }

    /// A frame received from the radio: GN -> BTP -> CA / DEN reception.
    pub(crate) fn deliver(&mut self, raw: &[u8], at_ms: u64) {
        self.clock.set(at_ms);
        self.gn.process_basic_header(raw);
        while let Ok(indication) = self.gn_btp_rx.try_recv() {
            self.btp.send_gn_data_indication(indication);
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(2) {
                if let Ok(btp) = self.cam_port_rx.try_recv() {
                    if self
                        .ca
                        .cam_reception_management
                        .reception_callback(&btp)
                        .is_ok()
                    {
                        self.cams += 1;
                    }
                    break;
                }
                if let Ok(btp) = self.denm_port_rx.try_recv() {
                    if process_indication(&self.den_coder, self.den.shared(), &btp).is_some() {
                        self.denms += 1;
                    }
                    break;
                }
                if let Some(Ok(btp)) = self.trust_list_rx.as_ref().map(|rx| rx.try_recv()) {
                    self.trust_lists.push(btp.data);
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let _ = self.drain(); // frames forwarded by the station
    }
}

/// The virtual clock and PKI of a test, its stations built on them.
struct World {
    clock: Clock,
    pki: Pki,
}

impl World {
    pub(crate) fn new() -> World {
        World::with(Pki::new())
    }
    fn with(pki: Pki) -> World {
        World {
            clock: Clock::new(),
            pki,
        }
    }
    /// The IUT, authorized with `at`.
    fn iut_with(&self, at: OwnCertificate, options: Options) -> Station {
        Station::new(&self.clock, &self.pki, vec![at], options)
    }
    /// The IUT, authorized with CERT_IUT_A_AT.
    fn iut(&mut self) -> Station {
        let at = self.pki.at();
        self.iut_with(at, Options::default())
    }
    /// A test system station (address n), authorized with `at`.
    fn tester_with(&self, at: OwnCertificate, n: u8, aas: Option<Vec<Certificate>>) -> Station {
        Station::new(
            &self.clock,
            &self.pki,
            vec![at],
            Options {
                n,
                station_id: TS_ID,
                aas,
                ..Options::default()
            },
        )
    }
    /// A test system station authorized with CERT_TS_A_AT.
    fn tester(&mut self) -> Station {
        let at = self.pki.at();
        self.tester_with(at, 9, None)
    }

    /// generationTime realistic (CUR_TIME +- tolerance) and inside the
    /// validity period of the signer certificate (IEEE 1609.2 5.2.3.2.2).
    fn assert_generation_time(&self, frame: &Secured, tolerance_us: u64) {
        let generation_time = frame.generation_time();
        assert!(generation_time.abs_diff(self.clock.its_us()) <= tolerance_us);
        let (start, end) = validity_window_us(frame.tbs());
        assert!(start <= generation_time);
        assert!(end - start > generation_time - start);
    }
}

fn header_has(header: &HeaderInfo) -> Vec<&'static str> {
    let mut fields = vec!["psid"];
    let present = [
        ("generationTime", header.generation_time.is_some()),
        ("expiryTime", header.expiry_time.is_some()),
        ("generationLocation", header.generation_location.is_some()),
        (
            "p2pcdLearningRequest",
            header.p2pcd_learning_request.is_some(),
        ),
        (
            "missingCrlIdentifier",
            header.missing_crl_identifier.is_some(),
        ),
        ("encryptionKey", header.encryption_key.is_some()),
        ("inlineP2pcdRequest", header.inline_p2pcd_request.is_some()),
        (
            "requestedCertificate",
            header.requested_certificate.is_some(),
        ),
    ];
    fields.extend(present.iter().filter(|(_, p)| *p).map(|(f, _)| *f));
    fields
}

fn psid_of(header: &HeaderInfo) -> u64 {
    u64::try_from(&header.psid.0).unwrap()
}

fn app_psids(tbs: &ToBeSignedCertificate) -> Vec<u64> {
    tbs.app_permissions
        .as_ref()
        .map(|p| {
            p.0.iter()
                .map(|i| u64::try_from(&i.psid.0).unwrap())
                .collect()
        })
        .unwrap_or_default()
}

fn asn_digest(certificate: &AsnCertificate) -> [u8; 8] {
    digest_of(certificate, false)
}

// ─── Sending: all messages ──────────────────────────────────────────────────

/// TP_SEC_ITSS_SND_MSG_01_BV: a secured message has protocolVersion 3.
#[test]
fn tp_sec_itss_snd_msg_01_bv() {
    let mut w = World::new();
    let at = w.pki.at();
    let mut iut = w.iut_with(
        at,
        Options {
            beacon: true,
            ..Options::default()
        },
    );
    let frames = [
        iut.cam_sent(0),
        iut.denm_sent(100),
        iut.beacon().expect("a Beacon"),
    ];
    for frame in frames {
        assert_eq!(frame.protocol_version, 3);
        assert_eq!(frame.data.protocol_version.0, 3);
    }
}

// ─── Sending: CAM ───────────────────────────────────────────────────────────

/// TP_SEC_ITSS_SND_CAM_01_BV: the CAM is sent in a signedData container.
#[test]
fn tp_sec_itss_snd_cam_01_bv() {
    let frame = World::new().iut().cam_sent(0);
    assert!(matches!(
        frame.data.content,
        Ieee1609Dot2Content::signedData(_)
    ));
}

/// TP_SEC_ITSS_SND_CAM_02_BV: headerInfo psid is AID_CAM.
#[test]
fn tp_sec_itss_snd_cam_02_bv() {
    assert_eq!(psid_of(World::new().iut().cam_sent(0).header()), AID_CAM);
}

/// TP_SEC_ITSS_SND_CAM_03_BV: headerInfo contains generationTime and none of
/// expiryTime, generationLocation, encryptionKey, p2pcdLearningRequest,
/// missingCrlIdentifier (certificate and digest CAMs).
#[test]
fn tp_sec_itss_snd_cam_03_bv() {
    let mut iut = World::new().iut();
    for frame in [iut.cam_sent(0), iut.cam_sent(100)] {
        let fields = header_has(frame.header());
        assert!(fields.contains(&"generationTime"));
        for field in [
            "expiryTime",
            "generationLocation",
            "encryptionKey",
            "p2pcdLearningRequest",
            "missingCrlIdentifier",
        ] {
            assert!(!fields.contains(&field), "{field}");
        }
    }
}

/// TP_SEC_ITSS_SND_CAM_04_BV: signer is a digest or a certificate with id
/// 'none', appPermissions containing AID_CAM and no certIssuePermissions.
#[test]
fn tp_sec_itss_snd_cam_04_bv() {
    let mut w = World::new();
    let at = w.pki.at();
    let mut iut = w.iut_with(at.clone(), Options::default());
    let (with_certificate, with_digest) = (iut.cam_sent(0), iut.cam_sent(100));
    let tbs = with_certificate.tbs();
    assert!(matches!(tbs.id, CertificateId::none(())));
    assert!(app_psids(tbs).contains(&AID_CAM));
    assert!(tbs.cert_issue_permissions.is_none());
    assert_eq!(with_digest.digest(), Some(asn_digest(&at.cert.inner.0)));
}

/// TP_SEC_ITSS_SND_CAM_05_BV: the digest signer is the last 8 octets of
/// the X_HASH of the canonical X_CERTIFICATE (A, AN: NIST P-256 compressed and
/// uncompressed, SHA-256; B, BN: brainpoolP256r1, SHA-256; C, CN:
/// brainpoolP384r1, SHA-384); the certificate and its chain use X_KEY.
#[test]
fn tp_sec_itss_snd_cam_05_bv() {
    for variant in ["A", "AN", "B", "BN", "C", "CN"] {
        let (algorithm, compressed) = curve_of(variant);
        let mut w = World::with(Pki::on(algorithm));
        let at = w.pki.at_with(None, algorithm, compressed, at_tbs());
        let mut iut = w.iut_with(at, Options::default());
        let first = iut.cam_sent(0);
        assert!(key_matches(first.key(), algorithm), "{variant}");
        let expected = if compressed {
            "compressed"
        } else {
            "uncompressed"
        };
        assert_eq!(point_choice(first.key()), expected, "{variant}");
        let subsequent = iut.cam_sent(100);
        assert_eq!(
            subsequent.digest(),
            Some(digest_of(first.certificate(), is_384(algorithm))),
            "{variant}"
        );
    }
}

/// TP_SEC_ITSS_SND_CAM_06_BV: with CAMs every 100 ms, a CAM containing the
/// certificate is at least 1 s after the previous one (TIME >= TIME_LAST + 1 s).
#[test]
fn tp_sec_itss_snd_cam_06_bv() {
    let frames = World::new().iut().cams_every_100_ms(0, 3500);
    let times: Vec<u64> = frames
        .iter()
        .filter(|f| f.signed_with_certificate())
        .map(Secured::generation_time)
        .collect();
    assert!(times.len() >= 3);
    assert!(frames.iter().any(|f| f.digest().is_some()));
    for pair in times.windows(2) {
        assert!(pair[1] - pair[0] >= ONE_S_US);
    }
}

/// TP_SEC_ITSS_SND_CAM_07_BV: a CAM with generationTime >= TIME_LAST + 1 s
/// (TIME_LAST: the last CAM containing the certificate) contains the certificate.
#[test]
fn tp_sec_itss_snd_cam_07_bv() {
    let frames = World::new().iut().cams_every_100_ms(0, 3500);
    let mut last: Option<u64> = None;
    for frame in &frames {
        let time = frame.generation_time();
        if last.is_some_and(|l| time >= l + ONE_S_US) {
            assert!(frame.signed_with_certificate());
        }
        if frame.signed_with_certificate() {
            last = Some(time);
        }
    }
    let signers: Vec<bool> = frames[..11]
        .iter()
        .map(Secured::signed_with_certificate)
        .collect();
    let mut expected = vec![true];
    expected.extend([false; 9]);
    expected.push(true);
    assert_eq!(signers, expected);
}

/// The test system, with CERT_TS_F_AT unknown to the IUT, sends a CAM signed
/// with its digest at `at_ms`; returns the test system.
fn unknown_digest(w: &mut World, iut: &mut Station, at_ms: u64) -> Station {
    let mut tester = w.tester();
    tester.cam_sent(at_ms - 100); // certificate, not received
    let frame = tester.cam_sent(at_ms);
    assert_eq!(frame.digest(), Some(tester.ats[0].as_hashedid8()));
    iut.deliver(&frame.raw, at_ms);
    assert_eq!(iut.cams, 0); // unknown signer: discarded
    tester
}

/// TP_SEC_ITSS_SND_CAM_08_BV: after a CAM signed with the digest of an
/// unknown certificate (TIME_1 < TIME_2 < TIME_1 + 1 s), the next CAM contains
/// the certificate (TIME_3 < TIME_1 + 1 s).
#[test]
fn tp_sec_itss_snd_cam_08_bv() {
    let mut w = World::new();
    let mut iut = w.iut();
    assert!(iut.cam_sent(0).signed_with_certificate()); // TIME_1
    assert!(iut.cam_sent(100).digest().is_some());
    unknown_digest(&mut w, &mut iut, 200); // TIME_2
    assert!(iut.cam_sent(400).signed_with_certificate()); // TIME_3
}

/// TP_SEC_ITSS_SND_CAM_09_BV: the certificate sent because of an unknown
/// signer (TIME_3) restarts the timer: the next CAM with the certificate is
/// 1 s later.
#[test]
fn tp_sec_itss_snd_cam_09_bv() {
    let mut w = World::new();
    let mut iut = w.iut();
    iut.cam_sent(0); // TIME_1
    unknown_digest(&mut w, &mut iut, 300); // TIME_2
    assert!(iut.cam_sent(400).signed_with_certificate()); // TIME_3
    let signers: Vec<bool> = iut
        .cams_every_100_ms(500, 1400)
        .iter()
        .map(Secured::signed_with_certificate)
        .collect();
    let mut expected = vec![false; 9];
    expected.push(true); // TIME_4 = TIME_3 + 1 s
    assert_eq!(signers, expected);
}

/// TP_SEC_ITSS_SND_CAM_10_BV: after a message signed with the digest DIGEST_F
/// of an unknown certificate, the CAM contains inlineP2pcdRequest with the
/// last 3 octets of DIGEST_F.
#[test]
fn tp_sec_itss_snd_cam_10_bv() {
    let mut w = World::new();
    let mut iut = w.iut();
    iut.cam_sent(0);
    let tester = unknown_digest(&mut w, &mut iut, 200);
    let digest = tester.ats[0].as_hashedid8();
    assert_eq!(
        iut.cam_sent(300).inline_requests(),
        vec![[digest[5], digest[6], digest[7]]]
    );
}

/// TP_SEC_ITSS_SND_CAM_11_BV_XX: after a CAM signed with a certificate whose
/// issuer (X_FIELD_1: A sha256AndDigest, B sha384AndDigest) DIGEST_F is
/// unknown, the CAM contains inlineP2pcdRequest with the last 3 octets of
/// DIGEST_F.
#[test]
fn tp_sec_itss_snd_cam_11_bv_xx() {
    for (variant, algorithm) in [("A", KeyAlgorithm::NistP256), ("B", KeyAlgorithm::NistP384)] {
        let mut w = World::new();
        let mut iut = w.iut();
        let unknown_aa = w.pki.new_aa(algorithm, false, ca_tbs());
        let at = w
            .pki
            .at_with(Some(&unknown_aa), KeyAlgorithm::NistP256, true, at_tbs());
        let aas = vec![w.pki.aa.cert.clone(), unknown_aa.cert.clone()];
        let mut tester = w.tester_with(at, 9, Some(aas));
        iut.cam_sent(0);
        let frame = tester.cam_sent(100);
        let digest = match (&frame.certificate().0.issuer, variant) {
            (IssuerIdentifier::sha256AndDigest(h), "A")
            | (IssuerIdentifier::sha384AndDigest(h), "B") => h.0.as_ref().to_vec(),
            _ => panic!("{variant}: wrong issuer choice"),
        };
        assert_eq!(digest, unknown_aa.as_hashedid8().to_vec());
        iut.deliver(&frame.raw, 100);
        assert_eq!(iut.cams, 0);
        assert_eq!(
            iut.cam_sent(200).inline_requests(),
            vec![[digest[5], digest[6], digest[7]]],
            "{variant}"
        );
    }
}

/// A test system CAM with inlineP2pcdRequest [h3] (signed with its certificate).
fn p2pcd_request(w: &World, tester: &mut Station, h3: [u8; 3], at_ms: u64) -> Vec<u8> {
    let frame = tester.certificate_cam(at_ms);
    resign(
        &frame.raw,
        &tester.ats[0],
        &w.pki.backend,
        |sd| {
            sd.tbs_data.header_info.inline_p2pcd_request =
                Some(SequenceOfHashedId3(vec![HashedId3(
                    FixedOctetString::from(h3),
                )]))
        },
        true,
        None,
    )
}

/// TP_SEC_ITSS_SND_CAM_12_BV: after a request of the current AT (HashedId3 in
/// inlineP2pcdRequest, TIME_1 < TIME_2 < TIME_1 + 1 s), the next CAM contains
/// that certificate (TIME_3 < TIME_1 + 1 s).
#[test]
fn tp_sec_itss_snd_cam_12_bv() {
    let mut w = World::new();
    let at = w.pki.at();
    let mut iut = w.iut_with(at.clone(), Options::default());
    let mut tester = w.tester();
    iut.cam_sent(0); // TIME_1
    assert!(iut.cam_sent(100).digest().is_some());
    let request = p2pcd_request(&w, &mut tester, h3(&at.cert), 200);
    iut.deliver(&request, 200); // TIME_2
    assert_eq!(iut.cams, 1);
    let frame = iut.cam_sent(300); // TIME_3
    assert_eq!(asn_digest(frame.certificate()), at.as_hashedid8());
}

/// TP_SEC_ITSS_SND_CAM_13_BV: after a request of the AA that issued the
/// current AT, the CAM contains requestedCertificate with CERT_IUT_A_AA.
#[test]
fn tp_sec_itss_snd_cam_13_bv() {
    let mut w = World::new();
    let (mut iut, mut tester) = (w.iut(), w.tester());
    iut.cam_sent(0);
    let request = p2pcd_request(&w, &mut tester, h3(&w.pki.aa.cert), 200);
    iut.deliver(&request, 200);
    let frame = iut.cam_sent(300);
    assert!(frame.digest().is_some());
    let requested = frame
        .header()
        .requested_certificate
        .as_ref()
        .expect("requestedCertificate");
    assert_eq!(asn_digest(requested), w.pki.aa.as_hashedid8());
}

/// TP_SEC_ITSS_SND_CAM_14_BV: after a request of a known AA (CERT_IUT_A_N_AA)
/// that did not issue the current AT, the CAM contains requestedCertificate
/// with it.
#[test]
fn tp_sec_itss_snd_cam_14_bv() {
    let mut w = World::new();
    let aa_n = w.pki.new_aa(KeyAlgorithm::NistP256, true, ca_tbs());
    let (mut iut, mut tester) = (w.iut(), w.tester());
    iut.cam_sent(0);
    let request = p2pcd_request(&w, &mut tester, h3(&aa_n.cert), 200);
    iut.deliver(&request, 200);
    let frame = iut.cam_sent(300);
    let requested = frame
        .header()
        .requested_certificate
        .as_ref()
        .expect("requestedCertificate");
    assert_eq!(asn_digest(requested), aa_n.as_hashedid8());
}

/// TP_SEC_ITSS_SND_CAM_15_BV: a request of CERT_IUT_A_AA (TIME_2 < TIME_1 +
/// 0.8 s) already answered by another station (requestedCertificate, TIME_3 <
/// TIME_2 + 0.1 s) is not answered: no requestedCertificate (TIME_4 < TIME_1 +
/// 0.9 s).
#[test]
fn tp_sec_itss_snd_cam_15_bv() {
    let mut w = World::new();
    let (mut iut, mut tester) = (w.iut(), w.tester());
    let at = w.pki.at();
    let mut answering = w.tester_with(at, 10, None);
    iut.cam_sent(0); // TIME_1
    let known = answering.cam_sent(50);
    iut.deliver(&known.raw, 50); // its AT is now known
    let request = p2pcd_request(&w, &mut tester, h3(&w.pki.aa.cert), 200);
    iut.deliver(&request, 200); // TIME_2
    let aa = w.pki.aa.cert.inner.0.clone();
    let answer = resign(
        &answering.cam_sent(250).raw,
        &answering.ats[0],
        &w.pki.backend,
        |sd| sd.tbs_data.header_info.requested_certificate = Some(aa),
        true,
        None,
    );
    iut.deliver(&answer, 250); // TIME_3
    assert_eq!(iut.cams, 3);
    let frame = iut.cam_sent(300); // TIME_4
    assert!(frame.digest().is_some());
    assert!(frame.header().requested_certificate.is_none());
}

/// TP_SEC_ITSS_SND_CAM_16_BV: a request of CERT_IUT_A_AA at TIME_2 = TIME_1 +
/// 0.9 s: the CAM containing the certificate does not contain
/// requestedCertificate. The certificate is due one second after TIME_1, so
/// TIME_3 = TIME_1 + 1 s (the TP's TIME_3 < TIME_1 + 1 s leaves no CAM with
/// the certificate).
#[test]
fn tp_sec_itss_snd_cam_16_bv() {
    let mut w = World::new();
    let (mut iut, mut tester) = (w.iut(), w.tester());
    iut.cams_every_100_ms(0, 800); // TIME_1 = 0
    let request = p2pcd_request(&w, &mut tester, h3(&w.pki.aa.cert), 900);
    iut.deliver(&request, 900); // TIME_2
    let frame = iut.cam_sent(1000); // TIME_3
    assert!(frame.signed_with_certificate());
    assert!(frame.header().requested_certificate.is_none());
}

/// TP_SEC_ITSS_SND_CAM_17_BV: a request of CERT_IUT_A_AA at TIME_1 + 0.9 s <
/// TIME_2 < TIME_1 + 1 s is answered in the first subsequent CAM signed with
/// digest.
#[test]
fn tp_sec_itss_snd_cam_17_bv() {
    let mut w = World::new();
    let (mut iut, mut tester) = (w.iut(), w.tester());
    iut.cams_every_100_ms(0, 900); // TIME_1 = 0
    let request = p2pcd_request(&w, &mut tester, h3(&w.pki.aa.cert), 950);
    iut.deliver(&request, 950); // TIME_2
    assert!(iut.cam_sent(1000).header().requested_certificate.is_none()); // certificate
    let frame = iut.cam_sent(1100);
    assert!(frame.digest().is_some());
    let requested = frame
        .header()
        .requested_certificate
        .as_ref()
        .expect("requestedCertificate");
    assert_eq!(asn_digest(requested), w.pki.aa.as_hashedid8());
}

/// TP_SEC_ITSS_SND_CAM_18_BV: generationTime within CUR_TIME +- 5 min and
/// inside the validity period of the signer certificate.
#[test]
fn tp_sec_itss_snd_cam_18_bv() {
    let mut w = World::new();
    let frame = w.iut().cam_sent(0);
    w.assert_generation_time(&frame, 300 * ONE_S_US);
}

/// TP_SEC_ITSS_SND_CAM_19_BV: the signed payload is 'data' with an
/// unsecuredData EtsiTs103097Data containing the (non-empty) CAM packet.
#[test]
fn tp_sec_itss_snd_cam_19_bv() {
    let frame = World::new().iut().cam_sent(0);
    assert_eq!(frame.inner.protocol_version.0, 3);
    assert!(frame.plain().len() > 44 - 4);
    assert!(matches!(frame.common.ht, HeaderType::Tsb));
}

/// TP_SEC_ITSS_SND_CAM_20_BV: the signer certificate's appPermissions contain AID_CAM.
#[test]
fn tp_sec_itss_snd_cam_20_bv() {
    let frame = World::new().iut().cam_sent(0);
    assert!(app_permission(frame.tbs(), AID_CAM).0);
}

/// TP_SEC_ITSS_SND_CAM_21_BV_XX: the signature (A ecdsaNistP256Signature, B
/// ecdsaBrainpoolP256r1Signature, C ecdsaBrainpoolP384r1Signature) verifies
/// with the key of X_CERTIFICATE, for certificate and digest signers.
#[test]
fn tp_sec_itss_snd_cam_21_bv_xx() {
    for variant in ["A", "B", "C"] {
        let algorithm = curve_of(variant).0;
        let mut w = World::with(Pki::on(algorithm));
        let at = w.pki.at_with(None, algorithm, true, at_tbs());
        let mut iut = w.iut_with(at.clone(), Options::default());
        let key = match &at.tbs().verify_key_indicator {
            VerificationKeyIndicator::verificationKey(k) => k.clone(),
            _ => unreachable!(),
        };
        for frame in [iut.cam_sent(0), iut.cam_sent(100)] {
            let expected = if is_384(algorithm) {
                HashAlgorithm::sha384
            } else {
                HashAlgorithm::sha256
            };
            assert_eq!(frame.sd.hash_id, expected, "{variant}");
            assert!(
                signature_matches(&frame.sd.signature, algorithm),
                "{variant}"
            );
            assert!(
                verifies(&frame, &at.cert.inner.0, &key, &w.pki.backend),
                "{variant}"
            );
            if let Some(digest) = frame.digest() {
                assert_eq!(digest, at.as_hashedid8());
            }
        }
    }
}

/// TP_SEC_ITSS_SND_CAM_22_BV_XX: the signature's rSig is x-only,
/// compressed-y-0 or compressed-y-1 (A, B, C as CAM_21).
#[test]
fn tp_sec_itss_snd_cam_22_bv_xx() {
    for variant in ["A", "B", "C"] {
        let algorithm = curve_of(variant).0;
        let mut w = World::with(Pki::on(algorithm));
        let at = w.pki.at_with(None, algorithm, true, at_tbs());
        let frame = w.iut_with(at, Options::default()).cam_sent(0);
        assert!(
            signature_matches(&frame.sd.signature, algorithm),
            "{variant}"
        );
        assert!(
            ["x-only", "compressed-y-0", "compressed-y-1"].contains(&r_choice(&frame.sd.signature))
        );
    }
}

/// TP_SEC_ITSS_SND_CAM_23_BV (both definitions): (1) an AT with 8
/// appPermissions, AID_CAM the last, signs the CAM (psid AID_CAM); (2) the
/// only AT has a rectangular region not containing the IUT position: no CAM.
#[test]
fn tp_sec_itss_snd_cam_23_bv() {
    let mut w = World::new();
    let mut permissions: Vec<_> = (0..7).map(|i| (130 + i, None)).collect();
    permissions.push(app_permissions()[0].clone());
    let at = w.pki.at_tbs(with_app(at_tbs(), &permissions));
    let frame = w.iut_with(at, Options::default()).cam_sent(0);
    assert_eq!(psid_of(frame.header()), AID_CAM);
    assert_eq!(app_psids(frame.tbs()).len(), 8);
    let at = w.pki.at_tbs(with_region(at_tbs(), far_rectangle()));
    let mut iut = w.iut_with(at, Options::default());
    assert!(iut.cam(100).is_none());
    assert!(iut.log.is_empty());
}

/// TP_SEC_ITSS_SND_CAM_24_BV (both definitions): (1) an AT issued by an AA
/// with 8 certIssuePermissions, AID_CAM the last, signs the CAM; (2) the only
/// AT has no region and its AA a rectangular region not containing the IUT
/// position: no CAM.
#[test]
fn tp_sec_itss_snd_cam_24_bv() {
    let mut w = World::new();
    let group = |psid: u64| {
        PsidGroupPermissions::new(
            SubjectPermissions::explicit(SequenceOfPsidSspRange(vec![PsidSspRange::new(
                Psid(Integer::from(psid)),
                None,
            )])),
            Integer::from(0),
            Integer::from(0),
            {
                let mut bits = FixedBitString::<8>::default();
                bits.set(0, true);
                EndEntityType(bits)
            },
        )
    };
    let mut aa8_tbs = ca_tbs();
    aa8_tbs.cert_issue_permissions = Some(SequenceOfPsidGroupPermissions(
        (0..7)
            .map(|i| group(130 + i))
            .chain([group(AID_CAM)])
            .collect(),
    ));
    let aa8 = w.pki.new_aa(KeyAlgorithm::NistP256, true, aa8_tbs);
    let at = w.pki.at_with(
        Some(&aa8),
        KeyAlgorithm::NistP256,
        true,
        with_app(at_tbs(), &app_permissions()[..1]),
    );
    let frame = w.iut_with(at, Options::default()).cam_sent(0);
    assert_eq!(psid_of(frame.header()), AID_CAM);
    let mut c3_tbs = ca_tbs();
    c3_tbs.region = Some(far_rectangle());
    let aa_c3 = w.pki.new_aa(KeyAlgorithm::NistP256, true, c3_tbs);
    let at = w
        .pki
        .at_with(Some(&aa_c3), KeyAlgorithm::NistP256, true, at_tbs());
    let mut iut = w.iut_with(at, Options::default());
    assert!(iut.cam(100).is_none());
    assert!(iut.log.is_empty());
}

fn assert_no_cam(tbs: ToBeSignedCertificate) {
    let mut w = World::new();
    let at = w.pki.at_tbs(tbs);
    let mut iut = w.iut_with(at, Options::default());
    assert!(iut.cam(0).is_none());
    assert!(iut.log.is_empty());
}

fn expired() -> ToBeSignedCertificate {
    let mut tbs = at_tbs();
    tbs.validity_period = validity(-7200, AsnDuration::hours(Uint16(1)));
    tbs
}

fn future() -> ToBeSignedCertificate {
    let mut tbs = at_tbs();
    tbs.validity_period = validity(3600, AsnDuration::hours(Uint16(1)));
    tbs
}

/// TP_SEC_ITSS_SND_CAM_25_BV: the only AT is expired (start + duration < now): no CAM.
#[test]
fn tp_sec_itss_snd_cam_25_bv() {
    assert_no_cam(expired());
}

/// TP_SEC_ITSS_SND_CAM_26_BV: the only AT starts in the future: no CAM.
#[test]
fn tp_sec_itss_snd_cam_26_bv() {
    assert_no_cam(future());
}

/// TP_SEC_ITSS_SND_CAM_27_BV: the only AT has no appPermissions for AID_CAM: no CAM.
#[test]
fn tp_sec_itss_snd_cam_27_bv() {
    assert_no_cam(with_app(at_tbs(), &app_permissions()[1..]));
}

// ─── Sending: DENM ──────────────────────────────────────────────────────────

/// generationLocation is the IUT position and lies inside `region`.
fn assert_inside(frame: &Secured, region: GeographicRegion) {
    assert_eq!(frame.location(), INSIDE);
    let mut base = frame.certificate().0.clone();
    base.to_be_signed.region = Some(region);
    let restricted = Certificate::from_asn(EtsiTs103097Certificate(AsnCertificate(base)), None);
    let (lat, lon) = frame.location();
    assert!(location_permitted(&restricted, lat, lon));
}

/// TP_SEC_ITSS_SND_DENM_01_BV: the DENM is sent in a signedData container.
#[test]
fn tp_sec_itss_snd_denm_01_bv() {
    let frame = World::new().iut().denm_sent(0);
    assert!(matches!(
        frame.data.content,
        Ieee1609Dot2Content::signedData(_)
    ));
}

/// TP_SEC_ITSS_SND_DENM_02_BV: headerInfo psid is AID_DENM.
#[test]
fn tp_sec_itss_snd_denm_02_bv() {
    assert_eq!(psid_of(World::new().iut().denm_sent(0).header()), AID_DENM);
}

/// TP_SEC_ITSS_SND_DENM_03_BV: headerInfo contains generationTime and
/// generationLocation and none of expiryTime, encryptionKey,
/// p2pcdLearningRequest, missingCrlIdentifier, inlineP2pcdRequest,
/// requestedCertificate.
#[test]
fn tp_sec_itss_snd_denm_03_bv() {
    let mut w = World::new();
    let (mut iut, mut tester) = (w.iut(), w.tester());
    iut.cam_sent(0);
    tester.cam_sent(0); // certificate, not received
    let digest_cam = tester.cam_sent(100);
    iut.deliver(&digest_cam.raw, 100); // unknown digest: pending P2PCD request
    assert!(!iut.cam_sent(200).inline_requests().is_empty());
    let frame = iut.denm_sent(300);
    let fields = header_has(frame.header());
    assert!(fields.contains(&"generationTime"));
    assert!(fields.contains(&"generationLocation"));
    for field in [
        "expiryTime",
        "encryptionKey",
        "p2pcdLearningRequest",
        "missingCrlIdentifier",
        "inlineP2pcdRequest",
        "requestedCertificate",
    ] {
        assert!(!fields.contains(&field), "{field}");
    }
}

/// TP_SEC_ITSS_SND_DENM_04_BV: signer is a certificate whose appPermissions
/// contain AID_DENM (every DENM, also within 1 s).
#[test]
fn tp_sec_itss_snd_denm_04_bv() {
    let mut iut = World::new().iut();
    for frame in [iut.denm_sent(0), iut.denm_sent(100)] {
        assert!(app_psids(frame.tbs()).contains(&AID_DENM));
    }
}

/// TP_SEC_ITSS_SND_DENM_05_BV: generationTime within CUR_TIME +- 10 min and
/// inside the validity period of the signer certificate.
#[test]
fn tp_sec_itss_snd_denm_05_bv() {
    let mut w = World::new();
    let frame = w.iut().denm_sent(0);
    w.assert_generation_time(&frame, 600 * ONE_S_US);
}

/// TP_SEC_ITSS_SND_DENM_06_BV: AT, AA and RCA without region: the DENM
/// contains generationLocation.
#[test]
fn tp_sec_itss_snd_denm_06_bv() {
    let mut w = World::new();
    let frame = w.iut().denm_sent(0);
    assert!(frame.tbs().region.is_none());
    assert!(w.pki.aa.tbs().region.is_none());
    assert!(w.pki.root.tbs().region.is_none());
    assert_eq!(frame.location().0, INSIDE.0);
}

/// TP_SEC_ITSS_SND_DENM_07_BV_XX: AT with region (B circularRegion, C
/// rectangularRegion, D polygonalRegion, E identifiedRegion):
/// generationLocation inside the region.
#[test]
fn tp_sec_itss_snd_denm_07_bv_xx() {
    for (variant, region) in regions() {
        let mut w = World::new();
        let at = w.pki.at_tbs(with_region(at_tbs(), region.clone()));
        let frame = w.iut_with(at, Options::default()).denm_sent(0);
        assert_eq!(
            std::mem::discriminant(frame.tbs().region.as_ref().unwrap()),
            std::mem::discriminant(&region),
            "{variant}"
        );
        assert_inside(&frame, region);
    }
}

/// TP_SEC_ITSS_SND_DENM_09_BV: AT without region, AA and RCA with a circular
/// REGION: generationLocation inside REGION.
#[test]
fn tp_sec_itss_snd_denm_09_bv() {
    let regional = || {
        let mut tbs = ca_tbs();
        tbs.region = Some(circle());
        tbs
    };
    let mut w = World::with(Pki::chain(KeyAlgorithm::NistP256, regional(), regional()));
    let frame = w.iut().denm_sent(0);
    assert!(frame.tbs().region.is_none());
    assert_inside(&frame, circle());
}

/// TP_SEC_ITSS_SND_DENM_10_BV: AT and AA without region, RCA with a circular
/// REGION: generationLocation inside REGION.
#[test]
fn tp_sec_itss_snd_denm_10_bv() {
    let mut root = ca_tbs();
    root.region = Some(circle());
    let mut w = World::with(Pki::chain(KeyAlgorithm::NistP256, root, ca_tbs()));
    let frame = w.iut().denm_sent(0);
    assert!(w.pki.aa.tbs().region.is_none());
    assert_inside(&frame, circle());
}

/// TP_SEC_ITSS_SND_DENM_11_BV: the signed payload is 'data' with an
/// unsecuredData EtsiTs103097Data containing the (non-empty) DENM packet.
#[test]
fn tp_sec_itss_snd_denm_11_bv() {
    let frame = World::new().iut().denm_sent(0);
    assert!(frame.plain().len() > 56);
    assert!(matches!(frame.common.ht, HeaderType::GeoBroadcast));
}

/// TP_SEC_ITSS_SND_DENM_12_BV: the signer certificate's appPermissions contain AID_DENM.
#[test]
fn tp_sec_itss_snd_denm_12_bv() {
    assert!(app_permission(World::new().iut().denm_sent(0).tbs(), AID_DENM).0);
}

/// TP_SEC_ITSS_SND_DENM_13_BV: the signer certificate is X_CERTIFICATE with
/// X_KEY and the signature X_SIGNATURE verifies with it (A NIST P-256, B
/// brainpoolP256r1, C brainpoolP384r1).
#[test]
fn tp_sec_itss_snd_denm_13_bv() {
    for variant in ["A", "B", "C"] {
        let algorithm = curve_of(variant).0;
        let mut w = World::with(Pki::on(algorithm));
        let at = w.pki.at_with(None, algorithm, true, at_tbs());
        let frame = w.iut_with(at.clone(), Options::default()).denm_sent(0);
        assert!(key_matches(frame.key(), algorithm), "{variant}");
        assert_eq!(
            digest_of(frame.certificate(), is_384(algorithm)),
            at.as_hashedid8()
        );
        let expected = if is_384(algorithm) {
            HashAlgorithm::sha384
        } else {
            HashAlgorithm::sha256
        };
        assert_eq!(frame.sd.hash_id, expected, "{variant}");
        assert!(
            signature_matches(&frame.sd.signature, algorithm),
            "{variant}"
        );
        assert!(verifies(
            &frame,
            frame.certificate(),
            frame.key(),
            &w.pki.backend
        ));
    }
}

/// TP_SEC_ITSS_SND_DENM_14_BV: AT rectangularRegion with 8 entries, one
/// containing the IUT: generationLocation inside that entry.
#[test]
fn tp_sec_itss_snd_denm_14_bv() {
    let mut w = World::new();
    let at = w.pki.at_tbs(with_region(at_tbs(), rectangles_8()));
    let frame = w.iut_with(at, Options::default()).denm_sent(0);
    let Some(GeographicRegion::rectangularRegion(r)) = &frame.tbs().region else {
        panic!("rectangularRegion")
    };
    assert_eq!(r.0.len(), 8);
    let west = 5_340_000 + 5 * 3_000_000;
    assert_inside(
        &frame,
        rectangles(&[(416_000_000, west, 415_000_000, west + 2_000_000)]),
    );
}

/// TP_SEC_ITSS_SND_DENM_15_BV: AT polygonalRegion with 8 points containing
/// the IUT: generationLocation inside the polygon.
#[test]
fn tp_sec_itss_snd_denm_15_bv() {
    let mut w = World::new();
    let at = w.pki.at_tbs(with_region(at_tbs(), polygon_8()));
    let frame = w.iut_with(at, Options::default()).denm_sent(0);
    let Some(GeographicRegion::polygonalRegion(p)) = &frame.tbs().region else {
        panic!("polygonalRegion")
    };
    assert_eq!(p.0.len(), 8);
    assert_inside(&frame, polygon_8());
}

/// TP_SEC_ITSS_SND_DENM_16_BV: AT identifiedRegion with 8 entries, one
/// containing the IUT: generationLocation inside that entry.
#[test]
fn tp_sec_itss_snd_denm_16_bv() {
    let mut w = World::new();
    let at = w.pki.at_tbs(with_region(at_tbs(), identified(9600..9608)));
    let frame = w.iut_with(at, Options::default()).denm_sent(0);
    let Some(GeographicRegion::identifiedRegion(i)) = &frame.tbs().region else {
        panic!("identifiedRegion")
    };
    assert_eq!(i.0.len(), 8);
    assert_inside(&frame, identified(9605..9606));
}

fn assert_no_denm(w: &World, at: OwnCertificate) {
    let mut iut = w.iut_with(at, Options::default());
    assert!(iut.denm(0).is_none());
    assert!(iut.log.is_empty());
}

/// TP_SEC_ITSS_SND_DENM_17_BV: the AT region (rectangular) does not contain
/// the IUT position: no DENM.
#[test]
fn tp_sec_itss_snd_denm_17_bv() {
    let mut w = World::new();
    let at = w.pki.at_tbs(with_region(at_tbs(), far_rectangle()));
    assert_no_denm(&w, at);
}

/// TP_SEC_ITSS_SND_DENM_18_BV: AT without region, issued by an AA whose
/// rectangular region does not contain the IUT position: no DENM.
#[test]
fn tp_sec_itss_snd_denm_18_bv() {
    let mut w = World::new();
    let mut c3 = ca_tbs();
    c3.region = Some(far_rectangle());
    let aa_c3 = w.pki.new_aa(KeyAlgorithm::NistP256, true, c3);
    let at = w
        .pki
        .at_with(Some(&aa_c3), KeyAlgorithm::NistP256, true, at_tbs());
    assert_no_denm(&w, at);
}

/// TP_SEC_ITSS_SND_DENM_19_BV: the only AT is expired: no DENM.
#[test]
fn tp_sec_itss_snd_denm_19_bv() {
    let mut w = World::new();
    let at = w.pki.at_tbs(expired());
    assert_no_denm(&w, at);
}

/// TP_SEC_ITSS_SND_DENM_20_BV: the only AT starts in the future: no DENM.
#[test]
fn tp_sec_itss_snd_denm_20_bv() {
    let mut w = World::new();
    let at = w.pki.at_tbs(future());
    assert_no_denm(&w, at);
}

/// TP_SEC_ITSS_SND_DENM_21_BV: the only AT has no appPermissions for AID_DENM: no DENM.
#[test]
fn tp_sec_itss_snd_denm_21_bv() {
    let mut w = World::new();
    let permissions = app_permissions();
    let at = w.pki.at_tbs(with_app(
        at_tbs(),
        &[permissions[0].clone(), permissions[2].clone()],
    ));
    assert_no_denm(&w, at);
}

// ─── Sending: other messages (GeoNetworking Beacon) ─────────────────────────

fn beacon_station(w: &World, at: OwnCertificate) -> Station {
    w.iut_with(
        at,
        Options {
            beacon: true,
            ..Options::default()
        },
    )
}

fn beacon(w: &mut World) -> Secured {
    let at = w.pki.at();
    beacon_station(w, at).beacon().expect("a Beacon")
}

/// TP_SEC_ITSS_SND_GENMSG_01_BV: the Beacon is sent in a signedData container.
#[test]
fn tp_sec_itss_snd_genmsg_01_bv() {
    let frame = beacon(&mut World::new());
    assert!(matches!(
        frame.data.content,
        Ieee1609Dot2Content::signedData(_)
    ));
    assert!(matches!(frame.common.ht, HeaderType::Beacon));
}

/// TP_SEC_ITSS_SND_GENMSG_02_BV: headerInfo psid is AID_GNMGMT (not AID_CAM/AID_DENM).
#[test]
fn tp_sec_itss_snd_genmsg_02_bv() {
    assert_eq!(psid_of(beacon(&mut World::new()).header()), AID_GNMGMT);
}

/// TP_SEC_ITSS_SND_GENMSG_03_BV: headerInfo contains generationTime and no
/// p2pcdLearningRequest nor missingCrlIdentifier.
#[test]
fn tp_sec_itss_snd_genmsg_03_bv() {
    let fields = header_has(beacon(&mut World::new()).header()).clone();
    assert!(fields.contains(&"generationTime"));
    assert!(!fields.contains(&"p2pcdLearningRequest"));
    assert!(!fields.contains(&"missingCrlIdentifier"));
}

/// TP_SEC_ITSS_SND_GENMSG_04_BV: signer is a certificate whose appPermissions
/// contain AID_GNMGMT, or its digest.
#[test]
fn tp_sec_itss_snd_genmsg_04_bv() {
    let mut w = World::new();
    let at = w.pki.at();
    let mut iut = beacon_station(&w, at.clone());
    let (first, second) = (iut.beacon().unwrap(), iut.beacon().unwrap());
    assert!(app_psids(first.tbs()).contains(&AID_GNMGMT));
    match second.digest() {
        Some(digest) => assert_eq!(digest, at.as_hashedid8()),
        None => assert_eq!(asn_digest(second.certificate()), at.as_hashedid8()),
    }
}

/// TP_SEC_ITSS_SND_GENMSG_05_BV: generationTime within CUR_TIME +- 10 min and
/// inside the validity period of the signer certificate.
#[test]
fn tp_sec_itss_snd_genmsg_05_bv() {
    let mut w = World::new();
    let frame = beacon(&mut w);
    w.assert_generation_time(&frame, 600 * ONE_S_US);
}

/// TP_SEC_ITSS_SND_GENMSG_06_BV: the signed payload is 'data' with an
/// unsecuredData EtsiTs103097Data containing the (non-empty) Beacon packet.
#[test]
fn tp_sec_itss_snd_genmsg_06_bv() {
    assert_eq!(beacon(&mut World::new()).plain().len(), 8 + 24);
}

/// TP_SEC_ITSS_SND_GENMSG_07_BV: the signer certificate's appPermissions contain AID_GNMGMT.
#[test]
fn tp_sec_itss_snd_genmsg_07_bv() {
    let mut w = World::new();
    assert!(app_permission(beacon(&mut w).tbs(), AID_GNMGMT).0);
    let at = w.pki.at_tbs(with_app(at_tbs(), &app_permissions()[..2]));
    assert!(beacon_station(&w, at).beacon().is_none()); // no AT for AID_GNMGMT: no Beacon
}

/// TP_SEC_ITSS_SND_GENMSG_08_BV: the signature X_SIGNATURE verifies with the
/// key of X_CERTIFICATE (A NIST P-256, B brainpoolP256r1, C brainpoolP384r1).
#[test]
fn tp_sec_itss_snd_genmsg_08_bv() {
    for variant in ["A", "B", "C"] {
        let algorithm = curve_of(variant).0;
        let mut w = World::with(Pki::on(algorithm));
        let at = w.pki.at_with(None, algorithm, true, at_tbs());
        let frame = beacon_station(&w, at.clone()).beacon().unwrap();
        let expected = if is_384(algorithm) {
            HashAlgorithm::sha384
        } else {
            HashAlgorithm::sha256
        };
        assert_eq!(frame.sd.hash_id, expected, "{variant}");
        assert!(
            signature_matches(&frame.sd.signature, algorithm),
            "{variant}"
        );
        assert!(verifies(
            &frame,
            &at.cert.inner.0,
            frame.key(),
            &w.pki.backend
        ));
    }
}

// ─── Receiving ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Cam,
    Denm,
}

fn received(iut: &Station, kind: Kind) -> usize {
    match kind {
        Kind::Cam => iut.cams,
        Kind::Denm => iut.denms,
    }
}

fn assert_accepted(iut: &mut Station, raw: &[u8], kind: Kind) {
    let before = received(iut, kind);
    let now = iut.clock.ms();
    iut.deliver(raw, now);
    assert_eq!(
        received(iut, kind),
        before + 1,
        "the IUT accepts the message"
    );
}

/// `raw` is not passed to the facility; a valid message of the same test
/// system sent afterwards is.
fn assert_discarded(iut: &mut Station, tester: &mut Station, raw: &[u8], kind: Kind) {
    let before = received(iut, kind);
    let now = iut.clock.ms();
    iut.deliver(raw, now);
    assert_eq!(received(iut, kind), before, "the IUT discards the message");
    let later = now + 100;
    let valid = match kind {
        Kind::Cam => tester.certificate_cam(later),
        Kind::Denm => tester.denm_sent(later),
    };
    assert_accepted(iut, &valid.raw, kind);
}

/// The message of TP_SEC_ITSS_RCV_CAM_01_BV / RCV_DENM_01_BV.
fn assert_rcv_01_content(w: &World, frame: &Secured, at: &OwnCertificate, kind: Kind) {
    assert_eq!(frame.protocol_version, 3);
    let expected_hash = if at.cert.uses_sha384() {
        HashAlgorithm::sha384
    } else {
        HashAlgorithm::sha256
    };
    assert_eq!(frame.sd.hash_id, expected_hash);
    assert_eq!(frame.inner.protocol_version.0, 3);
    let mut expected = vec!["psid", "generationTime"];
    if kind == Kind::Denm {
        expected.push("generationLocation");
    }
    assert_eq!(header_has(frame.header()), expected);
    assert_eq!(
        psid_of(frame.header()),
        if kind == Kind::Cam { AID_CAM } else { AID_DENM }
    );
    assert!(frame.generation_time().abs_diff(w.clock.its_us()) <= 2 * ONE_S_US);
    assert_eq!(frame.certificate_count(), 1);
    assert_eq!(
        digest_of(frame.certificate(), at.cert.uses_sha384()),
        at.as_hashedid8()
    );
    assert_eq!(r_choice(&frame.sd.signature), "x-only");
}

/// TP_SEC_ITSS_RCV_MSG_01_BV: a message with protocolVersion 3 is forwarded to the facilities.
#[test]
fn tp_sec_itss_rcv_msg_01_bv() {
    let mut w = World::new();
    let (mut iut, mut tester) = (w.iut(), w.tester());
    let frame = tester.cam_sent(0);
    assert_eq!(frame.protocol_version, 3);
    assert_accepted(&mut iut, &frame.raw, Kind::Cam);
}

fn version_discarded(version: u8) {
    let mut w = World::new();
    let (mut iut, mut tester) = (w.iut(), w.tester());
    let frame = tester.cam_sent(0);
    let raw = resign(
        &frame.raw,
        &tester.ats[0],
        &w.pki.backend,
        no_mutation,
        true,
        Some(version),
    );
    assert_discarded(&mut iut, &mut tester, &raw, Kind::Cam);
}

/// TP_SEC_ITSS_RCV_MSG_01_BO: protocolVersion 2 is discarded.
#[test]
fn tp_sec_itss_rcv_msg_01_bo() {
    version_discarded(2);
}

/// TP_SEC_ITSS_RCV_MSG_02_BO: protocolVersion 4 is discarded.
#[test]
fn tp_sec_itss_rcv_msg_02_bo() {
    version_discarded(4);
}

/// `raw` with the NIST P-256 signature's rSig as the point R (compressed-y-0
/// or -1, IEEE 1609.2 clause 6.3.30), R = u1*G + u2*Q recomputed from the
/// signature.
fn with_compressed_r(raw: &[u8], at: &OwnCertificate) -> Vec<u8> {
    use p256::elliptic_curve::ops::Reduce;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::elliptic_curve::PrimeField;
    let mut data = decode_ieee1609_dot2_data(&raw[4..]);
    let Ieee1609Dot2Content::signedData(sd) = &mut data.content else {
        panic!("signedData")
    };
    let signer = match &sd.signer {
        SignerIdentifier::certificate(seq) => seq.0[0].clone(),
        _ => panic!("certificate signer"),
    };
    let Ieee1609Signature::ecdsaNistP256Signature(sig) = &mut sd.signature else {
        panic!("NIST P-256 signature")
    };
    let EccP256CurvePoint::x_only(r_bytes) = &sig.r_sig else {
        panic!("x-only")
    };
    let r_bytes: [u8; 32] = r_bytes.as_ref().try_into().unwrap();
    let s_bytes: [u8; 32] = sig.s_sig.as_ref().try_into().unwrap();
    let h = Sha256::digest(
        [
            Sha256::digest(encode_tbs_data(&sd.tbs_data)).to_vec(),
            Sha256::digest(canonical_bytes(&signer)).to_vec(),
        ]
        .concat(),
    );
    let e = <p256::Scalar as Reduce<p256::U256>>::reduce_bytes(&h);
    let r = Option::<p256::Scalar>::from(p256::Scalar::from_repr(r_bytes.into())).unwrap();
    let s = Option::<p256::Scalar>::from(p256::Scalar::from_repr(s_bytes.into())).unwrap();
    let w = Option::<p256::Scalar>::from(s.invert()).unwrap();
    let VerificationKeyIndicator::verificationKey(PublicVerificationKey::ecdsaNistP256(q)) =
        &at.tbs().verify_key_indicator
    else {
        panic!("NIST P-256 key")
    };
    let sec1 = match q {
        EccP256CurvePoint::compressed_y_0(x) => [&[0x02u8][..], x.as_ref()].concat(),
        EccP256CurvePoint::compressed_y_1(x) => [&[0x03u8][..], x.as_ref()].concat(),
        _ => panic!("compressed key"),
    };
    let q = p256::PublicKey::from_sec1_bytes(&sec1)
        .unwrap()
        .to_projective();
    let point = (p256::ProjectivePoint::GENERATOR * (e * w) + q * (r * w)).to_affine();
    let encoded = point.to_encoded_point(true);
    assert_eq!(&encoded.x().unwrap()[..], &r_bytes, "signature verifies");
    let x = encoded.x().unwrap().to_vec().into();
    sig.r_sig = if encoded.as_bytes()[0] == 0x02 {
        EccP256CurvePoint::compressed_y_0(x)
    } else {
        EccP256CurvePoint::compressed_y_1(x)
    };
    [raw[..4].to_vec(), encode_ieee1609_dot2_data(&data)].concat()
}

/// TP_SEC_ITSS_RCV_CAM_01_BV: a valid CAM signed with certificate CERT_TS_A_AT is accepted.
#[test]
fn tp_sec_itss_rcv_cam_01_bv() {
    let mut w = World::new();
    let (mut iut, mut tester) = (w.iut(), w.tester());
    let frame = tester.cam_sent(0);
    assert_rcv_01_content(&w, &frame, &tester.ats[0], Kind::Cam);
    assert!(signature_matches(
        &frame.sd.signature,
        KeyAlgorithm::NistP256
    ));
    assert_accepted(&mut iut, &frame.raw, Kind::Cam);
}

/// TP_SEC_ITSS_RCV_CAM_02_BV: once CERT_TS_A_AT is known, a CAM signed with
/// its digest is accepted.
#[test]
fn tp_sec_itss_rcv_cam_02_bv() {
    let mut w = World::new();
    let (mut iut, mut tester) = (w.iut(), w.tester());
    assert_accepted(&mut iut, &tester.cam_sent(0).raw, Kind::Cam);
    let frame = tester.cam_sent(100);
    assert_eq!(frame.digest(), Some(tester.ats[0].as_hashedid8()));
    assert_accepted(&mut iut, &frame.raw, Kind::Cam);
}

/// TP_SEC_ITSS_RCV_CAM_03_BV: a CAM whose ecdsaNistP256Signature rSig is
/// compressed-y-0 or compressed-y-1 is accepted.
#[test]
fn tp_sec_itss_rcv_cam_03_bv() {
    let mut w = World::new();
    let (mut iut, mut tester) = (w.iut(), w.tester());
    let raw = with_compressed_r(&tester.cam_sent(0).raw, &tester.ats[0]);
    assert!(["compressed-y-0", "compressed-y-1"]
        .contains(&r_choice(&Secured::decode(&raw).sd.signature)));
    assert_accepted(&mut iut, &raw, Kind::Cam);
}

/// TP_SEC_ITSS_RCV_CAM_04_BV_XX: a CAM signed with an AT with region (01
/// circularRegion, 02 rectangularRegion, 03 polygonalRegion, 04
/// identifiedRegion) containing the IUT position is accepted.
#[test]
fn tp_sec_itss_rcv_cam_04_bv_xx() {
    for (variant, region) in regions() {
        let mut w = World::new();
        let mut iut = w.iut();
        let at = w.pki.at_tbs(with_region(at_tbs(), region));
        let mut tester = w.tester_with(at, 9, None);
        let frame = tester.cam_sent(0);
        assert!(frame.tbs().region.is_some(), "{variant}");
        assert_eq!(r_choice(&frame.sd.signature), "x-only");
        assert_accepted(&mut iut, &frame.raw, Kind::Cam);
    }
}

/// A CAM or DENM signed with an AT on `algorithm` is accepted.
fn brainpool(algorithm: KeyAlgorithm, kind: Kind) {
    let mut w = World::new();
    let mut iut = w.iut();
    let at = w.pki.at_with(None, algorithm, true, at_tbs());
    let mut tester = w.tester_with(at, 9, None);
    let frame = match kind {
        Kind::Cam => tester.cam_sent(0),
        Kind::Denm => tester.denm_sent(0),
    };
    assert!(key_matches(frame.key(), algorithm));
    let expected = if is_384(algorithm) {
        HashAlgorithm::sha384
    } else {
        HashAlgorithm::sha256
    };
    assert_eq!(frame.sd.hash_id, expected);
    assert!(signature_matches(&frame.sd.signature, algorithm));
    assert_eq!(r_choice(&frame.sd.signature), "x-only");
    assert_accepted(&mut iut, &frame.raw, kind);
}

/// TP_SEC_ITSS_RCV_CAM_05_BV: a CAM signed with brainpoolP256r1 (CERT_TS_A_B_AT) is accepted.
#[test]
fn tp_sec_itss_rcv_cam_05_bv() {
    brainpool(KeyAlgorithm::BrainpoolP256r1, Kind::Cam);
}

/// TP_SEC_ITSS_RCV_CAM_06_BV: a CAM signed with brainpoolP384r1 (CERT_TS_A_B3_AT) is accepted.
#[test]
fn tp_sec_itss_rcv_cam_06_bv() {
    brainpool(KeyAlgorithm::BrainpoolP384r1, Kind::Cam);
}

fn discarded(kind: Kind, mutate: impl FnOnce(&mut SignedData), sign: bool, digest: bool) {
    let mut w = World::new();
    let (mut iut, mut tester) = (w.iut(), w.tester());
    let frame = match kind {
        Kind::Cam if digest => {
            // the message of RCV_CAM_02_BV
            assert_accepted(&mut iut, &tester.cam_sent(0).raw, Kind::Cam);
            tester.cam_sent(100)
        }
        Kind::Cam => tester.cam_sent(0),
        Kind::Denm => tester.denm_sent(0),
    };
    let raw = resign(
        &frame.raw,
        &tester.ats[0],
        &w.pki.backend,
        mutate,
        sign,
        None,
    );
    assert_discarded(&mut iut, &mut tester, &raw, kind);
}

fn set_psid(psid: u64) -> impl FnOnce(&mut SignedData) {
    move |sd: &mut SignedData| sd.tbs_data.header_info.psid = Psid(Integer::from(psid))
}

fn expiry() -> impl FnOnce(&mut SignedData) {
    let at = Clock::new().its_us() + 60 * ONE_S_US;
    move |sd: &mut SignedData| sd.tbs_data.header_info.expiry_time = Some(Time64(Uint64(at)))
}

fn learning_request(sd: &mut SignedData) {
    sd.tbs_data.header_info.p2pcd_learning_request =
        Some(HashedId3(FixedOctetString::from([1, 2, 3])));
}

fn missing_crl(sd: &mut SignedData) {
    sd.tbs_data.header_info.missing_crl_identifier = Some(MissingCrlIdentifier::new(
        HashedId3(FixedOctetString::from([0u8; 3])),
        CrlSeries(Uint16(0)),
    ));
}

fn encryption_key(sd: &mut SignedData) {
    sd.tbs_data.header_info.encryption_key = Some(EncryptionKey::symmetric(
        SymmetricEncryptionKey::aes128Ccm(vec![0u8; 16].into()),
    ));
}

fn invalid_signature_algorithm(sd: &mut SignedData) {
    sd.signature = Ieee1609Signature::ecdsaNistP384Signature(EcdsaP384Signature {
        r_sig: EccP384CurvePoint::x_only(vec![0x11; 48].into()),
        s_sig: vec![0x22; 48].into(),
    });
}

fn self_signer(sd: &mut SignedData) {
    sd.signer = SignerIdentifier::R_self(());
}

fn altered_signature(sd: &mut SignedData) {
    if let Ieee1609Signature::ecdsaNistP256Signature(s) = &mut sd.signature {
        let mut bytes = s.s_sig.to_vec();
        bytes[31] ^= 0x01;
        s.s_sig = bytes.into();
    }
}

/// TP_SEC_ITSS_RCV_CAM_01_BO: a CAM (digest signer) whose psid is not AID_CAM is discarded.
#[test]
fn tp_sec_itss_rcv_cam_01_bo() {
    discarded(Kind::Cam, set_psid(AID_DENM), true, true);
}

/// TP_SEC_ITSS_RCV_CAM_02_BO: a CAM with generationLocation is discarded.
#[test]
fn tp_sec_itss_rcv_cam_02_bo() {
    let location = |sd: &mut SignedData| {
        sd.tbs_data.header_info.generation_location = Some(ThreeDLocation::new(
            Latitude(NinetyDegreeInt(INSIDE.0)),
            Longitude(OneEightyDegreeInt(INSIDE.1)),
            Elevation(Uint16(0xF000)),
        ))
    };
    discarded(Kind::Cam, location, true, false);
}

/// TP_SEC_ITSS_RCV_CAM_03_BO: a CAM with expiryTime is discarded.
#[test]
fn tp_sec_itss_rcv_cam_03_bo() {
    discarded(Kind::Cam, expiry(), true, false);
}

/// TP_SEC_ITSS_RCV_CAM_04_BO: a CAM with p2pcdLearningRequest is discarded.
#[test]
fn tp_sec_itss_rcv_cam_04_bo() {
    discarded(Kind::Cam, learning_request, true, false);
}

/// TP_SEC_ITSS_RCV_CAM_05_BO: a CAM with missingCrlIdentifier is discarded.
#[test]
fn tp_sec_itss_rcv_cam_05_bo() {
    discarded(Kind::Cam, missing_crl, true, false);
}

/// TP_SEC_ITSS_RCV_CAM_06_BO: a CAM with encryptionKey is discarded.
#[test]
fn tp_sec_itss_rcv_cam_06_bo() {
    discarded(Kind::Cam, encryption_key, true, false);
}

/// TP_SEC_ITSS_RCV_CAM_07_BO: a CAM whose signature algorithm does not match
/// the signer key (ecdsaNistP384Signature for a NIST P-256 key) is discarded.
#[test]
fn tp_sec_itss_rcv_cam_07_bo() {
    discarded(Kind::Cam, invalid_signature_algorithm, false, false);
}

/// TP_SEC_ITSS_RCV_CAM_08_BO: a CAM whose SignerIdentifier is 'self' is discarded.
#[test]
fn tp_sec_itss_rcv_cam_08_bo() {
    discarded(Kind::Cam, self_signer, true, false);
}

/// TP_SEC_ITSS_RCV_CAM_09_BO: a CAM with an altered signature value is discarded.
#[test]
fn tp_sec_itss_rcv_cam_09_bo() {
    discarded(Kind::Cam, altered_signature, false, false);
}

/// TP_SEC_ITSS_RCV_DENM_01_BV: a valid DENM signed with certificate CERT_TS_A_AT is accepted.
#[test]
fn tp_sec_itss_rcv_denm_01_bv() {
    let mut w = World::new();
    let (mut iut, mut tester) = (w.iut(), w.tester());
    let frame = tester.denm_sent(0);
    assert_rcv_01_content(&w, &frame, &tester.ats[0], Kind::Denm);
    assert!(signature_matches(
        &frame.sd.signature,
        KeyAlgorithm::NistP256
    ));
    assert_accepted(&mut iut, &frame.raw, Kind::Denm);
}

/// TP_SEC_ITSS_RCV_DENM_02_BV_XX: a DENM signed with an AT with region (01..04
/// as RCV_CAM_04) and generationLocation inside it is accepted.
#[test]
fn tp_sec_itss_rcv_denm_02_bv_xx() {
    for (variant, region) in regions() {
        let mut w = World::new();
        let mut iut = w.iut();
        let at = w.pki.at_tbs(with_region(at_tbs(), region));
        let mut tester = w.tester_with(at, 9, None);
        let frame = tester.denm_sent(0);
        assert!(frame.tbs().region.is_some(), "{variant}");
        assert_eq!(frame.location(), INSIDE);
        assert_accepted(&mut iut, &frame.raw, Kind::Denm);
    }
}

/// TP_SEC_ITSS_RCV_DENM_03_BV: a DENM signed with brainpoolP256r1 is accepted.
#[test]
fn tp_sec_itss_rcv_denm_03_bv() {
    brainpool(KeyAlgorithm::BrainpoolP256r1, Kind::Denm);
}

/// TP_SEC_ITSS_RCV_DENM_04_BV: a DENM signed with brainpoolP384r1 is accepted.
#[test]
fn tp_sec_itss_rcv_denm_04_bv() {
    brainpool(KeyAlgorithm::BrainpoolP384r1, Kind::Denm);
}

/// TP_SEC_ITSS_RCV_DENM_01_BO: a DENM whose psid is not AID_DENM is discarded.
#[test]
fn tp_sec_itss_rcv_denm_01_bo() {
    discarded(Kind::Denm, set_psid(AID_CAM), true, false);
}

/// TP_SEC_ITSS_RCV_DENM_02_BO: a DENM without generationLocation is discarded.
#[test]
fn tp_sec_itss_rcv_denm_02_bo() {
    let drop = |sd: &mut SignedData| sd.tbs_data.header_info.generation_location = None;
    discarded(Kind::Denm, drop, true, false);
}

/// TP_SEC_ITSS_RCV_DENM_03_BO: a DENM with expiryTime is discarded.
#[test]
fn tp_sec_itss_rcv_denm_03_bo() {
    discarded(Kind::Denm, expiry(), true, false);
}

/// TP_SEC_ITSS_RCV_DENM_04_BO: a DENM with p2pcdLearningRequest is discarded.
#[test]
fn tp_sec_itss_rcv_denm_04_bo() {
    discarded(Kind::Denm, learning_request, true, false);
}

/// TP_SEC_ITSS_RCV_DENM_05_BO: a DENM with missingCrlIdentifier is discarded.
#[test]
fn tp_sec_itss_rcv_denm_05_bo() {
    discarded(Kind::Denm, missing_crl, true, false);
}

/// TP_SEC_ITSS_RCV_DENM_06_BO: a DENM with encryptionKey is discarded.
#[test]
fn tp_sec_itss_rcv_denm_06_bo() {
    discarded(Kind::Denm, encryption_key, true, false);
}

/// TP_SEC_ITSS_RCV_DENM_07_BO: a DENM with an invalid signature algorithm is discarded.
#[test]
fn tp_sec_itss_rcv_denm_07_bo() {
    discarded(Kind::Denm, invalid_signature_algorithm, false, false);
}

/// TP_SEC_ITSS_RCV_DENM_08_BO: a DENM whose SignerIdentifier is 'self' is discarded.
#[test]
fn tp_sec_itss_rcv_denm_08_bo() {
    discarded(Kind::Denm, self_signer, true, false);
}

/// TP_SEC_ITSS_RCV_DENM_09_BO: a DENM with an altered signature value is discarded.
#[test]
fn tp_sec_itss_rcv_denm_09_bo() {
    discarded(Kind::Denm, altered_signature, false, false);
}

// ─── Implicit certificates ──────────────────────────────────────────────────

/// TP_SEC_ITSS_SND_IMPLICIT_CERT_01_BV: authorized with an implicit AT, the
/// IUT signs the CAM with it (signer certificate, ecdsaNistP256Signature
/// verifying with the key reconstructed from the reconstruction value).
#[test]
fn tp_sec_itss_snd_implicit_cert_01_bv() {
    let mut w = World::new();
    let implicit = w.pki.implicit_at();
    let frame = w.iut_with(implicit.clone(), Options::default()).cam_sent(0);
    let certificate = frame.certificate();
    assert!(matches!(
        certificate.0.to_be_signed.verify_key_indicator,
        VerificationKeyIndicator::reconstructionValue(_)
    ));
    assert!(certificate.0.signature.is_none());
    assert_eq!(asn_digest(certificate), implicit.as_hashedid8());
    assert!(signature_matches(
        &frame.sd.signature,
        KeyAlgorithm::NistP256
    ));
    let key = Certificate::from_asn(
        EtsiTs103097Certificate(certificate.clone()),
        Some(w.pki.aa.cert.clone()),
    )
    .verification_key()
    .expect("reconstructed key");
    assert!(verifies(&frame, certificate, &key, &w.pki.backend));
}

/// TP_SEC_ITSS_RCV_IMPLICIT_CERT_01_BV: a CAM signed with a known implicit AT
/// (CERT_TS_A_IMP_AT) is accepted.
#[test]
fn tp_sec_itss_rcv_implicit_cert_01_bv() {
    let mut w = World::new();
    let implicit = w.pki.implicit_at();
    let at = w.pki.at();
    let mut iut = w.iut_with(
        at,
        Options {
            known_ats: vec![implicit.cert.clone()],
            ..Options::default()
        },
    );
    let mut tester = w.tester_with(implicit, 9, None);
    let frame = tester.cam_sent(0);
    assert_eq!(frame.sd.hash_id, HashAlgorithm::sha256);
    assert!(frame.certificate().0.signature.is_none());
    assert_eq!(r_choice(&frame.sd.signature), "x-only");
    assert_accepted(&mut iut, &frame.raw, Kind::Cam);
}

/// TP_SEC_ITSS_RCV_IMPLICIT_CERT_02_BV: a CAM signed with an unknown implicit
/// AT (CERT_TS_F_AT_IMP) is accepted.
#[test]
fn tp_sec_itss_rcv_implicit_cert_02_bv() {
    let mut w = World::new();
    let mut iut = w.iut();
    let implicit = w.pki.implicit_at();
    let mut tester = w.tester_with(implicit, 9, None);
    let frame = tester.cam_sent(0);
    assert!(matches!(
        frame.tbs().verify_key_indicator,
        VerificationKeyIndicator::reconstructionValue(_)
    ));
    assert_accepted(&mut iut, &frame.raw, Kind::Cam);
}

/// TP_SEC_ITSS_RCV_IMPLICIT_CERT_01_BO: a CAM signed with an implicit AT that
/// contains a signature (CERT_TS_A_IMP_AT_BO) is discarded.
#[test]
fn tp_sec_itss_rcv_implicit_cert_01_bo() {
    let mut w = World::new();
    let mut iut = w.iut();
    let implicit = w.pki.implicit_at();
    let mut tester = w.tester_with(implicit.clone(), 9, None);
    let frame = tester.cam_sent(0);
    let backend = w.pki.backend.clone();
    let raw = resign(
        &frame.raw,
        &implicit,
        &backend,
        |sd| {
            let SignerIdentifier::certificate(seq) = &mut sd.signer else {
                panic!("certificate signer")
            };
            seq.0[0].0.signature = Some(Ieee1609Signature::ecdsaNistP256Signature(
                crate::security::ieee1609_dot2_base_types::EcdsaP256Signature {
                    r_sig: EccP256CurvePoint::x_only(vec![0x11; 32].into()),
                    s_sig: vec![0x22; 32].into(),
                },
            ));
            let input = [
                Sha256::digest(encode_tbs_data(&sd.tbs_data)).to_vec(),
                Sha256::digest(canonical_bytes(&seq.0[0])).to_vec(),
            ]
            .concat();
            sd.signature = backend.sign(&input, implicit.key_id);
        },
        false,
        None,
    );
    assert!(Secured::decode(&raw).certificate().0.signature.is_some());
    assert_discarded(&mut iut, &mut tester, &raw, Kind::Cam);
}

// ── Location service with itsGnSecurity ENABLED (no TS 103 096-2 TP) ─────────

/// A GUC request to `destination` with ITS-AID `its_aid`.
fn guc_request(destination: GNAddress, its_aid: u64) -> GNDataRequest {
    use crate::geonet::service_access_point::{
        Area, CommunicationProfile, HeaderSubType, PacketTransportType, TrafficClass,
        UnspecifiedHST,
    };
    GNDataRequest {
        upper_protocol_entity: CommonNH::BtpB,
        packet_transport_type: PacketTransportType {
            header_type: HeaderType::GeoUnicast,
            header_sub_type: HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
        },
        communication_profile: CommunicationProfile::Unspecified,
        traffic_class: TrafficClass {
            scf: false,
            channel_offload: false,
            tc_id: 0,
        },
        security_profile: crate::security::sn_sap::SecurityProfile::NoSecurity,
        its_aid,
        security_permissions: vec![],
        max_hop_limit: 0,
        max_packet_lifetime: None,
        destination: Some(destination),
        length: 7,
        data: b"\x07\xd1\x00\x00guc".to_vec(),
        area: Area {
            latitude: 0,
            longitude: 0,
            a: 0,
            b: 0,
            angle: 0,
        },
    }
}

fn header_psid(frame: &Secured) -> u64 {
    u64::try_from(&frame.sd.tbs_data.header_info.psid.0).unwrap()
}

/// ETSI TS 103 836-4-1 V2.2.1 clauses 10.3.7.1.2 and 10.3.7.3: LS Request and LS
/// Reply are signed with ITS-AID 141, SSP absent (tables 24 and 26); the IUT
/// verifies the reply and sends the buffered GUC.
#[test]
fn ls_request_and_reply_signed_with_gn_mgmt() {
    use crate::geonet::service_access_point::{HeaderSubType, LocationServiceHST};
    let mut w = World::new();
    let at = w.pki.at();
    let mut iut = w.iut_with(
        at,
        Options {
            beacon: true,
            ..Options::default()
        },
    );
    let mut tester = w.tester();
    let beacon = iut.beacon().expect("secured Beacon");
    let t = w.clock.ms();
    tester.deliver(&beacon.raw, t); // the tester knows the IUT, not vice versa
    let tester_addr = tester.gn.mib.itsGnLocalGnAddr;
    iut.gn.gn_data_request(guc_request(tester_addr, AID_GNMGMT));
    let request = iut.drain().expect("LS Request"); // the GUC waits for the LS
    assert_eq!(request.common.ht, HeaderType::Ls);
    assert_eq!(
        request.common.hst,
        HeaderSubType::LocationService(LocationServiceHST::LsRequest)
    );
    assert_eq!(header_psid(&request), AID_GNMGMT);
    let before = tester.log.len();
    tester.deliver(&request.raw, t);
    assert_eq!(tester.log.len(), before + 1);
    let reply = Secured::decode(&tester.log.last().unwrap().1);
    assert_eq!(
        reply.common.hst,
        HeaderSubType::LocationService(LocationServiceHST::LsReply)
    );
    assert_eq!(header_psid(&reply), AID_GNMGMT);
    let before = iut.log.len();
    iut.deliver(&reply.raw, t); // verified: the LS completes
    assert_eq!(iut.log.len(), before + 1);
    let guc = Secured::decode(&iut.log.last().unwrap().1);
    assert_eq!(guc.common.ht, HeaderType::GeoUnicast);
}

/// No AT may sign ITS-AID 141: the LS Request is not sent (as a Beacon).
#[test]
fn ls_not_sent_without_gn_mgmt_permission() {
    let mut w = World::new();
    let mut tbs = at_tbs();
    tbs.app_permissions = Some(psid_ssps(&app_permissions()[..1]));
    let at = w.pki.at_tbs(tbs);
    let mut iut = w.iut_with(at, Options::default());
    let tester = w.tester();
    let before = iut.log.len();
    iut.gn
        .gn_data_request(guc_request(tester.gn.mib.itsGnLocalGnAddr, AID_CAM));
    assert!(iut.drain().is_none());
    assert_eq!(iut.log.len(), before);
}

// ── DAD with itsGnSecurity ENABLED (no TS 103 096-2 TP) ──────────────────────

/// A CAM of the tester received with our link-layer address as sender (its
/// signature tampered with when `tamper`); our MID before and after.
fn frame_from_us(tamper: bool) -> (MID, MID) {
    let mut w = World::new();
    let mut iut = w.iut();
    let mut tester = w.tester();
    let mut raw = tester.certificate_cam(0).raw;
    if tamper {
        *raw.last_mut().unwrap() ^= 1; // last octet of the signature
    }
    let own = iut.gn.mib.itsGnLocalGnAddr.mid;
    iut.gn.process_incoming(&raw, Some(own.as_bytes()));
    (own, iut.gn.mib.itsGnLocalGnAddr.mid)
}

/// ETSI TS 103 836-4-1 V2.2.1 clause 10.2.1.5 step 1b with itsGnSecurity ENABLED:
/// a verified frame sent with our link-layer address makes the IUT take a new MID.
#[test]
fn verified_frame_with_our_mac_is_a_conflict() {
    let (before, after) = frame_from_us(false);
    assert_ne!(before.as_bytes(), after.as_bytes());
}

/// A frame that does not verify cannot change our address, even with our
/// link-layer address as sender.
#[test]
fn forged_frame_with_our_mac_is_ignored() {
    let (before, after) = frame_from_us(true);
    assert_eq!(before.as_bytes(), after.as_bytes());
}
