// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Generate a certificate chain: Root CA → AA → AT1 + AT2.
//!
//! The generated certificates and private keys are written to the `certs/`
//! directory, which is created if it does not exist.
//!
//! # Running
//! ```text
//! cargo run --example generate_certificate_chain --target x86_64-unknown-linux-gnu
//! ```

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::prelude::*;

use rustflexstack::security::certificate::{encode_certificate, OwnCertificate};
use rustflexstack::security::ecdsa_backend::EcdsaBackend;
use rustflexstack::security::security_asn::ieee1609_dot2::{
    CertificateId, EndEntityType, PsidGroupPermissions, SequenceOfAppExtensions,
    SequenceOfCertIssueExtensions, SequenceOfCertRequestExtensions,
    SequenceOfPsidGroupPermissions, SubjectPermissions, ToBeSignedCertificate,
    VerificationKeyIndicator,
};
use rustflexstack::security::security_asn::ieee1609_dot2_base_types::{
    CrlSeries, Duration, HashedId3, Hostname, Psid, PsidSsp, PsidSspRange,
    SequenceOfPsidSsp, SequenceOfPsidSspRange, Time32, Uint16, Uint32, ValidityPeriod,
};

// ITS-AID values
const ITS_AID_CAM: u64 = 36;
const ITS_AID_DENM: u64 = 37;
const ITS_AID_VAM: u64 = 638;

/// ITS epoch: 2004-01-01 00:00:00 UTC as a UNIX timestamp.
const ITS_EPOCH_UNIX: u64 = 1_072_915_200;

/// Current time as seconds since ITS epoch.
fn its_time32_now() -> Time32 {
    let unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let its_secs = unix_secs.saturating_sub(ITS_EPOCH_UNIX) as u32;
    Time32(Uint32(its_secs))
}

/// Default EndEntityType: app only (bit 0 = true, bit 1 = false).
fn default_ee_type() -> EndEntityType {
    let mut bits = FixedBitString::<8>::default();
    bits.set(0, true);
    EndEntityType(bits)
}

/// Helper: create a `SequenceOfPsidSsp` with the given PSIDs (no SSP).
fn app_permissions(psids: &[u64]) -> SequenceOfPsidSsp {
    let items: Vec<PsidSsp> = psids
        .iter()
        .map(|&p| PsidSsp::new(Psid(Integer::from(p as i128)), None))
        .collect();
    SequenceOfPsidSsp(items.into())
}

/// Helper: build a `SequenceOfPsidGroupPermissions` with
/// `SubjectPermissions::explicit` for the given PSIDs.
fn cert_issue_permissions_explicit(
    psids: &[u64],
    min_chain_length: i128,
) -> SequenceOfPsidGroupPermissions {
    let ranges: Vec<PsidSspRange> = psids
        .iter()
        .map(|&p| PsidSspRange::new(Psid(Integer::from(p as i128)), None))
        .collect();
    let perm = PsidGroupPermissions::new(
        SubjectPermissions::explicit(SequenceOfPsidSspRange(ranges.into())),
        Integer::from(min_chain_length),
        Integer::from(0i128),
        default_ee_type(),
    );
    SequenceOfPsidGroupPermissions(vec![perm].into())
}

/// Helper: build a `SequenceOfPsidGroupPermissions` with
/// `SubjectPermissions::all`.
fn cert_issue_permissions_all(min_chain_length: i128) -> SequenceOfPsidGroupPermissions {
    let perm = PsidGroupPermissions::new(
        SubjectPermissions::all(()),
        Integer::from(min_chain_length),
        Integer::from(0i128),
        default_ee_type(),
    );
    SequenceOfPsidGroupPermissions(vec![perm].into())
}

fn main() {
    let cert_dir = Path::new("certs");
    fs::create_dir_all(cert_dir).expect("failed to create certs/ directory");

    let mut backend = EcdsaBackend::new();

    // ─── Root CA ─────────────────────────────────────────────────────────
    let root_tbs = ToBeSignedCertificate::new(
        CertificateId::name(Hostname("RootCA".to_string().into())),
        HashedId3(FixedOctetString::from([0u8; 3])),
        CrlSeries(Uint16(0)),
        ValidityPeriod::new(its_time32_now(), Duration::years(Uint16(20))),
        None,                                               // region
        None,                                               // assuranceLevel
        Some(app_permissions(&[ITS_AID_CAM, ITS_AID_DENM, ITS_AID_VAM])), // appPermissions
        Some(cert_issue_permissions_all(2)),                 // certIssuePermissions
        None,                                               // certRequestPermissions
        None,                                               // canRequestRollover
        None,                                               // encryptionKey
        // placeholder — overwritten by initialize_self_signed
        VerificationKeyIndicator::verificationKey(
            rustflexstack::security::security_asn::ieee1609_dot2_base_types
                ::PublicVerificationKey::ecdsaNistP256(
                    rustflexstack::security::security_asn::ieee1609_dot2_base_types
                        ::EccP256CurvePoint::x_only(vec![0u8; 32].into()),
                ),
        ),
        None,
        SequenceOfAppExtensions(Default::default()),
        SequenceOfCertIssueExtensions(Default::default()),
        SequenceOfCertRequestExtensions(Default::default()),
    );
    let root_ca = OwnCertificate::initialize_self_signed(&mut backend, root_tbs);
    println!(
        "Root CA  HashedId8: {:02x?}",
        root_ca.as_hashedid8()
    );

    // ─── Authorization Authority ─────────────────────────────────────────
    let aa_tbs = ToBeSignedCertificate::new(
        CertificateId::name(Hostname("AA".to_string().into())),
        HashedId3(FixedOctetString::from([0u8; 3])),
        CrlSeries(Uint16(0)),
        ValidityPeriod::new(its_time32_now(), Duration::years(Uint16(10))),
        None,
        None,
        Some(app_permissions(&[ITS_AID_CAM, ITS_AID_DENM, ITS_AID_VAM])),
        Some(cert_issue_permissions_explicit(
            &[ITS_AID_CAM, ITS_AID_DENM, ITS_AID_VAM],
            1,
        )),
        None,
        None,
        None,
        VerificationKeyIndicator::verificationKey(
            rustflexstack::security::security_asn::ieee1609_dot2_base_types
                ::PublicVerificationKey::ecdsaNistP256(
                    rustflexstack::security::security_asn::ieee1609_dot2_base_types
                        ::EccP256CurvePoint::x_only(vec![0u8; 32].into()),
                ),
        ),
        None,
        SequenceOfAppExtensions(Default::default()),
        SequenceOfCertIssueExtensions(Default::default()),
        SequenceOfCertRequestExtensions(Default::default()),
    );
    let aa = OwnCertificate::initialize_issued(&mut backend, aa_tbs, &root_ca);
    println!(
        "AA       HashedId8: {:02x?}",
        aa.as_hashedid8()
    );

    // ─── Authorization Tickets ───────────────────────────────────────────
    let at_names = ["AT1", "AT2"];
    let mut at_certs = Vec::new();
    for name in &at_names {
        let at_tbs = ToBeSignedCertificate::new(
            CertificateId::none(()),
            HashedId3(FixedOctetString::from([0u8; 3])),
            CrlSeries(Uint16(0)),
            ValidityPeriod::new(its_time32_now(), Duration::years(Uint16(5))),
            None,
            None,
            Some(app_permissions(&[ITS_AID_CAM, ITS_AID_DENM, ITS_AID_VAM])),
            None, // no certIssuePermissions for AT
            None,
            None,
            None,
            VerificationKeyIndicator::verificationKey(
                rustflexstack::security::security_asn::ieee1609_dot2_base_types
                    ::PublicVerificationKey::ecdsaNistP256(
                        rustflexstack::security::security_asn::ieee1609_dot2_base_types
                            ::EccP256CurvePoint::x_only(vec![0u8; 32].into()),
                    ),
            ),
            None,
            SequenceOfAppExtensions(Default::default()),
            SequenceOfCertIssueExtensions(Default::default()),
            SequenceOfCertRequestExtensions(Default::default()),
        );
        let at = OwnCertificate::initialize_issued(&mut backend, at_tbs, &aa);
        println!(
            "{:<8} HashedId8: {:02x?}",
            name,
            at.as_hashedid8()
        );
        at_certs.push((name, at));
    }

    // ─── Write files ─────────────────────────────────────────────────────
    let write_cert = |filename: &str, own: &OwnCertificate| {
        let cert_bytes = encode_certificate(&own.cert.inner);
        let key_bytes = backend.export_signing_key(own.key_id);
        fs::write(cert_dir.join(format!("{}.cert", filename)), &cert_bytes)
            .unwrap_or_else(|e| panic!("write {}.cert: {}", filename, e));
        fs::write(cert_dir.join(format!("{}.key", filename)), &key_bytes)
            .unwrap_or_else(|e| panic!("write {}.key: {}", filename, e));
        println!(
            "  Wrote {}.cert ({} bytes) + {}.key ({} bytes)",
            filename,
            cert_bytes.len(),
            filename,
            key_bytes.len()
        );
    };

    write_cert("root_ca", &root_ca);
    write_cert("aa", &aa);
    for (name, at) in &at_certs {
        write_cert(&name.to_lowercase(), at);
    }

    // ─── Verify the chain ────────────────────────────────────────────────
    println!("\n=== Verification ===");
    println!("Root CA self-signed: {}", root_ca.verify(&backend));
    println!("AA issued by Root:   {}", aa.verify(&backend));
    for (name, at) in &at_certs {
        println!("{} issued by AA:    {}", name, at.verify(&backend));
    }
    println!("\nDone. Certificate files in certs/");
}
