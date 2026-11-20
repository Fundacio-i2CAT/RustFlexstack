//! Certificate handling — ETSI TS 103 097 V2.2.1 (2026-03) profiles.
//!
//! Provides [`Certificate`] (read-only wrapper) and [`OwnCertificate`]
//! (includes the private-key identifier for signing).

use sha2::{Digest, Sha256, Sha384};

use crate::security::ecdsa_backend::{
    key_uses_sha384, reconstruct_public_key, EcdsaBackend, KeyAlgorithm,
};

/// Input to the ECDSA signing and verification operations (IEEE Std
/// 1609.2-2016, clause 5.3.1, adopted by ETSI TS 103 097 V2.2.1):
/// `Hash(Data input) || Hash(Signer identifier input)`, which ECDSA hashes
/// again. `data` is the COER encoding of the ToBeSignedData or
/// ToBeSignedCertificate; `signer` is the canonical COER encoding of the
/// signer's certificate, or empty for self-signed data. `sha384` selects
/// SHA-384 (384-bit curves) instead of SHA-256.
pub fn signing_input(data: &[u8], signer: &[u8], sha384: bool) -> Vec<u8> {
    if sha384 {
        [
            Sha384::digest(data).to_vec(),
            Sha384::digest(signer).to_vec(),
        ]
        .concat()
    } else {
        [
            Sha256::digest(data).to_vec(),
            Sha256::digest(signer).to_vec(),
        ]
        .concat()
    }
}
use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
use crate::security::security_asn::ieee1609_dot2::Certificate as AsnCertificate;
use crate::security::security_asn::ieee1609_dot2::{
    CertificateBase, CertificateType, Ieee1609Dot2Data, IssuerIdentifier, ToBeSignedCertificate,
    ToBeSignedData,
};
use crate::security::security_asn::ieee1609_dot2::{SubjectPermissions, VerificationKeyIndicator};
use crate::security::security_asn::ieee1609_dot2_base_types::Signature as Ieee1609Signature;
use crate::security::security_asn::ieee1609_dot2_base_types::{
    BasePublicEncryptionKey, EccP256CurvePoint, EccP384CurvePoint, EcdsaP256Signature,
    HashAlgorithm, HashedId8, PublicVerificationKey, Uint8,
};

// ─── COER encode / decode helpers ────────────────────────────────────────

/// COER-encode an `EtsiTs103097Certificate`.
pub fn encode_certificate(cert: &EtsiTs103097Certificate) -> Vec<u8> {
    rasn::coer::encode(cert).expect("certificate COER encode failed")
}

/// COER-decode an `EtsiTs103097Certificate`.
pub fn decode_certificate(bytes: &[u8]) -> EtsiTs103097Certificate {
    rasn::coer::decode::<EtsiTs103097Certificate>(bytes).expect("certificate COER decode failed")
}

/// COER-encode `Ieee1609Dot2Data` (signed message envelope).
pub fn encode_ieee1609_dot2_data(data: &Ieee1609Dot2Data) -> Vec<u8> {
    rasn::coer::encode(data).expect("Ieee1609Dot2Data COER encode failed")
}

/// COER-decode `Ieee1609Dot2Data`.
/// COER-decode an `Ieee1609Dot2Data`, `None` when malformed (received data).
pub fn try_decode_ieee1609_dot2_data(bytes: &[u8]) -> Option<Ieee1609Dot2Data> {
    rasn::coer::decode::<Ieee1609Dot2Data>(bytes).ok()
}

pub fn decode_ieee1609_dot2_data(bytes: &[u8]) -> Ieee1609Dot2Data {
    rasn::coer::decode::<Ieee1609Dot2Data>(bytes).expect("Ieee1609Dot2Data COER decode failed")
}

/// COER-encode `ToBeSignedData` (the data that is actually signed).
pub fn encode_tbs_data(tbs: &ToBeSignedData) -> Vec<u8> {
    rasn::coer::encode(tbs).expect("ToBeSignedData COER encode failed")
}

/// COER-encode `ToBeSignedCertificate`.
pub fn encode_tbs_certificate(tbs: &ToBeSignedCertificate) -> Vec<u8> {
    rasn::coer::encode(tbs).expect("ToBeSignedCertificate COER encode failed")
}

// ─── HashedId8 / HashedId3 helpers ───────────────────────────────────────

/// Compute the HashedId8 of a COER-encoded certificate.
pub fn compute_hashedid8(cert_bytes: &[u8]) -> [u8; 8] {
    EcdsaBackend::hash_to_hashedid8(cert_bytes)
}

// ─── Canonicalization helpers (IEEE 1609.2 clause 6.4.3) ─────────────────

/// A verification key or reconstruction value point in compressed form.
fn compress_p256(point: &mut EccP256CurvePoint) {
    if let EccP256CurvePoint::uncompressedP256(u) = point {
        let even = u.y.as_ref().last().is_some_and(|b| b % 2 == 0);
        let x = u.x.clone();
        *point = if even {
            EccP256CurvePoint::compressed_y_0(x)
        } else {
            EccP256CurvePoint::compressed_y_1(x)
        };
    }
}

fn compress_p384(point: &mut EccP384CurvePoint) {
    if let EccP384CurvePoint::uncompressedP384(u) = point {
        let even = u.y.as_ref().last().is_some_and(|b| b % 2 == 0);
        let x = u.x.clone();
        *point = if even {
            EccP384CurvePoint::compressed_y_0(x)
        } else {
            EccP384CurvePoint::compressed_y_1(x)
        };
    }
}

/// The r of an ECDSA signature in x-only form.
fn x_only_p256(r: &mut EccP256CurvePoint) {
    let x = match r {
        EccP256CurvePoint::compressed_y_0(x) | EccP256CurvePoint::compressed_y_1(x) => x.clone(),
        EccP256CurvePoint::uncompressedP256(u) => u.x.clone(),
        _ => return,
    };
    *r = EccP256CurvePoint::x_only(x);
}

fn x_only_p384(r: &mut EccP384CurvePoint) {
    let x = match r {
        EccP384CurvePoint::compressed_y_0(x) | EccP384CurvePoint::compressed_y_1(x) => x.clone(),
        EccP384CurvePoint::uncompressedP384(u) => u.x.clone(),
        _ => return,
    };
    *r = EccP384CurvePoint::x_only(x);
}

// ─── Certificate (read-only) ─────────────────────────────────────────────

/// Immutable certificate wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The inner ASN.1 certificate.
    pub inner: EtsiTs103097Certificate,
    /// Cached COER encoding (for hashing).
    encoded: Vec<u8>,
    /// Optional issuer certificate (for chain verification).
    pub issuer: Option<Box<Certificate>>,
}

impl Certificate {
    /// Build from a decoded ASN.1 certificate.
    pub fn from_asn(asn: EtsiTs103097Certificate, issuer: Option<Certificate>) -> Self {
        let encoded = encode_certificate(&asn);
        Self {
            inner: asn,
            encoded,
            issuer: issuer.map(Box::new),
        }
    }

    /// Decode from COER bytes.
    pub fn from_bytes(bytes: &[u8], issuer: Option<Certificate>) -> Self {
        let asn = decode_certificate(bytes);
        let encoded = bytes.to_vec();
        Self {
            inner: asn,
            encoded,
            issuer: issuer.map(Box::new),
        }
    }

    /// Access the inner `CertificateBase`.
    pub fn base(&self) -> &CertificateBase {
        &(self.inner.0).0
    }

    /// Access `toBeSigned`.
    pub fn tbs(&self) -> &ToBeSignedCertificate {
        &self.base().to_be_signed
    }

    /// Return the COER encoding.
    pub fn encode(&self) -> &[u8] {
        &self.encoded
    }

    /// Convert certificate to IEEE 1609.2 / ETSI TS 103 097 canonical form:
    /// - Public verification key compressed (compressed_y_0/1).
    /// - Signature r_sig as x_only.
    pub fn to_canonical(&self) -> Certificate {
        let mut new_base = self.base().clone();
        let indicator = &mut new_base.to_be_signed.verify_key_indicator;
        match indicator {
            VerificationKeyIndicator::verificationKey(
                PublicVerificationKey::ecdsaNistP256(point)
                | PublicVerificationKey::ecdsaBrainpoolP256r1(point),
            )
            | VerificationKeyIndicator::reconstructionValue(point) => compress_p256(point),
            VerificationKeyIndicator::verificationKey(
                PublicVerificationKey::ecdsaBrainpoolP384r1(point)
                | PublicVerificationKey::ecdsaNistP384(point),
            ) => compress_p384(point),
            _ => {}
        }
        if let Some(key) = &mut new_base.to_be_signed.encryption_key {
            match &mut key.public_key {
                BasePublicEncryptionKey::eciesNistP256(point)
                | BasePublicEncryptionKey::eciesBrainpoolP256r1(point)
                | BasePublicEncryptionKey::ecencSm2(point) => compress_p256(point),
            }
        }
        match &mut new_base.signature {
            Some(
                Ieee1609Signature::ecdsaNistP256Signature(sig)
                | Ieee1609Signature::ecdsaBrainpoolP256r1Signature(sig),
            ) => x_only_p256(&mut sig.r_sig),
            Some(
                Ieee1609Signature::ecdsaBrainpoolP384r1Signature(sig)
                | Ieee1609Signature::ecdsaNistP384Signature(sig),
            ) => x_only_p384(&mut sig.r_sig),
            _ => {}
        }
        if new_base == *self.base() {
            return self.clone();
        }
        let new_asn = EtsiTs103097Certificate(AsnCertificate(new_base));
        let issuer = self.issuer.as_ref().map(|i| *i.clone());
        Certificate::from_asn(new_asn, issuer)
    }

    /// HashedId8 of the canonical certificate, with the hash for the curve of
    /// its verification key: SHA-384 for a 384-bit key, SHA-256 otherwise (the
    /// hashes approved by ETSI TS 103 097 V2.2.1 clause 4.2, paired with the
    /// curves as in the permutation tables of ETSI TS 103 096-2).
    pub fn as_hashedid8(&self) -> [u8; 8] {
        let canon = self.to_canonical();
        if !self.uses_sha384() {
            return compute_hashedid8(&canon.encoded);
        }
        let digest = Sha384::digest(&canon.encoded);
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest[40..48]);
        out
    }

    /// SHA-384 is the hash associated with the certificate's verification key
    /// (384-bit curve), used for its HashedId8, the hashId of data it signs
    /// and the issuer choice of certificates it issues; SHA-256 otherwise
    /// (and for implicit certificates).
    pub fn uses_sha384(&self) -> bool {
        matches!(&self.tbs().verify_key_indicator,
            VerificationKeyIndicator::verificationKey(pk) if key_uses_sha384(pk))
    }

    /// IssuerIdentifier of a certificate issued by this one.
    pub fn issuer_identifier(&self) -> IssuerIdentifier {
        let h8 = HashedId8(rasn::types::FixedOctetString::from(self.as_hashedid8()));
        if self.uses_sha384() {
            IssuerIdentifier::sha384AndDigest(h8)
        } else {
            IssuerIdentifier::sha256AndDigest(h8)
        }
    }

    /// Compute the last 3 bytes of HashedId8.
    pub fn as_hashedid3(&self) -> [u8; 3] {
        let h8 = self.as_hashedid8();
        [h8[5], h8[6], h8[7]]
    }

    /// Return the list of ITS-AID (PSID) values from `appPermissions`.
    pub fn get_list_of_its_aid(&self) -> Vec<u64> {
        let mut aids = Vec::new();
        if let Some(ref perms) = self.tbs().app_permissions {
            for psid_ssp in perms.0.iter() {
                // Psid wraps an Integer — convert via i128 then u64.
                let val = u64::try_from(&psid_ssp.psid.0).unwrap_or(0);
                aids.push(val);
            }
        }
        aids
    }

    /// Get issuer HashedId8 stored inside the certificate.
    /// Returns `None` if self-signed.
    pub fn get_issuer_hashedid8(&self) -> Option<[u8; 8]> {
        match &self.base().issuer {
            IssuerIdentifier::sha256AndDigest(h) => {
                let mut out = [0u8; 8];
                out.copy_from_slice(h.0.as_ref());
                Some(out)
            }
            IssuerIdentifier::R_self(_) => None,
            IssuerIdentifier::sha384AndDigest(h) => {
                let mut out = [0u8; 8];
                out.copy_from_slice(h.0.as_ref());
                Some(out)
            }
            _ => None,
        }
    }

    /// Check whether the signature uses NIST P-256.
    pub fn signature_is_nist_p256(&self) -> bool {
        matches!(
            self.base().signature,
            Some(Ieee1609Signature::ecdsaNistP256Signature(_))
        )
    }

    /// Check whether the verification key is NIST P-256.
    pub fn verification_key_is_nist_p256(&self) -> bool {
        matches!(
            &self.tbs().verify_key_indicator,
            VerificationKeyIndicator::verificationKey(PublicVerificationKey::ecdsaNistP256(_))
        )
    }

    /// Is the signature NIST P-256/P-384 or brainpoolP256r1/P384r1?
    pub fn signature_is_supported(&self) -> bool {
        matches!(
            self.base().signature,
            Some(
                Ieee1609Signature::ecdsaNistP256Signature(_)
                    | Ieee1609Signature::ecdsaBrainpoolP256r1Signature(_)
                    | Ieee1609Signature::ecdsaBrainpoolP384r1Signature(_)
                    | Ieee1609Signature::ecdsaNistP384Signature(_)
            )
        )
    }

    /// Is the verification key NIST P-256/P-384 or brainpoolP256r1/P384r1?
    pub fn verification_key_is_supported(&self) -> bool {
        matches!(
            &self.tbs().verify_key_indicator,
            VerificationKeyIndicator::verificationKey(
                PublicVerificationKey::ecdsaNistP256(_)
                    | PublicVerificationKey::ecdsaBrainpoolP256r1(_)
                    | PublicVerificationKey::ecdsaBrainpoolP384r1(_)
                    | PublicVerificationKey::ecdsaNistP384(_)
            )
        )
    }

    /// Is the certificate self-signed?
    pub fn is_self_signed(&self) -> bool {
        matches!(
            &self.base().issuer,
            IssuerIdentifier::R_self(HashAlgorithm::sha256 | HashAlgorithm::sha384)
        )
    }

    /// Is the certificate issued (not self-signed)?
    pub fn is_issued(&self) -> bool {
        matches!(
            &self.base().issuer,
            IssuerIdentifier::sha256AndDigest(_) | IssuerIdentifier::sha384AndDigest(_)
        )
    }

    /// Check whether the issuer's HashedId8 matches the given issuer certificate.
    pub fn check_corresponding_issuer(&self, issuer: &Certificate) -> bool {
        let choice_matches = match &self.base().issuer {
            IssuerIdentifier::sha256AndDigest(_) => !issuer.uses_sha384(),
            IssuerIdentifier::sha384AndDigest(_) => issuer.uses_sha384(),
            _ => false,
        };
        match self.get_issuer_hashedid8() {
            Some(h) => choice_matches && h == issuer.as_hashedid8(),
            None => false,
        }
    }

    /// Does `certIssuePermissions` have a subjectPermissions of `all`?
    pub fn has_all_permissions(&self) -> bool {
        if let Some(ref cip) = self.tbs().cert_issue_permissions {
            for perm in cip.0.iter() {
                if matches!(perm.subject_permissions, SubjectPermissions::all(_)) {
                    return true;
                }
            }
        }
        false
    }

    /// Get the PSID list from `certIssuePermissions.subjectPermissions.explicit`.
    pub fn get_allowed_permissions(&self) -> Vec<u64> {
        let mut out = Vec::new();
        if let Some(ref cip) = self.tbs().cert_issue_permissions {
            for perm in cip.0.iter() {
                if let SubjectPermissions::explicit(ref ranges) = perm.subject_permissions {
                    for r in ranges.0.iter() {
                        let val = u64::try_from(&r.psid.0).unwrap_or(0);
                        out.push(val);
                    }
                }
            }
        }
        out
    }

    /// Check whether the issuer has the right permissions to issue this cert.
    pub fn check_issuer_has_subject_permissions(&self, issuer: &Certificate) -> bool {
        if issuer.has_all_permissions() {
            return true;
        }
        let needed = self.get_list_of_its_aid();
        let allowed = issuer.get_allowed_permissions();
        needed.iter().all(|n| allowed.contains(n))
    }

    /// Verify the signature of a self-signed certificate: the signer input
    /// is the empty string (IEEE 1609.2 clause 5.3.1).
    pub fn verify_signature_with(
        backend: &EcdsaBackend,
        tbs: &ToBeSignedCertificate,
        signature: &Ieee1609Signature,
        verification_key: &PublicVerificationKey,
    ) -> bool {
        let tbs_bytes = encode_tbs_certificate(tbs);
        let payload = signing_input(&tbs_bytes, &[], key_uses_sha384(verification_key));
        backend.verify_with_pk(&payload, signature, verification_key)
    }

    /// Verify an issued certificate (chain to issuer).
    fn verify_issued(&self, backend: &EcdsaBackend) -> bool {
        let issuer = match &self.issuer {
            Some(i) => i,
            None => return false,
        };
        if !self.is_issued() {
            return false;
        }
        if !self.check_corresponding_issuer(issuer) {
            return false;
        }
        if !self.check_issuer_has_subject_permissions(issuer) {
            return false;
        }
        if !self.signature_is_supported() || !self.verification_key_is_supported() {
            return false;
        }
        let sig = match &self.base().signature {
            Some(s) => s,
            None => return false,
        };
        let Some(issuer_vk_owned) = issuer.verification_key() else {
            return false;
        };
        let issuer_vk = &issuer_vk_owned;
        // IEEE 1609.2 clause 5.3.1: Hash(Hash(tbs) || Hash(issuer certificate))
        let tbs_bytes = encode_tbs_certificate(self.tbs());
        let payload = signing_input(
            &tbs_bytes,
            issuer.to_canonical().encode(),
            key_uses_sha384(issuer_vk),
        );
        backend.verify_with_pk(&payload, sig, issuer_vk)
    }

    /// Verify a self-signed certificate.
    fn verify_self_signed(&self, backend: &EcdsaBackend) -> bool {
        if !self.is_self_signed() {
            return false;
        }
        if !self.signature_is_supported() || !self.verification_key_is_supported() {
            return false;
        }
        let sig = match &self.base().signature {
            Some(s) => s,
            None => return false,
        };
        let pk = match &self.tbs().verify_key_indicator {
            VerificationKeyIndicator::verificationKey(vk) => vk,
            _ => return false,
        };
        Certificate::verify_signature_with(backend, self.tbs(), sig, pk)
    }

    /// Full certificate verification (self-signed or chained).
    pub fn verify(&self, backend: &EcdsaBackend) -> bool {
        // §6: verifyKeyIndicator must match certificate type
        match self.base().r_type {
            CertificateType::explicit => {
                if !matches!(
                    self.tbs().verify_key_indicator,
                    VerificationKeyIndicator::verificationKey(_)
                ) {
                    return false;
                }
            }
            CertificateType::implicit => {
                // IEEE 1609.2 clause 6.4.2: reconstruction value and no
                // signature (IEEE 1609.2 clause 5.3.2)
                if !matches!(
                    self.tbs().verify_key_indicator,
                    VerificationKeyIndicator::reconstructionValue(_)
                ) || self.base().signature.is_some()
                {
                    return false;
                }
                return self.verify_implicit();
            }
        }
        if self.issuer.is_some() && self.is_issued() {
            return self.verify_issued(backend);
        }
        if self.is_self_signed() {
            return self.verify_self_signed(backend);
        }
        false
    }

    /// An implicit certificate has no signature: it is accepted when it is
    /// issued by its (known) issuer with the required permissions and its
    /// public key can be reconstructed. A wrong certificate yields a wrong
    /// key, so data it signs does not verify (SEC 4 section 3.5).
    fn verify_implicit(&self) -> bool {
        let Some(issuer) = &self.issuer else {
            return false;
        };
        self.is_issued()
            && self.check_corresponding_issuer(issuer)
            && self.check_issuer_has_subject_permissions(issuer)
            && self.verification_key().is_some()
    }

    /// True for an implicit certificate (reconstruction value, no signature).
    pub fn is_implicit(&self) -> bool {
        matches!(self.base().r_type, CertificateType::implicit)
    }

    /// e = Hn(Hash(ToBeSignedCertificate) || Hash(issuer certificate)): the
    /// leftmost floor(log2 n) = 255 bits of SHA-256 over the 1609.2 hash
    /// input (IEEE Std 1609.2-2016 clauses 5.3.2 and 6.4.3; SEC 4 section
    /// 2.3), as a big-endian 32-byte integer. `None` without issuer.
    pub fn implicit_hash_integer(&self) -> Option<[u8; 32]> {
        let issuer = self.issuer.as_ref()?;
        let tbs = encode_tbs_certificate(self.to_canonical().tbs());
        let digest = Sha256::digest(signing_input(&tbs, issuer.to_canonical().encode(), false));
        let mut e = [0u8; 32];
        let mut carry = 0u8;
        for (i, byte) in digest.iter().enumerate() {
            e[i] = (byte >> 1) | carry;
            carry = byte << 7;
        }
        Some(e)
    }

    /// Public verification key: the explicit key, or the key reconstructed
    /// from the reconstruction value and the issuer key (ECQV, IEEE Std
    /// 1609.2-2016 clause 5.3.2). `None` when not available.
    pub fn verification_key(&self) -> Option<PublicVerificationKey> {
        match &self.tbs().verify_key_indicator {
            VerificationKeyIndicator::verificationKey(pk) => Some(pk.clone()),
            VerificationKeyIndicator::reconstructionValue(rv) => {
                let issuer_key = self.issuer.as_ref()?.verification_key()?;
                reconstruct_public_key(rv, &issuer_key, &self.implicit_hash_integer()?)
            }
        }
    }

    // ── Profile checks (§7.2) ────────────────────────────────────────────

    /// §7.2.1 Authorization Ticket profile.
    pub fn is_authorization_ticket(&self) -> bool {
        if !self.is_issued() {
            return false;
        }
        let tbs = self.tbs();
        if !matches!(
            tbs.id,
            crate::security::security_asn::ieee1609_dot2::CertificateId::none(_)
        ) {
            return false;
        }
        if tbs.cert_issue_permissions.is_some() {
            return false;
        }
        tbs.app_permissions.is_some()
    }

    /// §7.2.3 Root CA profile.
    pub fn is_root_ca(&self) -> bool {
        if !matches!(self.base().r_type, CertificateType::explicit) {
            return false;
        }
        if !self.is_self_signed() {
            return false;
        }
        let tbs = self.tbs();
        tbs.cert_issue_permissions.is_some() && tbs.app_permissions.is_some()
    }
}

// ─── OwnCertificate ─────────────────────────────────────────────────────

/// A certificate for which we hold the private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnCertificate {
    pub cert: Certificate,
    pub key_id: usize,
}

impl OwnCertificate {
    /// Wrap an existing `Certificate` together with its key id.
    pub fn new(cert: Certificate, key_id: usize) -> Self {
        Self { cert, key_id }
    }

    /// Convert inner certificate to canonical form.
    pub fn to_canonical(&self) -> Certificate {
        self.cert.to_canonical()
    }

    /// Convenience delegations.
    pub fn as_hashedid8(&self) -> [u8; 8] {
        self.cert.as_hashedid8()
    }

    pub fn get_list_of_its_aid(&self) -> Vec<u64> {
        self.cert.get_list_of_its_aid()
    }

    pub fn tbs(&self) -> &ToBeSignedCertificate {
        self.cert.tbs()
    }

    pub fn base(&self) -> &CertificateBase {
        self.cert.base()
    }

    pub fn verify(&self, backend: &EcdsaBackend) -> bool {
        self.cert.verify(backend)
    }

    /// Sign `data` (the COER ToBeSignedData) with this certificate's key; the
    /// signer identifier input is this certificate (IEEE 1609.2 clause 5.3.1).
    pub fn sign_message(&self, backend: &EcdsaBackend, data: &[u8]) -> Ieee1609Signature {
        let signer = self.to_canonical().encode().to_vec();
        backend.sign(
            &signing_input(data, &signer, self.cert.uses_sha384()),
            self.key_id,
        )
    }

    /// Sign (or re-sign) `target`'s `toBeSigned` and return a new `Certificate`
    /// with the updated signature.
    pub fn sign_certificate(&self, backend: &EcdsaBackend, target: &Certificate) -> Certificate {
        // IEEE 1609.2 clause 5.3.1: Hash(Hash(tbs) || Hash(issuer certificate)),
        // with the empty string as signer input for a self-signed certificate.
        let tbs_bytes = encode_tbs_certificate(target.tbs());
        let signer = if matches!(
            target.base().issuer,
            IssuerIdentifier::sha256AndDigest(_) | IssuerIdentifier::sha384AndDigest(_)
        ) {
            self.to_canonical().encode().to_vec()
        } else {
            Vec::new()
        };
        let payload = signing_input(&tbs_bytes, &signer, self.cert.uses_sha384());
        let sig = backend.sign(&payload, self.key_id);

        let mut new_base = target.base().clone();
        new_base.signature = Some(sig);

        let new_asn = EtsiTs103097Certificate(AsnCertificate(new_base));
        Certificate::from_asn(new_asn, Some(self.cert.clone()))
    }

    /// Build the inner `AsnCertificate` from the wrapper's certificate dict,
    /// setting the issuer to `self`, signing, and returning the result.
    pub fn issue_certificate(&self, backend: &EcdsaBackend, target: &Certificate) -> Certificate {
        // Set issuer to our HashedId8
        let mut new_base = target.base().clone();
        new_base.issuer = self.cert.issuer_identifier();

        let target_with_issuer = Certificate::from_asn(
            EtsiTs103097Certificate(AsnCertificate(new_base)),
            Some(self.cert.clone()),
        );
        self.sign_certificate(backend, &target_with_issuer)
    }

    /// Create a brand-new self-signed certificate (NIST P-256 key).
    pub fn initialize_self_signed(backend: &mut EcdsaBackend, tbs: ToBeSignedCertificate) -> Self {
        Self::initialize_self_signed_with(backend, tbs, KeyAlgorithm::NistP256)
    }

    /// Create a brand-new self-signed certificate with a key on `algorithm`.
    pub fn initialize_self_signed_with(
        backend: &mut EcdsaBackend,
        tbs: ToBeSignedCertificate,
        algorithm: KeyAlgorithm,
    ) -> Self {
        let key_id = backend.create_key_with(algorithm);
        let pk = backend.get_public_key(key_id);
        let sha384 = key_uses_sha384(&pk);

        let mut tbs_owned = tbs;
        tbs_owned.verify_key_indicator = VerificationKeyIndicator::verificationKey(pk);

        // Placeholder signature — will be replaced below.
        let placeholder_sig = Ieee1609Signature::ecdsaNistP256Signature(EcdsaP256Signature {
            r_sig: EccP256CurvePoint::x_only(vec![0u8; 32].into()),
            s_sig: vec![0u8; 32].into(),
        });

        let base = CertificateBase::new(
            Uint8(3),
            CertificateType::explicit,
            IssuerIdentifier::R_self(if sha384 {
                HashAlgorithm::sha384
            } else {
                HashAlgorithm::sha256
            }),
            tbs_owned,
            Some(placeholder_sig),
        );

        // Sign the toBeSigned
        // IEEE 1609.2 clause 5.3.1: self-signed, the signer input is empty
        let tbs_bytes = encode_tbs_certificate(&base.to_be_signed);
        let sig = backend.sign(&signing_input(&tbs_bytes, &[], sha384), key_id);

        let mut final_base = base;
        final_base.signature = Some(sig);

        let asn = EtsiTs103097Certificate(AsnCertificate(final_base));
        let cert = Certificate::from_asn(asn, None);
        OwnCertificate { cert, key_id }
    }

    /// Create a new certificate issued by `issuer`.
    /// Issue an implicit certificate with ECQV (SEC 4 sections 3.3 to 3.6,
    /// as profiled by IEEE Std 1609.2-2016 clause 5.3.2) and return it with
    /// the reconstructed private key of its holder. The requester and the CA
    /// role are combined: k_U is the requester key, k the CA ephemeral key,
    /// P_U = (k_U + k) * G, r = e * k + d_CA and d_U = e * k_U + r.
    /// Only a NIST P-256 issuer key is supported.
    pub fn issue_implicit_certificate(
        &self,
        backend: &mut EcdsaBackend,
        tbs: ToBeSignedCertificate,
    ) -> OwnCertificate {
        use p256::elliptic_curve::ff::{Field, PrimeField};
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let mut rng = rand::thread_rng();
        let (k_u, k) = (
            p256::Scalar::random(&mut rng),
            p256::Scalar::random(&mut rng),
        );
        let p_u = (p256::ProjectivePoint::GENERATOR * (k_u + k)).to_affine();
        let encoded = p_u.to_encoded_point(true);
        let x = encoded.x().expect("x").to_vec().into();
        let rv = if encoded.as_bytes()[0] == 0x02 {
            EccP256CurvePoint::compressed_y_0(x)
        } else {
            EccP256CurvePoint::compressed_y_1(x)
        };
        let mut tbs = tbs;
        tbs.verify_key_indicator = VerificationKeyIndicator::reconstructionValue(rv);
        let base = CertificateBase::new(
            Uint8(3),
            CertificateType::implicit,
            IssuerIdentifier::sha256AndDigest(HashedId8(rasn::types::FixedOctetString::from(
                self.as_hashedid8(),
            ))),
            tbs,
            None,
        );
        let cert = Certificate::from_asn(
            EtsiTs103097Certificate(AsnCertificate(base)),
            Some(self.cert.clone()),
        );
        let e_bytes = cert.implicit_hash_integer().expect("issuer set");
        let e =
            Option::<p256::Scalar>::from(p256::Scalar::from_repr(e_bytes.into())).expect("e < n");
        let d_ca_bytes: [u8; 32] = backend
            .export_signing_key(self.key_id)
            .try_into()
            .expect("P-256 key");
        let d_ca =
            Option::<p256::Scalar>::from(p256::Scalar::from_repr(d_ca_bytes.into())).expect("key");
        let d_u = e * k_u + (e * k + d_ca);
        let key_id = backend.import_signing_key(&d_u.to_repr());
        OwnCertificate { cert, key_id }
    }

    pub fn initialize_issued(
        backend: &mut EcdsaBackend,
        tbs: ToBeSignedCertificate,
        issuer: &OwnCertificate,
    ) -> Self {
        Self::initialize_issued_with(backend, tbs, issuer, KeyAlgorithm::NistP256)
    }

    /// Create a new certificate issued by `issuer`, with a key on `algorithm`.
    pub fn initialize_issued_with(
        backend: &mut EcdsaBackend,
        tbs: ToBeSignedCertificate,
        issuer: &OwnCertificate,
        algorithm: KeyAlgorithm,
    ) -> Self {
        Self::initialize_issued_key(backend, tbs, issuer, algorithm, true)
    }

    /// Create a new certificate issued by `issuer`, with a key on `algorithm`
    /// given as a compressed or an uncompressed point.
    pub fn initialize_issued_key(
        backend: &mut EcdsaBackend,
        tbs: ToBeSignedCertificate,
        issuer: &OwnCertificate,
        algorithm: KeyAlgorithm,
        compressed_key: bool,
    ) -> Self {
        let key_id = backend.create_key_with(algorithm);
        let pk = backend.get_public_key_compressed(key_id, compressed_key);

        let mut tbs_owned = tbs;
        tbs_owned.verify_key_indicator = VerificationKeyIndicator::verificationKey(pk);

        let base = CertificateBase::new(
            Uint8(3),
            CertificateType::explicit,
            issuer.cert.issuer_identifier(),
            tbs_owned,
            None, // will be filled by sign
        );

        let target = Certificate::from_asn(
            EtsiTs103097Certificate(AsnCertificate(base)),
            Some(issuer.cert.clone()),
        );
        let signed_cert = issuer.sign_certificate(backend, &target);
        OwnCertificate {
            cert: signed_cert,
            key_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::security::ecdsa_backend::EcdsaBackend;
    use rasn::prelude::*;

    fn make_root_tbs() -> ToBeSignedCertificate {
        use crate::security::security_asn::ieee1609_dot2::{
            CertificateId, EndEntityType, PsidGroupPermissions, SequenceOfPsidGroupPermissions,
        };
        use crate::security::security_asn::ieee1609_dot2_base_types::{
            CrlSeries, Duration as AsnDuration, HashedId3, Time32, Uint16, Uint32, ValidityPeriod,
        };

        let validity = ValidityPeriod::new(Time32(Uint32(0)), AsnDuration::years(Uint16(30)));

        let perms = SequenceOfPsidGroupPermissions(vec![PsidGroupPermissions::new(
            SubjectPermissions::all(()),
            Integer::from(1),
            Integer::from(0),
            {
                let mut bits = FixedBitString::<8>::default();
                bits.set(0, true);
                EndEntityType(bits)
            },
        )]);

        let placeholder_pk =
            PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::x_only(vec![0u8; 32].into()));

        ToBeSignedCertificate::new(
            CertificateId::none(()),
            HashedId3(FixedOctetString::from([0u8; 3])),
            CrlSeries(Uint16(0)),
            validity,
            None,
            None,
            None,
            Some(perms),
            None,
            None,
            None,
            VerificationKeyIndicator::verificationKey(placeholder_pk),
            None,
            None,
            None,
            None,
        )
    }

    fn make_at_tbs() -> ToBeSignedCertificate {
        use crate::security::security_asn::ieee1609_dot2::CertificateId;
        use crate::security::security_asn::ieee1609_dot2_base_types::{
            CrlSeries, Duration as AsnDuration, HashedId3, Psid, PsidSsp, SequenceOfPsidSsp,
            Time32, Uint16, Uint32, ValidityPeriod,
        };

        let validity = ValidityPeriod::new(Time32(Uint32(0)), AsnDuration::years(Uint16(1)));

        let app_perms = SequenceOfPsidSsp(vec![PsidSsp::new(Psid(Integer::from(36_i64)), None)]);

        let placeholder_pk =
            PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::x_only(vec![0u8; 32].into()));

        ToBeSignedCertificate::new(
            CertificateId::none(()),
            HashedId3(FixedOctetString::from([0u8; 3])),
            CrlSeries(Uint16(0)),
            validity,
            None,
            None,
            Some(app_perms),
            None,
            None,
            None,
            None,
            VerificationKeyIndicator::verificationKey(placeholder_pk),
            None,
            None,
            None,
            None,
        )
    }

    /// IEEE 1609.2 clause 6.4.3: a certificate is hashed with every point of
    /// toBeSigned compressed and the signature r as x-only, on every curve.
    #[test]
    fn uncompressed_points_hash_as_compressed() {
        use crate::security::ecdsa_backend::KeyAlgorithm;
        use crate::security::security_asn::ieee1609_dot2_base_types::{
            EcdsaP384Signature, PublicEncryptionKey, SymmAlgorithm,
        };
        let mut backend = EcdsaBackend::new();
        for algorithm in [
            KeyAlgorithm::NistP256,
            KeyAlgorithm::BrainpoolP256r1,
            KeyAlgorithm::BrainpoolP384r1,
            KeyAlgorithm::NistP384,
        ] {
            let key = backend.create_key_with(algorithm);
            let encryption = backend.create_key();
            // r given as a point: reuse the key point (only the encoding matters here)
            let signature = |compressed_r: bool| -> Ieee1609Signature {
                let point = backend.get_public_key_compressed(key, true);
                match point {
                    PublicVerificationKey::ecdsaNistP256(p)
                    | PublicVerificationKey::ecdsaBrainpoolP256r1(p) => {
                        let x = match &p {
                            EccP256CurvePoint::compressed_y_0(x)
                            | EccP256CurvePoint::compressed_y_1(x) => x.clone(),
                            _ => unreachable!(),
                        };
                        let r = if compressed_r {
                            p.clone()
                        } else {
                            EccP256CurvePoint::x_only(x)
                        };
                        let sig = EcdsaP256Signature {
                            r_sig: r,
                            s_sig: vec![1u8; 32].into(),
                        };
                        if matches!(algorithm, KeyAlgorithm::NistP256) {
                            Ieee1609Signature::ecdsaNistP256Signature(sig)
                        } else {
                            Ieee1609Signature::ecdsaBrainpoolP256r1Signature(sig)
                        }
                    }
                    PublicVerificationKey::ecdsaBrainpoolP384r1(p)
                    | PublicVerificationKey::ecdsaNistP384(p) => {
                        let x = match &p {
                            EccP384CurvePoint::compressed_y_0(x)
                            | EccP384CurvePoint::compressed_y_1(x) => x.clone(),
                            _ => unreachable!(),
                        };
                        let r = if compressed_r {
                            p.clone()
                        } else {
                            EccP384CurvePoint::x_only(x)
                        };
                        let sig = EcdsaP384Signature {
                            r_sig: r,
                            s_sig: vec![1u8; 48].into(),
                        };
                        if matches!(algorithm, KeyAlgorithm::NistP384) {
                            Ieee1609Signature::ecdsaNistP384Signature(sig)
                        } else {
                            Ieee1609Signature::ecdsaBrainpoolP384r1Signature(sig)
                        }
                    }
                    _ => unreachable!(),
                }
            };
            let certificate = |compressed: bool, compressed_r: bool| -> Certificate {
                let mut tbs = make_at_tbs();
                tbs.verify_key_indicator = VerificationKeyIndicator::verificationKey(
                    backend.get_public_key_compressed(key, compressed),
                );
                let PublicVerificationKey::ecdsaNistP256(point) =
                    backend.get_public_key_compressed(encryption, compressed)
                else {
                    unreachable!()
                };
                tbs.encryption_key = Some(PublicEncryptionKey::new(
                    SymmAlgorithm::aes128Ccm,
                    BasePublicEncryptionKey::eciesNistP256(point),
                ));
                let base = CertificateBase::new(
                    Uint8(3),
                    CertificateType::explicit,
                    IssuerIdentifier::R_self(HashAlgorithm::sha256),
                    tbs,
                    Some(signature(compressed_r)),
                );
                Certificate::from_asn(EtsiTs103097Certificate(AsnCertificate(base)), None)
            };
            let reference = certificate(true, false);
            for (compressed, compressed_r) in [(false, false), (false, true), (true, true)] {
                let variant = certificate(compressed, compressed_r);
                assert_eq!(
                    variant.as_hashedid8(),
                    reference.as_hashedid8(),
                    "{algorithm:?}"
                );
                assert_eq!(
                    variant.to_canonical().encode(),
                    reference.encode(),
                    "{algorithm:?}"
                );
            }
        }
    }

    #[test]
    fn own_certificate_self_signed_roundtrip() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        assert!(own.verify(&backend));
        assert!(own.cert.is_self_signed());
        assert!(!own.cert.is_issued());
    }

    #[test]
    fn own_certificate_issued_roundtrip() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let at = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(), &root);
        assert!(at.verify(&backend));
        assert!(at.cert.is_issued());
        assert!(!at.cert.is_self_signed());
    }

    #[test]
    fn certificate_hashedid8_and_hashedid3() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let h8 = own.as_hashedid8();
        let h3 = own.cert.as_hashedid3();
        assert_eq!(h3, [h8[5], h8[6], h8[7]]);
    }

    #[test]
    fn certificate_encode_decode_roundtrip() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let encoded = own.cert.encode().to_vec();
        let decoded = Certificate::from_bytes(&encoded, None);
        assert_eq!(decoded.as_hashedid8(), own.as_hashedid8());
    }

    #[test]
    fn certificate_from_asn_and_from_bytes_same_hash() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let bytes = own.cert.encode().to_vec();
        let c1 = Certificate::from_bytes(&bytes, None);
        let c2 = Certificate::from_asn(own.cert.inner.clone(), None);
        assert_eq!(c1.as_hashedid8(), c2.as_hashedid8());
    }

    #[test]
    fn certificate_check_corresponding_issuer() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let at = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(), &root);
        assert!(at.cert.check_corresponding_issuer(&root.cert));
    }

    #[test]
    fn certificate_signature_is_nist_p256() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        assert!(own.cert.signature_is_nist_p256());
        assert!(own.cert.verification_key_is_nist_p256());
    }

    #[test]
    fn certificate_has_all_permissions() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        assert!(root.cert.has_all_permissions());
    }

    #[test]
    fn certificate_get_list_of_its_aid() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let at = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(), &root);
        let aids = at.get_list_of_its_aid();
        assert!(aids.contains(&36));
    }

    #[test]
    fn certificate_sign_message() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let sig = own.sign_message(&backend, b"test data");
        let pk = backend.get_public_key(own.key_id);
        // IEEE 1609.2 clause 5.3.1: Hash(data) || Hash(signer certificate)
        let input = signing_input(b"test data", own.to_canonical().encode(), false);
        assert!(backend.verify_with_pk(&input, &sig, &pk));
        assert!(!backend.verify_with_pk(b"test data", &sig, &pk));
    }

    #[test]
    fn certificate_verify_type_explicit() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        assert_eq!(own.cert.base().r_type, CertificateType::explicit);
    }

    #[test]
    fn certificate_at_is_authorization_ticket() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let at = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(), &root);
        assert!(at.cert.is_authorization_ticket());
    }

    #[test]
    fn certificate_self_signed_get_issuer_hashedid8_none() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        assert!(own.cert.get_issuer_hashedid8().is_none());
    }

    #[test]
    fn certificate_issued_get_issuer_hashedid8_some() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let at = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(), &root);
        let issuer_h8 = at.cert.get_issuer_hashedid8();
        assert!(issuer_h8.is_some());
        assert_eq!(issuer_h8.unwrap(), root.as_hashedid8());
    }

    #[test]
    fn certificate_decode_pythonpki_certs_if_present() {
        let rca_path = std::path::Path::new(
            "/home/jordimarias/Desktop/IDIADAPKI/pythonpki/rca_data/rca_cert.coer",
        );
        let ea_path =
            std::path::Path::new("/home/jordimarias/Desktop/IDIADAPKI/pythonpki/ea_data/cert.coer");
        let aa_path =
            std::path::Path::new("/home/jordimarias/Desktop/IDIADAPKI/pythonpki/aa_data/cert.coer");

        if rca_path.exists() {
            let bytes = std::fs::read(rca_path).expect("read rca");
            let cert = Certificate::from_bytes(&bytes, None);
            assert_eq!(cert.base().r_type, CertificateType::explicit);
        }
        if ea_path.exists() {
            let bytes = std::fs::read(ea_path).expect("read ea");
            let cert = Certificate::from_bytes(&bytes, None);
            assert_eq!(cert.base().r_type, CertificateType::explicit);
        }
        if aa_path.exists() {
            let bytes = std::fs::read(aa_path).expect("read aa");
            let cert = Certificate::from_bytes(&bytes, None);
            assert_eq!(cert.base().r_type, CertificateType::explicit);
        }
    }

    #[test]
    fn test_to_canonical() {
        use crate::security::security_asn::ieee1609_dot2_base_types::EccP256CurvePointUncompressedP256;

        let uncompressed_x = vec![1u8; 32];
        let mut uncompressed_y_even = vec![2u8; 31];
        uncompressed_y_even.push(2); // even y -> compressed_y_0
        let mut uncompressed_y_odd = vec![2u8; 31];
        uncompressed_y_odd.push(3); // odd y -> compressed_y_1

        // 1. Uncompressed verification key (even) and compressed_y_0 r_sig
        let mut tbs_even = make_root_tbs();
        tbs_even.verify_key_indicator =
            VerificationKeyIndicator::verificationKey(PublicVerificationKey::ecdsaNistP256(
                EccP256CurvePoint::uncompressedP256(EccP256CurvePointUncompressedP256 {
                    x: uncompressed_x.clone().into(),
                    y: uncompressed_y_even.into(),
                }),
            ));

        let sig_even = Ieee1609Signature::ecdsaNistP256Signature(EcdsaP256Signature {
            r_sig: EccP256CurvePoint::compressed_y_0(vec![5u8; 32].into()),
            s_sig: vec![6u8; 32].into(),
        });

        let base_even = CertificateBase::new(
            Uint8(3),
            CertificateType::explicit,
            IssuerIdentifier::R_self(HashAlgorithm::sha256),
            tbs_even,
            Some(sig_even),
        );

        let cert_even =
            Certificate::from_asn(EtsiTs103097Certificate(AsnCertificate(base_even)), None);
        let canon_even = cert_even.to_canonical();

        // Check key compressed to compressed_y_0
        match &canon_even.tbs().verify_key_indicator {
            VerificationKeyIndicator::verificationKey(PublicVerificationKey::ecdsaNistP256(
                EccP256CurvePoint::compressed_y_0(x),
            )) => {
                assert_eq!(x.as_ref(), uncompressed_x.as_slice());
            }
            _ => panic!("Expected compressed_y_0 verification key"),
        }

        // Check signature r_sig converted to x_only
        match &canon_even.base().signature {
            Some(Ieee1609Signature::ecdsaNistP256Signature(sig)) => {
                match &sig.r_sig {
                    EccP256CurvePoint::x_only(x) => {
                        assert_eq!(x.as_ref(), vec![5u8; 32].as_slice());
                    }
                    _ => panic!("Expected x_only r_sig"),
                }
                assert_eq!(sig.s_sig.as_ref(), vec![6u8; 32].as_slice());
            }
            _ => panic!("Expected ecdsaNistP256Signature"),
        }

        // 2. Uncompressed verification key (odd) and compressed_y_1 r_sig
        let mut tbs_odd = make_root_tbs();
        tbs_odd.verify_key_indicator =
            VerificationKeyIndicator::verificationKey(PublicVerificationKey::ecdsaNistP256(
                EccP256CurvePoint::uncompressedP256(EccP256CurvePointUncompressedP256 {
                    x: uncompressed_x.clone().into(),
                    y: uncompressed_y_odd.into(),
                }),
            ));

        let sig_odd = Ieee1609Signature::ecdsaNistP256Signature(EcdsaP256Signature {
            r_sig: EccP256CurvePoint::compressed_y_1(vec![7u8; 32].into()),
            s_sig: vec![8u8; 32].into(),
        });

        let base_odd = CertificateBase::new(
            Uint8(3),
            CertificateType::explicit,
            IssuerIdentifier::R_self(HashAlgorithm::sha256),
            tbs_odd,
            Some(sig_odd),
        );

        let cert_odd =
            Certificate::from_asn(EtsiTs103097Certificate(AsnCertificate(base_odd)), None);
        let canon_odd = cert_odd.to_canonical();

        match &canon_odd.tbs().verify_key_indicator {
            VerificationKeyIndicator::verificationKey(PublicVerificationKey::ecdsaNistP256(
                EccP256CurvePoint::compressed_y_1(x),
            )) => {
                assert_eq!(x.as_ref(), uncompressed_x.as_slice());
            }
            _ => panic!("Expected compressed_y_1 verification key"),
        }

        match &canon_odd.base().signature {
            Some(Ieee1609Signature::ecdsaNistP256Signature(sig)) => {
                match &sig.r_sig {
                    EccP256CurvePoint::x_only(x) => {
                        assert_eq!(x.as_ref(), vec![7u8; 32].as_slice());
                    }
                    _ => panic!("Expected x_only r_sig"),
                }
                assert_eq!(sig.s_sig.as_ref(), vec![8u8; 32].as_slice());
            }
            _ => panic!("Expected ecdsaNistP256Signature"),
        }

        // 3. Already canonical remains identical
        let canon_again = canon_even.to_canonical();
        assert_eq!(canon_even, canon_again);
    }

    #[test]
    fn test_as_hashedid8_canonical_equivalence() {
        use crate::security::security_asn::ieee1609_dot2_base_types::EccP256CurvePointUncompressedP256;

        let uncompressed_x = vec![1u8; 32];
        let mut uncompressed_y = vec![2u8; 31];
        uncompressed_y.push(2); // even -> compressed_y_0

        let mut tbs_uncomp = make_root_tbs();
        tbs_uncomp.verify_key_indicator =
            VerificationKeyIndicator::verificationKey(PublicVerificationKey::ecdsaNistP256(
                EccP256CurvePoint::uncompressedP256(EccP256CurvePointUncompressedP256 {
                    x: uncompressed_x.clone().into(),
                    y: uncompressed_y.into(),
                }),
            ));

        let sig = Ieee1609Signature::ecdsaNistP256Signature(EcdsaP256Signature {
            r_sig: EccP256CurvePoint::x_only(vec![5u8; 32].into()),
            s_sig: vec![6u8; 32].into(),
        });

        let cert_uncompressed = Certificate::from_asn(
            EtsiTs103097Certificate(AsnCertificate(CertificateBase::new(
                Uint8(3),
                CertificateType::explicit,
                IssuerIdentifier::R_self(HashAlgorithm::sha256),
                tbs_uncomp,
                Some(sig.clone()),
            ))),
            None,
        );

        let mut tbs_comp = make_root_tbs();
        tbs_comp.verify_key_indicator =
            VerificationKeyIndicator::verificationKey(PublicVerificationKey::ecdsaNistP256(
                EccP256CurvePoint::compressed_y_0(uncompressed_x.into()),
            ));

        let cert_compressed = Certificate::from_asn(
            EtsiTs103097Certificate(AsnCertificate(CertificateBase::new(
                Uint8(3),
                CertificateType::explicit,
                IssuerIdentifier::R_self(HashAlgorithm::sha256),
                tbs_comp,
                Some(sig),
            ))),
            None,
        );

        assert_eq!(
            cert_uncompressed.as_hashedid8(),
            cert_compressed.as_hashedid8()
        );
    }

    #[test]
    fn test_issued_certificate_digest_verification() {
        use crate::security::security_asn::ieee1609_dot2::CertificateId;
        use crate::security::security_asn::ieee1609_dot2_base_types::Hostname;

        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        assert!(root.verify(&backend));

        let child = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(), &root);
        assert!(child.verify(&backend));

        // Tamper with toBeSigned in child cert
        let mut tampered_base = child.cert.base().clone();
        tampered_base.to_be_signed.id = CertificateId::name(Hostname("tampered-ee".to_string()));
        let tampered_cert = Certificate::from_asn(
            EtsiTs103097Certificate(AsnCertificate(tampered_base)),
            Some(root.cert.clone()),
        );
        assert!(!tampered_cert.verify(&backend));
    }
}
