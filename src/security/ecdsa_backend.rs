//! ECDSA backend — signing with NIST P-256 (default), brainpoolP256r1,
//! brainpoolP384r1 and NIST P-384 keys (the curves of the IEEE 1609.2
//! PublicVerificationKey choices) and verification on the same curves.
//!
//! Uses the `p256` + `ecdsa` crates.  Keys are stored in an in-memory map
//! keyed by sequential integer identifiers, mirroring the Python
//! `PythonECDSABackend`.
//!
//! All public-key and signature representations use the IEEE 1609.2 /
//! `security_asn` types so they can be embedded directly into certificates
//! and signed messages without conversion.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256, Sha384};
use std::collections::HashMap;

use crate::security::security_asn::ieee1609_dot2_base_types::PublicVerificationKey;
use crate::security::security_asn::ieee1609_dot2_base_types::Signature as Ieee1609Signature;
use crate::security::security_asn::ieee1609_dot2_base_types::{
    EccP256CurvePoint, EccP256CurvePointUncompressedP256, EccP384CurvePoint, EcdsaP256Signature,
    EcdsaP384Signature,
};

/// Hash used with a verification key: SHA-384 for the 384-bit curves,
/// SHA-256 otherwise (IEEE 1609.2 clause 5.3.1).
pub fn key_uses_sha384(pk: &PublicVerificationKey) -> bool {
    matches!(
        pk,
        PublicVerificationKey::ecdsaBrainpoolP384r1(_) | PublicVerificationKey::ecdsaNistP384(_)
    )
}

/// SEC1 encoding of a 256-bit curve point (compressed or uncompressed).
fn p256_sec1(point: &EccP256CurvePoint) -> Option<Vec<u8>> {
    Some(match point {
        EccP256CurvePoint::uncompressedP256(u) => [&[0x04], u.x.as_ref(), u.y.as_ref()].concat(),
        EccP256CurvePoint::compressed_y_0(x) => [&[0x02], x.as_ref()].concat(),
        EccP256CurvePoint::compressed_y_1(x) => [&[0x03], x.as_ref()].concat(),
        _ => return None,
    })
}

/// SEC1 encoding of a 384-bit curve point (compressed or uncompressed).
fn p384_sec1(point: &EccP384CurvePoint) -> Option<Vec<u8>> {
    Some(match point {
        EccP384CurvePoint::uncompressedP384(u) => [&[0x04], u.x.as_ref(), u.y.as_ref()].concat(),
        EccP384CurvePoint::compressed_y_0(x) => [&[0x02], x.as_ref()].concat(),
        EccP384CurvePoint::compressed_y_1(x) => [&[0x03], x.as_ref()].concat(),
        _ => return None,
    })
}

/// r || s of a 256-bit signature; r is the x coordinate of R in any point form.
fn p256_rs(sig: &EcdsaP256Signature) -> Option<Vec<u8>> {
    let r = match &sig.r_sig {
        EccP256CurvePoint::x_only(b)
        | EccP256CurvePoint::compressed_y_0(b)
        | EccP256CurvePoint::compressed_y_1(b) => b.as_ref(),
        EccP256CurvePoint::uncompressedP256(u) => u.x.as_ref(),
        _ => return None,
    };
    Some([r, sig.s_sig.as_ref()].concat())
}

/// r || s of a 384-bit signature; r is the x coordinate of R in any point form.
fn p384_rs(sig: &EcdsaP384Signature) -> Option<Vec<u8>> {
    let r = match &sig.r_sig {
        EccP384CurvePoint::x_only(b)
        | EccP384CurvePoint::compressed_y_0(b)
        | EccP384CurvePoint::compressed_y_1(b) => b.as_ref(),
        EccP384CurvePoint::uncompressedP384(u) => u.x.as_ref(),
        _ => return None,
    };
    Some([r, sig.s_sig.as_ref()].concat())
}

/// ECQV public key extraction (SEC 4 v1.0 section 3.5, as profiled by IEEE
/// Std 1609.2-2016 clause 5.3.2): Q_U = e * P_U + Q_CA on the curve of the
/// issuer key (NIST P-256 or brainpoolP256r1). `e` is the big-endian integer
/// hash of the implicit certificate (`Certificate::implicit_hash_integer`).
pub fn reconstruct_public_key(
    reconstruction_value: &EccP256CurvePoint,
    issuer_key: &PublicVerificationKey,
    e: &[u8; 32],
) -> Option<PublicVerificationKey> {
    let rv = p256_sec1(reconstruction_value)?;
    match issuer_key {
        PublicVerificationKey::ecdsaNistP256(point) => {
            use p256::elliptic_curve::ff::PrimeField;
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            let p_u = p256::PublicKey::from_sec1_bytes(&rv).ok()?;
            let q_ca = p256::PublicKey::from_sec1_bytes(&p256_sec1(point)?).ok()?;
            let e = Option::<p256::Scalar>::from(p256::Scalar::from_repr((*e).into()))?;
            let q_u = p_u.to_projective() * e + q_ca.to_projective();
            let encoded = p256::PublicKey::from_affine(q_u.to_affine())
                .ok()?
                .to_encoded_point(false);
            Some(PublicVerificationKey::ecdsaNistP256(
                EccP256CurvePoint::uncompressedP256(EccP256CurvePointUncompressedP256 {
                    x: encoded.x()?.to_vec().into(),
                    y: encoded.y()?.to_vec().into(),
                }),
            ))
        }
        PublicVerificationKey::ecdsaBrainpoolP256r1(point) => {
            let q_u = bp256_reconstruct(&rv, &p256_sec1(point)?, e)?;
            Some(PublicVerificationKey::ecdsaBrainpoolP256r1(
                EccP256CurvePoint::uncompressedP256(EccP256CurvePointUncompressedP256 {
                    x: q_u[1..33].to_vec().into(),
                    y: q_u[33..65].to_vec().into(),
                }),
            ))
        }
        _ => None,
    }
}

/// e * P_U + Q_CA on brainpoolP256r1, as an uncompressed SEC1 point.
fn bp256_reconstruct(p_u: &[u8], q_ca: &[u8], e: &[u8; 32]) -> Option<Vec<u8>> {
    use bp256::elliptic_curve::ff::PrimeField;
    use bp256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
    let decode = |bytes: &[u8]| -> Option<bp256::r1::AffinePoint> {
        let point = bp256::r1::Sec1Point::from_bytes(bytes).ok()?;
        Option::from(bp256::r1::AffinePoint::from_sec1_point(&point))
    };
    let p_u = bp256::r1::ProjectivePoint::from(decode(p_u)?);
    let q_ca = bp256::r1::ProjectivePoint::from(decode(q_ca)?);
    let e = Option::<bp256::r1::Scalar>::from(bp256::r1::Scalar::from_repr((*e).into()))?;
    let q_u = (p_u * e + q_ca).to_affine();
    Some(q_u.to_sec1_point(false).as_bytes().to_vec())
}

/// ECDSA verification of a pre-computed digest on a brainpool curve (RustCrypto
/// `ecdsa` 0.17 stack).
macro_rules! brainpool_verify {
    ($name:ident, $curve:ty) => {
        fn $name(sec1: &[u8], rs: &[u8], digest: &[u8]) -> bool {
            use ecdsa_v017::signature::hazmat::PrehashVerifier as _;
            match (
                ecdsa_v017::VerifyingKey::<$curve>::from_sec1_bytes(sec1),
                ecdsa_v017::Signature::<$curve>::from_slice(rs),
            ) {
                (Ok(vk), Ok(sig)) => vk.verify_prehash(digest, &sig).is_ok(),
                _ => false,
            }
        }
    };
}
brainpool_verify!(verify_bp256, bp256::BrainpoolP256r1);
brainpool_verify!(verify_bp384, bp384::BrainpoolP384r1);

/// Curve of an own key pair (an IEEE 1609.2 PublicVerificationKey curve).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    NistP256,
    BrainpoolP256r1,
    BrainpoolP384r1,
    NistP384,
}

#[derive(Clone, Debug)]
enum OwnKey {
    NistP256(SigningKey),
    BrainpoolP256r1(ecdsa_v017::elliptic_curve::SecretKey<bp256::BrainpoolP256r1>),
    BrainpoolP384r1(ecdsa_v017::elliptic_curve::SecretKey<bp384::BrainpoolP384r1>),
    NistP384(p384::ecdsa::SigningKey),
}

/// IEEE 1609.2 point of a SEC1 encoding (02/03 || x, or 04 || x || y).
fn p256_point(sec1: &[u8]) -> EccP256CurvePoint {
    match sec1[0] {
        0x02 => EccP256CurvePoint::compressed_y_0(sec1[1..33].to_vec().into()),
        0x03 => EccP256CurvePoint::compressed_y_1(sec1[1..33].to_vec().into()),
        _ => EccP256CurvePoint::uncompressedP256(EccP256CurvePointUncompressedP256 {
            x: sec1[1..33].to_vec().into(),
            y: sec1[33..65].to_vec().into(),
        }),
    }
}

fn p384_point(sec1: &[u8]) -> EccP384CurvePoint {
    use crate::security::security_asn::ieee1609_dot2_base_types::EccP384CurvePointUncompressedP384;
    match sec1[0] {
        0x02 => EccP384CurvePoint::compressed_y_0(sec1[1..49].to_vec().into()),
        0x03 => EccP384CurvePoint::compressed_y_1(sec1[1..49].to_vec().into()),
        _ => EccP384CurvePoint::uncompressedP384(EccP384CurvePointUncompressedP384 {
            x: sec1[1..49].to_vec().into(),
            y: sec1[49..97].to_vec().into(),
        }),
    }
}

/// ECDSA backend managing own key pairs.
#[derive(Clone, Debug)]
pub struct EcdsaBackend {
    keys: HashMap<usize, OwnKey>,
    next_id: usize,
}

impl EcdsaBackend {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            next_id: 0,
        }
    }

    /// Generate a new P-256 key pair.  Returns the key identifier.
    pub fn create_key(&mut self) -> usize {
        self.create_key_with(KeyAlgorithm::NistP256)
    }

    /// Generate a new key pair on `algorithm`.  Returns the key identifier.
    pub fn create_key_with(&mut self, algorithm: KeyAlgorithm) -> usize {
        let mut rng = rand::thread_rng();
        let key = match algorithm {
            KeyAlgorithm::NistP256 => OwnKey::NistP256(SigningKey::random(&mut rng)),
            KeyAlgorithm::BrainpoolP256r1 => OwnKey::BrainpoolP256r1(random_secret(&mut rng)),
            KeyAlgorithm::BrainpoolP384r1 => OwnKey::BrainpoolP384r1(random_secret(&mut rng)),
            KeyAlgorithm::NistP384 => OwnKey::NistP384(p384::ecdsa::SigningKey::random(&mut rng)),
        };
        let id = self.next_id;
        self.keys.insert(id, key);
        self.next_id += 1;
        id
    }

    /// Curve of the key pair `id`.
    pub fn algorithm(&self, id: usize) -> KeyAlgorithm {
        match self.keys[&id] {
            OwnKey::NistP256(_) => KeyAlgorithm::NistP256,
            OwnKey::BrainpoolP256r1(_) => KeyAlgorithm::BrainpoolP256r1,
            OwnKey::BrainpoolP384r1(_) => KeyAlgorithm::BrainpoolP384r1,
            OwnKey::NistP384(_) => KeyAlgorithm::NistP384,
        }
    }

    /// Return the public verification key in IEEE 1609.2 format.
    /// Defaults to compressed format (compressed_y_0/1) per IEEE 1609.2 / ETSI TS 103 097.
    pub fn get_public_key(&self, id: usize) -> PublicVerificationKey {
        self.get_public_key_compressed(id, true)
    }

    /// Return the public verification key in IEEE 1609.2 format, optionally compressed.
    pub fn get_public_key_compressed(&self, id: usize, compressed: bool) -> PublicVerificationKey {
        use ecdsa_v017::elliptic_curve::sec1::ToSec1Point;
        match &self.keys[&id] {
            OwnKey::NistP256(sk) => PublicVerificationKey::ecdsaNistP256(p256_point(
                sk.verifying_key().to_encoded_point(compressed).as_bytes(),
            )),
            OwnKey::BrainpoolP256r1(sk) => PublicVerificationKey::ecdsaBrainpoolP256r1(p256_point(
                sk.public_key().to_sec1_point(compressed).as_bytes(),
            )),
            OwnKey::BrainpoolP384r1(sk) => PublicVerificationKey::ecdsaBrainpoolP384r1(p384_point(
                sk.public_key().to_sec1_point(compressed).as_bytes(),
            )),
            OwnKey::NistP384(sk) => PublicVerificationKey::ecdsaNistP384(p384_point(
                sk.verifying_key().to_encoded_point(compressed).as_bytes(),
            )),
        }
    }

    /// Sign `data` with the hash of the key's curve (SHA-256 for the 256-bit
    /// curves, SHA-384 for the 384-bit ones); brainpool signatures use a
    /// fresh random nonce from the thread CSPRNG (FIPS 186-4 ECDSA). Returns
    /// an IEEE 1609.2 `Signature` with r as x-only.
    pub fn sign(&self, data: &[u8], id: usize) -> Ieee1609Signature {
        match &self.keys[&id] {
            OwnKey::NistP256(sk) => {
                let sig: Signature = sk.sign(data);
                let (r, s) = sig.split_bytes();
                Ieee1609Signature::ecdsaNistP256Signature(EcdsaP256Signature {
                    r_sig: EccP256CurvePoint::x_only(r.to_vec().into()),
                    s_sig: s.to_vec().into(),
                })
            }
            OwnKey::NistP384(sk) => {
                use p384::ecdsa::signature::hazmat::PrehashSigner as _;
                let sig: p384::ecdsa::Signature = sk
                    .sign_prehash(&Sha384::digest(data))
                    .expect("P-384 signature");
                let (r, s) = sig.split_bytes();
                Ieee1609Signature::ecdsaNistP384Signature(EcdsaP384Signature {
                    r_sig: EccP384CurvePoint::x_only(r.to_vec().into()),
                    s_sig: s.to_vec().into(),
                })
            }
            OwnKey::BrainpoolP256r1(sk) => {
                let bytes = brainpool_sign(sk, &Sha256::digest(data));
                Ieee1609Signature::ecdsaBrainpoolP256r1Signature(EcdsaP256Signature {
                    r_sig: EccP256CurvePoint::x_only(bytes[..32].to_vec().into()),
                    s_sig: bytes[32..].to_vec().into(),
                })
            }
            OwnKey::BrainpoolP384r1(sk) => {
                let bytes = brainpool_sign(sk, &Sha384::digest(data));
                Ieee1609Signature::ecdsaBrainpoolP384r1Signature(EcdsaP384Signature {
                    r_sig: EccP384CurvePoint::x_only(bytes[..48].to_vec().into()),
                    s_sig: bytes[48..].to_vec().into(),
                })
            }
        }
    }

    /// Verify `data` against `signature` with public key `pk`, both in IEEE
    /// 1609.2 format. `data` is hashed with the hash of the curve (SHA-256 for
    /// the 256-bit curves, SHA-384 for the 384-bit ones); for messages and
    /// certificates it is the 1609.2 signing input (see
    /// `certificate::signing_input`).
    ///
    /// Supported: NIST P-256, brainpoolP256r1, brainpoolP384r1 and NIST P-384,
    /// with r given as x-only, compressed or uncompressed point. A signature
    /// whose algorithm does not match the key is not valid.
    pub fn verify_with_pk(
        &self,
        data: &[u8],
        signature: &Ieee1609Signature,
        pk: &PublicVerificationKey,
    ) -> bool {
        match (signature, pk) {
            (
                Ieee1609Signature::ecdsaNistP256Signature(sig),
                PublicVerificationKey::ecdsaNistP256(point),
            ) => {
                let (Some(sec1), Some(rs)) = (p256_sec1(point), p256_rs(sig)) else {
                    return false;
                };
                match (
                    VerifyingKey::from_sec1_bytes(&sec1),
                    Signature::from_slice(&rs),
                ) {
                    (Ok(vk), Ok(sig)) => vk.verify(data, &sig).is_ok(),
                    _ => false,
                }
            }
            (
                Ieee1609Signature::ecdsaBrainpoolP256r1Signature(sig),
                PublicVerificationKey::ecdsaBrainpoolP256r1(point),
            ) => {
                let (Some(sec1), Some(rs)) = (p256_sec1(point), p256_rs(sig)) else {
                    return false;
                };
                verify_bp256(&sec1, &rs, &Sha256::digest(data))
            }
            (
                Ieee1609Signature::ecdsaBrainpoolP384r1Signature(sig),
                PublicVerificationKey::ecdsaBrainpoolP384r1(point),
            ) => {
                let (Some(sec1), Some(rs)) = (p384_sec1(point), p384_rs(sig)) else {
                    return false;
                };
                verify_bp384(&sec1, &rs, &Sha384::digest(data))
            }
            (
                Ieee1609Signature::ecdsaNistP384Signature(sig),
                PublicVerificationKey::ecdsaNistP384(point),
            ) => {
                let (Some(sec1), Some(rs)) = (p384_sec1(point), p384_rs(sig)) else {
                    return false;
                };
                use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
                match (
                    p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1),
                    p384::ecdsa::Signature::from_slice(&rs),
                ) {
                    (Ok(vk), Ok(sig)) => vk.verify_prehash(&Sha384::digest(data), &sig).is_ok(),
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// Export the private scalar of the signing key (big-endian bytes).
    pub fn export_signing_key(&self, id: usize) -> Vec<u8> {
        match &self.keys[&id] {
            OwnKey::NistP256(sk) => sk.to_bytes().to_vec(),
            OwnKey::BrainpoolP256r1(sk) => sk.to_bytes().to_vec(),
            OwnKey::BrainpoolP384r1(sk) => sk.to_bytes().to_vec(),
            OwnKey::NistP384(sk) => sk.to_bytes().to_vec(),
        }
    }

    /// Import a signing key on `algorithm` from its private scalar bytes.
    /// Returns the new key id.
    pub fn import_signing_key_with(&mut self, algorithm: KeyAlgorithm, key_bytes: &[u8]) -> usize {
        let key = match algorithm {
            KeyAlgorithm::NistP256 => {
                OwnKey::NistP256(SigningKey::from_slice(key_bytes).expect("invalid key bytes"))
            }
            KeyAlgorithm::BrainpoolP256r1 => OwnKey::BrainpoolP256r1(
                ecdsa_v017::elliptic_curve::SecretKey::from_slice(key_bytes)
                    .expect("invalid key bytes"),
            ),
            KeyAlgorithm::BrainpoolP384r1 => OwnKey::BrainpoolP384r1(
                ecdsa_v017::elliptic_curve::SecretKey::from_slice(key_bytes)
                    .expect("invalid key bytes"),
            ),
            KeyAlgorithm::NistP384 => OwnKey::NistP384(
                p384::ecdsa::SigningKey::from_slice(key_bytes).expect("invalid key bytes"),
            ),
        };
        let id = self.next_id;
        self.keys.insert(id, key);
        self.next_id += 1;
        id
    }

    /// Import a signing key from SEC1 DER bytes.  Returns the new key id.
    pub fn import_signing_key(&mut self, key_bytes: &[u8]) -> usize {
        self.import_signing_key_with(KeyAlgorithm::NistP256, key_bytes)
    }

    /// Hash the COER-encoded certificate bytes and return the last 8 bytes (HashedId8).
    pub fn hash_to_hashedid8(data: &[u8]) -> [u8; 8] {
        let digest = Sha256::digest(data);
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest[24..32]);
        out
    }
}

/// ECDSA signature (r || s) of the prehashed `digest` with a random nonce.
fn brainpool_sign<C>(sk: &ecdsa_v017::elliptic_curve::SecretKey<C>, digest: &[u8]) -> Vec<u8>
where
    C: ecdsa_v017::EcdsaCurve + ecdsa_v017::elliptic_curve::CurveArithmetic,
    ecdsa_v017::SignatureSize<C>: ecdsa_v017::elliptic_curve::array::ArraySize,
{
    let d = sk.to_nonzero_scalar();
    let mut rng = rand::thread_rng();
    loop {
        let k = random_secret::<C>(&mut rng).to_nonzero_scalar();
        if let Ok((sig, _)) = ecdsa_v017::hazmat::sign_prehashed::<C>(&d, &k, digest) {
            return sig.to_bytes().to_vec();
        }
    }
}

fn random_secret<C>(rng: &mut impl rand::RngCore) -> ecdsa_v017::elliptic_curve::SecretKey<C>
where
    C: ecdsa_v017::elliptic_curve::CurveArithmetic,
{
    loop {
        let mut bytes = vec![0u8; ecdsa_v017::elliptic_curve::FieldBytes::<C>::default().len()];
        rng.fill_bytes(&mut bytes);
        if let Ok(key) = ecdsa_v017::elliptic_curve::SecretKey::<C>::from_slice(&bytes) {
            return key;
        }
    }
}

impl Default for EcdsaBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_new_empty() {
        let backend = EcdsaBackend::new();
        assert_eq!(backend.next_id, 0);
        assert!(backend.keys.is_empty());
    }

    #[test]
    fn backend_default() {
        let backend = EcdsaBackend::default();
        assert_eq!(backend.next_id, 0);
    }

    #[test]
    fn create_key_returns_sequential_ids() {
        let mut backend = EcdsaBackend::new();
        assert_eq!(backend.create_key(), 0);
        assert_eq!(backend.create_key(), 1);
        assert_eq!(backend.create_key(), 2);
    }

    #[test]
    fn get_public_key_compressed_and_uncompressed() {
        let mut backend = EcdsaBackend::new();
        let id = backend.create_key();

        // Default is compressed (compressed_y_0 or compressed_y_1)
        let pk = backend.get_public_key(id);
        match pk {
            PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::compressed_y_0(x))
            | PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::compressed_y_1(x)) => {
                assert_eq!(x.as_ref().len(), 32);
            }
            _ => panic!("Expected compressed_y_0 or compressed_y_1"),
        }

        // Explicit uncompressed
        let pk_uncomp = backend.get_public_key_compressed(id, false);
        match pk_uncomp {
            PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::uncompressedP256(u)) => {
                assert_eq!(u.x.as_ref().len(), 32);
                assert_eq!(u.y.as_ref().len(), 32);
            }
            _ => panic!("Expected uncompressedP256"),
        }
    }

    #[test]
    fn sign_and_verify_both_key_formats() {
        let mut backend = EcdsaBackend::new();
        let id = backend.create_key();
        let data = b"Hello, ETSI C-ITS!";
        let signature = backend.sign(data, id);

        // Verify with default (compressed) public key
        let pk_comp = backend.get_public_key(id);
        assert!(backend.verify_with_pk(data, &signature, &pk_comp));
        assert!(!backend.verify_with_pk(b"wrong data", &signature, &pk_comp));

        // Verify with uncompressed public key
        let pk_uncomp = backend.get_public_key_compressed(id, false);
        assert!(backend.verify_with_pk(data, &signature, &pk_uncomp));
        assert!(!backend.verify_with_pk(b"wrong data", &signature, &pk_uncomp));
    }

    #[test]
    fn verify_with_compressed_r_sig() {
        let mut backend = EcdsaBackend::new();
        let id = backend.create_key();
        let data = b"Test signature with compressed r_sig";
        let sig = backend.sign(data, id);
        let pk = backend.get_public_key(id);

        let (r_bytes, s_bytes) = match sig {
            Ieee1609Signature::ecdsaNistP256Signature(s) => match s.r_sig {
                EccP256CurvePoint::x_only(b) => (b, s.s_sig),
                _ => panic!("Expected x_only"),
            },
            _ => panic!("Expected ecdsaNistP256Signature"),
        };

        // Construct signature with compressed_y_0
        let sig_y0 = Ieee1609Signature::ecdsaNistP256Signature(EcdsaP256Signature {
            r_sig: EccP256CurvePoint::compressed_y_0(r_bytes.clone()),
            s_sig: s_bytes.clone(),
        });
        assert!(backend.verify_with_pk(data, &sig_y0, &pk));

        // Construct signature with compressed_y_1
        let sig_y1 = Ieee1609Signature::ecdsaNistP256Signature(EcdsaP256Signature {
            r_sig: EccP256CurvePoint::compressed_y_1(r_bytes),
            s_sig: s_bytes,
        });
        assert!(backend.verify_with_pk(data, &sig_y1, &pk));
    }

    /// Own keys on NIST P-256/P-384 and brainpoolP256r1/P384r1: signature
    /// choice and sizes follow the curve; a signature verifies with its key
    /// (compressed or uncompressed) only.
    #[test]
    fn sign_and_verify_on_every_curve() {
        let mut backend = EcdsaBackend::new();
        for algorithm in [
            KeyAlgorithm::NistP256,
            KeyAlgorithm::BrainpoolP256r1,
            KeyAlgorithm::BrainpoolP384r1,
            KeyAlgorithm::NistP384,
        ] {
            let id = backend.create_key_with(algorithm);
            assert_eq!(backend.algorithm(id), algorithm);
            let sig = backend.sign(b"data", id);
            let size = match (&sig, algorithm) {
                (Ieee1609Signature::ecdsaNistP256Signature(s), KeyAlgorithm::NistP256)
                | (
                    Ieee1609Signature::ecdsaBrainpoolP256r1Signature(s),
                    KeyAlgorithm::BrainpoolP256r1,
                ) => s.s_sig.len(),
                (
                    Ieee1609Signature::ecdsaBrainpoolP384r1Signature(s),
                    KeyAlgorithm::BrainpoolP384r1,
                )
                | (Ieee1609Signature::ecdsaNistP384Signature(s), KeyAlgorithm::NistP384) => {
                    s.s_sig.len()
                }
                _ => panic!("{algorithm:?}: wrong signature choice"),
            };
            let expected = if matches!(
                algorithm,
                KeyAlgorithm::NistP256 | KeyAlgorithm::BrainpoolP256r1
            ) {
                32
            } else {
                48
            };
            assert_eq!(size, expected);
            for compressed in [true, false] {
                let pk = backend.get_public_key_compressed(id, compressed);
                assert!(backend.verify_with_pk(b"data", &sig, &pk), "{algorithm:?}");
                assert!(
                    !backend.verify_with_pk(b"other", &sig, &pk),
                    "{algorithm:?}"
                );
            }
            let copy = EcdsaBackend::new()
                .import_signing_key_with(algorithm, &backend.export_signing_key(id));
            assert_eq!(copy, 0);
        }
    }

    #[test]
    fn sign_and_verify() {
        let mut backend = EcdsaBackend::new();
        let id = backend.create_key();
        let data = b"Hello, ETSI C-ITS!";
        let signature = backend.sign(data, id);
        let pk = backend.get_public_key(id);
        assert!(backend.verify_with_pk(data, &signature, &pk));
    }

    #[test]
    fn sign_wrong_data_fails_verification() {
        let mut backend = EcdsaBackend::new();
        let id = backend.create_key();
        let signature = backend.sign(b"correct data", id);
        let pk = backend.get_public_key(id);
        assert!(!backend.verify_with_pk(b"wrong data", &signature, &pk));
    }

    #[test]
    fn sign_wrong_key_fails_verification() {
        let mut backend = EcdsaBackend::new();
        let id1 = backend.create_key();
        let id2 = backend.create_key();
        let data = b"test data";
        let signature = backend.sign(data, id1);
        let pk2 = backend.get_public_key(id2);
        assert!(!backend.verify_with_pk(data, &signature, &pk2));
    }

    #[test]
    fn export_import_key_roundtrip() {
        let mut backend = EcdsaBackend::new();
        let id = backend.create_key();
        let exported = backend.export_signing_key(id);
        assert_eq!(exported.len(), 32);

        let mut backend2 = EcdsaBackend::new();
        let id2 = backend2.import_signing_key(&exported);

        // Sign with original, verify with imported (same key)
        let data = b"roundtrip test";
        let sig = backend.sign(data, id);
        let pk = backend2.get_public_key(id2);
        assert!(backend2.verify_with_pk(data, &sig, &pk));
    }

    #[test]
    fn hash_to_hashedid8_deterministic() {
        let data = b"certificate bytes";
        let h1 = EcdsaBackend::hash_to_hashedid8(data);
        let h2 = EcdsaBackend::hash_to_hashedid8(data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 8);
    }

    #[test]
    fn hash_to_hashedid8_different_input() {
        let h1 = EcdsaBackend::hash_to_hashedid8(b"input1");
        let h2 = EcdsaBackend::hash_to_hashedid8(b"input2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_to_hashedid8_is_last_8_bytes_of_sha256() {
        let data = b"test";
        let digest = Sha256::digest(data);
        let expected: [u8; 8] = digest[24..32].try_into().unwrap();
        assert_eq!(EcdsaBackend::hash_to_hashedid8(data), expected);
    }
}
