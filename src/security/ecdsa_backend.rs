//! ECDSA backend — NIST P-256 signing and verification.
//!
//! Uses the `p256` + `ecdsa` crates.  Keys are stored in an in-memory map
//! keyed by sequential integer identifiers, mirroring the Python
//! `PythonECDSABackend`.
//!
//! All public-key and signature representations use the IEEE 1609.2 /
//! `security_asn` types so they can be embedded directly into certificates
//! and signed messages without conversion.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::ecdsa::signature::Verifier;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::security::security_asn::ieee1609_dot2_base_types::{
    EccP256CurvePoint, EccP256CurvePointUncompressedP256, EcdsaP256Signature,
};
use crate::security::security_asn::ieee1609_dot2_base_types::{
    PublicVerificationKey,
};
use crate::security::security_asn::ieee1609_dot2_base_types::Signature as Ieee1609Signature;

/// ECDSA backend managing NIST P-256 key pairs.
pub struct EcdsaBackend {
    keys: HashMap<usize, SigningKey>,
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
        let sk = SigningKey::random(&mut rand::thread_rng());
        let id = self.next_id;
        self.keys.insert(id, sk);
        self.next_id += 1;
        id
    }

    /// Return the public verification key in IEEE 1609.2 format.
    pub fn get_public_key(&self, id: usize) -> PublicVerificationKey {
        let vk = self.keys[&id].verifying_key();
        let pt = vk.to_encoded_point(false);
        let x = pt.x().expect("x coord").to_vec().into();
        let y = pt.y().expect("y coord").to_vec().into();
        PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::uncompressedP256(
            EccP256CurvePointUncompressedP256 { x, y },
        ))
    }

    /// Sign `data` (pre-hash with SHA-256 is done by the `ecdsa` crate).
    /// Returns an IEEE 1609.2 `Signature`.
    pub fn sign(&self, data: &[u8], id: usize) -> Ieee1609Signature {
        let sk = &self.keys[&id];
        // Hash with SHA-256 first to match the Python behaviour (which signs
        // the raw data and lets the `ecdsa` library hash it).
        let sig: Signature = sk.sign(data);
        let (r_bytes, s_bytes) = sig.split_bytes();
        Ieee1609Signature::ecdsaNistP256Signature(EcdsaP256Signature {
            r_sig: EccP256CurvePoint::x_only(r_bytes.to_vec().into()),
            s_sig: s_bytes.to_vec().into(),
        })
    }

    /// Verify `data` against `signature` using public key `pk`.
    /// Both come in IEEE 1609.2 format.
    pub fn verify_with_pk(
        &self,
        data: &[u8],
        signature: &Ieee1609Signature,
        pk: &PublicVerificationKey,
    ) -> bool {
        let (r_bytes, s_bytes) = match signature {
            Ieee1609Signature::ecdsaNistP256Signature(sig) => {
                let r = match &sig.r_sig {
                    EccP256CurvePoint::x_only(b) => b.as_ref(),
                    _ => return false,
                };
                (r, sig.s_sig.as_ref())
            }
            _ => return false,
        };
        let point = match pk {
            PublicVerificationKey::ecdsaNistP256(pt) => pt,
            _ => return false,
        };
        let (x, y) = match point {
            EccP256CurvePoint::uncompressedP256(u) => (u.x.as_ref(), u.y.as_ref()),
            _ => return false,
        };
        // Reconstruct verifying key from uncompressed point
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(x);
        sec1.extend_from_slice(y);
        let vk = match VerifyingKey::from_sec1_bytes(&sec1) {
            Ok(v) => v,
            Err(_) => return false,
        };
        // Reconstruct ECDSA signature (r || s)
        let mut sig_bytes = Vec::with_capacity(64);
        sig_bytes.extend_from_slice(r_bytes);
        sig_bytes.extend_from_slice(s_bytes);
        let sig = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        vk.verify(data, &sig).is_ok()
    }

    /// Export the signing key as SEC1 DER bytes.
    pub fn export_signing_key(&self, id: usize) -> Vec<u8> {
        self.keys[&id].to_bytes().to_vec()
    }

    /// Import a signing key from SEC1 DER bytes.  Returns the new key id.
    pub fn import_signing_key(&mut self, key_bytes: &[u8]) -> usize {
        let sk = SigningKey::from_slice(key_bytes).expect("invalid key bytes");
        let id = self.next_id;
        self.keys.insert(id, sk);
        self.next_id += 1;
        id
    }

    /// Hash the COER-encoded certificate bytes and return the last 8 bytes (HashedId8).
    pub fn hash_to_hashedid8(data: &[u8]) -> [u8; 8] {
        let digest = Sha256::digest(data);
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest[24..32]);
        out
    }
}

impl Default for EcdsaBackend {
    fn default() -> Self {
        Self::new()
    }
}
