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
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::security::security_asn::ieee1609_dot2_base_types::PublicVerificationKey;
use crate::security::security_asn::ieee1609_dot2_base_types::Signature as Ieee1609Signature;
use crate::security::security_asn::ieee1609_dot2_base_types::{
    EccP256CurvePoint, EccP256CurvePointUncompressedP256, EcdsaP256Signature,
};

/// ECDSA backend managing NIST P-256 key pairs.
#[derive(Clone, Debug)]
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
    /// Defaults to compressed format (compressed_y_0/1) per IEEE 1609.2 / ETSI TS 103 097.
    pub fn get_public_key(&self, id: usize) -> PublicVerificationKey {
        self.get_public_key_compressed(id, true)
    }

    /// Return the public verification key in IEEE 1609.2 format, optionally compressed.
    pub fn get_public_key_compressed(&self, id: usize, compressed: bool) -> PublicVerificationKey {
        let vk = self.keys[&id].verifying_key();
        if compressed {
            let pt = vk.to_encoded_point(true);
            let tag = pt.as_bytes()[0];
            let x = pt.x().expect("x coord").to_vec().into();
            let curve_point = if tag == 0x02 {
                EccP256CurvePoint::compressed_y_0(x)
            } else {
                EccP256CurvePoint::compressed_y_1(x)
            };
            PublicVerificationKey::ecdsaNistP256(curve_point)
        } else {
            let pt = vk.to_encoded_point(false);
            let x = pt.x().expect("x coord").to_vec().into();
            let y = pt.y().expect("y coord").to_vec().into();
            PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::uncompressedP256(
                EccP256CurvePointUncompressedP256 { x, y },
            ))
        }
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
    /// Supports both compressed (compressed_y_0/1) and uncompressed public keys,
    /// and x_only, compressed_y_0, and compressed_y_1 signature r_sig.
    pub fn verify_with_pk(
        &self,
        data: &[u8],
        signature: &Ieee1609Signature,
        pk: &PublicVerificationKey,
    ) -> bool {
        let (r_bytes, s_bytes) = match signature {
            Ieee1609Signature::ecdsaNistP256Signature(sig) => {
                let r = match &sig.r_sig {
                    EccP256CurvePoint::x_only(b)
                    | EccP256CurvePoint::compressed_y_0(b)
                    | EccP256CurvePoint::compressed_y_1(b) => b.as_ref(),
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
        let vk = match point {
            EccP256CurvePoint::uncompressedP256(u) => {
                let mut sec1 = Vec::with_capacity(65);
                sec1.push(0x04);
                sec1.extend_from_slice(u.x.as_ref());
                sec1.extend_from_slice(u.y.as_ref());
                match VerifyingKey::from_sec1_bytes(&sec1) {
                    Ok(v) => v,
                    Err(_) => return false,
                }
            }
            EccP256CurvePoint::compressed_y_0(x) => {
                let mut sec1 = Vec::with_capacity(33);
                sec1.push(0x02);
                sec1.extend_from_slice(x.as_ref());
                match VerifyingKey::from_sec1_bytes(&sec1) {
                    Ok(v) => v,
                    Err(_) => return false,
                }
            }
            EccP256CurvePoint::compressed_y_1(x) => {
                let mut sec1 = Vec::with_capacity(33);
                sec1.push(0x03);
                sec1.extend_from_slice(x.as_ref());
                match VerifyingKey::from_sec1_bytes(&sec1) {
                    Ok(v) => v,
                    Err(_) => return false,
                }
            }
            _ => return false,
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
