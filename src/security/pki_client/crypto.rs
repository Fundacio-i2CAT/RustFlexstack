// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Sender-side cryptographic helpers for the ETSI C-ITS PKI client.
//!
//! Implements:
//! - IEEE 1609.2 §5.3.5 ECIES (encrypt only — ITS-S sends, PKI decrypts)
//! - KDF2 key derivation (two consecutive SHA-256 calls)
//! - AES-128-CCM symmetric encryption / decryption
//! - pskRecipInfo AES session-key reuse for response decryption
//! - HMAC-SHA256 for AT request `keyTag` computation
//! - ITS Time32 helper

use aes::Aes128;
use ccm::aead::Aead;
use ccm::consts::{U12, U16};
use ccm::Ccm;
use hmac::{Hmac, Mac};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::security::security_asn::ieee1609_dot2::One28BitCcmCiphertext;
use crate::security::security_asn::ieee1609_dot2_base_types::{
    BasePublicEncryptionKey, EccP256CurvePoint, EciesP256EncryptedKey, Opaque,
};

/// Unix timestamp of the ITS epoch: 2004-01-01 00:00:00 UTC.
pub const ITS_EPOCH_UNIX: u64 = 1_072_915_200;

/// Type alias for AES-128-CCM with 16-byte tag and 12-byte nonce.
pub type Aes128Ccm = Ccm<Aes128, U16, U12>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKey(String),
    EncryptionFailed,
    DecryptionFailed,
    InvalidNonceLength(usize),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidKey(msg) => write!(f, "Invalid ECC public key: {msg}"),
            CryptoError::EncryptionFailed => write!(f, "AES-128-CCM encryption failure"),
            CryptoError::DecryptionFailed => {
                write!(
                    f,
                    "AES-128-CCM decryption failure (invalid tag or corrupt ciphertext)"
                )
            }
            CryptoError::InvalidNonceLength(len) => {
                write!(f, "Invalid nonce length: expected 12 bytes, got {len}")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

/// Return current UTC time as a Time32 value (seconds since ITS epoch 2004-01-01 00:00:00 UTC).
pub fn now_time32() -> u32 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs();
    now.saturating_sub(ITS_EPOCH_UNIX) as u32
}

/// IEEE 1609.2 §5.3.5 KDF2 key derivation.
///
/// Derives two sub-keys from the ECDH shared x-coordinate and the COER-encoded recipient certificate:
/// - `k_enc`: 16 bytes (XOR-mask for session key A)
/// - `k_mac`: 32 bytes (HMAC-SHA256 key for authenticating `c = A ^ k_enc`)
pub fn kdf2(shared_x: &[u8], recipient_cert_coer: &[u8]) -> ([u8; 16], [u8; 32]) {
    let p1 = Sha256::digest(recipient_cert_coer);

    let mut h1_input = Vec::with_capacity(shared_x.len() + 4 + p1.len());
    h1_input.extend_from_slice(shared_x);
    h1_input.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    h1_input.extend_from_slice(&p1);
    let h1 = Sha256::digest(&h1_input);

    let mut h2_input = Vec::with_capacity(shared_x.len() + 4 + p1.len());
    h2_input.extend_from_slice(shared_x);
    h2_input.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
    h2_input.extend_from_slice(&p1);
    let h2 = Sha256::digest(&h2_input);

    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&h1);
    combined[32..].copy_from_slice(&h2);

    let mut k_enc = [0u8; 16];
    let mut k_mac = [0u8; 32];
    k_enc.copy_from_slice(&combined[..16]);
    k_mac.copy_from_slice(&combined[16..48]);

    (k_enc, k_mac)
}

/// Encrypt `plaintext` using AES-128-CCM with a 16-byte key and a 12-byte nonce.
///
/// Returns the ciphertext with the 16-byte authentication tag appended.
pub fn aes_ccm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use ccm::aead::KeyInit;
    let cipher = Aes128Ccm::new_from_slice(key).map_err(|_| CryptoError::EncryptionFailed)?;
    cipher
        .encrypt(nonce.into(), plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypt `ciphertext` (which includes 16-byte tag) using AES-128-CCM.
pub fn aes_ccm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use ccm::aead::KeyInit;
    let cipher = Aes128Ccm::new_from_slice(key).map_err(|_| CryptoError::DecryptionFailed)?;
    cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Convert a `p256::PublicKey` into a compressed `EccP256CurvePoint`.
pub fn compress_public_key(pub_key: &p256::PublicKey) -> EccP256CurvePoint {
    let point = pub_key.to_encoded_point(true);
    let tag = point.as_bytes()[0];
    let x_bytes = point.x().expect("x coord").to_vec();
    if tag == 0x02 {
        EccP256CurvePoint::compressed_y_0(x_bytes.into())
    } else {
        EccP256CurvePoint::compressed_y_1(x_bytes.into())
    }
}

/// Reconstruct a `p256::PublicKey` from an `EccP256CurvePoint`.
pub fn public_key_from_point(point: &EccP256CurvePoint) -> Result<p256::PublicKey, CryptoError> {
    match point {
        EccP256CurvePoint::compressed_y_0(x) => {
            let mut sec1 = Vec::with_capacity(33);
            sec1.push(0x02);
            sec1.extend_from_slice(x.as_ref());
            p256::PublicKey::from_sec1_bytes(&sec1)
                .map_err(|e| CryptoError::InvalidKey(e.to_string()))
        }
        EccP256CurvePoint::compressed_y_1(x) => {
            let mut sec1 = Vec::with_capacity(33);
            sec1.push(0x03);
            sec1.extend_from_slice(x.as_ref());
            p256::PublicKey::from_sec1_bytes(&sec1)
                .map_err(|e| CryptoError::InvalidKey(e.to_string()))
        }
        EccP256CurvePoint::uncompressedP256(u) => {
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(u.x.as_ref());
            sec1.extend_from_slice(u.y.as_ref());
            p256::PublicKey::from_sec1_bytes(&sec1)
                .map_err(|e| CryptoError::InvalidKey(e.to_string()))
        }
        _ => Err(CryptoError::InvalidKey(
            "Unsupported ECC point format for ECIES".into(),
        )),
    }
}

/// Reconstruct a `p256::PublicKey` from a `BasePublicEncryptionKey`.
pub fn public_key_from_base_enc_key(
    enc_key: &BasePublicEncryptionKey,
) -> Result<p256::PublicKey, CryptoError> {
    match enc_key {
        BasePublicEncryptionKey::eciesNistP256(pt) => public_key_from_point(pt),
        _ => Err(CryptoError::InvalidKey(
            "Unsupported encryption key algorithm (must be eciesNistP256)".into(),
        )),
    }
}

/// IEEE 1609.2 §5.3.5 ECIES encrypt — ITS-S sender side.
///
/// Encrypts `plaintext` towards recipient public key, diversified by `recipient_cert_coer`.
/// Returns:
/// - `EciesP256EncryptedKey`: KEM structure containing `v`, `c`, `t`
/// - `One28BitCcmCiphertext`: DEM structure containing `nonce` and `ccmCiphertext`
/// - `session_key_a`: 16-byte random session key (kept in memory for response decryption)
/// - `session_key_hashedid8`: last 8 bytes of `SHA-256(session_key_a)`
pub fn ecies_encrypt(
    plaintext: &[u8],
    recipient_pub: &p256::PublicKey,
    recipient_cert_coer: &[u8],
) -> Result<
    (
        EciesP256EncryptedKey,
        One28BitCcmCiphertext,
        [u8; 16],
        [u8; 8],
    ),
    CryptoError,
> {
    // 1. Ephemeral key pair
    let ephemeral_secret = SecretKey::random(&mut rand::thread_rng());
    let ephemeral_pub = ephemeral_secret.public_key();

    // 2. ECDH shared x-coordinate
    let shared = diffie_hellman(
        ephemeral_secret.to_nonzero_scalar(),
        recipient_pub.as_affine(),
    );
    let shared_x = shared.raw_secret_bytes();

    // 3. KDF2
    let (k_enc, k_mac) = kdf2(shared_x.as_ref(), recipient_cert_coer);

    // 4. Random session key A (16 bytes) and nonce n (12 bytes)
    let mut session_key_a = [0u8; 16];
    let mut nonce_n = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut session_key_a);
    rand::thread_rng().fill_bytes(&mut nonce_n);

    // 5. KEM: c = A ^ k_enc, t = HMAC-SHA256(k_mac, c)[..16]
    let mut c = [0u8; 16];
    for i in 0..16 {
        c[i] = session_key_a[i] ^ k_enc[i];
    }

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&k_mac).expect("valid HMAC key");
    mac.update(&c);
    let mac_result = mac.finalize().into_bytes();
    let mut t = [0u8; 16];
    t.copy_from_slice(&mac_result[..16]);

    // 6. DEM: AES-128-CCM with session key A
    let ciphertext_c = aes_ccm_encrypt(&session_key_a, &nonce_n, plaintext)?;

    // 7. Ephemeral public key V in compressed form
    let v_point = compress_public_key(&ephemeral_pub);

    let ecies_key = EciesP256EncryptedKey::new(v_point, c.to_vec().into(), t.to_vec().into());
    let aes_ccm = One28BitCcmCiphertext::new(nonce_n.to_vec().into(), Opaque(ciphertext_c.into()));

    // 8. HashedId8(A) = SHA-256(A)[24..32]
    let digest = Sha256::digest(session_key_a);
    let mut session_key_hashedid8 = [0u8; 8];
    session_key_hashedid8.copy_from_slice(&digest[24..32]);

    Ok((ecies_key, aes_ccm, session_key_a, session_key_hashedid8))
}

/// Decrypt a PKI response using `pskRecipInfo` (AES session-key reuse).
pub fn psk_decrypt(
    session_key_a: &[u8; 16],
    aes_ccm: &One28BitCcmCiphertext,
) -> Result<Vec<u8>, CryptoError> {
    let nonce_bytes = aes_ccm.nonce.as_ref();
    if nonce_bytes.len() != 12 {
        return Err(CryptoError::InvalidNonceLength(nonce_bytes.len()));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_bytes);

    aes_ccm_decrypt(session_key_a, &nonce, aes_ccm.ccm_ciphertext.0.as_ref())
}

/// Compute the AT request `keyTag` field:
/// `keyTag = HMAC-SHA256(hmacKey, COER(PublicKeys))[:16]`
pub fn compute_hmac_key_tag(hmac_key: &[u8], public_keys_coer: &[u8]) -> [u8; 16] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key).expect("valid HMAC key");
    mac.update(public_keys_coer);
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&result[..16]);
    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now_time32_range() {
        let t = now_time32();
        let expected = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - ITS_EPOCH_UNIX;
        assert!((t as i64 - expected as i64).abs() <= 2);
    }

    #[test]
    fn test_kdf2_lengths_and_determinism() {
        let shared_x = [0x11u8; 32];
        let cert_coer = vec![0x22u8; 100];
        let (k_enc, k_mac) = kdf2(&shared_x, &cert_coer);

        assert_eq!(k_enc.len(), 16);
        assert_eq!(k_mac.len(), 32);

        // Deterministic
        let (k_enc2, k_mac2) = kdf2(&shared_x, &cert_coer);
        assert_eq!(k_enc, k_enc2);
        assert_eq!(k_mac, k_mac2);

        // Different input yields different keys
        let (k_enc3, _) = kdf2(&[0x33u8; 32], &cert_coer);
        assert_ne!(k_enc, k_enc3);
    }

    #[test]
    fn test_aes_ccm_encrypt_decrypt() {
        let key = [0x42u8; 16];
        let nonce = [0x24u8; 12];
        let plaintext = b"Sensitive ITS message payload 12345";

        let ciphertext = aes_ccm_encrypt(&key, &nonce, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // 16-byte tag

        let recovered = aes_ccm_decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_aes_ccm_decrypt_invalid_tag() {
        let key = [0x42u8; 16];
        let nonce = [0x24u8; 12];
        let plaintext = b"Hello World";

        let mut ciphertext = aes_ccm_encrypt(&key, &nonce, plaintext).unwrap();
        ciphertext[0] ^= 0xFF; // corrupt ciphertext

        assert_eq!(
            aes_ccm_decrypt(&key, &nonce, &ciphertext),
            Err(CryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn test_compress_and_reconstruct_public_key() {
        let secret = SecretKey::random(&mut rand::thread_rng());
        let pub_key = secret.public_key();

        let point = compress_public_key(&pub_key);
        let recovered = public_key_from_point(&point).unwrap();
        assert_eq!(pub_key, recovered);
    }

    #[test]
    fn test_ecies_encrypt_and_decrypt() {
        let recipient_secret = SecretKey::random(&mut rand::thread_rng());
        let recipient_pub = recipient_secret.public_key();
        let cert_coer = b"dummy_cert_coer_representation_12345";
        let plaintext = b"Payload for PKI recipient (EA/AA)";

        let (ecies_key, aes_ccm, session_key_a, session_key_hid8) =
            ecies_encrypt(plaintext, &recipient_pub, cert_coer).unwrap();

        assert_eq!(ecies_key.c.as_ref().len(), 16);
        assert_eq!(ecies_key.t.as_ref().len(), 16);
        assert_eq!(aes_ccm.nonce.as_ref().len(), 12);
        assert_eq!(session_key_a.len(), 16);
        assert_eq!(session_key_hid8.len(), 8);

        // Verify session_key_hid8 is last 8 bytes of SHA-256(session_key_a)
        let digest = Sha256::digest(session_key_a);
        assert_eq!(session_key_hid8, &digest[24..32]);

        // Recipient manual decrypt (KEM recovery)
        let eph_pub = public_key_from_point(&ecies_key.v).unwrap();
        let shared = diffie_hellman(recipient_secret.to_nonzero_scalar(), eph_pub.as_affine());
        let shared_x = shared.raw_secret_bytes();
        let (k_enc, k_mac) = kdf2(shared_x.as_ref(), cert_coer);

        // Check tag
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&k_mac).unwrap();
        mac.update(ecies_key.c.as_ref());
        let expected_t = &mac.finalize().into_bytes()[..16];
        assert_eq!(ecies_key.t.as_ref(), expected_t);

        // Recover A
        let mut recovered_a = [0u8; 16];
        for i in 0..16 {
            recovered_a[i] = ecies_key.c.as_ref()[i] ^ k_enc[i];
        }
        assert_eq!(recovered_a, session_key_a);

        // Decrypt ciphertext using psk_decrypt
        let decrypted = psk_decrypt(&session_key_a, &aes_ccm).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_compute_hmac_key_tag() {
        let hmac_key = [0x55u8; 32];
        let public_keys_coer = b"coer_encoded_public_keys_data";

        let tag = compute_hmac_key_tag(&hmac_key, public_keys_coer);
        assert_eq!(tag.len(), 16);

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&hmac_key).unwrap();
        mac.update(public_keys_coer);
        let expected = &mac.finalize().into_bytes()[..16];
        assert_eq!(tag, expected);
    }
}
