use std::path::{Path, PathBuf};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

use crate::error::LicenseError;
use crate::license::SignedLicense;

const HKDF_SALT: &[u8] = b"susi-token-v1";
const HKDF_INFO: &[u8] = b"license-encryption";
const NONCE_SIZE: usize = 12;
const TOKEN_DIR: &str = ".susi";
const TOKEN_FILE: &str = "license.bin";

fn derive_key(usb_serial: &str) -> Result<[u8; 32], LicenseError> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), usb_serial.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .map_err(|e| LicenseError::TokenDecryptionFailed(format!("HKDF expand: {}", e)))?;
    Ok(key)
}

pub fn encrypt_token(signed: &SignedLicense, usb_serial: &str) -> Result<Vec<u8>, LicenseError> {
    let key_bytes = derive_key(usb_serial)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| LicenseError::UsbError(format!("AES init: {}", e)))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = serde_json::to_vec(signed)?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| LicenseError::UsbError(format!("AES encrypt: {}", e)))?;

    let mut blob = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

pub fn decrypt_token(blob: &[u8], usb_serial: &str) -> Result<SignedLicense, LicenseError> {
    if blob.len() < NONCE_SIZE + 16 {
        return Err(LicenseError::TokenDecryptionFailed(
            "Token file too short".to_string(),
        ));
    }

    let key_bytes = derive_key(usb_serial)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| LicenseError::TokenDecryptionFailed(format!("AES init: {}", e)))?;

    let nonce = Nonce::from_slice(&blob[..NONCE_SIZE]);
    let ciphertext = &blob[NONCE_SIZE..];

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        LicenseError::TokenDecryptionFailed(
            "Decryption failed (wrong USB device or corrupted token)".to_string(),
        )
    })?;

    let signed: SignedLicense = serde_json::from_slice(&plaintext)?;
    Ok(signed)
}

pub fn token_file_path(usb_mount: &Path) -> PathBuf {
    usb_mount.join(TOKEN_DIR).join(TOKEN_FILE)
}

pub fn write_token(
    usb_mount: &Path,
    signed: &SignedLicense,
    usb_serial: &str,
) -> Result<(), LicenseError> {
    let blob = encrypt_token(signed, usb_serial)?;
    let dir = usb_mount.join(TOKEN_DIR);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(token_file_path(usb_mount), blob)?;
    Ok(())
}

pub fn read_token(usb_mount: &Path, usb_serial: &str) -> Result<SignedLicense, LicenseError> {
    let path = token_file_path(usb_mount);
    let blob = std::fs::read(&path)?;
    decrypt_token(&blob, usb_serial)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let signed = SignedLicense {
            license_data: r#"{"id":"test","product":"FusionHub"}"#.to_string(),
            signature: "dGVzdHNpZw==".to_string(),
        };
        let serial = "ABC123DEF456";

        let blob = encrypt_token(&signed, serial).unwrap();
        assert!(blob.len() > NONCE_SIZE + 16);

        let decrypted = decrypt_token(&blob, serial).unwrap();
        assert_eq!(decrypted.license_data, signed.license_data);
        assert_eq!(decrypted.signature, signed.signature);
    }

    #[test]
    fn test_wrong_serial_fails() {
        let signed = SignedLicense {
            license_data: r#"{"id":"test"}"#.to_string(),
            signature: "dGVzdA==".to_string(),
        };
        let blob = encrypt_token(&signed, "CORRECT_SERIAL").unwrap();
        let result = decrypt_token(&blob, "WRONG_SERIAL");
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_blob_fails() {
        let signed = SignedLicense {
            license_data: r#"{"id":"test"}"#.to_string(),
            signature: "dGVzdA==".to_string(),
        };
        let mut blob = encrypt_token(&signed, "SERIAL").unwrap();
        if let Some(b) = blob.last_mut() {
            *b ^= 0xFF;
        }
        let result = decrypt_token(&blob, "SERIAL");
        assert!(result.is_err());
    }

    #[test]
    fn test_blob_too_short() {
        let result = decrypt_token(&[0u8; 10], "SERIAL");
        assert!(result.is_err());
    }
}
