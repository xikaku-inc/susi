use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

const HKDF_SALT: &[u8] = b"susi-clock-v1";
const HKDF_INFO: &[u8] = b"clock-mark";
const NONCE_SIZE: usize = 12;

fn cipher(machine_code: &str) -> Aes256Gcm {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(HKDF_SALT), machine_code.as_bytes())
        .expand(HKDF_INFO, &mut key)
        .expect("32 bytes is a valid HKDF length");
    Aes256Gcm::new(&key.into())
}

/// Encrypt a time so that it can only be read, unchanged, on this machine.
pub fn seal_time(time: DateTime<Utc>, machine_code: &str) -> Vec<u8> {
    let mut blob = vec![0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut blob);
    let ciphertext = cipher(machine_code)
        .encrypt(Nonce::from_slice(&blob), time.timestamp_micros().to_le_bytes().as_ref())
        .expect("AES-GCM encryption of 8 bytes cannot fail");
    blob.extend_from_slice(&ciphertext);
    blob
}

/// Decrypt a time from [`seal_time`]. `None` if the blob was changed or
/// sealed on another machine.
pub fn open_time(blob: &[u8], machine_code: &str) -> Option<DateTime<Utc>> {
    if blob.len() < NONCE_SIZE {
        return None;
    }
    let (nonce, ciphertext) = blob.split_at(NONCE_SIZE);
    let plain = cipher(machine_code).decrypt(Nonce::from_slice(nonce), ciphertext).ok()?;
    DateTime::from_timestamp_micros(i64::from_le_bytes(plain.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_time_opens_only_unchanged_on_the_same_machine() {
        let time = DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
        let blob = seal_time(time, "machine-a");
        assert_eq!(open_time(&blob, "machine-a"), Some(time));
        assert_eq!(open_time(&blob, "machine-b"), None);

        let mut changed = blob.clone();
        changed[NONCE_SIZE] ^= 1;
        assert_eq!(open_time(&changed, "machine-a"), None);
        assert_eq!(open_time(time.to_rfc3339().as_bytes(), "machine-a"), None);
        assert_eq!(open_time(&[], "machine-a"), None);
    }
}
