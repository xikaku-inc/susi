use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{
    pkcs1v15::{SigningKey, VerifyingKey},
    RsaPrivateKey, RsaPublicKey,
};

use crate::error::LicenseError;
use crate::license::{LicensePayload, SignedLicense};

/// Generate an RSA keypair with the given bit size (2048 or 4096).
pub fn generate_keypair(bits: usize) -> Result<(RsaPrivateKey, RsaPublicKey), LicenseError> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);
    Ok((private_key, public_key))
}

/// Export a private key as PEM string.
pub fn private_key_to_pem(key: &RsaPrivateKey) -> Result<String, LicenseError> {
    key.to_pkcs8_pem(LineEnding::LF)
        .map(|s| s.to_string())
        .map_err(|e| LicenseError::Pem(e.to_string()))
}

/// Export a public key as PEM string.
pub fn public_key_to_pem(key: &RsaPublicKey) -> Result<String, LicenseError> {
    key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| LicenseError::Pem(e.to_string()))
}

/// Import a private key from PEM string.
pub fn private_key_from_pem(pem: &str) -> Result<RsaPrivateKey, LicenseError> {
    RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| LicenseError::Pem(e.to_string()))
}

/// Import a public key from PEM string.
pub fn public_key_from_pem(pem: &str) -> Result<RsaPublicKey, LicenseError> {
    RsaPublicKey::from_public_key_pem(pem).map_err(|e| LicenseError::Pem(e.to_string()))
}

/// Sign a license payload with the private key.
/// Returns a SignedLicense containing the canonical JSON and base64 signature.
pub fn sign_license(
    private_key: &RsaPrivateKey,
    payload: &LicensePayload,
) -> Result<SignedLicense, LicenseError> {
    let license_data = serde_json::to_string(payload)?;
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let signature = signing_key.sign(license_data.as_bytes());
    let signature_b64 = BASE64.encode(signature.to_bytes());

    Ok(SignedLicense {
        license_data,
        signature: signature_b64,
    })
}

/// Verify a signed license using the public key.
/// Returns the deserialized LicensePayload if the signature is valid.
pub fn verify_license(
    public_key: &RsaPublicKey,
    signed: &SignedLicense,
) -> Result<LicensePayload, LicenseError> {
    let signature_bytes = BASE64.decode(&signed.signature)?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());
    let signature = rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| LicenseError::InvalidSignature)?;

    verifying_key
        .verify(signed.license_data.as_bytes(), &signature)
        .map_err(|_| LicenseError::InvalidSignature)?;

    let payload: LicensePayload = serde_json::from_str(&signed.license_data)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn make_test_payload() -> LicensePayload {
        LicensePayload {
            id: "test-id".to_string(),
            product: "FusionHub".to_string(),
            customer: "Test Corp".to_string(),
            license_key: "AAAA-BBBB-CCCC-DDDD".to_string(),
            created: Utc::now(),
            expires: Some(Utc::now() + Duration::days(365)),
            features: vec!["full_fusion".to_string(), "recorder".to_string()],
            machine_codes: vec!["abc123def456".to_string()],
            lease_expires: None,
            lease_grace_period: None,
        }
    }

    #[test]
    fn test_keypair_generation() {
        let (private, public) = generate_keypair(2048).unwrap();
        // Verify we can export and re-import
        let priv_pem = private_key_to_pem(&private).unwrap();
        let pub_pem = public_key_to_pem(&public).unwrap();
        assert!(priv_pem.contains("BEGIN PRIVATE KEY"));
        assert!(pub_pem.contains("BEGIN PUBLIC KEY"));

        let private2 = private_key_from_pem(&priv_pem).unwrap();
        let public2 = public_key_from_pem(&pub_pem).unwrap();
        assert_eq!(private, private2);
        assert_eq!(public, public2);
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let (private, public) = generate_keypair(2048).unwrap();
        let payload = make_test_payload();

        let signed = sign_license(&private, &payload).unwrap();
        assert!(!signed.signature.is_empty());
        assert!(!signed.license_data.is_empty());

        let verified = verify_license(&public, &signed).unwrap();
        assert_eq!(verified.id, payload.id);
        assert_eq!(verified.product, payload.product);
        assert_eq!(verified.customer, payload.customer);
        assert_eq!(verified.license_key, payload.license_key);
        assert_eq!(verified.features, payload.features);
        assert_eq!(verified.machine_codes, payload.machine_codes);
    }

    #[test]
    fn test_tampered_data_fails_verification() {
        let (private, public) = generate_keypair(2048).unwrap();
        let payload = make_test_payload();

        let mut signed = sign_license(&private, &payload).unwrap();

        // Tamper with the license data
        signed.license_data = signed.license_data.replace("Test Corp", "Evil Corp");

        let result = verify_license(&public, &signed);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LicenseError::InvalidSignature));
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let (private, _) = generate_keypair(2048).unwrap();
        let (_, wrong_public) = generate_keypair(2048).unwrap();
        let payload = make_test_payload();

        let signed = sign_license(&private, &payload).unwrap();
        let result = verify_license(&wrong_public, &signed);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_signature_fails_verification() {
        let (private, public) = generate_keypair(2048).unwrap();
        let payload = make_test_payload();

        let mut signed = sign_license(&private, &payload).unwrap();

        // Corrupt the signature
        let mut sig_bytes = BASE64.decode(&signed.signature).unwrap();
        if let Some(byte) = sig_bytes.first_mut() {
            *byte ^= 0xFF;
        }
        signed.signature = BASE64.encode(&sig_bytes);

        let result = verify_license(&public, &signed);
        assert!(result.is_err());
    }

    #[test]
    fn test_signed_license_json_roundtrip() {
        let (private, public) = generate_keypair(2048).unwrap();
        let payload = make_test_payload();

        let signed = sign_license(&private, &payload).unwrap();

        // Serialize to JSON and back (simulates writing to disk)
        let json = serde_json::to_string_pretty(&signed).unwrap();
        let deserialized: SignedLicense = serde_json::from_str(&json).unwrap();

        let verified = verify_license(&public, &deserialized).unwrap();
        assert_eq!(verified.id, payload.id);
    }
}
