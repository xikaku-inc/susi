use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{
    pkcs1v15::{SigningKey, VerifyingKey},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};

use crate::error::LicenseError;

/// A licensing method that the client may use to verify a license.
/// The order in which methods appear in [`LicenseProperties::methods`] defines
/// the order in which they are tried.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LicenseMethod {
    File,
    Token,
    Server,
}

/// Client-side licensing properties. Specifies which licensing methods
/// to attempt (in order) and any admin-controlled parameters (server URL,
/// cache path, local license file path). Runtime-specific parameters
/// (license key, friendly name) are supplied when the properties are
/// verified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicenseProperties {
    pub server_url: String,
    pub methods: Vec<LicenseMethod>,
}

/// A signed license properties that can be written to disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLicenseProperties {
    /// JSON-serialized LicenseProperties (canonical form).
    pub properties_data: String,
    /// Base64-encoded RSA-SHA256 signature of `properties_data`.
    pub signature: String,
}

/// Sign a [`LicenseProperties`] with the admin's private key and return the susi-properties.json
pub fn sign_properties(
    private_key: &RsaPrivateKey,
    properties: &LicenseProperties,
) -> Result<SignedLicenseProperties, LicenseError> {
     let properties_data = serde_json::to_string(properties)?;
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let signature = signing_key.sign(properties_data.as_bytes());
    let signature_b64 = BASE64.encode(signature.to_bytes());

    Ok(SignedLicenseProperties {
        properties_data,
        signature: signature_b64,
    })
}

/// Verify a binary signed `susi-properties.json` with the public key and
/// return the underlying [`LicenseProperties`].
pub fn verify_properties(
    public_key: &RsaPublicKey,
    signed: &SignedLicenseProperties,
) -> Result<LicenseProperties, LicenseError> {
    let signature_bytes = BASE64.decode(&signed.signature)?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());
    let signature = rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| LicenseError::InvalidSignature)?;

    verifying_key
        .verify(signed.properties_data.as_bytes(), &signature)
        .map_err(|_| LicenseError::InvalidSignature)?;

    let payload: LicenseProperties = serde_json::from_str(&signed.properties_data)?;

    if payload.methods.is_empty() {
        return Err(LicenseError::InvalidProperties("At least one license method must be specified".to_string()));
    } else if (1..payload.methods.len()).any(|i| payload.methods[i..].contains(&payload.methods[i - 1])) {
        return Err(LicenseError::InvalidProperties("Duplicate license methods are not allowed".to_string()));
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;

    fn sample_properties() -> LicenseProperties {
        LicenseProperties {
            server_url: "https://license.example.com".to_string(),
            methods: vec![
                LicenseMethod::Server,
                LicenseMethod::File,
                LicenseMethod::Token,
            ],
        }
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (priv_key, pub_key) = generate_keypair(2048).unwrap();
        let properties = sample_properties();
        let signed = sign_properties(&priv_key, &properties).unwrap();
        let verified = verify_properties(&pub_key, &signed).unwrap();
        assert_eq!(verified, properties);
    }

    #[test]
    fn test_tampered_payload_fails_verification() {
        let (priv_key, pub_key) = generate_keypair(2048).unwrap();
        let mut signed = sign_properties(&priv_key, &sample_properties()).unwrap();
        signed.properties_data = signed.properties_data.replace("license.example.com", "attacker.example.com");
        let err = verify_properties(&pub_key, &signed);
        assert!(matches!(err, Err(LicenseError::InvalidSignature)));
    }

    #[test]
    fn test_tampered_signature_fails_verification() {
        let (priv_key, pub_key) = generate_keypair(2048).unwrap();
        let mut signed = sign_properties(&priv_key, &sample_properties()).unwrap();
        let first = signed.signature.chars().next().unwrap();
        let replacement = if first == 'A' { 'B' } else { 'A' };
        signed.signature = replacement.to_string() + &signed.signature[1..];
        let err = verify_properties(&pub_key, &signed);
        assert!(err.is_err());
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let (priv_key, _) = generate_keypair(2048).unwrap();
        let (_, wrong_pub) = generate_keypair(2048).unwrap();
        let signed = sign_properties(&priv_key, &sample_properties()).unwrap();
        let err = verify_properties(&wrong_pub, &signed);
        assert!(matches!(err, Err(LicenseError::InvalidSignature)));
    }

    #[test]
    fn test_invalid_json_is_rejected() {
        let (priv_key, pub_key) = generate_keypair(2048).unwrap();
        let mut signed = sign_properties(&priv_key, &sample_properties()).unwrap();
        signed.properties_data = "not valid json".to_string();
        assert!(verify_properties(&pub_key, &signed).is_err());
    }

    #[test]
    fn test_invalid_base64_signature_is_rejected() {
        let (priv_key, pub_key) = generate_keypair(2048).unwrap();
        let mut signed = sign_properties(&priv_key, &sample_properties()).unwrap();
        signed.signature = "!!!not-base64!!!".to_string();
        assert!(verify_properties(&pub_key, &signed).is_err());
    }

    #[test]
    fn test_invalid_no_signature_is_rejected() {
        let (priv_key, pub_key) = generate_keypair(2048).unwrap();
        let mut signed = sign_properties(&priv_key, &sample_properties()).unwrap();
        signed.signature = String::new();
        assert!(verify_properties(&pub_key, &signed).is_err());
    }

    #[test]
    fn test_empty_methods_is_rejected() {
        let (priv_key, pub_key) = generate_keypair(2048).unwrap();
        let props = LicenseProperties { server_url: "https://license.example.com".to_string(), methods: vec![] };
        let signed = sign_properties(&priv_key, &props).unwrap();
        assert!(verify_properties(&pub_key, &signed).is_err());
    }

    #[test]
    fn test_duplicate_methods_is_rejected() {
        let (priv_key, pub_key) = generate_keypair(2048).unwrap();
        let props = LicenseProperties { server_url: "https://license.example.com".to_string(), methods: vec![LicenseMethod::File, LicenseMethod::Token, LicenseMethod::File] };
        let signed = sign_properties(&priv_key, &props).unwrap();
        assert!(verify_properties(&pub_key, &signed).is_err());
    }
}
