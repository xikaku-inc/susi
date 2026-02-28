use std::path::Path;

use chrono::{DateTime, Utc};
use susi_core::{
    crypto::{public_key_from_pem, verify_license},
    fingerprint, LicenseError, LicensePayload, SignedLicense,
};
use rsa::RsaPublicKey;

/// Result of a license verification.
#[derive(Debug)]
pub enum LicenseStatus {
    Valid {
        payload: LicensePayload,
    },
    /// License still works but the lease has expired and is in the grace period.
    /// Client should attempt to renew ASAP.
    ValidGracePeriod {
        payload: LicensePayload,
        lease_expired_at: DateTime<Utc>,
    },
    Expired {
        expired_at: DateTime<Utc>,
    },
    /// The lease has expired (including grace period). Must renew.
    LeaseExpired {
        lease_expired_at: DateTime<Utc>,
    },
    InvalidMachine {
        expected: Vec<String>,
        actual: String,
    },
    InvalidSignature,
    TokenNotFound,
    FileNotFound(String),
    Error(String),
}

impl LicenseStatus {
    pub fn is_valid(&self) -> bool {
        matches!(self, LicenseStatus::Valid { .. } | LicenseStatus::ValidGracePeriod { .. })
    }

    pub fn needs_renewal(&self) -> bool {
        matches!(self, LicenseStatus::ValidGracePeriod { .. } | LicenseStatus::LeaseExpired { .. })
    }

    /// Check if a specific feature is available in this license.
    pub fn has_feature(&self, feature: &str) -> bool {
        match self {
            LicenseStatus::Valid { payload } | LicenseStatus::ValidGracePeriod { payload, .. } => {
                payload.has_feature(feature)
            }
            _ => false,
        }
    }

    /// Get the list of features if the license is valid.
    pub fn features(&self) -> Vec<String> {
        match self {
            LicenseStatus::Valid { payload } | LicenseStatus::ValidGracePeriod { payload, .. } => {
                payload.features.clone()
            }
            _ => vec![],
        }
    }

    /// Get the expiry date if the license is valid. `None` for perpetual.
    pub fn expires(&self) -> Option<DateTime<Utc>> {
        match self {
            LicenseStatus::Valid { payload } | LicenseStatus::ValidGracePeriod { payload, .. } => {
                payload.expires
            }
            _ => None,
        }
    }

    /// Get the lease expiry if present.
    pub fn lease_expires(&self) -> Option<DateTime<Utc>> {
        match self {
            LicenseStatus::Valid { payload } | LicenseStatus::ValidGracePeriod { payload, .. } => {
                payload.lease_expires
            }
            _ => None,
        }
    }
}

/// Client for verifying licenses. Embedded in the FusionHub application.
pub struct LicenseClient {
    public_key: RsaPublicKey,
    server_url: Option<String>,
    /// Grace period in hours after lease expiry. Default: 24.
    grace_hours: i64,
}

impl LicenseClient {
    /// Create a new client from a PEM-encoded public key string.
    pub fn new(public_key_pem: &str) -> Result<Self, LicenseError> {
        let public_key = public_key_from_pem(public_key_pem)?;
        Ok(Self {
            public_key,
            server_url: None,
            grace_hours: susi_core::DEFAULT_LEASE_GRACE_HOURS as i64,
        })
    }

    /// Create a new client with an optional server URL for online refresh.
    pub fn with_server(public_key_pem: &str, server_url: String) -> Result<Self, LicenseError> {
        let mut client = Self::new(public_key_pem)?;
        client.server_url = Some(server_url);
        Ok(client)
    }

    /// Set the grace period (hours) for lease expiry.
    pub fn set_grace_hours(&mut self, hours: i64) {
        self.grace_hours = hours;
    }

    /// Verify a signed license file on disk.
    pub fn verify_file(&self, path: &Path) -> LicenseStatus {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => return LicenseStatus::FileNotFound(format!("{}: {}", path.display(), e)),
        };

        let signed: SignedLicense = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => return LicenseStatus::Error(format!("Invalid license file format: {}", e)),
        };

        self.verify_signed(&signed)
    }

    /// Verify a SignedLicense object (e.g. received from server or loaded from disk).
    pub fn verify_signed(&self, signed: &SignedLicense) -> LicenseStatus {
        let payload = match verify_license(&self.public_key, signed) {
            Ok(p) => p,
            Err(LicenseError::InvalidSignature) => return LicenseStatus::InvalidSignature,
            Err(e) => return LicenseStatus::Error(format!("Verification error: {}", e)),
        };

        if payload.is_expired() {
            return LicenseStatus::Expired {
                expired_at: payload.expires.unwrap(),
            };
        }

        // Check machine code if the payload has machine restrictions
        if !payload.machine_codes.is_empty() {
            match fingerprint::get_machine_code() {
                Ok(local_code) => {
                    if !payload.is_machine_authorized(&local_code) {
                        return LicenseStatus::InvalidMachine {
                            expected: payload.machine_codes.clone(),
                            actual: local_code,
                        };
                    }
                }
                Err(e) => {
                    return LicenseStatus::Error(format!(
                        "Could not compute machine fingerprint: {}",
                        e
                    ));
                }
            }
        }

        // Check lease expiry
        if payload.is_lease_expired() {
            if payload.is_in_grace_period(self.grace_hours) {
                return LicenseStatus::ValidGracePeriod {
                    lease_expired_at: payload.lease_expires.unwrap(),
                    payload,
                };
            }
            return LicenseStatus::LeaseExpired {
                lease_expired_at: payload.lease_expires.unwrap(),
            };
        }

        LicenseStatus::Valid { payload }
    }

    /// Try to refresh the license from the server, falling back to the local file.
    /// This both renews the lease and verifies the license.
    pub fn verify_and_refresh(&self, path: &Path, license_key: &str) -> LicenseStatus {
        if let Some(ref server_url) = self.server_url {
            match self.try_online_activate(server_url, license_key) {
                Ok(signed) => {
                    if let Ok(json) = serde_json::to_string_pretty(&signed) {
                        let _ = std::fs::write(path, json);
                    }
                    return self.verify_signed(&signed);
                }
                Err(e) => {
                    log::warn!("Online license refresh failed, using cached file: {}", e);
                }
            }
        }

        // Fall back to local file
        self.verify_file(path)
    }

    fn try_online_activate(
        &self,
        server_url: &str,
        license_key: &str,
    ) -> Result<SignedLicense, String> {
        let machine_code = fingerprint::get_machine_code()
            .map_err(|e| format!("Fingerprint error: {}", e))?;

        let friendly_name = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_default();

        let url = format!("{}/activate", server_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "license_key": license_key,
            "machine_code": machine_code,
            "friendly_name": friendly_name,
        });

        let response = reqwest::blocking::Client::new()
            .post(&url)
            .json(&body)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_default();
            return Err(format!("Server returned {}: {}", status, text));
        }

        response
            .json::<SignedLicense>()
            .map_err(|e| format!("Invalid server response: {}", e))
    }

    /// Verify a license from a connected USB hardware token.
    /// Scans all connected USB mass storage devices for a valid token.
    pub fn verify_token(&self) -> LicenseStatus {
        let devices = match susi_core::usb::enumerate_usb_devices() {
            Ok(d) => d,
            Err(e) => return LicenseStatus::Error(format!("USB enumeration failed: {}", e)),
        };

        if devices.is_empty() {
            return LicenseStatus::TokenNotFound;
        }

        let mut last_error = String::new();

        for device in &devices {
            let token_path = susi_core::token::token_file_path(&device.mount_path);
            if !token_path.exists() {
                continue;
            }

            match susi_core::token::read_token(&device.mount_path, &device.serial) {
                Ok(signed) => {
                    let status = self.verify_signed(&signed);
                    if status.is_valid() {
                        return status;
                    }
                    last_error = format!("Token on {} invalid: {:?}", device.mount_path.display(), status);
                }
                Err(e) => {
                    last_error = format!(
                        "Token on {} decryption failed: {}",
                        device.mount_path.display(), e
                    );
                    continue;
                }
            }
        }

        if last_error.is_empty() {
            LicenseStatus::TokenNotFound
        } else {
            LicenseStatus::Error(format!("No valid USB token found. Last error: {}", last_error))
        }
    }

    /// Get the machine code for the current machine.
    pub fn get_machine_code() -> Result<String, LicenseError> {
        fingerprint::get_machine_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use susi_core::crypto::{generate_keypair, private_key_to_pem, public_key_to_pem, sign_license};

    fn make_keypair_pems() -> (String, String, rsa::RsaPrivateKey) {
        let (private, public) = generate_keypair(2048).unwrap();
        let priv_pem = private_key_to_pem(&private).unwrap();
        let pub_pem = public_key_to_pem(&public).unwrap();
        (priv_pem, pub_pem, private)
    }

    fn make_valid_payload(machine_code: Option<String>) -> LicensePayload {
        LicensePayload {
            id: "test-id".to_string(),
            product: "FusionHub".to_string(),
            customer: "Test Corp".to_string(),
            license_key: "AAAA-BBBB-CCCC-DDDD".to_string(),
            created: Utc::now(),
            expires: Some(Utc::now() + Duration::days(365)),
            features: vec!["full_fusion".to_string(), "recorder".to_string()],
            machine_codes: machine_code.into_iter().collect(),
            lease_expires: None,
        }
    }

    #[test]
    fn test_client_creation() {
        let (_, pub_pem, _) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem);
        assert!(client.is_ok());
    }

    #[test]
    fn test_verify_valid_license() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem).unwrap();
        let payload = make_valid_payload(None);
        let signed = sign_license(&private, &payload).unwrap();

        let status = client.verify_signed(&signed);
        assert!(status.is_valid());
        assert!(status.has_feature("full_fusion"));
        assert!(status.has_feature("recorder"));
        assert!(!status.has_feature("vehicular"));
    }

    #[test]
    fn test_verify_expired_license() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem).unwrap();
        let payload = LicensePayload {
            id: "test".to_string(),
            product: "FusionHub".to_string(),
            customer: "Test".to_string(),
            license_key: "AAAA-BBBB-CCCC-DDDD".to_string(),
            created: Utc::now() - Duration::days(60),
            expires: Some(Utc::now() - Duration::days(1)),
            features: vec![],
            machine_codes: vec![],
            lease_expires: None,
        };
        let signed = sign_license(&private, &payload).unwrap();

        let status = client.verify_signed(&signed);
        assert!(!status.is_valid());
        assert!(matches!(status, LicenseStatus::Expired { .. }));
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let (_, _, private) = make_keypair_pems();
        let (_, wrong_pub_pem, _) = make_keypair_pems();
        let client = LicenseClient::new(&wrong_pub_pem).unwrap();
        let payload = make_valid_payload(None);
        let signed = sign_license(&private, &payload).unwrap();

        let status = client.verify_signed(&signed);
        assert!(matches!(status, LicenseStatus::InvalidSignature));
    }

    #[test]
    fn test_verify_machine_locked_license() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem).unwrap();
        let local_code = LicenseClient::get_machine_code().unwrap();

        // License locked to this machine
        let payload = make_valid_payload(Some(local_code.clone()));
        let signed = sign_license(&private, &payload).unwrap();
        let status = client.verify_signed(&signed);
        assert!(status.is_valid());

        // License locked to a different machine
        let payload = make_valid_payload(Some("wrong_machine_code".to_string()));
        let signed = sign_license(&private, &payload).unwrap();
        let status = client.verify_signed(&signed);
        assert!(matches!(status, LicenseStatus::InvalidMachine { .. }));
    }

    #[test]
    fn test_verify_file_not_found() {
        let (_, pub_pem, _) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem).unwrap();
        let status = client.verify_file(Path::new("/nonexistent/license.json"));
        assert!(matches!(status, LicenseStatus::FileNotFound(_)));
    }

    #[test]
    fn test_verify_file_roundtrip() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem).unwrap();
        let payload = make_valid_payload(None);
        let signed = sign_license(&private, &payload).unwrap();

        let tmp = std::env::temp_dir().join("test_license_verify.json");
        let json = serde_json::to_string_pretty(&signed).unwrap();
        std::fs::write(&tmp, &json).unwrap();

        let status = client.verify_file(&tmp);
        assert!(status.is_valid());
        assert_eq!(status.features(), vec!["full_fusion", "recorder"]);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_verify_perpetual_license() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem).unwrap();
        let payload = LicensePayload {
            id: "perpetual".to_string(),
            product: "FusionHub".to_string(),
            customer: "Perpetual Corp".to_string(),
            license_key: "PPPP-PPPP-PPPP-PPPP".to_string(),
            created: Utc::now(),
            expires: None,
            features: vec!["full_fusion".to_string()],
            machine_codes: vec![],
            lease_expires: None,
        };
        let signed = sign_license(&private, &payload).unwrap();

        let status = client.verify_signed(&signed);
        assert!(status.is_valid());
        assert!(status.expires().is_none());
        assert!(status.has_feature("full_fusion"));
    }

    #[test]
    fn test_verify_valid_lease() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem).unwrap();
        let mut payload = make_valid_payload(None);
        payload.lease_expires = Some(Utc::now() + Duration::days(7));
        let signed = sign_license(&private, &payload).unwrap();

        let status = client.verify_signed(&signed);
        assert!(status.is_valid());
        assert!(!status.needs_renewal());
        assert!(status.lease_expires().is_some());
    }

    #[test]
    fn test_verify_expired_lease_in_grace() {
        let (_, pub_pem, private) = make_keypair_pems();
        let mut client = LicenseClient::new(&pub_pem).unwrap();
        client.set_grace_hours(24);

        let mut payload = make_valid_payload(None);
        payload.lease_expires = Some(Utc::now() - Duration::hours(2)); // expired 2h ago
        let signed = sign_license(&private, &payload).unwrap();

        let status = client.verify_signed(&signed);
        assert!(status.is_valid()); // still valid in grace
        assert!(status.needs_renewal());
        assert!(matches!(status, LicenseStatus::ValidGracePeriod { .. }));
    }

    #[test]
    fn test_verify_expired_lease_past_grace() {
        let (_, pub_pem, private) = make_keypair_pems();
        let mut client = LicenseClient::new(&pub_pem).unwrap();
        client.set_grace_hours(24);

        let mut payload = make_valid_payload(None);
        payload.lease_expires = Some(Utc::now() - Duration::hours(48)); // expired 48h ago
        let signed = sign_license(&private, &payload).unwrap();

        let status = client.verify_signed(&signed);
        assert!(!status.is_valid());
        assert!(matches!(status, LicenseStatus::LeaseExpired { .. }));
    }

    #[test]
    fn test_verify_no_lease_enforcement() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem).unwrap();
        let mut payload = make_valid_payload(None);
        payload.lease_expires = None;
        let signed = sign_license(&private, &payload).unwrap();

        let status = client.verify_signed(&signed);
        assert!(status.is_valid());
        assert!(!status.needs_renewal());
    }

    #[test]
    fn test_status_features_on_invalid() {
        let status = LicenseStatus::InvalidSignature;
        assert!(!status.is_valid());
        assert!(!status.has_feature("anything"));
        assert!(status.features().is_empty());
        assert!(status.expires().is_none());
    }
}
