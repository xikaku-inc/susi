pub mod workspace;

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use susi_core::{
    crypto::{public_key_from_pem, verify_license},
    fingerprint, LicenseError, LicensePayload, SignedLicense,
};
use rsa::RsaPublicKey;

/// Run an async future to completion on a fresh current-thread tokio runtime.
/// Used by the blocking API wrappers. Must NOT be called from inside a tokio
/// runtime — in that case, call the `_async` variant directly.
pub(crate) fn blocking_run<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime for blocking susi_client call")
        .block_on(fut)
}

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
    InvalidLicenseKey,
    Revoked,
    /// Machine was removed by an administrator. Distinct from Revoked (which
    /// kills the whole license) — only this machine slot is affected. Re-activation
    /// is blocked for the tombstone window.
    Deactivated,
    /// No cached license on disk — the install has never been activated on
    /// this machine, or was explicitly deactivated. User must click Activate.
    NotActivated,
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
    /// Optional on-disk cache for the machine fingerprint. When set, once the
    /// fingerprint has been computed successfully it is reused on subsequent
    /// runs even if the underlying hardware ID lookup later fails transiently.
    machine_code_cache: Option<PathBuf>,
}

impl LicenseClient {
    /// Create a new client from a PEM-encoded public key string.
    pub fn new(public_key_pem: &str) -> Result<Self, LicenseError> {
        let public_key = public_key_from_pem(public_key_pem)?;
        Ok(Self {
            public_key,
            server_url: None,
            machine_code_cache: None,
        })
    }

    /// Create a new client with an optional server URL for online refresh.
    pub fn with_server(public_key_pem: &str, server_url: String) -> Result<Self, LicenseError> {
        let mut client = Self::new(public_key_pem)?;
        client.server_url = Some(server_url);
        Ok(client)
    }

    /// Set a path where the computed machine fingerprint is cached. See
    /// [`susi_core::fingerprint::get_or_cache_machine_code`].
    pub fn set_machine_code_cache<P: Into<PathBuf>>(&mut self, path: P) {
        self.machine_code_cache = Some(path.into());
    }

    /// Builder helper around [`Self::set_machine_code_cache`].
    pub fn with_machine_code_cache<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.set_machine_code_cache(path);
        self
    }

    fn current_machine_code(&self) -> Result<String, LicenseError> {
        match &self.machine_code_cache {
            Some(p) => fingerprint::get_or_cache_machine_code(p),
            None => fingerprint::get_machine_code(),
        }
    }

    /// Verify a signed license file on disk.
    pub fn verify_file(&self, path: &Path) -> LicenseStatus {
        blocking_run(self.verify_file_async(path))
    }

    /// Async variant of [`verify_file`].
    pub async fn verify_file_async(&self, path: &Path) -> LicenseStatus {
        let content = match tokio::fs::read_to_string(path).await {
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
     /// Use local machine code for machine check.
    pub fn verify_signed(&self, signed: &SignedLicense) -> LicenseStatus {
        match self.current_machine_code() {
            Ok(local_code) => {
                return self.verify_signed_with_activation_code(signed, &local_code);
            }
            Err(e) => {
                return LicenseStatus::Error(format!(
                    "Could not compute machine fingerprint: {}",
                    e
                ));
            }
        }
    }

    /// Verify a SignedLicense object (e.g. received from server or loaded from disk).
    /// Use given activation code for machine check.
    pub fn verify_signed_with_activation_code(&self, signed: &SignedLicense, activation_code: &str) -> LicenseStatus {
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
        if !payload.is_machine_authorized(&activation_code) {
            return LicenseStatus::InvalidMachine {
                expected: payload.machine_codes.clone(),
                actual: activation_code.to_string(),
            };
        }

        // Check lease expiry; prefer grace hours from the payload over the client default
        if payload.is_lease_expired() {
            let grace_hours = payload.lease_grace_period
                .map(|h| h as i64)
                .unwrap_or(susi_core::DEFAULT_LEASE_GRACE_HOURS as i64);
            if payload.is_in_grace_period(grace_hours) {
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

    /// Renew the lease for an already-activated machine via the server's
    /// `/verify` endpoint. Does NOT add a machine back if it was removed —
    /// that's the whole point of this method.
    ///
    /// Behavior:
    /// - No cached license on disk → [`LicenseStatus::NotActivated`]. The
    ///   install has never activated here (or was explicitly deactivated), so
    ///   we must not silently claim a slot on every startup.
    /// - Cached license + reachable server → `/verify` refreshes the signed
    ///   license and its lease; cache is overwritten.
    /// - Server says the machine is no longer activated → clear cache, report
    ///   [`LicenseStatus::Deactivated`].
    /// - Server unreachable / transient error → fall back to the cached file
    ///   (offline grace).
    ///
    /// For first-time activation, call [`Self::activate_async`] instead.
    pub fn verify_and_refresh(&self, path: &Path, license_key: &str, _friendly_name: Option<&str>) -> LicenseStatus {
        blocking_run(self.verify_and_refresh_async(path, license_key, _friendly_name))
    }

    /// Async variant of [`verify_and_refresh`].
    pub async fn verify_and_refresh_async(&self, path: &Path, license_key: &str, _friendly_name: Option<&str>) -> LicenseStatus {
        // Absence of a cached license is the canonical signal that this install
        // is not activated here. Never silently /activate in this path.
        if !path.exists() {
            return LicenseStatus::NotActivated;
        }

        if let Some(ref server_url) = self.server_url {
            match self.try_online_verify_async(server_url, license_key).await {
                Ok(signed) => {
                    if let Ok(json) = serde_json::to_string_pretty(&signed) {
                        let _ = tokio::fs::write(path, json).await;
                    }
                    return self.verify_signed(&signed);
                }
                Err(LicenseError::Revoked) => {
                    log::warn!("License revoked by server - removing cached file");
                    let _ = tokio::fs::remove_file(path).await;
                    return LicenseStatus::Revoked;
                }
                Err(LicenseError::Deactivated) => {
                    log::warn!("Machine no longer activated on server - removing cached file");
                    let _ = tokio::fs::remove_file(path).await;
                    return LicenseStatus::Deactivated;
                }
                Err(LicenseError::NotFound) => {
                    log::warn!("License not found on server - removing cached file");
                    let _ = tokio::fs::remove_file(path).await;
                    return LicenseStatus::InvalidLicenseKey;
                }
                Err(e) => {
                    log::warn!("Online license verify failed, using cached file: {}", e);
                }
            }
        } else {
            log::warn!("No server supplied. Falling back to cached file.");
        }

        self.verify_file_async(path).await
    }

    /// Explicit activation — user clicked the Activate button. Calls the
    /// server's `/activate` endpoint, claims a machine slot, and writes the
    /// signed license to `path`.
    pub fn activate(&self, path: &Path, license_key: &str, friendly_name: Option<&str>) -> LicenseStatus {
        blocking_run(self.activate_async(path, license_key, friendly_name))
    }

    /// Async variant of [`activate`].
    pub async fn activate_async(&self, path: &Path, license_key: &str, friendly_name: Option<&str>) -> LicenseStatus {
        let server_url = match &self.server_url {
            Some(u) => u.clone(),
            None => return LicenseStatus::Error("No license server configured".into()),
        };
        match self.try_online_activate_async(&server_url, license_key, friendly_name).await {
            Ok(signed) => {
                if let Ok(json) = serde_json::to_string_pretty(&signed) {
                    let _ = tokio::fs::write(path, json).await;
                }
                self.verify_signed(&signed)
            }
            Err(LicenseError::Revoked) => LicenseStatus::Revoked,
            Err(LicenseError::Deactivated) => LicenseStatus::Deactivated,
            Err(LicenseError::NotFound) => LicenseStatus::InvalidLicenseKey,
            Err(LicenseError::MachineLimitReached(max)) => {
                LicenseStatus::Error(format!("Machine limit reached: {}", max))
            }
            Err(e) => LicenseStatus::Error(format!("Activation failed: {}", e)),
        }
    }

    async fn try_online_verify_async(
        &self,
        server_url: &str,
        license_key: &str,
    ) -> Result<SignedLicense, LicenseError> {
        let machine_code = self.current_machine_code()
            .map_err(|e| LicenseError::Other(format!("Fingerprint error: {}", e)))?;

        let url = format!("{}/verify", server_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "license_key": license_key,
            "machine_code": machine_code,
        });

        let response = reqwest::Client::new()
            .post(&url)
            .json(&body)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| LicenseError::Other(format!("HTTP request failed: {}", e)))?;

        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            return response
                .json::<SignedLicense>()
                .await
                .map_err(|e| LicenseError::Other(format!("Invalid server response: {}", e)));
        }

        #[derive(serde::Deserialize)]
        struct ErrorBody { error: String }
        let msg = response.json::<ErrorBody>()
            .await
            .map(|b| b.error)
            .unwrap_or_default();

        // `/verify` on a removed machine returns 403 "Machine not authorized".
        // Semantically this is the same as tombstone-driven deactivation: the
        // machine is simply not in the active set anymore.
        Err(match status {
            404 => LicenseError::NotFound,
            403 if msg.contains("revoked") => LicenseError::Revoked,
            403 if msg.contains("not authorized") => LicenseError::Deactivated,
            403 if msg.contains("expired") => LicenseError::Expired(msg),
            _ => LicenseError::Other(format!("Server returned {}: {}", status, msg)),
        })
    }

    async fn try_online_activate_async(
        &self,
        server_url: &str,
        license_key: &str,
        friendly_name: Option<&str>,
    ) -> Result<SignedLicense, LicenseError> {
        let machine_code = self.current_machine_code()
            .map_err(|e| LicenseError::Other(format!("Fingerprint error: {}", e)))?;

        let friendly_name = friendly_name
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_default()
            });

        let url = format!("{}/activate", server_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "license_key": license_key,
            "machine_code": machine_code,
            "friendly_name": friendly_name,
        });

        let response = reqwest::Client::new()
            .post(&url)
            .json(&body)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| LicenseError::Other(format!("HTTP request failed: {}", e)))?;

        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            return response
                .json::<SignedLicense>()
                .await
                .map_err(|e| LicenseError::Other(format!("Invalid server response: {}", e)));
        }

        #[derive(serde::Deserialize)]
        struct ErrorBody { error: String }
        let msg = response.json::<ErrorBody>()
            .await
            .map(|b| b.error)
            .unwrap_or_default();

        Err(match status {
            404 => LicenseError::NotFound,
            403 if msg.contains("revoked") => LicenseError::Revoked,
            403 if msg.contains("removed by an administrator") => LicenseError::Deactivated,
            403 if msg.contains("expired") => LicenseError::Expired(msg),
            403 if msg.contains("Machine limit") => {
                let max = msg.split("max ").nth(1)
                    .and_then(|s| s.trim_end_matches(')').parse().ok())
                    .unwrap_or(0);
                LicenseError::MachineLimitReached(max)
            }
            _ => LicenseError::Other(format!("Server returned {}: {}", status, msg)),
        })
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
                    let activation_code = format!("usb:{}", device.serial);
                    let status = self.verify_signed_with_activation_code(&signed, &activation_code);
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
            lease_grace_period: None,
        }
    }

    // Real fingerprint lookup fails on some CI runners (e.g. GitHub's
    // ubuntu-latest where /sys/block/<disk>/serial is empty), which would
    // cause every verify_signed call to fall through to LicenseStatus::Error
    // regardless of actual signature validity. The tests do not care about
    // machine-binding — inject a stable synthetic code via the cache.
    const TEST_MACHINE_CODE: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    fn test_machine_code_cache() -> PathBuf {
        let path = std::env::temp_dir().join("susi_client_test_machine_code");
        let _ = std::fs::write(&path, TEST_MACHINE_CODE);
        path
    }

    fn new_test_client(pub_pem: &str) -> LicenseClient {
        LicenseClient::new(pub_pem)
            .unwrap()
            .with_machine_code_cache(test_machine_code_cache())
    }

    fn new_test_client_with_server(pub_pem: &str, server_url: String) -> LicenseClient {
        let mut client = LicenseClient::with_server(pub_pem, server_url).unwrap();
        client.set_machine_code_cache(test_machine_code_cache());
        client
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
        let client = new_test_client(&pub_pem);
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
        let client = new_test_client(&pub_pem);
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
            lease_grace_period: None,
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
        let client = new_test_client(&wrong_pub_pem);
        let payload = make_valid_payload(None);
        let signed = sign_license(&private, &payload).unwrap();

        let status = client.verify_signed(&signed);
        assert!(matches!(status, LicenseStatus::InvalidSignature));
    }

    #[test]
    fn test_verify_machine_locked_license() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = new_test_client(&pub_pem);

        // License locked to this machine (use the synthetic test code so the
        // client's cached fingerprint matches).
        let payload = make_valid_payload(Some(TEST_MACHINE_CODE.to_string()));
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
        let client = new_test_client(&pub_pem);
        let status = client.verify_file(Path::new("/nonexistent/license.json"));
        assert!(matches!(status, LicenseStatus::FileNotFound(_)));
    }

    #[test]
    fn test_verify_file_roundtrip() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = new_test_client(&pub_pem);
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
        let client = new_test_client(&pub_pem);
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
            lease_grace_period: None,
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
        let client = new_test_client(&pub_pem);
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
        let client = new_test_client(&pub_pem);

        let mut payload: LicensePayload = make_valid_payload(None);
        payload.lease_expires = Some(Utc::now() - Duration::hours(2)); // expired 2h ago
        payload.lease_grace_period = Some(24);
        let signed = sign_license(&private, &payload).unwrap();

        let status = client.verify_signed(&signed);
        assert!(status.is_valid()); // still valid in grace
        assert!(status.needs_renewal());
        assert!(matches!(status, LicenseStatus::ValidGracePeriod { .. }));
    }

    #[test]
    fn test_verify_expired_lease_past_grace() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = new_test_client(&pub_pem);

        let mut payload = make_valid_payload(None);
        payload.lease_expires = Some(Utc::now() - Duration::hours(48)); // expired 48h ago
        payload.lease_grace_period = Some(24);
        let signed = sign_license(&private, &payload).unwrap();

        let status = client.verify_signed(&signed);
        assert!(!status.is_valid());
        assert!(matches!(status, LicenseStatus::LeaseExpired { .. }));
    }

    #[test]
    fn test_verify_no_lease_enforcement() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = new_test_client(&pub_pem);
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

    // -----------------------------------------------------------------------
    // Async smoke tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_file_async_roundtrip() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = new_test_client(&pub_pem);
        let payload = make_valid_payload(None);
        let signed = sign_license(&private, &payload).unwrap();

        let tmp = std::env::temp_dir().join("test_license_verify_async.json");
        let json = serde_json::to_string_pretty(&signed).unwrap();
        tokio::fs::write(&tmp, &json).await.unwrap();

        let status = client.verify_file_async(&tmp).await;
        assert!(status.is_valid());
        assert_eq!(status.features(), vec!["full_fusion", "recorder"]);

        let _ = tokio::fs::remove_file(&tmp).await;
    }

    #[tokio::test]
    async fn test_verify_file_async_not_found() {
        let (_, pub_pem, _) = make_keypair_pems();
        let client = new_test_client(&pub_pem);
        let status = client.verify_file_async(Path::new("/nonexistent/license.json")).await;
        assert!(matches!(status, LicenseStatus::FileNotFound(_)));
    }

    #[tokio::test]
    async fn test_verify_and_refresh_async_no_server_falls_back_to_file() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = new_test_client(&pub_pem);
        // no server_url set
        let payload = make_valid_payload(None);
        let signed = sign_license(&private, &payload).unwrap();

        let tmp = std::env::temp_dir().join("test_license_refresh_async.json");
        let json = serde_json::to_string_pretty(&signed).unwrap();
        tokio::fs::write(&tmp, &json).await.unwrap();

        let status = client.verify_and_refresh_async(&tmp, "AAAA-BBBB-CCCC-DDDD", None).await;
        assert!(status.is_valid());

        let _ = tokio::fs::remove_file(&tmp).await;
    }

    #[tokio::test]
    async fn test_try_online_activate_async_network_error() {
        let (_, pub_pem, _) = make_keypair_pems();
        let client = new_test_client(&pub_pem);
        // 127.0.0.1:1 is reserved, TCP connect fails fast.
        let result = client
            .try_online_activate_async("http://127.0.0.1:1", "AAAA-BBBB-CCCC-DDDD", None)
            .await;
        assert!(matches!(result, Err(LicenseError::Other(_))));
    }

    /// Serve a single canned HTTP response on a free port and return the base URL.
    /// Minimal — just enough to exercise the /activate response parsing.
    async fn spawn_canned_http_response(status: u16, body: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Drain request headers so the client sees the response.
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let reason = match status {
                    403 => "Forbidden",
                    404 => "Not Found",
                    _ => "OK",
                };
                let resp = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status, reason, body.len(), body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        format!("http://{}", addr)
    }

    /// Regression: a 403 "removed by an administrator" response must map to
    /// LicenseError::Deactivated (not the generic Other), so verify_and_refresh_async
    /// can act on it by clearing the cached license.
    #[tokio::test]
    async fn test_try_online_activate_maps_admin_removal_to_deactivated() {
        let url = spawn_canned_http_response(
            403,
            r#"{"error":"Machine was removed by an administrator; re-activation is blocked for 1440 more minutes"}"#,
        ).await;

        let (_, pub_pem, _) = make_keypair_pems();
        let client = new_test_client(&pub_pem);
        let result = client
            .try_online_activate_async(&url, "ANY-KEY", None)
            .await;
        assert!(matches!(result, Err(LicenseError::Deactivated)), "got {:?}", result);
    }

    /// Regression: when the server reports the machine is no longer active
    /// (via /verify), the cached license file MUST be deleted and the status
    /// MUST be Deactivated. Without this, FusionHub would keep showing "Valid"
    /// until the cached lease expired even after the machine was removed.
    #[tokio::test]
    async fn test_verify_and_refresh_clears_cache_on_deactivation() {
        let url = spawn_canned_http_response(
            403,
            r#"{"error":"Machine not authorized for this license"}"#,
        ).await;

        let (_, pub_pem, private) = make_keypair_pems();
        let client = new_test_client_with_server(&pub_pem, url);

        // Seed a cached (still-valid-looking) license on disk.
        let payload = make_valid_payload(None);
        let signed = sign_license(&private, &payload).unwrap();
        let tmp = std::env::temp_dir().join("test_deactivation_cache.json");
        let json = serde_json::to_string_pretty(&signed).unwrap();
        tokio::fs::write(&tmp, &json).await.unwrap();
        assert!(tmp.exists());

        let status = client.verify_and_refresh_async(&tmp, "ANY-KEY", None).await;
        assert!(matches!(status, LicenseStatus::Deactivated), "got {:?}", status);
        assert!(!status.is_valid());
        assert!(!tmp.exists(), "cached license file must be deleted on deactivation");
    }

    /// Regression: the defining invariant of the new design. If no cached
    /// license exists on disk, `verify_and_refresh_async` must return
    /// `NotActivated` — it must NOT silently call /activate on every startup.
    /// That auto-activation was the original ghost-slot bug.
    #[tokio::test]
    async fn regression_verify_and_refresh_no_cache_returns_not_activated() {
        let (_, pub_pem, _) = make_keypair_pems();
        // Point at a URL that would noisily fail if it were ever called —
        // no cache file means the method must short-circuit before the server.
        let client = new_test_client_with_server(&pub_pem, "http://127.0.0.1:1".into());

        let nonexistent = std::env::temp_dir().join("definitely_not_there_license.json");
        let _ = tokio::fs::remove_file(&nonexistent).await;
        assert!(!nonexistent.exists());

        let status = client
            .verify_and_refresh_async(&nonexistent, "ANY-KEY", None)
            .await;
        assert!(matches!(status, LicenseStatus::NotActivated), "got {:?}", status);
        assert!(!status.is_valid());
        // Cache must not have been created as a side effect.
        assert!(!nonexistent.exists());
    }

    /// Regression: the explicit activate path (user clicks Activate) still
    /// calls /activate and writes the cache. This is what re-enables a
    /// previously-deactivated machine.
    #[tokio::test]
    async fn regression_activate_async_writes_cache_on_success() {
        use susi_core::LicensePayload;
        let (_, pub_pem, private) = make_keypair_pems();

        // Canned /activate response with a valid signed license.
        let payload = LicensePayload {
            id: "t".into(),
            product: "FusionHub".into(),
            customer: "T".into(),
            license_key: "X".into(),
            created: Utc::now(),
            expires: Some(Utc::now() + Duration::days(30)),
            features: vec![],
            machine_codes: vec![],
            lease_expires: Some(Utc::now() + Duration::hours(168)),
            lease_grace_period: None,
        };
        let signed = sign_license(&private, &payload).unwrap();
        let body = serde_json::to_string(&signed).unwrap();
        // Leak the string so it has 'static lifetime required by the helper.
        let leaked: &'static str = Box::leak(body.into_boxed_str());
        let url = spawn_canned_http_response(200, leaked).await;

        let client = new_test_client_with_server(&pub_pem, url);
        let tmp = std::env::temp_dir().join("test_activate_writes_cache.json");
        let _ = tokio::fs::remove_file(&tmp).await;

        let status = client.activate_async(&tmp, "X", None).await;
        assert!(status.is_valid(), "got {:?}", status);
        assert!(tmp.exists(), "cache file must be written on successful activate");

        let _ = tokio::fs::remove_file(&tmp).await;
    }

    /// Control test: unrelated 403 errors (e.g. transient server glitches whose
    /// message doesn't match any of our specific patterns) must still fall back
    /// to the cached file, so a flaky server doesn't knock everyone offline.
    #[tokio::test]
    async fn test_verify_and_refresh_keeps_cache_on_generic_403() {
        let url = spawn_canned_http_response(
            403,
            r#"{"error":"some unrelated server error"}"#,
        ).await;

        let (_, pub_pem, private) = make_keypair_pems();
        let client = new_test_client_with_server(&pub_pem, url);

        let payload = make_valid_payload(None);
        let signed = sign_license(&private, &payload).unwrap();
        let tmp = std::env::temp_dir().join("test_generic_403_cache.json");
        let json = serde_json::to_string_pretty(&signed).unwrap();
        tokio::fs::write(&tmp, &json).await.unwrap();

        let status = client.verify_and_refresh_async(&tmp, "ANY-KEY", None).await;
        // Fell back to cached file, which is still valid.
        assert!(status.is_valid(), "generic 403 should not invalidate cache; got {:?}", status);
        assert!(tmp.exists(), "cached license must survive a generic 403");

        let _ = tokio::fs::remove_file(&tmp).await;
    }

    #[tokio::test]
    async fn test_sync_verify_file_from_async_context() {
        // The sync wrapper uses its own current-thread runtime inside block_on.
        // Calling it from an async context via spawn_blocking must not panic —
        // this is exactly the failure mode this refactor is meant to fix when
        // callers migrate to the _async variants, but existing sync callers
        // wrapped in spawn_blocking must still work.
        let (_, pub_pem, private) = make_keypair_pems();
        let client = std::sync::Arc::new(new_test_client(&pub_pem));
        let payload = make_valid_payload(None);
        let signed = sign_license(&private, &payload).unwrap();

        let tmp = std::env::temp_dir().join("test_license_sync_from_async.json");
        let json = serde_json::to_string_pretty(&signed).unwrap();
        tokio::fs::write(&tmp, &json).await.unwrap();

        let tmp_clone = tmp.clone();
        let status = tokio::task::spawn_blocking(move || client.verify_file(&tmp_clone))
            .await
            .unwrap();
        assert!(status.is_valid());

        let _ = tokio::fs::remove_file(&tmp).await;
    }
}
