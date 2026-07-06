//! Integration tests for the susi licensing system.
//!
//! These tests spin up the **real** `susi-server` binary (the one produced by
//! the current `cargo build` invocation via [`env!("CARGO_BIN_EXE_susi-server")`])
//! and exercise the full client → server → client round-trip using both the
//! Rust [`susi_client::LicenseClient`] and the C++ `PackageTest` binary.
//!
//! # Running the tests
//!
//! ```text
//! cargo test --test integration
//! ```
//!
//! Each test allocates its own temporary directory and an ephemeral TCP port,
//! so tests can safely run in parallel.
//!
//! # Testing binary-signature enforcement
//!
//! [`test_require_signed_binary_enforcement`] adapts to the signing state of
//! the test runner binary at the time it executes:
//!
//! - **Unsigned binary** (default in development) → expects
//!   [`LicenseStatus::UnsignedBinary`].  No setup needed.
//! - **Signed binary** → expects [`LicenseStatus::Valid`].
//!
//! To exercise the signed path, create a test certificate once and then use
//! the helper script to build, sign, and run:
//!
//! **Windows**
//! ```powershell
//! # One-time setup (adds cert to CurrentUser\Root + TrustedPublisher)
//! .\scripts\create-test-codesign-cert.ps1
//!
//! # Build, sign the test binary, and run
//! .\scripts\sign-and-test.ps1
//!
//! # Tear down when finished
//! .\scripts\remove-test-codesign-cert.ps1
//! ```
//!
//! **macOS**
//! ```bash
//! # One-time setup
//! bash scripts/create-test-codesign-cert.sh
//!
//! # Build tests without running
//! cargo test --no-run --test integration
//!
//! # Sign the test binary (path printed by cargo above)
//! codesign -s "Susi Test Code Signing" --force \
//!     target/debug/deps/integration-<hash>
//!
//! # Run
//! cargo test --test integration
//! ```
//!
//! # C++ integration test
//!
//! When `conan` is detected at build time, `build.rs` compiles the C++ test
//! binary (`cpp/test_package/PackageTest`) and embeds its path in the
//! compile-time environment variable `SUSI_CPP_TEST_BIN`.
//! [`test_cpp_client_against_server`] then spawns that binary against the
//! same live server used by the Rust tests.
//!
//! If conan is absent or the C++ build fails, `SUSI_CPP_TEST_BIN` is unset
//! and the test is **skipped** (reported as `ignored` by the test runner).
//! The build script emits `cargo:warning` messages explaining what happened.
//!
//! # Server harness
//!
//! [`TestServer`] encapsulates the lifecycle of a server process:
//! spawn → wait-for-ready → run tests → kill on drop.
//! The default admin account (`admin` / `changeme`) is set up automatically;
//! [`TestServer::admin_token`] logs in and clears the forced-password-change
//! flag so that all admin API endpoints become accessible.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use serde_json::{json, Value};
use susi_client::{binary_signing, LicenseClient, LicenseStatus};
use susi_core::crypto::{generate_keypair, private_key_to_pem, public_key_to_pem};
use totp_rs::{Algorithm, Secret, TOTP};

// ---------------------------------------------------------------------------
// TestServer harness
// ---------------------------------------------------------------------------

/// A `susi-server` process managed for the duration of a single test.
///
/// The server is spawned against a fresh temporary directory (isolated SQLite
/// database, private key, and data directory) and an ephemeral TCP port.
/// Dropping the value kills the child process and deletes the temporary files.
struct TestServer {
    child: Child,
    /// Base URL, e.g. `http://127.0.0.1:54321`
    pub url: String,
    /// API base URL, e.g. `http://127.0.0.1:54321/api/v1`
    pub api_url: String,
    /// PEM-encoded public key matching the server's private key.
    pub public_key_pem: String,
    /// Kept alive so the temp dir is not deleted until the server is dropped.
    _dir: tempfile::TempDir,
}

impl TestServer {
    /// Spawn a server with a freshly-generated 2048-bit RSA keypair, wait
    /// until `/health` responds, and return the handle.
    fn start() -> Self {
        Self::start_with_env(&[])
    }

    /// Like `start`, with extra environment variables for the child process
    /// (e.g. STRIPE_WEBHOOK_SECRET to enable the webhook endpoint).
    fn start_with_env(envs: &[(&str, &str)]) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");

        let (private_key, public_key) = generate_keypair(2048).expect("keygen");
        let private_pem = private_key_to_pem(&private_key).expect("private pem");
        let public_pem = public_key_to_pem(&public_key).expect("public pem");

        let key_path = dir.path().join("private.pem");
        let db_path = dir.path().join("licenses.db");
        std::fs::write(&key_path, &private_pem).expect("write key");

        let port = free_port();
        let url = format!("http://127.0.0.1:{}", port);
        let api_url = format!("{}/api/v1", url);

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_susi-server"));
        cmd.arg("--private-key").arg(&key_path)
            .arg("--db").arg(&db_path)
            .arg("--listen").arg(format!("127.0.0.1:{}", port))
            .arg("--data-dir").arg(dir.path());
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let child = cmd.spawn().expect("spawn susi-server");

        let server = TestServer {
            child,
            url: url.clone(),
            api_url,
            public_key_pem: public_pem,
            _dir: dir,
        };
        server.wait_ready();
        server
    }

    /// Poll `/health` until the server responds or 10 seconds elapse.
    fn wait_ready(&self) {
        let client = Client::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if Instant::now() > deadline {
                panic!("susi-server did not become ready within 10 s");
            }
            if client.get(format!("{}/health", self.url)).send().is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn http(&self) -> Client {
        Client::new()
    }

    /// Log in as the default `admin` user, clear the forced-password-change
    /// flag (required before any admin endpoint accepts requests), and return
    /// the JWT for use in subsequent calls.
    fn admin_token(&self) -> String {
        let client = self.http();

        let resp = client
            .post(format!("{}/auth/login", self.api_url))
            .json(&json!({"username": "admin", "password": "changeme"}))
            .send()
            .expect("login");
        assert!(
            resp.status().is_success(),
            "login failed: {}",
            resp.text().unwrap_or_default()
        );
        let token = resp.json::<Value>().expect("login json")["token"]
            .as_str()
            .expect("token field")
            .to_string();

        // Clearing must_change_password is required before admin endpoints work.
        // The change revokes the login token; adopt the fresh one it returns.
        let resp = client
            .post(format!("{}/auth/change-password", self.api_url))
            .bearer_auth(&token)
            .json(&json!({
                "current_password": "changeme",
                "new_password": "testpassword1"
            }))
            .send()
            .expect("change-password");
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        assert!(status.is_success(), "change-password failed: {}", body);
        let token = serde_json::from_str::<Value>(&body).expect("change-password json")["token"]
            .as_str()
            .expect("fresh token")
            .to_string();

        // Set up 2FA (required before admin endpoints accept requests).
        let resp = client
            .post(format!("{}/auth/setup-2fa", self.api_url))
            .bearer_auth(&token)
            .send()
            .expect("setup-2fa");
        assert!(
            resp.status().is_success(),
            "setup-2fa failed: {}",
            resp.text().unwrap_or_default()
        );
        let secret_b32 = resp.json::<Value>().expect("setup-2fa json")["secret"]
            .as_str()
            .expect("secret field")
            .to_string();

        let secret_bytes = Secret::Encoded(secret_b32).to_bytes().expect("decode secret");
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes,
            Some("Susi License Server".into()), "admin".into())
            .expect("totp");
        let totp_code = totp.generate_current().expect("generate totp");

        let resp = client
            .post(format!("{}/auth/verify-2fa", self.api_url))
            .bearer_auth(&token)
            .json(&json!({"totp_code": totp_code}))
            .send()
            .expect("verify-2fa");
        assert!(
            resp.status().is_success(),
            "verify-2fa failed: {}",
            resp.text().unwrap_or_default()
        );

        token
    }

    /// Create a 30-day license via the admin API and return its license key.
    fn create_license(&self, token: &str, require_signed_binary: bool) -> String {
        let resp = self
            .http()
            .post(format!("{}/licenses", self.api_url))
            .bearer_auth(token)
            .json(&json!({
                "customer": "Test Corp",
                "days": 30,
                "features": ["imu_optical_fusion"],
                "require_signed_binary": require_signed_binary,
            }))
            .send()
            .expect("create license");
        assert_eq!(
            resp.status().as_u16(),
            201,
            "create license failed: {}",
            resp.text().unwrap_or_default()
        );
        resp.json::<Value>().expect("license json")["license_key"]
            .as_str()
            .expect("license_key")
            .to_string()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

/// Bind to port 0 to let the OS choose a free port, then immediately close
/// the listener.  The port number is returned for use by the test server.
/// There is a small TOCTOU window, but it is negligible for local tests.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind :0");
    l.local_addr().expect("local addr").port()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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


/// Full happy-path: activate a `require_signed_binary=false` license via the
/// server, then verify it locally through [`LicenseClient::activate`].
///
/// This is the baseline test that must pass on every machine without any
/// certificate setup.
#[test]
fn test_activate_and_refresh_unsigned_ok() {
    let server = TestServer::start();
    let token = server.admin_token();
    let license_key = server.create_license(&token, false);

    let license_path = server._dir.path().join("license.json");
    let client = LicenseClient::with_server(&server.public_key_pem, server.api_url.clone())
        .expect("LicenseClient")
        .with_machine_code_cache(test_machine_code_cache());

    let status = client.activate(&license_path, &license_key, None);
    assert!(status.is_valid(), "expected Valid, got: {:?}", status);
    assert!(status.has_feature("imu_optical_fusion"));
    assert!(!status.has_feature("vehicular_fusion"));
}

/// Calling [`LicenseClient::verify_and_refresh`] after [`LicenseClient::activate`]
/// to renew the lease.  Both calls must return `Valid`.
#[test]
fn test_lease_renewal_via_server() {
    let server = TestServer::start();
    let token = server.admin_token();
    let license_key = server.create_license(&token, false);

    let license_path = server._dir.path().join("license.json");
    let client = LicenseClient::with_server(&server.public_key_pem, server.api_url.clone())
        .expect("LicenseClient")
        .with_machine_code_cache(test_machine_code_cache());

    let status = client.activate(&license_path, &license_key, None);
    assert!(status.is_valid(), "first check: {:?}", status);

    let status = client.verify_and_refresh(&license_path, &license_key, None);
    assert!(status.is_valid(), "renewal: expected Valid, got: {:?}", status);
}

/// When the server is unreachable after the license has been cached locally,
/// [`LicenseClient::verify_and_refresh`] falls back to the cached file and
/// still returns `Valid`.
///
/// The temp dir is kept alive independently of the server so the cached file
/// survives the server being killed.
#[test]
fn test_fallback_to_cached_file() {
    let dir = tempfile::tempdir().expect("temp dir");

    let (private_key, public_key) = generate_keypair(2048).expect("keygen");
    let private_pem = private_key_to_pem(&private_key).expect("private pem");
    let public_pem = public_key_to_pem(&public_key).expect("public pem");

    let key_path = dir.path().join("private.pem");
    let db_path = dir.path().join("licenses.db");
    std::fs::write(&key_path, &private_pem).unwrap();

    let port = free_port();
    let api_url = format!("http://127.0.0.1:{}/api/v1", port);

    let mut child = Command::new(env!("CARGO_BIN_EXE_susi-server"))
        .arg("--private-key").arg(&key_path)
        .arg("--db").arg(&db_path)
        .arg("--listen").arg(format!("127.0.0.1:{}", port))
        .arg("--data-dir").arg(dir.path())
        .spawn()
        .unwrap();

    // Wait for ready.
    let http = Client::new();
    let base = format!("http://127.0.0.1:{}", port);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() > deadline { panic!("server timeout"); }
        if http.get(format!("{}/health", base)).send().is_ok() { break; }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Set up admin and create a license.
    let resp = http.post(format!("{}/auth/login", api_url))
        .json(&json!({"username": "admin", "password": "changeme"}))
        .send().unwrap();
    let token = resp.json::<Value>().unwrap()["token"].as_str().unwrap().to_string();
    let resp = http.post(format!("{}/auth/change-password", api_url))
        .bearer_auth(&token)
        .json(&json!({"current_password": "changeme", "new_password": "testpassword1"}))
        .send().unwrap();
    let token = resp.json::<Value>().unwrap()["token"].as_str().unwrap().to_string();

    let resp = http.post(format!("{}/auth/setup-2fa", api_url))
        .bearer_auth(&token).send().unwrap();
    let secret_b32 = resp.json::<Value>().unwrap()["secret"].as_str().unwrap().to_string();
    let secret_bytes = Secret::Encoded(secret_b32).to_bytes().unwrap();
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes,
        Some("Susi License Server".into()), "admin".into()).unwrap();
    http.post(format!("{}/auth/verify-2fa", api_url))
        .bearer_auth(&token)
        .json(&json!({"totp_code": totp.generate_current().unwrap()}))
        .send().unwrap();

    let resp = http.post(format!("{}/licenses", api_url))
        .bearer_auth(&token)
        .json(&json!({"customer": "Corp", "days": 30, "require_signed_binary": false}))
        .send().unwrap();
    let license_key = resp.json::<Value>().unwrap()["license_key"]
        .as_str().unwrap().to_string();

    // Prime the on-disk cache.
    let license_path = dir.path().join("license.json");
    let client = LicenseClient::with_server(&public_pem, api_url.clone())
        .unwrap()
        .with_machine_code_cache(test_machine_code_cache());
    let status = client.activate(&license_path, &license_key, None);
    assert!(status.is_valid(), "initial: {:?}", status);

    // Kill server — dir (and cached file) remain alive.
    child.kill().ok();
    child.wait().ok();

    // A second client aimed at the now-dead server must fall back to the file.
    let client2 = LicenseClient::with_server(&public_pem, api_url)
        .unwrap()
        .with_machine_code_cache(test_machine_code_cache());
    let status = client2.verify_and_refresh(&license_path, &license_key, None);
    assert!(status.is_valid(), "fallback: expected Valid from cache, got: {:?}", status);
}

/// Verifies end-to-end handling of `require_signed_binary = true`.
///
/// The test creates a license with the flag set, activates it via HTTP, and
/// confirms:
///
/// 1. The signed payload returned by the server carries
///    `"require_signed_binary": true`.
/// 2. Local verification returns [`LicenseStatus::UnsignedBinary`] when the
///    test runner binary is not code-signed (the default in development), or
///    [`LicenseStatus::Valid`] when it is signed.
///
/// To exercise the `Valid` branch, sign the test binary before running:
/// - **Windows**: `.\scripts\sign-and-test.ps1`
/// - **macOS**: `codesign -s "Susi Test Code Signing" --force <test-binary>`
#[test]
fn test_require_signed_binary_enforcement() {
    let server = TestServer::start();
    let token = server.admin_token();
    let license_key = server.create_license(&token, true);

    // Activate manually to inspect the raw SignedLicense.
    let machine_code = TEST_MACHINE_CODE;
    let resp = server
        .http()
        .post(format!("{}/activate", server.api_url))
        .json(&json!({"license_key": license_key, "machine_code": machine_code}))
        .send()
        .expect("activate");
    assert!(
        resp.status().is_success(),
        "activate failed: {}",
        resp.text().unwrap_or_default()
    );

    let signed: susi_core::SignedLicense = resp.json().expect("signed license json");

    // The payload (before local check) must carry the flag.
    let payload: Value =
        serde_json::from_str(&signed.license_data).expect("payload json");
    assert_eq!(
        payload["require_signed_binary"], true,
        "server payload must carry require_signed_binary=true"
    );

    // Local verification result depends on whether the test binary is signed.
    let client = LicenseClient::new(&server.public_key_pem)
        .expect("LicenseClient")
        .with_machine_code_cache(test_machine_code_cache());
    let status = client.verify_signed(&signed);

    if binary_signing::is_binary_signed() {
        assert!(
            matches!(status, LicenseStatus::Valid { .. }),
            "signed binary: expected Valid, got: {:?}",
            status
        );
    } else {
        assert!(
            matches!(status, LicenseStatus::UnsignedBinary),
            "unsigned binary: expected UnsignedBinary, got: {:?}",
            status
        );
    }
}

/// The `require_signed_binary` field is persisted in the database and exposed
/// correctly in the admin `GET /licenses/{key}` response.
#[test]
fn test_require_signed_binary_in_api_response() {
    let server = TestServer::start();
    let token = server.admin_token();
    let key_true = server.create_license(&token, true);
    let key_false = server.create_license(&token, false);

    let http = server.http();

    let body: Value = http
        .get(format!("{}/licenses/{}", server.api_url, key_true))
        .bearer_auth(&token)
        .send().unwrap()
        .json().unwrap();
    assert_eq!(body["require_signed_binary"], true);

    let body: Value = http
        .get(format!("{}/licenses/{}", server.api_url, key_false))
        .bearer_auth(&token)
        .send().unwrap()
        .json().unwrap();
    assert_eq!(body["require_signed_binary"], false);
}

/// `require_signed_binary` can be toggled via `PUT /licenses/{key}`.
///
/// After updating a license from `true` to `false`, the next activation must
/// return a signed payload with the flag cleared, and local verification must
/// succeed regardless of whether the binary is signed.
#[test]
fn test_update_require_signed_binary() {
    let server = TestServer::start();
    let token = server.admin_token();
    let key = server.create_license(&token, true);

    let http = server.http();

    // Flip to false via PUT.
    let body: Value = http
        .put(format!("{}/licenses/{}", server.api_url, key))
        .bearer_auth(&token)
        .json(&json!({"require_signed_binary": false}))
        .send().unwrap()
        .json().unwrap();
    assert_eq!(body["require_signed_binary"], false, "API response must reflect update");

    // Re-activate and inspect the fresh payload.
    let machine_code = TEST_MACHINE_CODE;
    let signed: susi_core::SignedLicense = http
        .post(format!("{}/activate", server.api_url))
        .json(&json!({"license_key": key, "machine_code": machine_code}))
        .send().unwrap()
        .json().unwrap();

    let payload: Value = serde_json::from_str(&signed.license_data).unwrap();
    assert_eq!(
        payload["require_signed_binary"], false,
        "updated payload must carry require_signed_binary=false"
    );

    // Local check: unsigned binary is now accepted.
    let client = LicenseClient::new(&server.public_key_pem)
        .unwrap()
        .with_machine_code_cache(test_machine_code_cache());
    let status = client.verify_signed(&signed);
    assert!(status.is_valid(), "expected Valid after update, got: {:?}", status);
}

// ---------------------------------------------------------------------------
// CA pinning integration test
// ---------------------------------------------------------------------------

/// Helpers for building synthetic DER certificate chains without needing a real
/// signed binary.  Uses `rcgen` to create a CA cert and a leaf cert signed by it.
mod cert_helpers {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair,
    };

    pub struct CaAndLeaf {
        pub ca_pem: String,
        pub leaf_der: Vec<u8>,
    }

    pub fn make_ca_and_leaf() -> CaAndLeaf {
        // CA certificate (self-signed)
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.distinguished_name.push(DnType::CommonName, "Test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Leaf certificate signed by the CA
        let mut leaf_params = CertificateParams::new(vec![]).unwrap();
        leaf_params.distinguished_name.push(DnType::CommonName, "Test Leaf");
        leaf_params.is_ca = IsCa::NoCa;
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        CaAndLeaf {
            ca_pem: ca_cert.pem(),
            leaf_der: leaf_cert.der().to_vec(),
        }
    }

    /// A self-signed cert that is NOT signed by the test CA.
    pub fn make_unrelated_cert_der() -> Vec<u8> {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.distinguished_name.push(DnType::CommonName, "Attacker CA");
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }
}

impl TestServer {
    /// Start a server configured with `--trusted-signing-ca <ca_pem>`.
    fn start_with_trusted_ca(ca_pem: &str) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");

        let (private_key, public_key) = generate_keypair(2048).expect("keygen");
        let private_pem = private_key_to_pem(&private_key).expect("private pem");
        let public_pem = public_key_to_pem(&public_key).expect("public pem");

        let key_path = dir.path().join("private.pem");
        let db_path  = dir.path().join("licenses.db");
        let ca_path  = dir.path().join("trusted_ca.pem");
        std::fs::write(&key_path, &private_pem).expect("write key");
        std::fs::write(&ca_path, ca_pem).expect("write ca pem");

        let port = free_port();
        let url = format!("http://127.0.0.1:{}", port);
        let api_url = format!("{}/api/v1", url);

        let child = Command::new(env!("CARGO_BIN_EXE_susi-server"))
            .arg("--private-key").arg(&key_path)
            .arg("--db").arg(&db_path)
            .arg("--listen").arg(format!("127.0.0.1:{}", port))
            .arg("--data-dir").arg(dir.path())
            .arg("--trusted-signing-ca").arg(&ca_path)
            .spawn()
            .expect("spawn susi-server");

        let server = TestServer {
            child, url: url.clone(), api_url, public_key_pem: public_pem, _dir: dir,
        };
        server.wait_ready();
        server
    }
}

/// Verifies server-side CA pinning enforcement:
///
/// 1. No chain provided → 403
/// 2. Chain from an unrelated self-signed cert → 403
/// 3. Leaf cert signed by the trusted CA → 200
///
/// The test uses synthetically generated DER certificates (via `rcgen`) so it
/// works without a real code-signed binary.
#[test]
fn test_ca_pinning_enforcement() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use cert_helpers::{make_ca_and_leaf, make_unrelated_cert_der};

    let CaAndLeaf { ca_pem, leaf_der } = make_ca_and_leaf();
    use cert_helpers::CaAndLeaf;

    let attacker_der = make_unrelated_cert_der();

    let server = TestServer::start_with_trusted_ca(&ca_pem);
    let token = server.admin_token();
    let license_key = server.create_license(&token, true);
    let machine_code = TEST_MACHINE_CODE;

    let http = server.http();
    let activate_url = format!("{}/activate", server.api_url);

    // Case 1: no chain → 403
    let resp = http.post(&activate_url)
        .json(&serde_json::json!({
            "license_key": license_key,
            "machine_code": machine_code,
        }))
        .send()
        .expect("request");
    assert_eq!(resp.status().as_u16(), 403, "request without chain should be rejected");
    let body = resp.text().unwrap_or_default();
    assert!(body.contains("certificate chain required"), "got: {}", body);

    // Case 2: unrelated self-signed cert → 403
    let resp = http.post(&activate_url)
        .json(&serde_json::json!({
            "license_key": license_key,
            "machine_code": machine_code,
            "signing_cert_chain": [STANDARD.encode(&attacker_der)],
        }))
        .send()
        .expect("request");
    assert_eq!(resp.status().as_u16(), 403, "attacker cert should be rejected");
    let body = resp.text().unwrap_or_default();
    assert!(body.contains("trusted CA"), "got: {}", body);

    // Case 3: leaf signed by the trusted CA → 200
    let resp = http.post(&activate_url)
        .json(&serde_json::json!({
            "license_key": license_key,
            "machine_code": machine_code,
            "signing_cert_chain": [STANDARD.encode(&leaf_der)],
        }))
        .send()
        .expect("request");
    assert_eq!(
        resp.status().as_u16(), 200,
        "valid chain should be accepted: {}",
        resp.text().unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// C++ client integration test
// ---------------------------------------------------------------------------

/// Runs the C++ `PackageTest` binary against a live server and verifies the
/// activate → offline-fallback round-trip from the C++ client's perspective.
///
/// # Skipping vs failing
///
/// - `conan` **not installed**: test is `ignored`.
/// - `conan` **installed** but C++ build failed: test **fails** with the
///   build error from `build.rs` (see `cargo:warning` output for details).
/// - C++ build **succeeded**: test runs normally.
///
/// Run `cargo build` with conan available to enable this test:
/// ```text
/// cargo test --test integration test_cpp_client_against_server -- --ignored
/// ```
/// or simply run the full suite (ignored tests are included with `--include-ignored`):
/// ```text
/// cargo test --test integration -- --include-ignored
/// ```
#[cfg_attr(not(susi_conan_available), ignore = "conan not installed")]
#[test]
fn test_cpp_client_against_server() {
    #[cfg(not(susi_cpp_built))]
    panic!(
        "conan is installed but C++ build failed: {}",
        option_env!("SUSI_CPP_BUILD_ERROR").unwrap_or("unknown reason — check cargo:warning output")
    );

    #[cfg(susi_cpp_built)]
    {
        let cpp_bin = env!("SUSI_CPP_TEST_BIN");

        let server = TestServer::start();
        let token = server.admin_token();

        // Create a license with require_signed_binary=false so the C++ test binary
        // (which is not code-signed in CI) can verify it successfully.
        let license_key = server.create_license(&token, false);

        // Write the public key to a temp file so the C++ binary can load it.
        let pub_key_path = server._dir.path().join("public.pem");
        std::fs::write(&pub_key_path, &server.public_key_pem).expect("write public key");

        let output = Command::new(cpp_bin)
            .arg("--server-url").arg(&server.api_url)
            .arg("--public-key-file").arg(&pub_key_path)
            .arg("--license-key").arg(&license_key)
            .output()
            .expect("spawn C++ test binary");

        // Always print what the binary wrote so failures are diagnosable.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stdout.is_empty() { print!("{}", stdout); }
        if !stderr.is_empty() { eprint!("{}", stderr); }

        assert!(
            output.status.success(),
            "C++ PackageTest exited with {:?}",
            output.status.code()
        );
    }
}

// ---------------------------------------------------------------------------
// Admin invite flow
// ---------------------------------------------------------------------------

/// Admin-created user with an explicit `password` field (manual fallback):
/// account works immediately, no invitation is sent.
#[test]
fn test_create_user_with_explicit_password_skips_invite() {
    let server = TestServer::start();
    let token = server.admin_token();

    let resp = server
        .http()
        .post(format!("{}/auth/users", server.api_url))
        .bearer_auth(&token)
        .json(&json!({
            "username": "manual_alice",
            "email": "manual_alice@example.com",
            "role": "user",
            "password": "manualpw123",
        }))
        .send()
        .expect("create user");
    assert!(resp.status().is_success(), "create user: {}", resp.text().unwrap_or_default());
    let body = resp.json::<Value>().expect("create user json");
    assert_eq!(body["invitation_sent"], json!(false));

    // The user can immediately log in with that password.
    let resp = server
        .http()
        .post(format!("{}/auth/login", server.api_url))
        .json(&json!({"username": "manual_alice", "password": "manualpw123"}))
        .send()
        .expect("login");
    assert!(resp.status().is_success(), "login: {}", resp.text().unwrap_or_default());

    // The email address works as the login identifier too, resolving to the
    // same account.
    let resp = server
        .http()
        .post(format!("{}/auth/login", server.api_url))
        .json(&json!({"username": "manual_alice@example.com", "password": "manualpw123"}))
        .send()
        .expect("login by email");
    assert!(resp.status().is_success(), "login by email: {}", resp.text().unwrap_or_default());
    let body = resp.json::<Value>().expect("login json");
    assert_eq!(body["username"], json!("manual_alice"));
}

/// Without SMTP configured, asking for the invite path (no password) returns
/// 503 with a clear hint rather than silently creating an unreachable user.
#[test]
fn test_create_user_without_password_requires_smtp() {
    let server = TestServer::start();
    let token = server.admin_token();

    let resp = server
        .http()
        .post(format!("{}/auth/users", server.api_url))
        .bearer_auth(&token)
        .json(&json!({
            "username": "invite_bob",
            "email": "invite_bob@example.com",
            "role": "user",
        }))
        .send()
        .expect("create user");
    assert_eq!(resp.status().as_u16(), 503);
    let body = resp.json::<Value>().expect("error json");
    assert!(
        body["error"].as_str().unwrap_or("").contains("Email is not configured"),
        "unexpected error: {}",
        body
    );

    // Verify no user row was created.
    let users = server
        .http()
        .get(format!("{}/auth/users", server.api_url))
        .bearer_auth(&token)
        .send()
        .expect("list users")
        .json::<Value>()
        .expect("users json");
    let arr = users.as_array().expect("users is array");
    assert!(!arr.iter().any(|u| u["username"] == "invite_bob"));
}

/// Resending an invitation when SMTP isn't configured surfaces the same 503.
#[test]
fn test_resend_invitation_requires_smtp() {
    let server = TestServer::start();
    let token = server.admin_token();

    server
        .http()
        .post(format!("{}/auth/users", server.api_url))
        .bearer_auth(&token)
        .json(&json!({
            "username": "manual_carol",
            "email": "manual_carol@example.com",
            "role": "user",
            "password": "manualpw123",
        }))
        .send()
        .expect("create user")
        .error_for_status()
        .expect("create user ok");

    let resp = server
        .http()
        .post(format!("{}/auth/users/manual_carol/resend-invitation", server.api_url))
        .bearer_auth(&token)
        .send()
        .expect("resend");
    assert_eq!(resp.status().as_u16(), 503);
}

/// End-to-end: a second product gets its own docs, reuses a version tag the
/// default product also uses, and the two stay isolated. Exercises the products
/// CRUD, the product-scoped doc routes, and the legacy (default-product) routes.
#[test]
fn test_product_scoped_docs_flow() {
    let server = TestServer::start();
    let token = server.admin_token();
    let http = server.http();

    // The default product is seeded and listed.
    let resp = http
        .get(format!("{}/products", server.api_url))
        .send()
        .expect("list products");
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.json::<Value>().expect("products json");
    let slugs: Vec<&str> = body["products"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["slug"].as_str().unwrap())
        .collect();
    assert!(slugs.contains(&"fusionhub"), "default product must be seeded");

    // Create a second product.
    let resp = http
        .post(format!("{}/products", server.api_url))
        .bearer_auth(&token)
        .json(&json!({ "slug": "lpvr", "name": "LPVR" }))
        .send()
        .expect("create product");
    assert_eq!(resp.status().as_u16(), 200, "create product: {}", resp.text().unwrap_or_default());

    // Author a page under lpvr / v1.0 via the product-scoped route.
    let resp = http
        .put(format!("{}/products/lpvr/docs/v1.0/pages/intro", server.api_url))
        .bearer_auth(&token)
        .json(&json!({ "title": "LPVR Intro", "body_md": "# Hello LPVR" }))
        .send()
        .expect("upsert lpvr page");
    assert_eq!(resp.status().as_u16(), 200, "upsert: {}", resp.text().unwrap_or_default());

    // It shows up in lpvr's releases and reads back.
    let resp = http
        .get(format!("{}/products/lpvr/docs/releases", server.api_url))
        .send()
        .expect("lpvr releases");
    let body = resp.json::<Value>().expect("json");
    let tags: Vec<&str> = body["releases"].as_array().unwrap().iter()
        .map(|r| r["tag"].as_str().unwrap()).collect();
    assert_eq!(tags, vec!["v1.0"]);

    let resp = http
        .get(format!("{}/products/lpvr/docs/v1.0/pages/intro", server.api_url))
        .send()
        .expect("lpvr page");
    assert_eq!(resp.json::<Value>().unwrap()["body_md"].as_str().unwrap(), "# Hello LPVR");

    // The default product has NO docs yet — isolation holds on both the
    // product-scoped and the legacy routes.
    for url in [
        format!("{}/products/fusionhub/docs/releases", server.api_url),
        format!("{}/docs/releases", server.api_url),
    ] {
        let resp = http.get(&url).send().expect("fusionhub releases");
        let body = resp.json::<Value>().expect("json");
        assert!(body["releases"].as_array().unwrap().is_empty(), "{} must be empty", url);
    }

    // Reuse the same tag under the default product via the legacy route — the
    // composite (product, tag) key allows it, and the two pages are distinct.
    let resp = http
        .put(format!("{}/docs/v1.0/pages/intro", server.api_url))
        .bearer_auth(&token)
        .json(&json!({ "title": "FH Intro", "body_md": "# Hello FusionHub" }))
        .send()
        .expect("upsert fusionhub page");
    assert_eq!(resp.status().as_u16(), 200, "legacy upsert: {}", resp.text().unwrap_or_default());

    let fh = http.get(format!("{}/docs/v1.0/pages/intro", server.api_url))
        .send().expect("fh page").json::<Value>().unwrap();
    let lpvr = http.get(format!("{}/products/lpvr/docs/v1.0/pages/intro", server.api_url))
        .send().expect("lpvr page").json::<Value>().unwrap();
    assert_eq!(fh["body_md"].as_str().unwrap(), "# Hello FusionHub");
    assert_eq!(lpvr["body_md"].as_str().unwrap(), "# Hello LPVR");

    // A product that still owns a release cannot be deleted.
    let resp = http
        .delete(format!("{}/products/lpvr", server.api_url))
        .bearer_auth(&token)
        .send()
        .expect("delete product");
    assert_eq!(resp.status().as_u16(), 409, "product with releases must not delete");
}

/// End-to-end self-serve licensing: admin assigns a license to a customer
/// account, the customer sees it via /my/licenses, exports a license file for
/// an offline machine, removes the machine again, and loses access once the
/// admin unassigns. Foreign licenses must stay invisible (404).
#[test]
fn test_license_user_self_serve_flow() {
    let server = TestServer::start();
    let admin = server.admin_token();
    let client = server.http();

    // Customer account (explicit password - no SMTP in tests).
    client
        .post(format!("{}/auth/users", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({
            "username": "cust@example.com",
            "email": "cust@example.com",
            "role": "user",
            "password": "custpass123",
        }))
        .send()
        .expect("create user")
        .error_for_status()
        .expect("create user ok");

    let resp = client
        .post(format!("{}/auth/login", server.api_url))
        .json(&json!({"username": "cust@example.com", "password": "custpass123"}))
        .send()
        .expect("customer login");
    assert!(resp.status().is_success(), "login: {}", resp.text().unwrap_or_default());
    let cust = resp.json::<Value>().expect("login json")["token"]
        .as_str()
        .expect("token")
        .to_string();

    // No licenses assigned yet.
    let mine = client
        .get(format!("{}/my/licenses", server.api_url))
        .bearer_auth(&cust)
        .send()
        .expect("my licenses")
        .json::<Value>()
        .expect("my licenses json");
    assert_eq!(mine.as_array().expect("array").len(), 0);

    // Create one license assigned at creation time and one foreign license.
    let resp = client
        .post(format!("{}/licenses", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({
            "customer": "Cust Corp",
            "days": 30,
            "features": ["imu_optical_fusion"],
            "assign_to": ["cust@example.com"],
        }))
        .send()
        .expect("create license");
    assert_eq!(resp.status().as_u16(), 201, "{}", resp.text().unwrap_or_default());
    let lic = resp.json::<Value>().expect("license json");
    let key = lic["license_key"].as_str().expect("key").to_string();
    assert_eq!(lic["users"], json!(["cust@example.com"]));

    let foreign_key = server.create_license(&admin, false);

    // Assigning to a non-existent user fails.
    let resp = client
        .post(format!("{}/licenses/{}/users", server.api_url, foreign_key))
        .bearer_auth(&admin)
        .json(&json!({"username": "nobody"}))
        .send()
        .expect("assign");
    assert_eq!(resp.status().as_u16(), 404);

    // Customer sees exactly their license.
    let mine = client
        .get(format!("{}/my/licenses", server.api_url))
        .bearer_auth(&cust)
        .send()
        .expect("my licenses")
        .json::<Value>()
        .expect("my licenses json");
    let arr = mine.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["license_key"].as_str(), Some(key.as_str()));

    // Foreign license is invisible: export and machine-removal 404.
    let resp = client
        .post(format!("{}/my/licenses/{}/export", server.api_url, foreign_key))
        .bearer_auth(&cust)
        .json(&json!({"machine_code": TEST_MACHINE_CODE, "friendly_name": "Nope"}))
        .send()
        .expect("foreign export");
    assert_eq!(resp.status().as_u16(), 404);

    // Offline export of the assigned license activates the machine and
    // returns a signed license file.
    let resp = client
        .post(format!("{}/my/licenses/{}/export", server.api_url, key))
        .bearer_auth(&cust)
        .json(&json!({"machine_code": TEST_MACHINE_CODE, "friendly_name": "Lab PC"}))
        .send()
        .expect("export");
    assert!(resp.status().is_success(), "export: {}", resp.text().unwrap_or_default());
    let signed = resp.json::<Value>().expect("signed license json");
    assert!(signed["signature"].is_string(), "missing signature: {}", signed);

    let mine = client
        .get(format!("{}/my/licenses", server.api_url))
        .bearer_auth(&cust)
        .send()
        .expect("my licenses")
        .json::<Value>()
        .expect("json");
    assert_eq!(mine[0]["machines"].as_array().expect("machines").len(), 1);

    // Self-service machine removal frees the slot (and tombstones it).
    let resp = client
        .delete(format!(
            "{}/my/licenses/{}/machines/{}",
            server.api_url, key, TEST_MACHINE_CODE
        ))
        .bearer_auth(&cust)
        .send()
        .expect("remove machine");
    assert!(resp.status().is_success(), "remove: {}", resp.text().unwrap_or_default());
    let mine = client
        .get(format!("{}/my/licenses", server.api_url))
        .bearer_auth(&cust)
        .send()
        .expect("my licenses")
        .json::<Value>()
        .expect("json");
    assert_eq!(mine[0]["machines"].as_array().expect("machines").len(), 0);

    // Admin users list shows the assignment.
    let users = client
        .get(format!("{}/auth/users", server.api_url))
        .bearer_auth(&admin)
        .send()
        .expect("list users")
        .json::<Value>()
        .expect("users json");
    let cust_row = users
        .as_array()
        .expect("array")
        .iter()
        .find(|u| u["username"] == "cust@example.com")
        .expect("customer row");
    assert_eq!(cust_row["licenses"].as_array().expect("licenses").len(), 1);

    // Unassign removes portal visibility.
    let resp = client
        .delete(format!("{}/licenses/{}/users/cust@example.com", server.api_url, key))
        .bearer_auth(&admin)
        .send()
        .expect("unassign");
    assert!(resp.status().is_success());
    let mine = client
        .get(format!("{}/my/licenses", server.api_url))
        .bearer_auth(&cust)
        .send()
        .expect("my licenses")
        .json::<Value>()
        .expect("json");
    assert_eq!(mine.as_array().expect("array").len(), 0);
}

/// Passwordless plumbing without SMTP: request-code always answers a generic
/// OK (never enumerates accounts) and magic-login rejects unknown tokens.
#[test]
fn test_request_code_and_magic_login_guards() {
    let server = TestServer::start();
    let client = server.http();

    let resp = client
        .post(format!("{}/auth/request-code", server.api_url))
        .json(&json!({"identifier": "whoever@example.com"}))
        .send()
        .expect("request-code");
    assert!(resp.status().is_success());
    let body = resp.json::<Value>().expect("json");
    assert_eq!(body["status"], json!("OK"));

    let resp = client
        .post(format!("{}/auth/magic-login", server.api_url))
        .json(&json!({"token": "deadbeef"}))
        .send()
        .expect("magic-login");
    assert_eq!(resp.status().as_u16(), 401);
}

/// Global release binaries require product entitlement: a license key only
/// unlocks its own product's downloads, a session with no assigned license
/// gets nothing, and assignment (or admin) opens the gate. Probed via the
/// download-ticket endpoint, which runs the same authorization without
/// touching disk: 403 = entitlement denied, 200 = authorized.
#[test]
fn test_release_download_product_entitlement() {
    let server = TestServer::start();
    let admin = server.admin_token();
    let client = server.http();

    let mint = |auth_header: Option<&str>, jwt: Option<&str>, product: Option<&str>| {
        let mut req = client
            .post(format!("{}/updates/download-ticket", server.api_url))
            .json(&json!({"tag": "v1.0", "asset": "tool.zip", "product": product}));
        if let Some(key) = auth_header {
            req = req.header("X-License-Key", key);
        }
        if let Some(t) = jwt {
            req = req.bearer_auth(t);
        }
        req.send().expect("mint ticket").status().as_u16()
    };

    client
        .post(format!("{}/products", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({"slug": "otherprod", "name": "Other Product"}))
        .send()
        .expect("create product")
        .error_for_status()
        .expect("create product ok");
    let license_key = server.create_license(&admin, false);

    // A default-product license key cannot fetch another product's binaries,
    // but passes authorization for its own product.
    assert_eq!(mint(Some(&license_key), None, Some("otherprod")), 403);
    assert_eq!(mint(Some(&license_key), None, None), 200);

    // A logged-in user with no license assignment is denied.
    client
        .post(format!("{}/auth/users", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({"username": "plainuser", "email": "plain@example.com", "role": "user", "password": "plainpass123"}))
        .send()
        .expect("create user")
        .error_for_status()
        .expect("create user ok");
    let user_jwt = client
        .post(format!("{}/auth/login", server.api_url))
        .json(&json!({"username": "plainuser", "password": "plainpass123"}))
        .send()
        .expect("login")
        .json::<Value>()
        .expect("json")["token"]
        .as_str()
        .expect("token")
        .to_string();
    assert_eq!(mint(None, Some(&user_jwt), None), 403);

    // Assigning the license entitles the user to that product - and only
    // that product.
    client
        .post(format!("{}/licenses/{}/users", server.api_url, license_key))
        .bearer_auth(&admin)
        .json(&json!({"username": "plainuser"}))
        .send()
        .expect("assign license")
        .error_for_status()
        .expect("assign license ok");
    assert_eq!(mint(None, Some(&user_jwt), None), 200);
    assert_eq!(mint(None, Some(&user_jwt), Some("otherprod")), 403);

    // Admins are entitled to every product.
    assert_eq!(mint(None, Some(&admin), Some("otherprod")), 200);
}

/// Every response carries the output security headers set by the global
/// layer - HTML shells and JSON API alike.
#[test]
fn test_security_headers_present() {
    let server = TestServer::start();
    for path in ["/", "/health"] {
        let resp = server
            .http()
            .get(format!("{}{}", server.url, path))
            .send()
            .expect("request");
        let h = resp.headers();
        assert_eq!(
            h.get("x-frame-options").and_then(|v| v.to_str().ok()),
            Some("DENY"),
            "{} missing X-Frame-Options", path
        );
        assert_eq!(
            h.get("x-content-type-options").and_then(|v| v.to_str().ok()),
            Some("nosniff"),
            "{} missing X-Content-Type-Options", path
        );
        assert_eq!(
            h.get("referrer-policy").and_then(|v| v.to_str().ok()),
            Some("strict-origin-when-cross-origin"),
            "{} missing Referrer-Policy", path
        );
        let csp = h
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_else(|| panic!("{} missing Content-Security-Policy", path));
        assert!(csp.contains("frame-ancestors 'none'"), "CSP incomplete: {}", csp);
    }
}

/// Changing the password revokes every outstanding session JWT: the token
/// used before the change is rejected afterwards, while the fresh token
/// returned by change-password keeps working.
#[test]
fn test_password_change_revokes_sessions() {
    let server = TestServer::start();
    let client = server.http();

    let resp = client
        .post(format!("{}/auth/login", server.api_url))
        .json(&json!({"username": "admin", "password": "changeme"}))
        .send()
        .expect("login");
    assert!(resp.status().is_success());
    let old_token = resp.json::<Value>().expect("json")["token"]
        .as_str()
        .expect("token")
        .to_string();

    let resp = client
        .post(format!("{}/auth/change-password", server.api_url))
        .bearer_auth(&old_token)
        .json(&json!({"current_password": "changeme", "new_password": "brandnewpass1"}))
        .send()
        .expect("change-password");
    assert!(resp.status().is_success());
    let new_token = resp.json::<Value>().expect("json")["token"]
        .as_str()
        .expect("fresh token")
        .to_string();

    let resp = client
        .get(format!("{}/auth/status", server.api_url))
        .bearer_auth(&old_token)
        .send()
        .expect("status with old token");
    assert_eq!(resp.status().as_u16(), 401, "pre-change token must be revoked");

    let resp = client
        .get(format!("{}/auth/status", server.api_url))
        .bearer_auth(&new_token)
        .send()
        .expect("status with new token");
    assert!(resp.status().is_success(), "fresh token must be accepted");
}

/// Sessions are listed per account and individually revocable: revoking a
/// session kills its token immediately while other sessions keep working,
/// and revoke-others keeps only the calling session alive.
#[test]
fn test_session_list_and_revoke() {
    let server = TestServer::start();
    let client = server.http();

    let login = || {
        client
            .post(format!("{}/auth/login", server.api_url))
            .json(&json!({"username": "admin", "password": "changeme"}))
            .send()
            .expect("login")
            .json::<Value>()
            .expect("json")["token"]
            .as_str()
            .expect("token")
            .to_string()
    };
    let token_a = login();
    let token_b = login();

    // From session A: both sessions visible, exactly one marked current.
    let sessions = client
        .get(format!("{}/auth/me/sessions", server.api_url))
        .bearer_auth(&token_a)
        .send()
        .expect("list sessions")
        .json::<Value>()
        .expect("json")["sessions"]
        .as_array()
        .cloned()
        .expect("sessions array");
    assert_eq!(sessions.len(), 2, "sessions: {:?}", sessions);
    assert_eq!(sessions.iter().filter(|s| s["current"] == json!(true)).count(), 1);

    // Revoke session B from session A: B's token dies, A's keeps working.
    let b_id = sessions
        .iter()
        .find(|s| s["current"] == json!(false))
        .expect("other session")["id"]
        .as_i64()
        .expect("id");
    let resp = client
        .delete(format!("{}/auth/me/sessions/{}", server.api_url, b_id))
        .bearer_auth(&token_a)
        .send()
        .expect("revoke");
    assert!(resp.status().is_success());

    let resp = client
        .get(format!("{}/auth/status", server.api_url))
        .bearer_auth(&token_b)
        .send()
        .expect("status b");
    assert_eq!(resp.status().as_u16(), 401, "revoked session must be rejected");
    let resp = client
        .get(format!("{}/auth/status", server.api_url))
        .bearer_auth(&token_a)
        .send()
        .expect("status a");
    assert!(resp.status().is_success());

    // revoke-others keeps only the calling session.
    let token_c = login();
    let resp = client
        .post(format!("{}/auth/me/sessions/revoke-others", server.api_url))
        .bearer_auth(&token_a)
        .send()
        .expect("revoke others");
    assert!(resp.status().is_success());
    let resp = client
        .get(format!("{}/auth/status", server.api_url))
        .bearer_auth(&token_c)
        .send()
        .expect("status c");
    assert_eq!(resp.status().as_u16(), 401);
    let resp = client
        .get(format!("{}/auth/status", server.api_url))
        .bearer_auth(&token_a)
        .send()
        .expect("status a again");
    assert!(resp.status().is_success());
}

/// Admin actions land in the audit trail with actor/action/target; the
/// endpoint itself is admin-only.
#[test]
fn test_audit_log_records_admin_actions() {
    let server = TestServer::start();
    let admin = server.admin_token();
    let client = server.http();

    let license_key = server.create_license(&admin, false);
    client
        .post(format!("{}/auth/users", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({"username": "auditee", "email": "auditee@example.com", "role": "user", "password": "auditpass123"}))
        .send()
        .expect("create user")
        .error_for_status()
        .expect("create user ok");

    let entries = client
        .get(format!("{}/audit", server.api_url))
        .bearer_auth(&admin)
        .send()
        .expect("audit")
        .json::<Value>()
        .expect("json")["entries"]
        .as_array()
        .cloned()
        .expect("entries array");

    let has = |action: &str, target: &str| {
        entries.iter().any(|e| {
            e["action"] == json!(action) && e["target"] == json!(target) && e["actor"] == json!("admin")
        })
    };
    assert!(has("license.create", &license_key), "missing license.create: {:?}", entries);
    assert!(has("user.create", "auditee"), "missing user.create: {:?}", entries);
    assert!(has("auth.2fa_enabled", "admin"), "missing 2fa_enabled: {:?}", entries);

    // Non-admins are denied.
    let user_jwt = client
        .post(format!("{}/auth/login", server.api_url))
        .json(&json!({"username": "auditee", "password": "auditpass123"}))
        .send()
        .expect("login")
        .json::<Value>()
        .expect("json")["token"]
        .as_str()
        .expect("token")
        .to_string();
    let resp = client
        .get(format!("{}/audit", server.api_url))
        .bearer_auth(&user_jwt)
        .send()
        .expect("audit as user");
    assert_eq!(resp.status().as_u16(), 403);
}

/// Stripe-style webhook signature over `{t}.{payload}` with the given secret.
fn stripe_sig(secret: &str, payload: &str, ts: i64) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(ts.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload.as_bytes());
    format!("t={},v1={}", ts, hex::encode(mac.finalize().into_bytes()))
}

/// checkout.session.completed only records an order as 'paid' when Stripe
/// says the payment settled; delayed methods land as 'pending_payment' and
/// flip to 'paid' on checkout.session.async_payment_succeeded.
#[test]
fn test_webhook_respects_payment_status() {
    const SECRET: &str = "whsec_testsecret";
    let server = TestServer::start_with_env(&[("STRIPE_WEBHOOK_SECRET", SECRET)]);
    let admin = server.admin_token();
    let client = server.http();

    let post_event = |event: &Value| {
        let payload = event.to_string();
        let sig = stripe_sig(SECRET, &payload, chrono_now());
        client
            .post(format!("{}/shop/webhook", server.api_url))
            .header("Stripe-Signature", sig)
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .expect("post webhook")
    };
    let order_status = |session_id: &str| -> Option<String> {
        let orders = client
            .get(format!("{}/shop/admin/orders", server.api_url))
            .bearer_auth(&admin)
            .send()
            .expect("list orders")
            .json::<Value>()
            .expect("orders json")["orders"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        orders
            .iter()
            .find(|o| o["stripe_session_id"] == json!(session_id))
            .and_then(|o| o["status"].as_str().map(String::from))
    };
    let session_event = |event_type: &str, session_id: &str, payment_status: &str| {
        json!({
            "type": event_type,
            "data": { "object": {
                "id": session_id,
                "payment_status": payment_status,
                "amount_total": 4200,
                "currency": "usd",
                "customer_details": { "email": "buyer@example.com", "name": "Buyer" },
            }}
        })
    };

    // Card-style settled session records as paid immediately.
    let resp = post_event(&session_event("checkout.session.completed", "cs_card", "paid"));
    assert!(resp.status().is_success());
    assert_eq!(order_status("cs_card").as_deref(), Some("paid"));

    // Delayed method: completed but unpaid -> pending_payment, not paid.
    let resp = post_event(&session_event("checkout.session.completed", "cs_sepa", "unpaid"));
    assert!(resp.status().is_success());
    assert_eq!(order_status("cs_sepa").as_deref(), Some("pending_payment"));

    // Settlement arrives -> order flips to paid.
    let resp = post_event(&session_event(
        "checkout.session.async_payment_succeeded",
        "cs_sepa",
        "paid",
    ));
    assert!(resp.status().is_success());
    assert_eq!(order_status("cs_sepa").as_deref(), Some("paid"));

    // A failed delayed payment is marked, not shipped.
    let resp = post_event(&session_event("checkout.session.completed", "cs_fail", "unpaid"));
    assert!(resp.status().is_success());
    let resp = post_event(&session_event(
        "checkout.session.async_payment_failed",
        "cs_fail",
        "unpaid",
    ));
    assert!(resp.status().is_success());
    assert_eq!(order_status("cs_fail").as_deref(), Some("payment_failed"));
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Failed password logins are counted per account, not just per IP: after 8
/// misses the account locks and even the correct password is rejected with
/// 429 until the window drains.
#[test]
fn test_login_account_lockout() {
    let server = TestServer::start();
    let client = server.http();

    for _ in 0..8 {
        let resp = client
            .post(format!("{}/auth/login", server.api_url))
            .json(&json!({"username": "admin", "password": "wrong-password"}))
            .send()
            .expect("login");
        assert_eq!(resp.status().as_u16(), 401);
    }

    let resp = client
        .post(format!("{}/auth/login", server.api_url))
        .json(&json!({"username": "admin", "password": "changeme"}))
        .send()
        .expect("login");
    assert_eq!(resp.status().as_u16(), 429);
    let body = resp.json::<Value>().expect("json");
    assert!(
        body["error"].as_str().unwrap_or("").contains("failed login"),
        "expected account-lockout message, got: {}",
        body
    );
}

/// Wrong sign-in code guesses are counted per account: after 5 misses the
/// exchange endpoint returns 429 for that account instead of another generic
/// 401, independent of the per-IP limit.
#[test]
fn test_signin_code_guess_lockout() {
    let server = TestServer::start();
    let client = server.http();

    for _ in 0..5 {
        let resp = client
            .post(format!("{}/auth/signin-code", server.api_url))
            .json(&json!({"username": "admin", "code": "000000"}))
            .send()
            .expect("signin-code");
        assert_eq!(resp.status().as_u16(), 401);
    }

    let resp = client
        .post(format!("{}/auth/signin-code", server.api_url))
        .json(&json!({"username": "admin", "code": "000000"}))
        .send()
        .expect("signin-code");
    assert_eq!(resp.status().as_u16(), 429);

    // A different account is unaffected by admin's lockout.
    let resp = client
        .post(format!("{}/auth/signin-code", server.api_url))
        .json(&json!({"username": "someone-else", "code": "000000"}))
        .send()
        .expect("signin-code");
    assert_eq!(resp.status().as_u16(), 401);
}

/// Renaming a user migrates every username-keyed row: license assignments,
/// API tokens (and the auth cache), and flags self-renames so the UI can
/// force a re-login.
#[test]
fn test_rename_user_migrates_everything() {
    let server = TestServer::start();
    let admin = server.admin_token();
    let client = server.http();

    client
        .post(format!("{}/auth/users", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({
            "username": "old_name",
            "email": "old@example.com",
            "role": "user",
            "password": "oldpass123",
        }))
        .send()
        .expect("create user")
        .error_for_status()
        .expect("create user ok");

    // Assign a license and mint an API token as that user.
    let key = server.create_license(&admin, false);
    client
        .post(format!("{}/licenses/{}/users", server.api_url, key))
        .bearer_auth(&admin)
        .json(&json!({"username": "old_name"}))
        .send()
        .expect("assign")
        .error_for_status()
        .expect("assign ok");

    let user_jwt = client
        .post(format!("{}/auth/login", server.api_url))
        .json(&json!({"username": "old_name", "password": "oldpass123"}))
        .send()
        .expect("login")
        .json::<Value>()
        .expect("json")["token"]
        .as_str()
        .expect("token")
        .to_string();
    let api_token = client
        .post(format!("{}/auth/api-tokens", server.api_url))
        .bearer_auth(&user_jwt)
        .json(&json!({"name": "ci"}))
        .send()
        .expect("mint token")
        .json::<Value>()
        .expect("json")["token"]
        .as_str()
        .expect("token")
        .to_string();

    // Rename via admin.
    let resp = client
        .post(format!("{}/auth/users/old_name/rename", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({"new_username": "new_name"}))
        .send()
        .expect("rename");
    let body = resp.json::<Value>().expect("json");
    assert_eq!(body["status"], json!("OK"));
    assert_eq!(body["self_renamed"], json!(false));

    // The old-name JWT no longer resolves to an existing account - the
    // token-version check rejects it outright.
    let mine = client
        .get(format!("{}/my/licenses", server.api_url))
        .bearer_auth(&user_jwt)
        .send()
        .expect("my licenses");
    assert_eq!(mine.status().as_u16(), 401, "old-name JWT must be rejected");

    // The API token still works and resolves to the new name.
    let mine = client
        .get(format!("{}/my/licenses", server.api_url))
        .bearer_auth(&api_token)
        .send()
        .expect("my licenses via api token")
        .json::<Value>()
        .expect("json");
    assert_eq!(mine.as_array().expect("array").len(), 1);

    // Fresh login under the new name sees the license.
    let new_jwt = client
        .post(format!("{}/auth/login", server.api_url))
        .json(&json!({"username": "new_name", "password": "oldpass123"}))
        .send()
        .expect("relogin")
        .json::<Value>()
        .expect("json")["token"]
        .as_str()
        .expect("token")
        .to_string();
    let mine = client
        .get(format!("{}/my/licenses", server.api_url))
        .bearer_auth(&new_jwt)
        .send()
        .expect("my licenses new name")
        .json::<Value>()
        .expect("json");
    assert_eq!(mine.as_array().expect("array").len(), 1);
}

/// Rename onto a name that still has orphaned membership rows (e.g. from a
/// deleted account) must merge instead of failing: one surviving row, and
/// the whole rename stays atomic.
#[test]
fn test_rename_user_merges_conflicting_memberships() {
    let server = TestServer::start();
    let admin = server.admin_token();
    let client = server.http();

    for name in ["merge_x", "merge_y"] {
        client
            .post(format!("{}/auth/users", server.api_url))
            .bearer_auth(&admin)
            .json(&json!({
                "username": name,
                "email": format!("{}@example.com", name),
                "role": "user",
                "password": "mergepass123",
            }))
            .send()
            .expect("create user")
            .error_for_status()
            .expect("create user ok");
    }

    let ws = client
        .post(format!("{}/workspaces", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({"name": "Merge WS", "product": "fusionhub", "description": ""}))
        .send()
        .expect("create ws")
        .json::<Value>()
        .expect("ws json");
    let ws_id = ws["id"].as_str().expect("ws id").to_string();

    for name in ["merge_x", "merge_y"] {
        client
            .post(format!("{}/workspaces/{}/members", server.api_url, ws_id))
            .bearer_auth(&admin)
            .json(&json!({"username": name}))
            .send()
            .expect("add member")
            .error_for_status()
            .expect("add member ok");
    }

    // Push a config revision as merge_y so the rename has authorship to migrate.
    let merge_y_jwt = client
        .post(format!("{}/auth/login", server.api_url))
        .json(&json!({"username": "merge_y", "password": "mergepass123"}))
        .send()
        .expect("login merge_y")
        .json::<Value>()
        .expect("json")["token"]
        .as_str()
        .expect("token")
        .to_string();
    // Clear the must-change-password bootstrap gate so the push isn't 403'd.
    // Adopt the fresh token (the change revokes the login token).
    let merge_y_jwt = client
        .post(format!("{}/auth/change-password", server.api_url))
        .bearer_auth(&merge_y_jwt)
        .json(&json!({"current_password": "mergepass123", "new_password": "mergepass456"}))
        .send()
        .expect("change pw")
        .error_for_status()
        .expect("change pw ok")
        .json::<Value>()
        .expect("json")["token"]
        .as_str()
        .expect("token")
        .to_string();
    client
        .post(format!("{}/workspaces/{}/configs", server.api_url, ws_id))
        .bearer_auth(&merge_y_jwt)
        .json(&json!({"config_json": "{}", "name": "test rev", "description": ""}))
        .send()
        .expect("push config")
        .error_for_status()
        .expect("push config ok");

    // Deleting merge_x leaves its membership row orphaned (no FK on username).
    client
        .delete(format!("{}/auth/users/merge_x", server.api_url))
        .bearer_auth(&admin)
        .send()
        .expect("delete user")
        .error_for_status()
        .expect("delete ok");

    // Rename merge_y -> merge_x: must merge with the orphan row, not 500.
    let resp = client
        .post(format!("{}/auth/users/merge_y/rename", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({"new_username": "merge_x"}))
        .send()
        .expect("rename");
    assert!(resp.status().is_success(), "rename: {}", resp.text().unwrap_or_default());

    let ws = client
        .get(format!("{}/workspaces/{}", server.api_url, ws_id))
        .bearer_auth(&admin)
        .send()
        .expect("get ws")
        .json::<Value>()
        .expect("ws json");
    let members: Vec<&str> = ws["members"]
        .as_array()
        .expect("members")
        .iter()
        .map(|m| m["username"].as_str().unwrap())
        .collect();
    let merge_rows: Vec<_> = members.iter().filter(|u| **u == "merge_x").collect();
    assert_eq!(merge_rows.len(), 1, "exactly one surviving membership: {:?}", members);

    // Config-revision authorship follows the rename.
    let configs = client
        .get(format!("{}/workspaces/{}/configs", server.api_url, ws_id))
        .bearer_auth(&admin)
        .send()
        .expect("list configs")
        .json::<Value>()
        .expect("configs json");
    let revs = configs["configs"]
        .as_array()
        .or_else(|| configs.as_array())
        .expect("configs array")
        .clone();
    assert!(!revs.is_empty(), "expected a config revision: {}", configs);
    assert_eq!(revs[0]["author"], json!("merge_x"), "author must follow rename: {}", configs);
}

/// A site admin who is not a member of a workspace must still have full access
/// (read detail, manage members, push configs) - the same as an owner/editor
/// member. Non-admin non-members stay denied.
#[test]
fn test_admin_non_member_has_full_workspace_access() {
    let server = TestServer::start();
    let admin = server.admin_token();
    let client = server.http();

    // Admin creates a workspace (auto-added as a member), then removes its own
    // membership so it is a pure non-member site admin.
    let ws_id = client
        .post(format!("{}/workspaces", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({"name": "Admin Access WS", "product": "fusionhub", "description": ""}))
        .send()
        .expect("create ws")
        .json::<Value>()
        .expect("ws json")["id"]
        .as_str()
        .expect("ws id")
        .to_string();

    client
        .delete(format!("{}/workspaces/{}/members/admin", server.api_url, ws_id))
        .bearer_auth(&admin)
        .send()
        .expect("remove self membership")
        .error_for_status()
        .expect("remove ok");

    // Non-member admin can still read the workspace detail.
    let resp = client
        .get(format!("{}/workspaces/{}", server.api_url, ws_id))
        .bearer_auth(&admin)
        .send()
        .expect("get ws");
    assert!(resp.status().is_success(), "admin get ws: {}", resp.text().unwrap_or_default());
    let ws = resp.json::<Value>().expect("ws json");
    assert_eq!(ws["name"], json!("Admin Access WS"), "admin sees workspace detail: {}", ws);

    // ... and manage members.
    client
        .post(format!("{}/auth/users", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({"username": "regular_u", "email": "regular_u@example.com", "role": "user", "password": "regularpass123"}))
        .send()
        .expect("create user")
        .error_for_status()
        .expect("create user ok");
    let resp = client
        .post(format!("{}/workspaces/{}/members", server.api_url, ws_id))
        .bearer_auth(&admin)
        .json(&json!({"username": "regular_u"}))
        .send()
        .expect("add member");
    assert!(resp.status().is_success(), "admin add member: {}", resp.text().unwrap_or_default());

    // ... and push a config (write access comes with membership).
    let resp = client
        .post(format!("{}/workspaces/{}/configs", server.api_url, ws_id))
        .bearer_auth(&admin)
        .json(&json!({"config_json": "{}", "name": "admin rev", "description": ""}))
        .send()
        .expect("push config");
    assert_eq!(resp.status().as_u16(), 201, "admin push config: {}", resp.text().unwrap_or_default());

    // A non-admin who is not a member is still denied.
    client
        .post(format!("{}/auth/users", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({"username": "outsider", "email": "outsider@example.com", "role": "user", "password": "outsiderpass123"}))
        .send()
        .expect("create outsider")
        .error_for_status()
        .expect("create outsider ok");
    let outsider_jwt = client
        .post(format!("{}/auth/login", server.api_url))
        .json(&json!({"username": "outsider", "password": "outsiderpass123"}))
        .send()
        .expect("login outsider")
        .json::<Value>()
        .expect("json")["token"]
        .as_str()
        .expect("token")
        .to_string();
    let outsider_jwt = client
        .post(format!("{}/auth/change-password", server.api_url))
        .bearer_auth(&outsider_jwt)
        .json(&json!({"current_password": "outsiderpass123", "new_password": "outsiderpass456"}))
        .send()
        .expect("change pw")
        .error_for_status()
        .expect("change pw ok")
        .json::<Value>()
        .expect("json")["token"]
        .as_str()
        .expect("token")
        .to_string();
    let resp = client
        .get(format!("{}/workspaces/{}", server.api_url, ws_id))
        .bearer_auth(&outsider_jwt)
        .send()
        .expect("outsider get ws");
    assert_eq!(resp.status().as_u16(), 403, "non-admin non-member must be denied");
}

/// Admins can promote a user to admin and demote them back, but cannot change
/// their own role (self-lockout guard). Invalid roles and unknown users are
/// rejected.
#[test]
fn test_set_user_role() {
    let server = TestServer::start();
    let admin = server.admin_token();
    let client = server.http();

    client
        .post(format!("{}/auth/users", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({"username": "promote_me", "email": "promote_me@example.com", "role": "user", "password": "promotepass123"}))
        .send()
        .expect("create user")
        .error_for_status()
        .expect("create user ok");

    let role_of = |username: &str| -> String {
        client
            .get(format!("{}/auth/users", server.api_url))
            .bearer_auth(&admin)
            .send()
            .expect("list users")
            .json::<Value>()
            .expect("json")
            .as_array()
            .expect("array")
            .iter()
            .find(|u| u["username"] == json!(username))
            .expect("user present")["role"]
            .as_str()
            .expect("role")
            .to_string()
    };

    assert_eq!(role_of("promote_me"), "user");

    // Promote, then demote.
    let resp = client
        .put(format!("{}/auth/users/promote_me/role", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({"role": "admin"}))
        .send()
        .expect("promote");
    assert!(resp.status().is_success(), "promote: {}", resp.text().unwrap_or_default());
    assert_eq!(role_of("promote_me"), "admin");

    let resp = client
        .put(format!("{}/auth/users/promote_me/role", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({"role": "user"}))
        .send()
        .expect("demote");
    assert!(resp.status().is_success(), "demote: {}", resp.text().unwrap_or_default());
    assert_eq!(role_of("promote_me"), "user");

    // Cannot change own role.
    let resp = client
        .put(format!("{}/auth/users/admin/role", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({"role": "user"}))
        .send()
        .expect("self role");
    assert_eq!(resp.status().as_u16(), 400, "self role-change must be rejected");
    assert_eq!(role_of("admin"), "admin", "admin must remain admin");

    // Invalid role rejected.
    let resp = client
        .put(format!("{}/auth/users/promote_me/role", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({"role": "superuser"}))
        .send()
        .expect("bad role");
    assert_eq!(resp.status().as_u16(), 400, "invalid role must be rejected");

    // Unknown user -> 404.
    let resp = client
        .put(format!("{}/auth/users/ghost/role", server.api_url))
        .bearer_auth(&admin)
        .json(&json!({"role": "admin"}))
        .send()
        .expect("ghost role");
    assert_eq!(resp.status().as_u16(), 404, "unknown user must 404");
}
