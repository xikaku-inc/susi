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

use std::process::{Child, Command};
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use serde_json::{json, Value};
use susi_client::{binary_signing, LicenseClient, LicenseStatus};
use susi_core::crypto::{generate_keypair, private_key_to_pem, public_key_to_pem};

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

        let child = Command::new(env!("CARGO_BIN_EXE_susi-server"))
            .arg("--private-key").arg(&key_path)
            .arg("--db").arg(&db_path)
            .arg("--listen").arg(format!("127.0.0.1:{}", port))
            .arg("--data-dir").arg(dir.path())
            .spawn()
            .expect("spawn susi-server");

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
        let resp = client
            .post(format!("{}/auth/change-password", self.api_url))
            .bearer_auth(&token)
            .json(&json!({
                "current_password": "changeme",
                "new_password": "testpassword1"
            }))
            .send()
            .expect("change-password");
        assert!(
            resp.status().is_success(),
            "change-password failed: {}",
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

/// Full happy-path: activate a `require_signed_binary=false` license via the
/// server, then verify it locally through [`LicenseClient::verify_and_refresh`].
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
        .expect("LicenseClient");

    let status = client.verify_and_refresh(&license_path, &license_key, None);
    assert!(status.is_valid(), "expected Valid, got: {:?}", status);
    assert!(status.has_feature("imu_optical_fusion"));
    assert!(!status.has_feature("vehicular_fusion"));
}

/// Calling [`LicenseClient::verify_and_refresh`] a second time contacts the
/// server again to renew the lease.  Both calls must return `Valid`.
#[test]
fn test_lease_renewal_via_server() {
    let server = TestServer::start();
    let token = server.admin_token();
    let license_key = server.create_license(&token, false);

    let license_path = server._dir.path().join("license.json");
    let client = LicenseClient::with_server(&server.public_key_pem, server.api_url.clone())
        .expect("LicenseClient");

    let status = client.verify_and_refresh(&license_path, &license_key, None);
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
    http.post(format!("{}/auth/change-password", api_url))
        .bearer_auth(&token)
        .json(&json!({"current_password": "changeme", "new_password": "testpassword1"}))
        .send().unwrap();

    let resp = http.post(format!("{}/licenses", api_url))
        .bearer_auth(&token)
        .json(&json!({"customer": "Corp", "days": 30, "require_signed_binary": false}))
        .send().unwrap();
    let license_key = resp.json::<Value>().unwrap()["license_key"]
        .as_str().unwrap().to_string();

    // Prime the on-disk cache.
    let license_path = dir.path().join("license.json");
    let client = LicenseClient::with_server(&public_pem, api_url.clone()).unwrap();
    let status = client.verify_and_refresh(&license_path, &license_key, None);
    assert!(status.is_valid(), "initial: {:?}", status);

    // Kill server — dir (and cached file) remain alive.
    child.kill().ok();
    child.wait().ok();

    // A second client aimed at the now-dead server must fall back to the file.
    let client2 = LicenseClient::with_server(&public_pem, api_url).unwrap();
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
    let machine_code = LicenseClient::get_machine_code().expect("machine code");
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
    let client = LicenseClient::new(&server.public_key_pem).expect("LicenseClient");
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
    let machine_code = LicenseClient::get_machine_code().unwrap();
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
    let client = LicenseClient::new(&server.public_key_pem).unwrap();
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
    let license_key = server.create_license(&token, false);
    let machine_code = susi_client::LicenseClient::get_machine_code()
        .expect("machine code");

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
    assert_eq!(resp.status().as_u16(), 403, "no chain should be rejected");
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
