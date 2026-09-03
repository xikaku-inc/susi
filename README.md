# susi

*Susi* (Tagalog for "key") - a self-hosted backend platform written in Rust. It started as a software-licensing server and has grown to bundle everything a small product company needs around a downloadable application: signed licensing, release distribution, a documentation knowledge base, a public website, a Stripe-backed shop, and a contact form - all served from a single binary with a SQLite store.

## Features

### Licensing
- **RSA-SHA256 signed license files** - tamper-proof, offline-verifiable
- **Node-locked licenses** - bind licenses to specific machines via hardware fingerprint
- **Feature flags, expiry dates, machine limits** - fine-grained per-license policy
- **Lease-based seat management** - time-limited activations that expire automatically, preventing unauthorized concurrent usage
- **USB hardware tokens** - bind a license to a physical USB stick instead of a machine
- **Binary signing enforcement** - optionally require the consuming binary to carry a valid code signature, making tampering detectable at license-verification time
- **Cross-platform** - Linux and Windows support
- **Rust + C++ client libraries** - drop-in verification for both ecosystems

### Releases & workspaces
- **Workspaces** - group licenses, files, configs, and docs per product/team
- **Workspace files & docs** - flat member-writable file share and documentation per workspace
- **Workspace tickets** - customer-visible issue list per workspace with comments; admins get a cross-workspace queue
- **Versioned config revisions** - push, fetch, and roll back JSON configs per workspace
- **Binary release channel** - upload signed installers/binaries; clients fetch via license-key-protected `/api/v1/updates`

### Documentation & website
- **Documentation knowledge base** - per-release doc sets at `/docs`, with Markdown editor, asset uploads, bulk import, and origin tagging (pipeline-generated vs. user-edited pages)
- **Public marketing website** - `/site` with in-browser Markdown editor, asset library, page revision history, and per-page SEO (`robots.txt`, `sitemap.xml`, `llms.txt`)

### Commerce
- **Stripe-backed shop** - products, shipping rates, automatic-tax checkout, branded order confirmations with PDF invoices, and an admin fulfillment workflow
- **Public contact form** - Cloudflare Turnstile + honeypot + per-IP rate limit, served at the `/site` chrome

### Auth & ops
- **Multi-user dashboard** with Argon2id passwords, **TOTP 2FA + backup codes**, **emailed sign-in code for new devices**, **trusted-device list**, **password reset via email**, and **API tokens** for headless clients
- **Optional activation server** - HTTP server for online activation, lease renewal, and machine management
- **One-command deploy** - Docker + Compose with separate production / staging environments
- **Cross-platform clients** - Linux, Windows, macOS

## Architecture

```
┌──────────────────┐     ┌────────────────────────────────────┐     ┌─────────────────────┐
│  susi_admin      │     │           susi_server              │     │  susi_client        │
│  (CLI tool)      │     │       (HTTP server + UI)           │     │  (Rust library)     │
│                  │     │                                    │     │                     │
│  keygen          │     │  /api/v1/{auth, licenses,          │     │  verify signature   │
│  create license  │     │           activate, verify,        │     │  check expiry       │
│  export / list   │     │           workspaces, releases,    │     │  check machine      │
│  export-token    │     │           docs, website, shop,     │     │  check features     │
│  revoke          │     │           contact, ...}            │     │  check lease        │
│                  │     │                                    │     │  verify USB token   │
│                  │     │  Dashboard + /site + /docs + /shop │     │  workspace client   │
└────────┬─────────┘     └────────────────────┬───────────────┘     └─────────────────────┘
         │                                    │
         └────────────────┬───────────────────┘
                          ▼
                 ┌─────────────────┐
                 │   susi_core     │
                 │  (shared lib)   │
                 │                 │
                 │  data models    │
                 │  RSA sign/verify│
                 │  HW fingerprint │
                 │  USB token crypt│
                 │  SQLite storage │
                 └─────────────────┘
```

| Crate | Type | Description |
|---|---|---|
| `susi_core` | Library | Shared types, RSA crypto, hardware fingerprinting, USB token encryption, SQLite storage |
| `susi_client` | Library | Verification library + workspace/release/docs HTTP client (sync + async APIs) |
| `susi_admin` | Binary | CLI tool for key generation, license creation, and management |
| `susi_server` | Binary | HTTP server with SQLite backend - licensing, releases, docs, website, shop, contact |
| `susi_helper` | Binary | End-user utility for retrieving machine fingerprints and USB serial numbers |
| `cpp/` | C++ Library | Standalone verification client for C++ applications |

`susi_server` is split into one module per surface area (`docs.rs`, `website.rs`, `shop.rs`, `contact.rs`, `email.rs`, `invoice_pdf.rs` plus the licensing/auth core in `main.rs`) so each feature can be reasoned about independently.

## Quick Start

### 1. Generate a keypair

```bash
susi-admin keygen --output-dir ./keys/
```

This creates `private.pem` (keep secret) and `public.pem` (distribute with your application).

### 2. Create a license

```bash
# Time-limited license with lease enforcement (default: 3-day lease, 24h grace)
susi-admin create \
  --customer "Acme Corp" \
  --product "MyApp" \
  --days 365 \
  --features "pro,analytics" \
  --max-machines 3

# Custom lease duration (48-hour lease, 12-hour grace period)
susi-admin create \
  --customer "Acme Corp" \
  --days 365 \
  --features "pro" \
  --max-machines 1 \
  --lease-duration 48 \
  --lease-grace 12

# Perpetual license without lease enforcement (trusted customer)
susi-admin create \
  --customer "Acme Corp" \
  --perpetual \
  --features "pro" \
  --lease-duration 0

# Allow unsigned binaries (e.g. development/internal build)
susi-admin create \
  --customer "Acme Corp" \
  --days 365 \
  --features "pro" \
  --no-require-signed-binary
```

### 3. Export a signed license file

```bash
# Lock to a specific machine
susi-admin export \
  --key "XXXXX-XXXXX-XXXXX-XXXXX" \
  --auto \
  --private-key ./keys/private.pem \
  --output license.json

# Or specify a machine code manually
susi-admin export \
  --key "XXXXX-XXXXX-XXXXX-XXXXX" \
  --machine-code "a1b2c3..." \
  --name "Production Server" \
  --private-key ./keys/private.pem
```

### 4. Verify in your application

```rust
use susi_client::{LicenseClient, LicenseStatus};
use std::path::Path;

let client = LicenseClient::new(include_str!("public.pem")).unwrap();
let status = client.verify_file(Path::new("license.json"));

match status {
    LicenseStatus::Valid { payload } => {
        println!("Licensed to: {}", payload.customer);
        println!("Features: {:?}", payload.features);
        if payload.has_feature("pro") {
            // enable pro features
        }
    }
    LicenseStatus::ValidGracePeriod { payload, lease_expired_at } => {
        // License still works, but lease needs renewal
        eprintln!("Lease expired at {}, renew soon!", lease_expired_at);
        // trigger background renewal...
    }
    LicenseStatus::LeaseExpired { lease_expired_at } => {
        eprintln!("Lease expired at {} - must renew to continue", lease_expired_at);
    }
    LicenseStatus::Expired { expired_at } => {
        eprintln!("License expired on {}", expired_at.format("%Y-%m-%d"));
    }
    LicenseStatus::InvalidMachine { .. } => {
        eprintln!("License not valid for this machine");
    }
    LicenseStatus::InvalidSignature => {
        eprintln!("License file has been tampered with");
    }
    LicenseStatus::FileNotFound(err) => {
        eprintln!("License file not found: {}", err);
    }
    other => eprintln!("License error: {:?}", other),
}
```

### 5. Verify in your C++ application

The `cpp/` directory contains a standalone C++ client that uses OpenSSL for verification. There are two ways to integrate it:

#### Option A: Conan package

Build and publish the library to your local Conan cache, then consume it from your project:


1. Install susi into your local cache, by executing this in the `cpp/` directory: `conan create .`
2. In you project's conanfile, add: `requires = "susi/<version>"/self.requires("susi/<version>")`
3. Add the following two lines to you ´CMakeLists.txt´:
```cmake
find_package(susi REQUIRED)
...
target_link_libraries(your_target PRIVATE susi::susi)
```
4. Build using conan and CMake:
```bash
conan install . --build=missing
cmake --preset=<preset>
cmake --build --preset=<preset>
```

#### Option B: CMake add_subdirectory

1. Copy or clone the `cpp/` directory into your project
2. Add it as a subdirectory to you `CMakeLists.txt`:
```cmake
add_subdirectory(susi/cpp)
target_link_libraries(your_target PRIVATE susi::susi)
```
3. Build using CMake:
```bash
cmake -B build -S .
cmake --build build
```

With this approach you must provide the dependecies (OpenSSL, nlohmann/json and libcurl) yourself and make sure CMake can find them.

Then you can use it in your project:

```cpp
#include <susi.h>

SusiClient susi("your-public-key");

// Pass path to license file
auto status = susi.checkLicense("license.json");

switch (status) {
    case SusiClient::LicenseStatus::Valid:
        // License is valid
        break;
    case SusiClient::LicenseStatus::ValidGracePeriod:
        // Lease expired but still in grace period - trigger renewal
        break;
    case SusiClient::LicenseStatus::Expired:
        // License has expired
        break;
    case SusiClient::LicenseStatus::LeaseExpired:
        // Lease and grace period both expired - must renew
        break;
    case SusiClient::LicenseStatus::InvalidMachine:
        // License not valid for this machine
        break;
    case SusiClient::LicenseStatus::InvalidSignature:
        // License file has been tampered with
        break;
    case SusiClient::LicenseStatus::FileNotFound:
        // License file not found
        break;
    default:
        // Other error
        break;
}

if (susi.isValid()){
  // license valid
  if (susi.hasFeature("pro")) {
    // enable pro features
  }
}
```

To use your own logging framework instead of `fprintf`, define `SUSI_LOG` before including `susi.cpp`:

```cpp
#define SUSI_LOG(fmt, ...) my_logger("susi", fmt, ##__VA_ARGS__)
```

### 6. License Status Values

All verification methods return a status indicating the result. The following table lists all possible values:

| Description                                                            | Rust                                                            | C++                                |
| ---------------------------------------------------------------------- | --------------------------------------------------------------- | ---------------------------------- |
| License is valid and active                                            | `LicenseStatus::Valid { payload }`                              | `LicenseStatus::Valid`             |
| Lease expired but within grace period                                  | `LicenseStatus::ValidGracePeriod { payload, lease_expired_at }` | `LicenseStatus::ValidGracePeriod`  |
| Lease and grace period both expired                                    | `LicenseStatus::LeaseExpired { lease_expired_at }`              | `LicenseStatus::LeaseExpired`      |
| License expired                                                        | `LicenseStatus::Expired { expired_at }`                         | `LicenseStatus::Expired`           |
| License not valid for this machine or machine limit of license reached | `LicenseStatus::InvalidMachine { expected, actual }`            | `LicenseStatus::InvalidMachine`    |
| License file has been tampered with                                    | `LicenseStatus::InvalidSignature`                               | `LicenseStatus::InvalidSignature`  |
| License key not recognized                                             | `LicenseStatus::InvalidLicenseKey`                              | `LicenseStatus::InvalidLicenseKey` |
| License has been revoked                                               | `LicenseStatus::Revoked`                                        | `LicenseStatus::Revoked`           |
| Binary is not code-signed (requires_signed_binary license flag is set) | `LicenseStatus::UnsignedBinary`                                 | `LicenseStatus::UnsignedBinary`    |
| No USB token found                                                     | `LicenseStatus::TokenNotFound`                                  | `LicenseStatus::TokenNotFound`     |
| License file not found on disk                                         | `LicenseStatus::FileNotFound(String)`                           | `LicenseStatus::FileNotFound`      |
| Other error (parse error, crypto failure, etc.)                        | `LicenseStatus::Error(String)`                                  | `LicenseStatus::Error`             |

## License File Format

The signed license file is JSON with two fields:

```json
{
  "license_data": "{\"id\":\"...\",\"product\":\"MyApp\",\"customer\":\"Acme Corp\",...}",
  "signature": "Base64-encoded RSA-SHA256 signature of license_data"
}
```

The `license_data` field is a JSON-serialized `LicensePayload`:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "product": "MyApp",
  "customer": "Acme Corp",
  "license_key": "XXXXX-XXXXX-XXXXX-XXXXX",
  "created": "2025-01-15T00:00:00Z",
  "expires": "2026-01-15T23:59:59Z",
  "features": ["pro", "analytics"],
  "machine_codes": ["a1b2c3d4..."],
  "lease_expires": "2025-01-22T00:00:00Z"
}
```

- `expires` - `null` for perpetual licenses
- `lease_expires` - omitted when lease enforcement is disabled (`lease_duration = 0`). When present, the client must renew before this time or the license stops working (after the grace period).
- `require_signed_binary` - omitted in old license files (defaults to `false`). When `true`, the client checks that the running binary carries a valid code signature before returning `Valid`.

## Hardware Fingerprinting

Machine identity is computed differently depending on the operating system:
- Windows: BIOS UUID + CPU processor ID
- Linux: /etc/machine-id + serial number of root drive
- macOS: IOPlatformUUID + IOPlatformSerialNumber

These values are combined and hashed with SHA-256 to produce a stable fingerprint. Print the current machine's fingerprint with:

```bash
susi-helper fingerprint
```

> Admins can also use `susi-admin fingerprint`, but `susi-helper` is the lightweight tool intended for end users.

## USB Hardware Tokens

Instead of binding a license to a specific machine, you can bind it to a physical USB stick. The license file is stored on the USB drive, encrypted with a key derived from the device's hardware serial number. Plug the stick into any machine and the software is licensed - remove it and it's not. Copying the file to a different USB stick fails because the serial number won't match.

### How it works

1. The admin exports a license to a USB stick via `susi-admin export-token`
2. The signed license is encrypted with `AES-256-GCM` using a key derived from `HKDF-SHA256(usb_serial_number)`
3. The encrypted blob is written to `<usb_mount>/.susi/license.bin`
4. At runtime, the client scans connected USB drives for this file, decrypts it using the device's serial, and verifies the RSA signature as usual

Token-bound licenses have a machine code based on the serial number of the USB stick: `usb:<serial>`.

On **Linux**, the client reads the USB hardware serial from sysfs (the same string exposed under the block device’s USB parent). On **Windows** the same value is resolved from the **PnP device instance ID** for `USBSTOR` (the `SERIAL` segment before `&0` in the instance path), not the SCSI/storage inquiry serial. That keeps the reported serial aligned across platforms for typical USB mass-storage sticks.

### Export a license to a USB token

Insert a USB stick, then:

```bash
susi-admin export-token \
  --key "XXXXX-XXXXX-XXXXX-XXXXX" \
  --private-key ./keys/private.pem
```

If only one USB device is connected it is selected automatically. With multiple devices, the tool lists them and you specify which one:

```bash
susi-admin export-token \
  --key "XXXXX-XXXXX-XXXXX-XXXXX" \
  --private-key ./keys/private.pem \
  --usb-serial "ABC123DEF456"
```

### Verify from a USB token (Rust)

```rust
let client = LicenseClient::new(include_str!("public.pem")).unwrap();
let status = client.verify_token();

if status.is_valid() {
    // license valid
    if status.has_feature("pro") {
        // enable pro features
    }
}
```

### Verify from a USB token (C++)

```cpp
SusiClient susi("your-public-key");
auto status = susi.checkLicenseToken();

if (susi.isValid()) {
    // license valid
    if (susi.hasFeature("pro")) {
        // enable pro features
    }
}
```

### Token file format

The `.susi/license.bin` file on the USB stick contains:

| Offset | Size | Content |
|---|---|---|
| 0 | 12 bytes | Random AES-GCM nonce |
| 12 | N bytes | AES-256-GCM ciphertext (encrypted `SignedLicense` JSON) |
| 12+N | 16 bytes | AES-GCM authentication tag |

The encryption key is derived as: `HKDF-SHA256(ikm=usb_serial, salt="susi-token-v1", info="license-encryption")`.

## Binary Signing Enforcement

Licenses can require that the consuming binary carries a valid OS-level code signature. If the binary has been tampered with or replaced, the signature check fails and the client returns `LicenseStatus::UnsignedBinary` instead of `Valid`.

The check is performed by the client library at license-verification time using native platform APIs:

| Platform | Mechanism | What passes |
|---|---|---|
| Windows | `WinVerifyTrust` (Authenticode) | Binaries signed with a certificate trusted by the machine's certificate store |
| macOS | `SecStaticCodeCheckValidity` | Binaries with any valid code signature (cryptographic integrity) |
| Linux | - | Always passes (no standard mechanism) |

### Per-license control

New licenses have `require_signed_binary: false` by default. Use `--require-signed-binary` to opt in:

```bash
# Default: no binary signature check
susi-admin create --customer "Acme Corp" --days 365 --features "pro"

# Opt in: binary signature required
susi-admin create --customer "Acme Corp" --days 365 --features "pro" \
  --require-signed-binary
```

Old license files that pre-date this feature have no `require_signed_binary` field; they are treated as `false` (backward compatible).

### Startup enforcement

Beyond checking at license-verification time, you can optionally abort the process at startup (before `main()`) if the binary is not signed.

**Rust** - enable the `require-signed-binary` Cargo feature:

```toml
[dependencies]
susi_client = { path = "…", features = ["require-signed-binary"] }
```

This installs a global constructor that calls `abort()` before `main()` if the binary signature check fails. No call-site code is needed.

**C++** - set the `SUSI_REQUIRE_SIGNED_BINARY` build option:

```bash
# Via Conan
conan install . -o susi/*:require_signed_binary=True --build=missing

# Via conanfile.py
default_options = {
  "susi/*:require_signed_binary": True
}

# Via CMake directly
cmake -DSUSI_REQUIRE_SIGNED_BINARY=ON <source_dir>

# Via parent CMakeLists.txt (before add_subdirectory)
set(SUSI_REQUIRE_SIGNED_BINARY ON)
```

This defines the preprocessor macro `SUSI_REQUIRE_SIGNED_BINARY=1`, which installs a C++ static object whose constructor aborts the process at startup if the binary is unsigned.

### Testing with a self-signed certificate

To test the signed-binary path in development you need a code-signing certificate trusted by the local machine. Helper scripts are provided in `scripts/`:

**Windows**

```powershell
# One-time setup: create a self-signed CA and add it to the machine trust stores.
# Requires an elevated PowerShell prompt.
.\scripts\create-test-codesign-cert.ps1

# Build tests without running, sign the test binary, then run the tests.
.\scripts\sign-and-test.ps1

# Sign an arbitrary binary
.\scripts\sign-binary.ps1 -BinaryPath .\target\release\myapp.exe

# Clean up (removes cert from trust stores and deletes the PFX)
.\scripts\remove-test-codesign-cert.ps1
```

**macOS**

```bash
# One-time setup: create a self-signed cert and trust it in the system keychain.
# Requires sudo for the trust step.
bash scripts/create-test-codesign-cert.sh

# Build tests without running (cargo prints the path to the test binary)
cargo test --no-run --test integration

# Sign the test binary
codesign -s "Susi Test Code Signing" --force /path/to/test/binary

# Run the tests
cargo test --test integration
```

### Limitations

The check runs inside the process being verified, on hardware the licensee controls. A sufficiently motivated local administrator can bypass it by:

- Adding a self-signed certificate to the machine's trust store and re-signing a modified binary (Windows)
- Signing a modified binary with any certificate (macOS, with the current `kSecCSDefaultFlags` / NULL requirement)

The feature meaningfully raises the bar against casual binary patching but is not a hard cryptographic boundary against a determined local admin. Future server-side CA pinning (planned) will require the client to prove its signing certificate traces to the vendor's CA during every activation, closing the self-signed certificate bypass.

## Susi Helper

`susi-helper` is a small end-user utility that helps customers provide the information needed to activate a license. It requires no database or private key - it is safe to ship to end users alongside your product.

```bash
# Print the hardware fingerprint of the current machine
# (paste this into the dashboard's "Machine Code" field when exporting a license)
susi-helper fingerprint

# List all connected USB drives and their serial numbers
# (use the serial shown here when exporting a USB token license)
susi-helper list-usb-serials
```

Example output of `list-usb-serials`:

```
NAME              SERIAL
----------------  ------------
My USB Drive      ABC123DEF456
Backup Stick      XYZ789000000
```

## Server

`susi-server` is the single HTTP server that hosts the dashboard, the licensing API, the workspace / release / docs / website / shop / contact endpoints, and the public-facing pages. Run it with:

```bash
susi-server \
  --private-key ./keys/private.pem \
  --db licenses.db \
  --listen 0.0.0.0:3100
```

On first run, the server creates an `admin` user with a random one-time password printed once to the server log. Open the dashboard in your browser to log in and manage users.

The remainder of this section documents the licensing API specifically. See [Workspaces](#workspaces--config-revisions), [Releases](#releases), [Documentation Knowledge Base](#documentation-knowledge-base), [Public Website](#public-website), [Shop](#shop), and [Public Contact Form](#public-contact-form) for the other modules.

### Licensing API endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/activate` | Public | Activate a license on a machine (grants/renews lease) |
| `POST` | `/api/v1/verify` | Public | Verify a license and renew its lease (heartbeat) |
| `POST` | `/api/v1/deactivate` | Public | Remove a machine activation |
| `GET` | `/api/v1/licenses/{key}/status` | Public | Lightweight status probe for a license key |
| `GET` | `/api/v1/licenses` | JWT | List all licenses |
| `POST` | `/api/v1/licenses` | JWT | Create a new license |
| `GET` / `PUT` / `DELETE` | `/api/v1/licenses/{key}` | JWT | Get / update / delete a license |
| `POST` | `/api/v1/licenses/{key}/revoke` | JWT | Revoke a license |
| `POST` | `/api/v1/licenses/{key}/export` | JWT | Export a signed license file |
| `POST` | `/api/v1/licenses/{key}/export-token` | JWT | Export a signed license file bound to a USB token |
| `DELETE` | `/api/v1/licenses/{key}/machines/{code}` | JWT | Deactivate a machine |
| `DELETE` | `/api/v1/licenses/{key}/machines/{code}/tombstone` | JWT | Clear the deactivation tombstone (allow re-activation) |
| `GET` | `/health` | None | Health check |

Admin endpoints require JWT authentication (see below).

### Web Dashboard

The server includes a built-in web dashboard at the root URL (`http://localhost:3100/`). It provides a browser-based interface for managing licenses, viewing activations, and administering users - no API calls required.

### Authentication & Multi-User Support

The server uses JWT-based authentication with multi-user support. Each team member gets their own account with independent credentials and optional 2FA.

**Default credentials** - on first run, the server seeds an `admin` user with a random one-time password printed once to the server log. This must be changed on first login.

#### Auth Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | None | Login with username + password (+ TOTP if enabled) |
| `POST` | `/api/v1/auth/signin-code` | None | Exchange an emailed 6-digit sign-in code for a JWT |
| `POST` | `/api/v1/auth/forgot-password` | None | Request a password-reset email (accepts username or email) |
| `POST` | `/api/v1/auth/reset-password` | None | Submit a new password against a reset token |
| `GET` | `/api/v1/auth/status` | JWT | Check session status, get username and 2FA/password state |
| `POST` | `/api/v1/auth/change-password` | JWT | Change own password |
| `POST` | `/api/v1/auth/setup-2fa` | JWT | Generate TOTP secret and QR code |
| `POST` | `/api/v1/auth/verify-2fa` | JWT | Verify TOTP code to enable 2FA |
| `POST` | `/api/v1/auth/disable-2fa` | JWT | Disable 2FA (requires valid TOTP code) |
| `POST` | `/api/v1/auth/regenerate-backup-codes` | JWT | Issue a fresh set of one-shot backup codes |
| `PUT` | `/api/v1/auth/me/email` | JWT | Set own contact email (used for sign-in code / password reset) |
| `GET` | `/api/v1/auth/me/devices` | JWT | List trusted devices |
| `DELETE` | `/api/v1/auth/me/devices/{fp}` | JWT | Revoke a trusted device |
| `POST` | `/api/v1/auth/api-tokens` | JWT | Create a personal API token (`susi_pat_…`) |
| `GET` | `/api/v1/auth/api-tokens` | JWT | List own API tokens |
| `DELETE` | `/api/v1/auth/api-tokens/{id}` | JWT | Revoke own API token |
| `GET` | `/api/v1/auth/api-tokens/all` | JWT (admin) | List every user's API tokens |
| `GET` / `POST` | `/api/v1/auth/users` | JWT (admin) | List / create users |
| `DELETE` | `/api/v1/auth/users/{username}` | JWT (admin) | Delete a user (cannot delete self or last user) |
| `PUT` | `/api/v1/auth/users/{username}/email` | JWT (admin) | Set a user's email |
| `POST` | `/api/v1/auth/users/{username}/rename` | JWT (admin) | Rename a user |
| `POST` | `/api/v1/auth/users/{username}/reset-password` | JWT (admin) | Force-reset a user's password |

#### Security

- Three roles, each a superset of the one below: **user** (customer portal),
  **admin** (full site administration), **owner** (admin plus the newsletter and
  the ability to grant or revoke ownership). Ownership is closed - only an owner
  can create one, and only an owner can administer an owner account (change its
  role, reset its password, repoint its email, or delete it), since any of those
  is a route to taking it over. Bootstrap with `SUSI_OWNER_EMAILS`.
- Passwords are hashed with **Argon2id**
- Sessions use **HS256 JWT tokens** with 24-hour expiry
- 2FA uses **TOTP** with one-shot **backup codes**, plus **trusted-device fingerprints** so a known browser doesn't re-prompt every login
- **Emailed sign-in code** is required the first time a user signs in from a new device - a 6-digit code is sent to the registered email (15-minute TTL); enabled when SMTP is configured
- **Password reset** sends a time-limited token to the user's email
- New users and password resets force a password change on next login
- Login, shop checkout, Stripe webhook, and the contact form are each rate-limited per source IP (sliding window). When fronted by the on-host nginx proxy, `X-Forwarded-For` is honoured so the limiter sees the real client

#### If email breaks, you can be locked out

The emailed sign-in code is required from any unrecognised device, so a broken
SMTP relay (revoked app password, expired credential, provider outage) can stop
every admin logging in from a new browser. Backup codes do **not** help - TOTP
is checked *after* the sign-in-code step, so login never gets that far.

Two behaviours worth knowing:

- If SMTP is unconfigured **at startup**, the gate is off entirely and
  new-device logins are accepted on password alone; the device is then trusted
  permanently. This is deliberate, so a fresh server can be set up before SMTP
  is, but it is a downgrade to single factor for accounts without TOTP. Every
  occurrence writes an `auth.unverified_new_device` row to the audit log -
  **if you see one you did not expect, your mail config is broken.**
  Note `SUSI_MAGIC_LINK_BASE_URL` also gates this: clearing it disables the
  sign-in code just as surely as clearing `SUSI_SMTP_HOST`.
- If SMTP is configured but the relay is *unreachable*, login fails with a 503
  saying the code could not be sent, and writes `auth.signin_code_send_failed`.
  It does not pretend to have sent anything.

**Prepare a break-glass credential before you need it.** Mint an admin API
token (Dashboard -> Actions -> API Tokens) and keep it in a password manager,
off the server. API tokens skip the trusted-device gate, the password-change
gate and TOTP, so one turns a lockout into a `curl` call.

**Recovery without a token:** on the host, clear the SMTP host in
`/opt/susi/.env` and restart. That puts the server back on the bootstrap path
above, letting you log in with a password, fix the mail configuration, and
restart again.

```bash
sudo sed -i 's/^SUSI_SMTP_HOST=.*/SUSI_SMTP_HOST=/' /opt/susi/.env
cd /opt/susi && docker compose up -d
# ... log in, repair the real credentials, then restore SUSI_SMTP_HOST and
# `docker compose up -d` once more.
```

#### API tokens (`susi_pat_…`) and 2FA

API tokens are long-lived bearers for headless clients (CI, scripts) and **bypass interactive 2FA**. The trade-off is deliberate: requiring a TOTP seed alongside an API token in CI raises attack surface without raising the bar - anyone with access to the bearer would also have access to the seed.

Operational consequences:

- Treat each API token as equivalent to a password + 2FA. Store it in a secret manager, never check it into git.
- Tokens are SHA-256-hashed at rest and revocable from the dashboard. Rotate them on any suspected compromise and on every team-member departure.
- For day-to-day admin work in the browser, use a JWT login - TOTP is enforced on every admin write that uses a JWT principal.
- Limit API tokens to the smallest set of users that need them, and audit `/api/v1/auth/api-tokens/all` periodically (admin-only).

### Activate a license

```bash
curl -X POST http://localhost:3100/api/v1/activate \
  -H "Content-Type: application/json" \
  -d '{"license_key": "XXXXX-XXXXX-XXXXX-XXXXX", "machine_code": "a1b2c3...", "friendly_name": "Server-1"}'
```

Returns a `SignedLicense` JSON that can be saved to disk for offline verification. The response includes a `lease_expires` timestamp - the client must call activate or verify again before this time to renew the lease.

### Create a license via API

```bash
# First, obtain a JWT token by logging in:
TOKEN=$(curl -s -X POST http://localhost:3100/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}' | jq -r .token)

# Then create a license:
curl -X POST http://localhost:3100/api/v1/licenses \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "customer": "Acme Corp",
    "product": "MyApp",
    "days": 365,
    "features": ["pro"],
    "max_machines": 2,
    "lease_duration_hours": 72,
    "lease_grace_hours": 24
  }'
```

## Client Library with Online Refresh

The client library can optionally contact the server to refresh the license and renew the lease, falling back to the cached local file if the server is unreachable.

### Rust

```rust
let client = LicenseClient::with_server(
    include_str!("public.pem"),
    "http://license.example.com/api/v1".to_string(),
).unwrap();

let status = client.verify_and_refresh(
    Path::new("license.json"),
    "XXXXX-XXXXX-XXXXX-XXXXX",
);

if status.needs_renewal() {
    // Lease expired or in grace period - try again soon
}
```

### C++

```cpp
// Pass the server URL as the second constructor argument
SusiClient susi("your-public-key", "https://license.example.com/api/v1");

// Contacts the server to renew the lease, writes the updated license.json,
// then verifies it. Falls back to the cached file if the server is unreachable.
auto status = susi.checkLicenseAndRefresh("license.json", "XXXXX-XXXXX-XXXXX-XXXXX");

if (susi.isValid()) {
    // license valid
    if (susi.hasFeature("pro")) {
        // enable pro features
    }
}

if (susi.isInGracePeriod() || susi.isLeaseExpired()){
  // Lease expired or in grace period - try again soon
}
```

Call `verify_and_refresh`/`checkLicenseAndRefresh` periodically (e.g. at startup and every few hours) to keep the lease alive. The server will renew the lease on each successful call.

## Lease System

Leases prevent customers from running more concurrent machines than they've paid for. Instead of permanent machine activations that require manual deactivation, each activation now has a time-limited lease that must be renewed periodically.

### How It Works

```
Customer activates on Machine A:
  → Server grants a 3-day lease
  → Client stores the signed license (includes lease_expires timestamp)
  → Client calls /activate or /verify periodically to renew

Customer wants to move to Machine B:
  → They stop running on Machine A
  → After 3 days, Machine A's lease expires and the seat is freed
  → Machine B can now activate
  → Machine A's record is kept as history ("stale" in the dashboard,
    with a last-seen timestamp) so activations stay visible even when
    a customer goes offline after activating

Customer tries to run on both:
  → Machine A has an active lease
  → Machine B tries to activate → "Machine limit reached"
  → Enforced automatically - no trust required
```

### Configuration

| Parameter | Default | Description |
|---|---|---|
| `--lease-duration` | `72` (3 days) | Lease duration in hours. `0` disables lease enforcement. |
| `--lease-grace` | `24` (1 day) | Grace period in hours after lease expiry. The software continues working during the grace period but should attempt to renew urgently. |

Lease parameters are set per-license at creation time, so different customers can have different lease windows.

### Client-Side States

| State | `is_valid()` | `needs_renewal()` | Description |
|---|---|---|---|
| `Valid` | `true` | `false` | Lease is active, everything normal. |
| `ValidGracePeriod` | `true` | `true` | Lease expired but within grace period. Software works but should renew ASAP. |
| `LeaseExpired` | `false` | `true` | Lease and grace period both expired. Software must renew to continue. |

### Disabling Leases

Set `--lease-duration 0` when creating a license to disable lease enforcement entirely. Machine activations become permanent (the original behavior), suitable for trusted customers or air-gapped environments.

### Offline Exports Carry No Lease

Exported license files (dashboard export, self-serve "Activate offline machine", `susi-admin export`) and USB tokens never contain a lease, regardless of the license's lease settings - an offline machine cannot phone home to renew, so a leased file would stop validating after lease + grace. The license expiry date still applies. The exported machine holds its seat until it is removed manually in the dashboard.

## Managing Licenses

```bash
# List all licenses
susi-admin list

# Revoke a license
susi-admin revoke --key "XXXXX-XXXXX-XXXXX-XXXXX"

# Deactivate a machine
susi-admin deactivate --key "XXXXX-XXXXX-XXXXX-XXXXX" --machine-code "a1b2c3..."
```

## Workspaces & Config Revisions

Workspaces are the unit of grouping for everything customer-facing: licenses, files, docs, and config revisions can all be scoped to a workspace. Each workspace has a `name`, `product`, optional `description`, a `created_by` user, and a member list with one of three roles:

| Role | Read | Edit pages / configs | Manage members | Delete workspace |
|---|---|---|---|---|
| `viewer` | yes | no | no | no |
| `editor` | yes | yes | no | no |
| `owner` | yes | yes | yes | no (admin-only) |

Site admins can create, rename, re-attribute, and delete workspaces; non-admin members only see workspaces they belong to.

### Config revisions

Each workspace has an append-only history of JSON configs. Push a new revision and clients can fetch either a specific id or `…/configs/latest`. Useful for shipping operating parameters to deployed installations without rebuilding the binary.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` / `POST` | `/api/v1/workspaces` | JWT | List own / create (admin) |
| `GET` / `PUT` / `DELETE` | `/api/v1/workspaces/{id}` | JWT | Read / update / delete |
| `POST` | `/api/v1/workspaces/{id}/members` | JWT (admin) | Add a member |
| `DELETE` | `/api/v1/workspaces/{id}/members/{username}` | JWT (admin) | Remove a member |
| `GET` / `POST` | `/api/v1/workspaces/{id}/configs` | JWT | List / push a config revision |
| `GET` | `/api/v1/workspaces/{id}/configs/latest` | JWT | Fetch the most recent revision |
| `GET` / `PUT` / `DELETE` | `/api/v1/workspaces/{id}/configs/{config_id}` | JWT | Read / update metadata / delete |

`susi_client::workspace` provides a typed Rust client (sync + async) over these endpoints.

### Workspace files & docs

Each workspace has a flat, member-writable file share (bytes on disk under the data dir) and its own flat documentation page tree, both independent of the release concept. The `?auth=` query parameter carries the JWT where browsers can't set an Authorization header (`<a href>` downloads, `<img>` loads).

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` / `POST` | `/api/v1/workspaces/{id}/files` | JWT (member) | List / upload files (multipart, up to 500 MB) |
| `GET` / `DELETE` | `/api/v1/workspaces/{id}/files/{file}` | JWT (member) | Download / delete a file |
| `GET` | `/api/v1/workspaces/{id}/docs/pages` | JWT (member) | List pages + assets |
| `GET` / `PUT` / `DELETE` | `/api/v1/workspaces/{id}/docs/pages/{slug}` | JWT (member) | Read / upsert / delete a page |
| `POST` | `/api/v1/workspaces/{id}/docs/pages/{slug}/rename` | JWT (member) | Rename a page (cascades to children) |
| `POST` | `/api/v1/workspaces/{id}/docs/assets` | JWT (member) | Upload a doc asset (up to 100 MB) |
| `GET` / `DELETE` | `/api/v1/workspaces/{id}/docs/assets/{file}` | JWT (member) | Fetch / delete a doc asset |

### Workspace tickets

The shared record of customer-reported problems, scoped to a workspace so a report sits next to the config revisions, recordings and files that reproduce it. Status is `open`, `in_progress` or `closed`.

Every member reads and writes every ticket and comment in their workspace - there are no internal-only notes, so treat anything written here as customer-visible. Deleting a ticket or a comment is restricted to its author or a site admin; everything else, including status changes, is open to any member.

Ticket events send **no email**. The notification path (workspace members plus site admins, minus the actor) is implemented but switched off behind `SEND_TICKET_EMAILS` in `crates/susi_server/src/tickets.rs`; flip that const and rebuild to enable it.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` / `POST` | `/api/v1/workspaces/{id}/tickets` | JWT (member) | List / open a ticket |
| `GET` / `PUT` / `DELETE` | `/api/v1/workspaces/{id}/tickets/{tid}` | JWT (member) | Read with comments / update / delete |
| `POST` | `/api/v1/workspaces/{id}/tickets/{tid}/comments` | JWT (member) | Add a comment |
| `DELETE` | `/api/v1/workspaces/{id}/tickets/{tid}/comments/{cid}` | JWT (member) | Delete a comment |
| `GET` | `/api/v1/admin/tickets` | JWT (admin) | Every workspace's tickets, `?status=` optional |

## Releases

Upload signed binaries (installers, archives, etc.) and let licensed clients fetch them through an authenticated update channel. Releases are global per product; per-customer builds belong in workspace files instead.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/updates/releases` | License key | List releases the caller can download |
| `GET` | `/api/v1/updates/download/{tag}/{asset}` | License key, JWT, or `?ticket=` | Stream a release asset to the caller |
| `POST` | `/api/v1/updates/download-ticket` | License key or JWT | Mint a 60 s single-asset ticket for the download URL |
| `GET` | `/api/v1/releases` | JWT | List all releases (admin view) |
| `POST` | `/api/v1/releases` | JWT | Upload a new release (multipart, up to 500 MB) |
| `PUT` / `DELETE` | `/api/v1/releases/{tag}` | JWT | Update metadata / delete |

When a binary upload creates a new release, the previous release's user-edited doc set is **seeded forward** so hand-authored docs carry over automatically.

## Documentation Knowledge Base

The `/docs` page is a per-release documentation site with an in-browser editor (EasyMDE, vendored). Each release has its own collection of pages and assets, addressed by tag. Workspace documentation uses the same viewer/editor (`/docs?workspace={id}`) but is a single flat page tree per workspace (see above).

Pages carry an **origin tag** of either `pipeline` (generated from a build pipeline / bulk import) or `user` (hand-edited in the dashboard). Pipeline pages are replaced wholesale on the next bulk import; user pages are preserved across imports and copied forward into newly-created releases.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/docs` | None | HTML viewer + editor |
| `GET` | `/api/v1/docs/releases` | None | List doc releases |
| `GET` | `/api/v1/docs/releases/latest` | None | Latest release |
| `GET` | `/api/v1/docs/{tag}/pages` | None | List pages in a release |
| `GET` | `/api/v1/docs/{tag}/pages/{slug}` | None | Get a page (markdown + rendered HTML) |
| `GET` | `/api/v1/docs/{tag}/assets/{file}` | None | Fetch an asset |
| `PUT` / `DELETE` | `/api/v1/docs/{tag}/pages/{slug}` | JWT | Upsert / delete a page |
| `POST` | `/api/v1/docs/{tag}/pages/{slug}/rename` | JWT | Rename a slug |
| `POST` | `/api/v1/docs/{tag}/import` | JWT | Bulk import a tarball of pages + assets |
| `POST` / `DELETE` | `/api/v1/docs/{tag}/assets[/{file}]` | JWT | Upload / delete an asset |

> **Editing rule:** never `PUT` a full page from outside the dashboard - fetch first, then send a targeted patch to `body_md`. Wholesale overwrites trash user edits.

## Public Website

A small CMS that powers the marketing site at `/site`. Pages are Markdown, edited through the dashboard, and served with per-page SEO meta. There's no release concept here - all content is hand-authored.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/site`, `/site/{slug}` | None | Public-rendered HTML |
| `GET` | `/api/v1/website/pages[/{slug}]` | None | List / fetch a page |
| `PUT` / `DELETE` | `/api/v1/website/pages/{slug}` | JWT | Upsert / delete |
| `POST` | `/api/v1/website/pages/{slug}/rename` | JWT | Rename a slug |
| `GET` | `/api/v1/website/pages/{slug}/revisions` | JWT | Page revision history |
| `GET` | `/api/v1/website/pages/{slug}/revisions/{id}` | JWT | Fetch an old revision |
| `POST` | `/api/v1/website/pages/{slug}/revisions/{id}/restore` | JWT | Restore an old revision |
| `GET` / `POST` / `DELETE` | `/api/v1/website/assets[/{file}]` | mixed | Public read; JWT for upload / delete |
| `POST` | `/api/v1/website/assets/{file}/rename` | JWT | Rename an asset |
| `GET` | `/api/v1/website/admin/assets` | JWT | List assets with usage info |
| `GET` | `/robots.txt`, `/sitemap.xml`, `/llms.txt` | None | SEO / crawler metadata |

Brand assets (`/static/logo.png`, `/static/og-image.png`, `/favicon.ico`, etc.) are embedded in the binary.

## Shop

Stripe-backed checkout for physical goods. The cart lives in the browser (`localStorage`); the server looks up authoritative prices from the DB at checkout time and hands the line items to Stripe Checkout with `automatic_tax: true`. Stripe collects address + payment, computes tax, and redirects to `success_url` / `cancel_url`. Set `STRIPE_SECRET_KEY` (and `STRIPE_WEBHOOK_SECRET`) to enable; otherwise the public product pages still render but checkout returns 503.

After a successful checkout, susi:

1. Verifies the Stripe webhook signature (HMAC-SHA256, 5-minute timestamp tolerance)
2. De-duplicates webhook deliveries
3. Renders a paid-invoice PDF locally and emails the customer a branded confirmation with the PDF attached
4. Notifies the configured admin recipients

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/shop`, `/shop/{sku}`, `/shop/success`, `/shop/cancel` | None | Public HTML shell |
| `GET` | `/api/v1/shop/products[/{sku}]` | None | Public catalog |
| `POST` | `/api/v1/shop/checkout` | None | Create a Stripe Checkout Session |
| `POST` | `/api/v1/shop/webhook` | Stripe sig | Stripe webhook handler |
| `GET` / `PUT` / `DELETE` | `/api/v1/shop/admin/products[/{sku}]` | JWT | Product CRUD |
| `GET` / `POST` / `PUT` / `DELETE` | `/api/v1/shop/admin/shipping_rates[/{id}]` | JWT | Shipping-rate CRUD |
| `GET` | `/api/v1/shop/admin/orders[/{id}]` | JWT | Orders list / detail |
| `POST` | `/api/v1/shop/admin/orders/{id}/ship` | JWT | Mark shipped (sends customer email) |
| `PUT` | `/api/v1/shop/admin/orders/{id}/notes` | JWT | Update internal notes |
| `GET` / `PUT` | `/api/v1/shop/admin/settings` | JWT | Admin notification recipients, customer email toggles, support contact |

Checkout is restricted to a configured set of destination countries. SKUs are validated, product image references are sanitized, and admin-authored thank-you HTML is sanitized before being inlined into customer mail.

## Public Contact Form

Served at the `/site` chrome and disabled (503) unless `SUSI_CONTACT_TO_ADDR` and SMTP are both set. Hardening stack:

- Hidden honeypot field that real browsers leave empty
- Cloudflare Turnstile siteverify when `SUSI_TURNSTILE_SECRET` is set (otherwise honeypot + rate limit only)
- Per-IP sliding-window rate limit (3/hour, 20/day)
- All fields mandatory (name, company, email, subject, message) - filters low-effort scam inquiries
- Field length caps + minimum body length
- Sender email syntactically validated; outbound mail body is plain text

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/contact/config` | None | Returns whether the form is enabled and the public Turnstile site key |
| `POST` | `/api/v1/contact` | None | Submit a contact-form message |

## Dropbox Backups

Rotating, encrypted offsite backups of the whole `/data` volume (SQLite DB via
`VACUUM INTO`, `private.pem`, `db_secret.bin`, `jwt_secret.bin`, `docs/`,
optionally `releases/`) to a Dropbox App Folder. Redundant to the primary AWS
backups; managed from the dashboard's admin-only Backups page.

Setup:

1. Create a scoped Dropbox app (App folder access) with permissions
   `files.content.write`, `files.content.read`, `files.metadata.read`.
2. Set in the server environment (`/opt/susi/.env`):
   - `SUSI_DROPBOX_APP_KEY` / `SUSI_DROPBOX_APP_SECRET`
   - `SUSI_BACKUP_KEY` - 64 hex chars (`openssl rand -hex 32`). Archives are
     encrypted with chunked AES-256-GCM under this key before upload. Keep a
     copy off-server (password manager) - without it backups are unreadable.
   - `SUSI_BACKUP_PREFIX` - archive name prefix (`prod` / `staging`); rotation
     only ever touches archives with the instance's own prefix.
3. On the dashboard Backups page: Connect Dropbox (opens the consent page,
   paste the one-time code back), then enable the nightly backup.

Scheduling: one backup per day at the configured UTC hour, retried hourly on
failure. Rotation is grandfather-father-son - newest archive per day/week/month
up to the configured counts (default 7/4/12), and nothing younger than 48 h is
ever deleted. The OAuth refresh token is stored sealed with the DB at-rest key;
access tokens are minted per run and never persisted.

Restore:

```bash
# Download the archive from Dropbox (Apps/<app name>/), then:
susi-server decrypt-backup prod-backup-20260706-030000.tar.gz.enc --key <SUSI_BACKUP_KEY>
tar -xzf prod-backup-20260706-030000.tar.gz   # unpack into a fresh /data volume
```

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/admin/backup/status` | Admin JWT | Settings, connection state, run history |
| `PUT` | `/api/v1/admin/backup/settings` | Admin JWT | Schedule + retention |
| `GET` | `/api/v1/admin/backup/connect-url` | Admin JWT | Dropbox consent URL |
| `POST` | `/api/v1/admin/backup/connect` | Admin JWT | Exchange pasted code for a refresh token |
| `POST` | `/api/v1/admin/backup/disconnect` | Admin JWT | Revoke + forget the connection |
| `POST` | `/api/v1/admin/backup/run` | Admin JWT | Trigger a manual backup |

## Deploying to AWS Lightsail

The project includes a Dockerfile, docker-compose.yml, and a deploy script for one-command deployment to an AWS Lightsail (or any EC2/VPS) instance.

### 1. Create a Lightsail instance

1. Go to [AWS Lightsail Console](https://lightsail.aws.amazon.com/)
2. Create an instance: **Linux/Unix** → **OS Only** → **Ubuntu 22.04 LTS** (or 24.04)
3. Choose a plan - **$5/mo (1 GB RAM, 1 vCPU)** is sufficient
4. Under **Networking**, add a firewall rule: **Custom TCP, Port 3100**

### 2. Install Docker on the instance

SSH into the instance and install Docker:

```bash
ssh -i ~/.ssh/LightsailDefaultKey-*.pem ubuntu@<YOUR_INSTANCE_IP>

sudo apt-get update && sudo apt-get upgrade -y
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker ubuntu
exit
```

Log back in for the group change to take effect and verify:

```bash
docker --version
docker compose version
```

### 3. Deploy

From your **local machine**, in the susi project root:

```bash
# Production (port 3100, volume susi-data, compose file docker-compose.yml)
./deploy.sh ubuntu@<YOUR_INSTANCE_IP> ~/.ssh/LightsailDefaultKey-*.pem

# Staging (port 3101, volume susi-data-staging, compose file docker-compose.staging.yml)
./deploy.sh ubuntu@<YOUR_INSTANCE_IP> ~/.ssh/LightsailDefaultKey-*.pem --staging
```

> **Important:** run `deploy.sh` from the `external/susi` directory only. The rsync step has no `--delete` flag, but running from a parent directory will copy unrelated files into `/opt/susi` and pollute the deploy.

The script will:
1. Create `/opt/susi` on the server and rsync project files
2. Generate a **4096-bit RSA keypair** if none exists in the data volume
3. Build the Docker image and start the container

On first run, the server creates an `admin` user with a random one-time password printed once to the server log (`docker compose logs`). Log in at `http://<YOUR_INSTANCE_IP>:3100/` and change the password immediately.

### 3a. Configure environment variables

The container reads optional integrations from `/opt/susi/.env`. The deploy script creates an empty file on first deploy; add settings manually as needed:

```bash
# /opt/susi/.env  (chmod 600)

# Sign-in code / password-reset / outbound mail (Gmail SMTP relay shown)
SUSI_SMTP_HOST=smtp.gmail.com
SUSI_SMTP_PORT=587
SUSI_SMTP_USER=you@example.com
SUSI_SMTP_PASSWORD=<google-app-password>
SUSI_SMTP_FROM_NAME=Susi
SUSI_SMTP_FROM_ADDR=noreply@example.com
SUSI_MAGIC_LINK_BASE_URL=https://susi.example.com

# Newsletter. Deliberately SEPARATE credentials from the relay above:
# campaign mail must not be able to trip a sending limit that would then block
# sign-in codes and password resets. There is no fallback - leave the host
# empty and the send endpoints respond 503 while drafts and previews still
# work. Sending is hard-disabled on staging regardless of this file.
SUSI_NEWSLETTER_SMTP_HOST=smtp.gmail.com
SUSI_NEWSLETTER_SMTP_PORT=587
SUSI_NEWSLETTER_SMTP_USER=news@example.com
SUSI_NEWSLETTER_SMTP_PASSWORD=<google-app-password>
SUSI_NEWSLETTER_SMTP_FROM_NAME=Susi by LP-Research
SUSI_NEWSLETTER_SMTP_FROM_ADDR=news@example.com
# Addresses attempted per minute. Every send is a fresh TCP+STARTTLS+AUTH
# handshake, and providers cap daily recipients - keep this modest.
SUSI_NEWSLETTER_RATE_PER_MIN=30

# Per-site newsletters (any non-default site with has_newsletter) send over
# their own relay: SUSI_NEWSLETTER_SMTP_{HOST|PORT|USER|PASSWORD|FROM_NAME|
# FROM_ADDR}_{SITE} with the site id uppercased and '-' becoming '_', same
# convention as the per-site Stripe keys. No cross-site fallback: without
# these, that site's sends respond 503 while drafts and previews still work.
# Their audience is the site's own double-opt-in subscriber list (public
# signup on the site's /newsletter page), not user accounts.
SUSI_NEWSLETTER_SMTP_HOST_KLAUS=smtp.example.com
SUSI_NEWSLETTER_SMTP_USER_KLAUS=news@klaus.example.com
SUSI_NEWSLETTER_SMTP_PASSWORD_KLAUS=<app-password>
SUSI_NEWSLETTER_SMTP_FROM_ADDR_KLAUS=news@klaus.example.com

# Gmail connector (optional alternative to SUSI_NEWSLETTER_SMTP_USER/_PASSWORD).
# With these set, an admin connects a Google Workspace account from the
# Newsletter page and campaign mail goes out over Gmail with OAuth - no app
# password on the host. Static credentials above take precedence if both exist.
SUSI_GOOGLE_CLIENT_ID=<id>.apps.googleusercontent.com
SUSI_GOOGLE_CLIENT_SECRET=<secret>

# Accounts promoted to the `owner` role on every start (comma-separated).
# Owner is the only role that can send newsletters or grant ownership, and it
# can only be granted by an existing owner - so this is how the first one
# exists on a database that predates the role, and the way back in if the last
# owner is ever lost. Applied idempotently on each boot.
SUSI_OWNER_EMAILS=you@example.com,you@other-domain.com

# Shop (leave empty to disable checkout - product pages still render)
STRIPE_SECRET_KEY=sk_live_…
STRIPE_WEBHOOK_SECRET=whsec_…
SUSI_SHOP_BASE_URL=https://susi.example.com
SUSI_SHOP_NOTIFY_ADDR=orders@example.com

# Contact form (empty contact_to_addr disables; turnstile keys are optional)
SUSI_CONTACT_TO_ADDR=hello@example.com
SUSI_TURNSTILE_SECRET=…
SUSI_TURNSTILE_SITE_KEY=…
```

Re-run `docker compose -f <file> up -d` after editing `.env` to pick up changes.

### 3b. Gmail connector for newsletters (optional)

Sends campaign mail over Gmail with OAuth instead of an app password. One-time
setup in the [Google Cloud console](https://console.cloud.google.com/):

1. Create (or pick) a project in the **lp-research.com Workspace org**.
2. **APIs & Services -> OAuth consent screen**: set User type to **Internal**.
   This is the step that matters - `gmail.send` is a *restricted* scope, and an
   External app would need a full Google verification review. Internal apps
   inside the org are exempt.
3. **Credentials -> Create credentials -> OAuth client ID**, type **Web
   application**. Add the authorised redirect URI:
   `https://susi.lp-research.com/api/v1/newsletter/google/callback`
   (must match `SUSI_MAGIC_LINK_BASE_URL` exactly - the dashboard shows the
   expected value on the Newsletter page).
4. Put the client ID and secret in `/opt/susi/.env` as `SUSI_GOOGLE_CLIENT_ID`
   and `SUSI_GOOGLE_CLIENT_SECRET`, then redeploy.
5. In the dashboard: **Newsletter -> Connect Gmail**, approve, done. The refresh
   token is stored encrypted at rest; only short-lived access tokens are held in
   memory.

Notes:

- Do **not** leave the consent screen in *Testing* mode - refresh tokens issued
  there expire after 7 days and the connection would break weekly.
- OAuth does not raise Gmail's daily recipient cap. For genuinely large lists a
  dedicated ESP (SES / Postmark / Resend) is the better fit, and needs no code
  change - just the `SUSI_NEWSLETTER_SMTP_*` variables.
- If Google returns "no refresh token" on connect, revoke susi's access at
  [myaccount.google.com/permissions](https://myaccount.google.com/permissions)
  and connect again; Google only issues one on first consent.

### 4. Verify

```bash
curl http://<YOUR_INSTANCE_IP>:3100/health
# → {"status":"ok"}
```

### 5. Retrieve the public key

SSH into the instance and copy the public key (you'll embed this in your application):

```bash
VOLUME_DIR=$(docker volume inspect susi-data --format '{{.Mountpoint}}')
sudo cat $VOLUME_DIR/public.pem
```

Embed this key in:
- **Rust**: `LicenseClient::new(include_str!("public.pem"))`
- **C++**: the `DEFAULT_PUBLIC_KEY` constant in `susi.cpp`

### 6. Create and activate licenses

Use the web dashboard at `http://<YOUR_INSTANCE_IP>:3100/` to create licenses and manage users. Or use the API:

```bash
SERVER="http://<YOUR_INSTANCE_IP>:3100"

# Login to get a JWT token
TOKEN=$(curl -s -X POST $SERVER/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}' | jq -r .token)

# Create a license
curl -X POST $SERVER/api/v1/licenses \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "customer": "Acme Corp",
    "product": "MyApp",
    "days": 365,
    "features": ["pro"],
    "max_machines": 2,
    "lease_duration_hours": 72,
    "lease_grace_hours": 24
  }'

# Activate from a client machine (public)
curl -X POST $SERVER/api/v1/activate \
  -H "Content-Type: application/json" \
  -d '{
    "license_key": "XXXXX-XXXXX-XXXXX-XXXXX",
    "machine_code": "a1b2c3...",
    "friendly_name": "Production-Server-1"
  }'
```

Save the activation response as `license.json` - it contains the signed license with lease timestamp.

### 7. Maintenance

```bash
# SSH into instance, then:
cd /opt/susi

docker compose logs -f          # view logs
docker compose restart           # restart
docker compose down              # stop
docker compose up -d --build     # rebuild after code changes

# Backup the database
VOLUME_DIR=$(docker volume inspect susi-data --format '{{.Mountpoint}}')
sudo cp $VOLUME_DIR/licenses.db ~/licenses-backup-$(date +%F).db
```

### 8. HTTPS reverse proxy (required for production)

The containers bind to `127.0.0.1:3100` (prod) and `127.0.0.1:3101` (staging) -
they are *not* reachable from the public internet. All external traffic must
go through the on-host nginx reverse proxy over TLS. This protects credentials
and JWTs that would otherwise cross the network in plaintext, and gives the
in-process rate limiter a real client IP via `X-Forwarded-For`.

1. In Lightsail → **Networking** → attach a **static IP** to your instance.
2. Create DNS A-records for both hostnames pointing at that static IP, e.g.
   `susi.lp-research.com` and `staging.susi.lp-research.com`.
3. Install nginx + certbot and configure one vhost per environment:

```bash
sudo apt-get install -y nginx certbot python3-certbot-nginx

sudo tee /etc/nginx/sites-available/susi <<'EOF'
# Production
server {
    listen 80;
    server_name susi.lp-research.com;

    location / {
        proxy_pass http://127.0.0.1:3100;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Staging
server {
    listen 80;
    server_name staging.susi.lp-research.com;

    location / {
        proxy_pass http://127.0.0.1:3101;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/susi /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d susi.lp-research.com -d staging.susi.lp-research.com
```

4. Lightsail firewall: open **22, 80, 443**; **close 3100 and 3101** if they
   were previously open. The docker-compose loopback binding already makes
   the ports unreachable externally, but the firewall is belt-and-braces.

`X-Forwarded-For` is required - the Rust login rate-limiter reads it to
identify the real client when the TCP peer is loopback (nginx). Without it,
every request looks like it's coming from `127.0.0.1` and the per-IP limit
becomes a per-box limit.

### Adding a new site

The backend serves any number of public sites, resolved from the request's
Host header via the site registry (seeded from built-in definitions on first
boot, then managed from the dashboard). Adding one:

1. **Create the site** (owner account): dashboard → Website → Site Settings →
   Identity card → **+ New Site**. Id is a short immutable slug; hosts are
   bare hostnames (one per line, include the staging name); public base URL is
   the canonical `https://` origin. Save.
2. **Add content**: switch the site selector to the new site, create pages
   (`+ New Page`), and upload a logo/background under Site Settings. Without a
   logo the header shows the site name as text.
3. **DNS**: point an A record for each hostname at the server IP (both the
   production and staging names).
4. **TLS**: expand the staging SAN cert and issue a production cert on the box
   (the nginx authenticator answers the ACME challenges):

   ```bash
   sudo certbot certonly --nginx --expand --cert-name staging.xikaku.com \
     -d staging.xikaku.com -d staging.lp-research.com -d staging.<name>
   sudo certbot certonly --nginx --cert-name <domain> -d <domain>
   ```

5. **nginx**: add the staging hostname to both `server_name` lines in
   `nginx/staging.sites.conf`, and create a production vhost from an existing
   one (`nginx/klaus.xikaku.com.conf` is the template: proxy to `:3100`, keep
   the pre-launch `noindex` + robots override until the site should be
   indexed). Copy both to `/etc/nginx/conf.d/` on the box, then
   `sudo nginx -t && sudo systemctl reload nginx`.

Content and settings are per site; the shop and newsletter are shared
instances that the per-site flags merely show or hide.

### Quick reference

| Item | Location |
|---|---|
| Server binary | Docker container `susi-server` (prod) / `susi-server-staging` |
| Private key | Docker volume `susi-data` → `/data/private.pem` |
| Public key | Docker volume `susi-data` → `/data/public.pem` |
| Database | Docker volume `susi-data` → `/data/licenses.db` |
| Release assets | Docker volume `susi-data` → `/data/releases/{tag}/` |
| Doc pages + assets | Docker volume `susi-data` → `/data/docs/{tag}/` |
| Website assets | Docker volume `susi-data` → `/data/website/assets/` |
| Dashboard | `http://<IP>:3100/` (or your TLS hostname) |
| Public website | `http://<IP>:3100/site` |
| Documentation | `http://<IP>:3100/docs` |
| Shop | `http://<IP>:3100/shop` |
| Default login | `admin` / random one-time password from the server log (must change on first login) |
| Logs | `docker compose logs -f` in `/opt/susi` |
| Health check | `GET http://<IP>:3100/health` |

## Building

```bash
cargo build --workspace --release
```

Binaries are output to `target/release/`:
- `susi-admin` - CLI management tool
- `susi-server` - HTTP activation server
- `susi-helper` - end-user utility for fingerprinting and USB serial lookup

## Testing

```bash
cargo test --workspace
```

## Dependencies

Key dependencies:
- [`rsa`](https://crates.io/crates/rsa) - RSA key generation, signing, verification
- [`sha2`](https://crates.io/crates/sha2) - SHA-256 hashing
- [`aes-gcm`](https://crates.io/crates/aes-gcm) - AES-256-GCM encryption for USB tokens
- [`hkdf`](https://crates.io/crates/hkdf) - HKDF-SHA256 key derivation for USB tokens
- [`axum`](https://crates.io/crates/axum) - HTTP server with multipart support (susi_server only)
- [`tower-http`](https://crates.io/crates/tower-http) - CORS middleware (susi_server only)
- [`argon2`](https://crates.io/crates/argon2) - Argon2id password hashing (susi_server only)
- [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken) - JWT session tokens (susi_server only)
- [`totp-rs`](https://crates.io/crates/totp-rs) - TOTP 2FA (susi_server only)
- [`lettre`](https://crates.io/crates/lettre) - SMTP client for sign-in code / order / contact email (susi_server only)
- [`hmac`](https://crates.io/crates/hmac) - Stripe webhook signature verification (susi_server only)
- [`printpdf`](https://crates.io/crates/printpdf) - paid-invoice PDF generation (susi_server only)
- [`ammonia`](https://crates.io/crates/ammonia) - HTML sanitizer for admin-authored content in customer email (susi_server only)
- [`rusqlite`](https://crates.io/crates/rusqlite) - SQLite storage (server/admin only, bundled)
- [`reqwest`](https://crates.io/crates/reqwest) - HTTP client for online refresh, Stripe API, Turnstile siteverify

The `susi_client` crate is intentionally lightweight - it only pulls in the crypto and HTTP dependencies needed for verification and the workspace/release/docs API client.

## License

MIT
