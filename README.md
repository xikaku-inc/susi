# susi

*Susi* (Tagalog for "key") - a self-hosted backend platform written in Rust. It started as a software-licensing server and has grown to bundle everything a small product company needs around a downloadable application: signed licensing, release distribution, a documentation knowledge base, any number of public websites with blogs and newsletters, a Stripe-backed shop, customer workspaces, and a contact form - all served from a single binary with a SQLite store.

## Features

### Licensing
- **RSA-SHA256 signed license files** - tamper-proof, offline-verifiable
- **Node-locked licenses** - bind licenses to specific machines via hardware fingerprint
- **Feature flags, expiry dates, machine limits** - fine-grained per-license policy, editable after creation
- **Lease-based seat management** - time-limited activations that expire automatically, preventing unauthorized concurrent usage
- **USB hardware tokens** - bind a license to a physical USB stick instead of a machine
- **Binary signing enforcement** - optionally require the consuming binary to carry a valid code signature; the server can additionally pin the signing CA
- **Customer portal** - licenses are assigned to user accounts; customers see their own licenses in the dashboard and export offline activation files themselves
- **Cross-platform** - Linux, Windows, and macOS support
- **Rust + C++ client libraries** - drop-in verification for both ecosystems

### Products, releases & workspaces
- **Products** - a catalog of products, each owning its releases and doc sets; a product flagged `download_public` serves license-free installers through stable `/download/{product}/{platform}` links
- **Binary release channel** - upload installers; licensed clients fetch via `/api/v1/updates`, with short-lived download tickets for browsers
- **Workspaces** - per-customer collaboration space: member-writable file share, flat docs tree, versioned JSON config revisions, tickets with comments, a shared node graph with optimistic locking, federation secret + peer registry for the FusionHub data plane, and S3-backed recordings

### Documentation & websites
- **Documentation knowledge base** - per-product, per-release doc sets at `/docs`, server-rendered with SEO meta, Markdown editor, drafts, asset uploads, bulk import, and origin tagging (pipeline-generated vs. user-edited pages)
- **Multi-site CMS** - any number of public sites resolved from the Host header, each with pages, blog posts, drafts, revision history, redirect maps, nav structure, translations, branding, font presets, SEO (`sitemap.xml`, `robots.txt`, `llms.txt`, IndexNow, JSON-LD), and a consent-gated analytics layer
- **Newsletter** - per-site double-opt-in subscriber lists, Markdown issues with inline images and video posters, test sends, delivery reports, public archive, RFC 8058 one-click unsubscribe, SMTP or Gmail OAuth relay
- **Email templates** - every transactional email editable from the dashboard, with per-site and per-language overrides

### Commerce
- **Stripe-backed shop** - per-site shops with their own Stripe keys, bilingual en/ja catalog with USD and JPY pricing, shipping rates and destination countries, automatic-tax checkout, locally rendered paid-invoice PDFs, Merchant Center feed, and an admin fulfillment workflow
- **Public contact form** - Cloudflare Turnstile + honeypot + per-IP rate limit, served in the site chrome

### Auth & ops
- **Multi-user dashboard** with three roles (user / admin / owner), **Argon2id passwords**, **TOTP 2FA + backup codes**, **emailed sign-in code for new devices**, **trusted devices**, **session list + revocation**, **invitation and password-reset email**, and **API tokens** for headless clients
- **Audit log**, **self-serve data export and account deletion**, scheduled data-retention purges
- **Encrypted offsite backups** to Dropbox with grandfather-father-son rotation
- **One-command deploy** - Docker image built locally and shipped to the host; separate production / staging environments behind nginx
- **Cross-platform clients** - Linux, Windows, macOS

## Architecture

```
┌──────────────────┐     ┌────────────────────────────────────┐     ┌─────────────────────┐
│  susi_admin      │     │           susi_server              │     │  susi_client        │
│  (CLI tool)      │     │       (HTTP server + UI)           │     │  (Rust library)     │
│                  │     │                                    │     │                     │
│  keygen          │     │  /api/v1/{auth, licenses,          │     │  verify signature   │
│  create license  │     │    activate, verify, products,     │     │  check expiry       │
│  export / list   │     │    releases, updates, workspaces,  │     │  check machine      │
│  export-token    │     │    docs, website, sites,           │     │  check features     │
│  revoke          │     │    newsletter, shop, contact,      │     │  check lease        │
│                  │     │    audit, admin/backup, ...}       │     │  verify USB token   │
│                  │     │                                    │     │  workspace client   │
│                  │     │  Dashboard + /site + /docs + /shop │     │                     │
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
| `susi_core` | Library | Shared types, RSA crypto, hardware fingerprinting, USB token encryption; SQLite storage behind the `db` feature (one module per domain under `src/db/`) |
| `susi_client` | Library | Verification library + workspace/config HTTP client (sync + async APIs) |
| `susi_admin` | Binary | CLI tool for key generation, license creation, and management |
| `susi_server` | Binary | HTTP server with SQLite backend - everything listed above |
| `susi_helper` | Binary | End-user utility for retrieving machine fingerprints and USB serial numbers |
| `cpp/` | C++ Library | Standalone verification client for C++ applications (Conan or `add_subdirectory`) |

`susi_server` is split into one module per surface area: `auth.rs` / `users.rs` (sessions, 2FA, accounts), `licenses.rs` / `client_api.rs` (admin and client licensing), `releases.rs` (products, releases, public downloads), `workspaces.rs` / `tickets.rs`, `docs.rs`, `website.rs` / `sites.rs` (multi-site CMS), `newsletter.rs`, `email_templates.rs` / `email_md.rs` / `email.rs` (transactional mail), `shop.rs` / `invoice_pdf.rs` / `countries.rs`, `contact.rs`, `backup.rs`, `s3.rs`, with the router, auth middleware, rate limiters, security headers, and retention jobs in `main.rs`. The dashboard, docs viewer, and site shell are single-file HTML apps embedded in the binary (`dashboard.html`, `docs.html`, `website.html`).

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
auto status = susi.verifyFile("license.json");

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
| Machine was removed from the license by an administrator               | `LicenseStatus::Deactivated`                                    | `LicenseStatus::Deactivated`       |
| Machine not activated yet (no cached license file)                     | `LicenseStatus::NotActivated`                                   | `LicenseStatus::NotActivated`      |
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
auto status = susi.verifyToken();

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

`susi-server` is the single HTTP server that hosts the dashboard, the licensing API, the product / release / workspace / docs / website / newsletter / shop / contact endpoints, and all public-facing pages. Run it with:

```bash
susi-server \
  --private-key ./keys/private.pem \
  --db licenses.db \
  --data-dir ./data \
  --listen 0.0.0.0:3100
```

`--data-dir` (default `/data`) holds the at-rest secrets (`jwt_secret.bin`, `db_secret.bin`), release assets, doc assets, website assets, and workspace files. Every integration (SMTP, Stripe, Dropbox, S3, ...) is configured through environment variables or the matching `--flag`; see [Configure environment variables](#3a-configure-environment-variables) for the full list. `--trusted-signing-ca <pem>` pins a code-signing CA: licenses with `require_signed_binary` then only activate when the client proves its signing certificate chains to that CA. Without the flag such licenses fail closed (503).

On first run, the server creates an `admin` owner account with a random one-time password printed once to the server log (`SUSI_SEED_ADMIN_PASSWORD` overrides it for test rigs). Open the dashboard, log in, change the password, and enable TOTP - admin endpoints refuse browser sessions without it.

`susi-server decrypt-backup <archive.tar.gz.enc> --key <hex>` decrypts a Dropbox backup archive (see [Dropbox Backups](#dropbox-backups)).

The remainder of this section documents the licensing API and authentication. See [Workspaces](#workspaces), [Products & Releases](#products--releases), [Documentation Knowledge Base](#documentation-knowledge-base), [Public Websites](#public-websites), [Newsletter](#newsletter), [Email Templates](#email-templates), [Shop](#shop), [Public Contact Form](#public-contact-form), [Audit Log & Data Protection](#audit-log--data-protection), and [Dropbox Backups](#dropbox-backups) for the other modules.

### Licensing API endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/activate` | Public | Activate a license on a machine (grants/renews lease) |
| `POST` | `/api/v1/verify` | Public | Verify a license and renew its lease (heartbeat) |
| `POST` | `/api/v1/deactivate` | Public | Remove a machine activation (no tombstone) |
| `GET` | `/api/v1/licenses/{key}/status` | Public | Lightweight status probe; the key in the path is the credential |
| `GET` | `/api/v1/features` | Public | Static list of feature flags with labels |
| `GET` | `/api/v1/licenses` | Admin | List all licenses, including assigned portal users |
| `POST` | `/api/v1/licenses` | Admin | Create a license (`customer`, `product`, `days` / `expires` / `perpetual`, `features`, `max_machines`, `lease_duration_hours`, `lease_grace_hours`, `require_signed_binary`, `assign_to[]`) |
| `GET` / `PUT` / `DELETE` | `/api/v1/licenses/{key}` | Admin | Get / update / delete. `PUT` takes any subset of `customer`, `product`, `expires` (`YYYY-MM-DD` or `"perpetual"`), `features`, `max_machines`, `lease_duration_hours`, `lease_grace_hours`, `require_signed_binary` |
| `POST` | `/api/v1/licenses/{key}/revoke` | Admin | Revoke a license |
| `POST` | `/api/v1/licenses/{key}/export` | Admin | Export a signed license file for a machine code |
| `POST` | `/api/v1/licenses/{key}/export-token` | Admin | Export a signed license file bound to a USB token |
| `POST` / `DELETE` | `/api/v1/licenses/{key}/users[/{username}]` | Admin | Assign / unassign a user account (customer portal access) |
| `DELETE` | `/api/v1/licenses/{key}/machines/{code}` | Admin | Deactivate a machine (24 h re-activation tombstone) |
| `DELETE` | `/api/v1/licenses/{key}/machines/{code}/tombstone` | Admin | Clear the tombstone (allow immediate re-activation) |
| `GET` | `/api/v1/my/licenses` | Any user | Licenses assigned to the caller |
| `POST` | `/api/v1/my/licenses/{key}/export` | Any user | Self-serve offline activation file for an assigned license |
| `DELETE` | `/api/v1/my/licenses/{key}/machines/{code}` | Any user | Self-serve seat release (24 h tombstone) |
| `GET` | `/health` | None | Health check |

The public client endpoints share a per-IP limit of 60 requests per minute. "Admin" means a session JWT (with TOTP enabled) or an API token of an admin or owner account.

### Web Dashboard

The server includes a built-in web dashboard at the root URL (`http://localhost:3100/`). Sections: Licenses, My Licenses (customer portal), Products, Releases, Workspaces (files, docs, configs, tickets), Tickets (cross-workspace admin queue), Website (sites, pages, posts, assets, redirects, settings), Newsletter, Shop, Emails (template editor), Users, Audit, and Backups. The account menu covers profile, sessions, 2FA, and API tokens. Non-admin users only see the customer-facing sections they have access to.

Each public site's admin chrome has a Dashboard button, and the dashboard hands a session to the site's own origin through a single-use SSO ticket (`/api/v1/auth/sso-ticket` + `/api/v1/auth/sso-redeem`, 120 s TTL), so editing a site never requires a second login.

### Authentication & Multi-User Support

The server uses JWT-based authentication with multi-user support. Each team member gets their own account with independent credentials and optional 2FA.

**Default credentials** - on first run, the server seeds an `admin` owner with a random one-time password printed once to the server log. This must be changed on first login.

#### Auth Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | None | Login with username or email + password (+ TOTP if enabled); new devices get an emailed sign-in code |
| `POST` | `/api/v1/auth/signin-code` | None | Exchange an emailed 6-digit sign-in code for a JWT |
| `POST` | `/api/v1/auth/request-code` | None | Re-request a sign-in code |
| `POST` | `/api/v1/auth/magic-login` | None | Redeem an invitation link (non-admin accounts only) |
| `POST` | `/api/v1/auth/forgot-password` | None | Request a password-reset email (accepts username or email) |
| `POST` | `/api/v1/auth/reset-password` | None | Submit a new password against a reset or invitation token |
| `POST` | `/api/v1/auth/sso-ticket` / `sso-redeem` | JWT / None | Dashboard-to-site session handoff |
| `GET` | `/api/v1/auth/status` | JWT | Session status: role, email, name, 2FA state, backup codes left |
| `POST` | `/api/v1/auth/logout` | JWT | Revoke the current session server-side |
| `POST` | `/api/v1/auth/change-password` | JWT | Change own password (revokes all other sessions and API tokens) |
| `POST` | `/api/v1/auth/setup-2fa` / `verify-2fa` / `disable-2fa` | JWT | TOTP enrolment (returns 8 backup codes) and removal |
| `POST` | `/api/v1/auth/regenerate-backup-codes` | JWT | Issue a fresh set of one-shot backup codes |
| `PUT` | `/api/v1/auth/me/{email,name,username,newsletter}` | JWT | Edit own profile and newsletter consent |
| `GET` | `/api/v1/auth/me/export` | JWT | Download everything stored about the caller as JSON |
| `DELETE` | `/api/v1/auth/me` | JWT + password | Delete own account (refused for the last owner) |
| `GET` / `DELETE` | `/api/v1/auth/me/devices[/{fp}]` | JWT | List / revoke trusted devices |
| `GET` / `DELETE` | `/api/v1/auth/me/sessions[/{id}]` | JWT | List / revoke sessions; `POST .../sessions/revoke-others` drops all but the current one |
| `POST` / `GET` / `DELETE` | `/api/v1/auth/api-tokens[/{id}]` | JWT | Create (`susi_pat_...`, shown once, 365-day expiry) / list / revoke own API tokens |
| `GET` / `DELETE` | `/api/v1/auth/api-tokens/all[/{id}]` | Admin | List / revoke every user's API tokens |
| `POST` | `/api/v1/auth/api-tokens[/all]/{id}/delete` | JWT / Admin | Permanently delete a revoked or expired API token (own / any user's) |
| `GET` / `POST` | `/api/v1/auth/users` | Admin | List / create users (explicit password or invitation email) |
| `DELETE` | `/api/v1/auth/users/{username}` | Admin | Delete a user (cannot delete self or last user) |
| `PUT` | `/api/v1/auth/users/{username}/{email,profile,role}` | Admin | Set a user's email, name, or role (`user` / `admin` / `owner`) |
| `POST` | `/api/v1/auth/users/{username}/{rename,reset-password,resend-invitation}` | Admin | Rename across every table, force a password reset, re-send the invitation |
| `PUT` / `POST` | `/api/v1/auth/users/{username}/newsletter`, `/api/v1/auth/newsletter-bulk` | Owner | Set newsletter consent for one or up to 5000 accounts |
| `GET` | `/api/v1/audit` | Admin | Audit log, newest first (`?limit=` up to 500, `?before=` cursor) |

#### Security

- Three roles, each a superset of the one below: **user** (customer portal),
  **admin** (full site administration), **owner** (admin plus the newsletter,
  site creation, and the ability to grant or revoke ownership). Ownership is
  closed - only an owner can create one, and only an owner can administer an
  owner account (change its role, reset its password, repoint its email, or
  delete it), since any of those is a route to taking it over. Bootstrap with
  `SUSI_OWNER_EMAILS`.
- Passwords are hashed with **Argon2id** (off the async runtime)
- Sessions use **HS256 JWT tokens** with a 30-day lifetime and a 7-day idle
  timeout. Every session has a server-side row, so logout, "revoke other
  sessions", password changes, and admin resets kill tokens immediately
- 2FA uses **TOTP** (replay-protected) with one-shot **backup codes**, plus
  **trusted-device fingerprints** (30-day trust) so a known browser doesn't
  re-prompt for the emailed code. Admins and owners must enable TOTP before any
  admin endpoint accepts their browser session
- **Emailed sign-in code** is required the first time a user signs in from a
  new device - a 6-digit code is sent to the registered email (15-minute TTL);
  enabled when SMTP and `SUSI_MAGIC_LINK_BASE_URL` are configured. Five wrong
  guesses invalidate every outstanding code for the account
- **Per-account login lockout** after 8 failed password/TOTP attempts in 15
  minutes, checked before the password hash is even computed
- **Invitations** - new users can be created without a password; they receive
  a 7-day invitation link and choose their own. Password reset uses the same
  link flow with a 30-minute token. New users and admin resets force a password
  change on next login
- **Per-IP sliding-window rate limits**: 10/min on every login-adjacent
  endpoint, 60/min on the license client API, 10/min on shop checkout, 300/min
  on the Stripe webhook, 5/hour on newsletter signup, 3/hour on the contact
  form. `X-Forwarded-For` / `X-Real-IP` are honoured only from trusted proxy
  peers (loopback and private IPv4 ranges by default, or the CIDRs in
  `SUSI_TRUSTED_PROXIES`)
- **Default-deny API middleware**: every `/api/v1/...` request needs a valid
  principal unless the method + path is on an explicit public allow-list
- **Security headers** on every response: a CSP (self plus the analytics,
  Turnstile, and video-embed hosts the sites use), `X-Frame-Options: DENY`,
  `nosniff`, `Referrer-Policy`, `Permissions-Policy`, and
  `Cross-Origin-Opener-Policy`. HSTS is added by nginx
- TOTP secrets, Stripe keys entered in the dashboard, the Gmail and Dropbox
  refresh tokens, and workspace federation secrets are sealed at rest with
  `db_secret.bin`

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
token (Dashboard -> account menu -> API Tokens) and keep it in a password
manager, off the server. API tokens skip the trusted-device gate, the
password-change gate and TOTP, so one turns a lockout into a `curl` call.

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

#### API tokens (`susi_pat_...`) and 2FA

API tokens are long-lived bearers for headless clients (CI, scripts) and **bypass interactive 2FA**. The trade-off is deliberate: requiring a TOTP seed alongside an API token in CI raises attack surface without raising the bar - anyone with access to the bearer would also have access to the seed.

Operational consequences:

- Treat each API token as equivalent to a password + 2FA. Store it in a secret manager, never check it into git.
- Tokens expire after 365 days, are SHA-256-hashed at rest, and are revocable from the dashboard. Rotate them on any suspected compromise and on every team-member departure. A password change or admin reset revokes all of the account's tokens.
- Tokens cannot mint or revoke other tokens, list or revoke sessions, or delete the account - those need a browser session.
- For day-to-day admin work in the browser, use a JWT login - TOTP is enforced on every admin endpoint that uses a JWT principal.
- Limit API tokens to the smallest set of users that need them, and audit `/api/v1/auth/api-tokens/all` periodically (admin-only).

### Activate a license

```bash
curl -X POST http://localhost:3100/api/v1/activate \
  -H "Content-Type: application/json" \
  -d '{"license_key": "XXXXX-XXXXX-XXXXX-XXXXX", "machine_code": "a1b2c3...", "friendly_name": "Server-1"}'
```

Returns a `SignedLicense` JSON that can be saved to disk for offline verification. The response includes a `lease_expires` timestamp - the client must call activate or verify again before this time to renew the lease. When the license requires a signed binary and the server pins a CA, the request must also carry `signing_cert_chain` (base64 DER certificates, leaf first).

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
// Never activates: returns NotActivated if no license.json exists yet.
auto status = susi.verifyAndRefresh("license.json", "XXXXX-XXXXX-XXXXX-XXXXX");

if (status == SusiClient::LicenseStatus::NotActivated) {
    // Only when the user explicitly activates: claims a machine slot and writes license.json
    status = susi.activate("license.json", "XXXXX-XXXXX-XXXXX-XXXXX");
}

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

Call `verify_and_refresh`/`verifyAndRefresh` periodically (e.g. at startup and every few hours) to keep the lease alive. The server will renew the lease on each successful call.

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

Lease parameters are set per license at creation time and can be changed later on an existing license (dashboard edit, or `PUT /api/v1/licenses/{key}` with `lease_duration_hours` / `lease_grace_hours`). The new values apply from the next activation or heartbeat.

A machine whose lease lapsed stays listed on the license and renews on its next `/verify` as long as a seat is free. A machine an admin removed is gone from the license and gets 403 until it activates again (after the 24 h tombstone).

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

## Workspaces

Workspaces are the unit of grouping for everything customer-facing: a workspace has a `name`, `product`, optional `description`, a `created_by` user, and a flat member list. Membership grants full read and write access to everything inside the workspace; creating, deleting, re-attributing, and managing members is reserved for site admins. Non-admin users only see workspaces they belong to. The list endpoint reports the caller's relationship to each workspace as `role`: `owner` (creator), `member`, or `admin` (a site admin looking at a workspace they are not a member of).

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` / `POST` | `/api/v1/workspaces` | JWT / admin | List own (all for admins) / create |
| `GET` / `PUT` / `DELETE` | `/api/v1/workspaces/{id}` | member / member / admin | Read with members / update name, product, description (`created_by` is admin-only) / delete incl. files on disk |
| `POST` / `DELETE` | `/api/v1/workspaces/{id}/members[/{username}]` | admin | Add / remove a member |
| `GET` | `/api/v1/workspaces/{id}/releases` | member | Back-compat shim, always empty - releases are global per product |

### Config revisions

Each workspace has an append-only history of JSON configs. Push a new revision and clients can fetch either a specific id or `.../configs/latest`. Useful for shipping operating parameters to deployed installations without rebuilding the binary.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` / `POST` | `/api/v1/workspaces/{id}/configs` | member | List / push a revision (body must be valid JSON) |
| `GET` | `/api/v1/workspaces/{id}/configs/latest` | member | Fetch the most recent revision |
| `GET` / `PUT` / `DELETE` | `/api/v1/workspaces/{id}/configs/{config_id}` | member | Read / update metadata or body / delete |

`susi_client::workspace` provides a typed Rust client (sync + async) over the workspace and config endpoints.

### Files & docs

Each workspace has a flat, member-writable file share (bytes on disk under `{data_dir}/workspaces/{id}/files`) and its own flat documentation page tree, edited in the same viewer as product docs (`/docs?workspace={id}`). Browsers that cannot set an `Authorization` header download files through a 60-second single-file ticket.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` / `POST` | `/api/v1/workspaces/{id}/files` | member | List / upload files (multipart, repeated `file`, up to 500 MB; re-upload overwrites) |
| `GET` / `DELETE` | `/api/v1/workspaces/{id}/files/{file}` | member or `?ticket=` | Download / delete a file |
| `POST` | `/api/v1/workspaces/{id}/files/{file}/ticket` | member | Mint a 60 s download ticket |
| `GET` | `/api/v1/workspaces/{id}/docs/pages` | member | List pages + assets |
| `GET` / `PUT` / `DELETE` | `/api/v1/workspaces/{id}/docs/pages/{slug}` | member | Read / upsert / delete a page |
| `POST` | `/api/v1/workspaces/{id}/docs/pages/{slug}/rename` | member | Rename a page |
| `POST` | `/api/v1/workspaces/{id}/docs/assets` | member | Upload a doc asset (up to 100 MB) |
| `GET` / `DELETE` | `/api/v1/workspaces/{id}/docs/assets/{file}` | member | Fetch / delete a doc asset |

### Tickets

The shared record of customer-reported problems, scoped to a workspace so a report sits next to the config revisions, recordings and files that reproduce it. Status is `open`, `in_progress` or `closed`.

Every member reads and writes every ticket and comment in their workspace - there are no internal-only notes, so treat anything written here as customer-visible. Deleting a ticket or a comment is restricted to its author or a site admin; everything else, including status changes, is open to any member.

Ticket events send **no email**. The notification path (workspace members plus site admins, minus the actor) is implemented but switched off behind `SEND_TICKET_EMAILS` in `crates/susi_server/src/tickets.rs`; flip that const and rebuild to enable it.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` / `POST` | `/api/v1/workspaces/{id}/tickets` | member | List (open first) / open a ticket (title up to 200 chars, body up to 20 000) |
| `GET` / `PUT` / `DELETE` | `/api/v1/workspaces/{id}/tickets/{tid}` | member (delete: author or admin) | Read with comments / update title, body, status / delete |
| `POST` | `/api/v1/workspaces/{id}/tickets/{tid}/comments` | member | Add a comment |
| `DELETE` | `/api/v1/workspaces/{id}/tickets/{tid}/comments/{cid}` | author or admin | Delete a comment |
| `GET` | `/api/v1/admin/tickets` | admin | Every workspace's tickets, `?status=` optional |

### Federation, graph & recordings

These endpoints back the FusionHub data plane: hubs in a workspace share one symmetric channel secret, discover each other through a peer registry, and synchronise one node graph.

- **Federation secret** - 32 random bytes, created on first fetch and stored sealed at rest. Rotating it forces every connected hub to re-fetch and rekey. The response also carries `relay_url` (`SUSI_RELAY_URL`, empty when no relay is configured) and the current `graph_version` so hubs only pull the graph body when behind.
- **Peers** - idempotent on `(workspace, host_id)`; URLs must be `ws`, `wss`, `http`, or `https` without embedded credentials. Private-range hosts are allowed on purpose for LAN federation.
- **Graph** - one JSON document per workspace with an optimistic-lock `graph_version`; a `PUT` with a stale `expected_version` returns 409 carrying the current version.
- **Recordings** - two-phase S3 upload. Susi presigns a 15-minute `PUT` URL under `workspaces/{id}/recordings/`, the client uploads directly to S3, then calls `complete`; downloads are 5-minute presigned `GET`s. Bytes never pass through susi. Requires `SUSI_S3_BUCKET` and `SUSI_S3_REGION` plus AWS credentials from the default provider chain; otherwise these endpoints answer 503.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/workspaces/{id}/federation` | member | Channel secret, peers, relay URL, graph version |
| `POST` | `/api/v1/workspaces/{id}/federation/rotate` | member | Mint a new channel secret |
| `POST` / `DELETE` | `/api/v1/workspaces/{id}/peers[/{host_id}]` | member | Register / remove a peer |
| `GET` / `PUT` | `/api/v1/workspaces/{id}/graph` | member | Fetch / replace the shared graph (`{expected_version, config}`) |
| `GET` / `POST` | `/api/v1/workspaces/{id}/recordings` | member | List / start a recording upload (returns presigned `upload_url`) |
| `POST` | `/api/v1/workspaces/{id}/recordings/{rid}/complete` | member | Confirm the upload landed (409 until the object exists) |
| `GET` / `DELETE` | `/api/v1/workspaces/{id}/recordings/{rid}[/download]` | member | Presigned download URL / delete |

## Products & Releases

Products are the catalog that releases and doc sets hang off. The default product is `fusionhub`. A product flagged `download_public` serves its installers to anyone, without a license or login, which is how the public download buttons on the marketing site work; everything else stays gated.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/products` | None | Catalog with `download_public` flags |
| `POST` | `/api/v1/products` | admin | Create (`slug`, `name`, `description`, `ord`, `download_public`) |
| `PUT` / `DELETE` | `/api/v1/products/{product}` | admin | Update (slug immutable) / delete (refused for the default product or while releases exist) |
| `GET` | `/api/v1/updates/releases?product=` | License key, JWT, or public product | List releases + assets the caller can download |
| `POST` | `/api/v1/updates/download-ticket` | License key or JWT | Mint a 60 s single-asset ticket for the download URL |
| `GET` | `/api/v1/updates/download/{tag}/{asset}?product=` | License key, JWT, `?ticket=`, or public product | Stream a release asset |
| `GET` | `/download/{product}/{platform}` | None | 302 to the newest installer for `windows`, `macos`, or `linux` (public products only) |
| `GET` / `POST` | `/api/v1/releases` | admin | List all releases / upload (multipart `tag`, `product`, `name`, `body`, `prerelease`, repeated `file`; up to 500 MB) |
| `PUT` / `DELETE` | `/api/v1/releases/{tag}?product=` | admin | Update metadata / delete release and its files |
| `POST` | `/api/v1/releases/{tag}/assets/{file}/replace` | admin | Replace one asset in place |
| `DELETE` | `/api/v1/releases/{tag}/assets/{file}?product=` | admin | Delete one asset |

Download authorization for non-public products: a license key only entitles its own product; a logged-in user needs to be a site admin, hold an assigned license for that product, or belong to a workspace whose `product` matches. Releases are global per product; per-customer builds belong in workspace files. Re-uploading an existing tag upserts, so a CI retry keeps the doc pages that were already attached to the release.

The `/download/{product}/{platform}` redirect picks by file extension (`.msi`/`.exe`, `.dmg`/`.pkg`, `.appimage`/`.deb`/`.rpm`), prefers the newest stable release, and falls back to the newest prerelease that shipped that platform - so a site can link to it once and never edit the link per release.

When an upload creates a new release, the previous release's user-edited doc set is **seeded forward** so hand-authored docs carry over automatically.

## Documentation Knowledge Base

The `/docs` page is a per-release documentation site with an in-browser editor (EasyMDE, vendored). Each product has its own releases, and each release its own collection of pages and assets, addressed by tag. Workspace documentation uses the same viewer/editor (`/docs?workspace={id}`) but is a single flat page tree per workspace (see above).

Pages carry an **origin tag** of either `pipeline` (generated from a build pipeline / bulk import) or `user` (hand-edited in the dashboard). Pipeline pages are replaced wholesale on the next bulk import; user pages are preserved across imports and copied forward into newly created releases. New pages start as hidden drafts and go live with a Publish step; hidden pages are invisible to anonymous readers and excluded from the sitemap and `llms` files.

Every doc page is also server-rendered for crawlers and direct links: `/docs/{slug}` resolves against the latest public release, `/docs/{tag}/{slug}` pins a release, and `/docs/{slug}/{heading}` deep-links a section. `/llms-full.txt` concatenates the whole latest release as one Markdown document.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/docs`, `/docs/{slug}`, `/docs/{tag}/{slug}` | None | Viewer + editor shell, server-rendered with SEO meta |
| `GET` | `/api/v1/products/{product}/docs/releases[/latest]` | None | Doc releases of a product (only releases with pages) |
| `GET` | `/api/v1/products/{product}/docs/{tag}/pages[/{slug}]` | None | List pages + assets / get a page (markdown + rendered HTML) |
| `PUT` / `DELETE` | `/api/v1/products/{product}/docs/{tag}/pages/{slug}` | admin | Upsert (optional `hidden`) / delete a page |
| `POST` | `/api/v1/products/{product}/docs/{tag}/pages/{slug}/rename` | admin | Rename a slug (cascades to children) |
| `POST` | `/api/v1/products/{product}/docs/{tag}/import` | admin | Bulk import: multipart `release_name`, `manifest` (JSON keyed by slug: `title`, `parent_slug`, `ord`), repeated `page` (`<slug>.md`) and `asset` fields |
| `POST` / `GET` / `DELETE` | `/api/v1/products/{product}/docs/{tag}/assets[/{file}]` | admin / None / admin | Upload / fetch / delete an asset |
| `GET` | `/llms-full.txt` | None | Latest public release as one Markdown file |

The legacy `/api/v1/docs/...` routes (same shapes, no product segment) are a compatibility shim for the default product. `scripts/migrate_lpms_docs.py` shows the import format end to end: it fetches a Confluence space, converts it to Markdown, and bulk-imports it as a product.

> **Editing rule:** never `PUT` a full page from outside the dashboard - fetch first, then send a targeted patch to `body_md`. Wholesale overwrites trash user edits.

## Public Websites

A small CMS that serves any number of public marketing sites from one server. The site is resolved from the request's `Host` header (exact match against each site's host list; `?site=` overrides for previews; unknown hosts fall back to the default site `xikaku`). Pages are Markdown, edited in the site's own admin chrome or the dashboard, and server-rendered with per-page SEO meta and JSON-LD. There is no release concept here - all content is hand-authored.

### Sites

The site registry is seeded from two built-in definitions (`xikaku` and `lpr`) on first boot and then managed from the dashboard. Each site definition holds: `name`, `tagline`, `hosts` (bare hostnames, including the staging name), `public_base` (canonical `https://` origin used for every canonical, sitemap, and RSS URL), `contact_email`, `org_legal_name`, `person_name` (non-empty switches the JSON-LD entity from Organization to Person), `addr_locality` / `addr_country`, `og_image_url`, `social_links`, `area_served`, `llms_blurb`, feature flags `has_shop`, `has_newsletter`, `has_blog`, `show_updated`, and `langs` (extra content languages served under `/{lang}/`).

Per-site settings (dashboard Website -> Site Settings) cover analytics (`google_analytics_id`, `google_ads_id` + conversion labels, `reddit_pixel_id`), `nav_structure` (JSON groups of page slugs, `__blog__` / `__shop__` pseudo-entries, relabeled pages, and external links), branding (`logo_image`, `logo_dark_image`, `logo_height`, `favicon_image`, `bg_image`, `bg_veil`, `bg_parallax`, `theme_mode`, `no_topbar`, `sidebar_logo`), and `font` (`mono`, `serif`, or the self-hosted `inter` preset). Brand images are uploaded website assets; sites without a logo show their name as text.

Analytics and ad pixels load only after the visitor accepts the consent banner, which is shown to browsers in a European timezone or an EU territory; the choice is stored in `localStorage` and can be reopened from a `[data-cookie-settings]` link.

### Pages and posts

- **Kinds** - `page` or `post`. Posts form the blog (`/blog`, 3 per page, RSS at `/blog/rss.xml`), get a `published_at` date on first publish, and carry an author byline.
- **Drafts** - new pages and posts start `hidden`; Publish flips the flag. Hidden pages are invisible to anonymous readers and excluded from nav, sitemap, and `llms.txt`.
- **Navigation** - `ord` for sorting, `parent_slug` for one level of nesting, `nav_title` for a short sidebar label, and the site-level `nav_structure` for grouping.
- **SEO** - `meta_description` (derived from the body when empty), optional `og_image` override (asset name, path, or URL; falls back to the first body image, then the site card), canonical URLs from `public_base`, hreflang alternates from `translation_of`, JSON-LD (`WebSite`, `WebPage`, `BlogPosting`, `BreadcrumbList`, `Organization` / `Person`).
- **Translations** - a page in an extra language links to its default-language page via `translation_of`; nginx maps `/{lang}/...` onto the same routes with `?lang=`.
- **Revisions** - every changing update snapshots the previous title, body, parent, and order; old revisions can be viewed and restored.
- **Redirect map** - per-site 301 table for retired slugs and legacy (WordPress) permalinks, including multi-segment paths. A page can also be retired by setting `redirect_to`, which hides it and installs the redirect in one step.
- **Shortcodes** - `{{newsletter-signup}}`, `{{newsletter-archive}}`, `{{contact-form}}`, and `{{email:user@domain}}` (click-to-reveal, never a plaintext address in the HTML). Images accept Pandoc-style attributes (`![alt](file.png){width=400px}`), `.mp4` / `.webm` become inline videos, and YouTube / Vimeo URLs in image syntax become embeds.
- **Markdown** - tables, footnotes, strikethrough, task lists, smart punctuation; sanitized with ammonia. Tables with an empty header row render as CSS grids; real tables scroll horizontally on phones.
- **Legal pages** - `privacy` and `imprint` are seeded once for the default site from `content/`.
- **IndexNow** - every content change pings `api.indexnow.org` with the affected URLs; the key file is served at `/api/v1/indexnow/{key}.txt`.

Rendered pages are cached for 5 minutes per site, language, and slug; every content or settings write clears the cache.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/site`, `/site/{slug}`, `/site/blog/{slug}`, `/site/{lang}/...` | None | Public-rendered HTML (nginx rewrites `/{slug}` to `/site/{slug}` on the marketing hosts) |
| `GET` | `/site/blog/rss.xml`, `/robots.txt`, `/sitemap.xml`, `/llms.txt` | None | Feeds and crawler metadata for the resolved site |
| `GET` | `/api/v1/website/pages[/{slug}]` | None | List pages, assets, nav, and sites / fetch a page (hidden pages for admins only) |
| `PUT` / `DELETE` | `/api/v1/website/pages/{slug}` | admin | Upsert / delete |
| `POST` | `/api/v1/website/pages/{slug}/rename` | admin | Rename a slug (cascades parent and translation links) |
| `POST` | `/api/v1/website/pages/{slug}/visibility` | admin | Publish / unpublish |
| `GET` | `/api/v1/website/pages/{slug}/revisions[/{id}]` | admin | Revision history / one revision |
| `POST` | `/api/v1/website/pages/{slug}/revisions/{id}/restore` | admin | Restore an old revision |
| `GET` / `POST` / `DELETE` | `/api/v1/website/assets[/{file}]` | None / admin / admin | Serve (with `Range` support) / upload (up to 100 MB) / delete |
| `POST` | `/api/v1/website/assets/{file}/rename` | admin | Rename an asset, rewriting references in pages and products |
| `GET` | `/api/v1/website/admin/assets` | admin | Assets with usage counts |
| `GET` / `PUT` / `DELETE` | `/api/v1/website/redirects[/{id}]` | admin | Redirect map CRUD; `POST .../redirects/import` bulk-loads up to 5000 |
| `POST` | `/api/v1/website/import` | admin | Bulk import: multipart `manifest` (JSON keyed by slug), repeated `page` and `asset` fields; `tools/wp_migrate` builds one from a WordPress export |
| `GET` / `PUT` | `/api/v1/site/admin/settings` | admin | Per-site settings |
| `GET` / `POST` / `PUT` | `/api/v1/sites[/{id}]` | admin / owner / owner | Site registry |
| `GET` | `/static/logo.png`, `/static/logo-dark.png`, `/static/icon.png`, `/static/favicon-*.png`, `/favicon.ico`, `/static/bg.jpg`, `/static/og-image.png` | None | Per-site brand assets (uploaded, else compiled-in for the built-in sites) |

## Newsletter

Each site with `has_newsletter` has its own double-opt-in subscriber list and its own issues; the audience of an issue is exactly that site's confirmed subscribers. Public signup goes through the `{{newsletter-signup}}` shortcode on any page, mails a confirmation link (14-day TTL), and uses a honeypot plus a 5/hour per-IP limit. Account-level newsletter consent in the dashboard is a view over the default site's list keyed by the account email.

Issues are Markdown and share the site's asset library: local images are embedded as inline attachments (raster only, 4 MB cap), YouTube / Vimeo links become a poster frame linking to the video, and `[TOC]` renders a table of contents. Every campaign mail carries a `List-Unsubscribe` header and a footer link; the unsubscribe token never expires so archived mail keeps working, and the endpoint supports RFC 8058 one-click. Sent issues can be flagged `public` to appear in the site's `{{newsletter-archive}}`.

Sending is owner-only. An issue goes `draft` -> `sending` -> `sent`: the send call snapshots the audience into delivery rows and returns immediately; a background sender drains them at `SUSI_NEWSLETTER_RATE_PER_MIN` (default 30) with up to 3 attempts per address, and resumes after a restart without re-mailing. Transport per site: the default site uses `SUSI_NEWSLETTER_SMTP_*` or the Gmail OAuth connector; every other site needs its own `SUSI_NEWSLETTER_SMTP_*_{SITE}` relay (site id uppercased, `-` -> `_`). There is deliberately no fallback to the account-mail relay. Staging blanks all newsletter transports so a test can never mail the real list.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/newsletter/subscribe` | None (5/hour per IP) | Public signup, sends the confirmation mail |
| `GET` | `/api/v1/newsletter/confirm?token=` | None | Double-opt-in confirmation |
| `GET` / `POST` | `/api/v1/newsletter/unsubscribe?token=` | None | Unsubscribe page / one-click unsubscribe |
| `GET` | `/api/v1/newsletter/public` | None | Issues flagged for the public archive |
| `GET` | `/api/v1/newsletter/config` | owner | Transport state (relay kind, Gmail account, rate, env suffix for the site) |
| `GET` | `/api/v1/newsletter/audience` | owner | Confirmed and pending counts plus a small sample |
| `GET` / `POST` | `/api/v1/newsletter/issues` | owner | List / create a draft |
| `GET` / `PUT` / `DELETE` | `/api/v1/newsletter/issues/{id}` | owner | Read / edit / delete (drafts only) |
| `POST` | `/api/v1/newsletter/preview` | owner | Render `body_md` exactly as a send would |
| `POST` | `/api/v1/newsletter/issues/{id}/test` | owner | Send a `[TEST]` copy to the caller |
| `POST` | `/api/v1/newsletter/issues/{id}/send` | owner | Queue the issue for its audience (optional `expect_recipients` guard) |
| `GET` | `/api/v1/newsletter/issues/{id}/deliveries` | owner | Per-address delivery report |
| `POST` | `/api/v1/newsletter/issues/{id}/visibility` | owner | Show / hide a sent issue in the archive |
| `GET` / `DELETE` | `/api/v1/newsletter/subscribers[?email=]` | owner | List / remove subscribers of the site |
| `GET` | `/api/v1/newsletter/google/authorize`, `/callback`; `POST .../disconnect` | owner / None / owner | Gmail OAuth connector (see [3b](#3b-gmail-connector-for-newsletters-optional)) |

## Email Templates

All transactional mail is rendered from Markdown templates whose defaults live in code and whose overrides live in the database, so an untouched template keeps receiving upstream improvements. Templates: `signin_code`, `password_reset`, `invitation`, `ticket_notification`, `newsletter_confirm`, `order_confirmation`, and `order_shipped`. Body is always editable; subject is editable everywhere except the ticket notification. `newsletter_confirm` and the two shop templates can be overridden per site and per language (`ja` for the shop).

The renderer produces one consistent layout (centered logo, one heading size, one body size, black text everywhere) plus a plain-text twin derived from the same Markdown. Two shortcodes exist: `{{code:483920}}` for a large one-time code box and `{{button:Label|https://...}}` for a call-to-action button with a paste-link fallback. Lines that reference a variable with no value are dropped, so optional sections disappear cleanly.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` / `PUT` | `/api/v1/admin/email_templates` | admin | List templates / save an override for `{id, lang, site}` (empty body and subject reset to the default) |
| `POST` | `/api/v1/admin/email_templates/preview` | admin | Render with sample data; also returns the default subject, body, and variables |
| `POST` | `/api/v1/admin/email_templates/test` | admin | Send a `[Test]` copy to the caller |

## Shop

Stripe-backed checkout for physical goods, per site: every shop endpoint resolves the site from the Host header and answers 404 when the site has no shop. Products, shipping rates, orders, and settings are scoped per site. The cart lives in the browser (`localStorage`); the server looks up authoritative prices from the DB at checkout time and hands the line items to Stripe Checkout with `automatic_tax: true`, address and phone collection, and Stripe invoice creation. Stripe collects address + payment, computes tax, and redirects to `success_url` / `cancel_url`.

Stripe keys come from the per-shop settings (entered in the dashboard, sealed at rest) or, as fallback, from the environment: `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET` for the default site and `STRIPE_SECRET_KEY_{SITE}` / `STRIPE_WEBHOOK_SECRET_{SITE}` for other sites. Without a secret key the public product pages still render but checkout returns 503. The webhook identifies the site by which configured signing secret verifies the payload.

Products carry an English and a Japanese title and description plus a base price in the product's currency and an optional whole-yen `price_jpy`. A Japanese storefront (`/ja/shop`) checks out in JPY; mixed currencies in one cart are rejected. Shipping is restricted to the admin-enabled destination countries (default `US`, `CA`) and the regions of the active shipping rates. A product whose title contains "pre-order" gets pre-order copy in the confirmation email and is left out of the Merchant Center feed.

After a successful checkout, susi:

1. Verifies the Stripe webhook signature (HMAC-SHA256, 5-minute timestamp tolerance, constant-time compare)
2. De-duplicates webhook deliveries and records `pending_payment` until Stripe reports the session paid (delayed payment methods are handled through the `async_payment_*` events)
3. Renders a paid-invoice PDF locally (Stripe's own PDF is frozen at "amount due") and emails the customer a branded confirmation in the site's language with the PDF attached
4. Notifies the configured admin recipients

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/shop`, `/shop/{sku}`, `/shop/success`, `/shop/cancel` | None | Public HTML shell (product pages carry `Product` JSON-LD) |
| `GET` | `/shop/feed.xml?lang=` | None | Google Merchant Center product feed |
| `GET` | `/api/v1/shop/products[/{sku}]` | None | Public catalog (active products) |
| `GET` | `/api/v1/shop/shipping_countries` | None | Enabled destination countries |
| `POST` | `/api/v1/shop/checkout` | None (10/min per IP) | Create a Stripe Checkout Session (`items`, `country`, `currency`, `lang`) |
| `POST` | `/api/v1/shop/webhook` | Stripe signature | Stripe webhook handler |
| `GET` / `PUT` / `DELETE` | `/api/v1/shop/admin/products[/{sku}]` | admin | Product CRUD (image must be an uploaded website asset) |
| `GET` / `POST` / `PUT` / `DELETE` | `/api/v1/shop/admin/shipping_rates[/{id}]` | admin | Shipping-rate CRUD (label, amount, currency, delivery window, regions) |
| `GET` | `/api/v1/shop/admin/countries` | admin | Full country catalog for the settings UI |
| `GET` / `DELETE` | `/api/v1/shop/admin/orders[/{id}]` | admin | Orders list (`?status=`) / detail with Stripe link / erase an order |
| `POST` | `/api/v1/shop/admin/orders/{id}/ship` | admin | Mark shipped with carrier + tracking (optionally emails the customer) |
| `PUT` | `/api/v1/shop/admin/orders/{id}/notes` | admin | Update internal notes |
| `GET` / `PUT` | `/api/v1/shop/admin/settings` | admin | `notification_emails`, `customer_email_enabled`, `support_contact`, `shipping_countries`, `invoice_from`, `stripe_secret_key`, `stripe_webhook_secret` (secrets returned masked) |

## Public Contact Form

Served in the site chrome (`{{contact-form}}` shortcode) and disabled (503) unless a recipient (the site's `contact_email`, falling back to `SUSI_CONTACT_TO_ADDR`) and SMTP are both set. Hardening stack:

- Hidden honeypot field that real browsers leave empty (a filled honeypot gets a fake success)
- Cloudflare Turnstile siteverify when `SUSI_TURNSTILE_SECRET` is set (otherwise honeypot + rate limit only)
- Per-IP sliding-window rate limit (3 per hour)
- All fields mandatory (name, company, email, subject, message) - filters low-effort scam inquiries
- Field length caps + minimum body length; sender email syntactically validated and CRLF-free
- Mail is sent from the server's own address (SPF/DKIM stay valid) with the visitor's address in the body, subject prefixed with the site name, body plain text

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/contact/config` | None | Returns whether the form is enabled and the public Turnstile site key |
| `POST` | `/api/v1/contact` | None | Submit a contact-form message |

## Audit Log & Data Protection

Every administrative action (user, role, token, license, release, workspace, ticket, shop, newsletter, template, and backup changes, plus auth anomalies) writes an `audit_log` row with actor, action, target, and details. `GET /api/v1/audit` pages through it newest first; the dashboard's Audit section is a view over the same endpoint. Writes are best-effort and never fail the request.

Personal data has a defined lifecycle:

- **Self-serve export** - `GET /api/v1/auth/me/export` returns account fields, devices, sessions, tokens, licenses, newsletter deliveries, audit entries, and shop orders matched by email as one JSON download.
- **Deletion** - self-serve (`DELETE /api/v1/auth/me`) or by an admin. Account rows are deleted and the username is scrubbed from every table that keeps history (tickets, pages, revisions, configs, audit log, deliveries), since usernames may be email addresses. Shop orders can be erased individually by an admin.
- **Retention** - a scheduled job (every 5 minutes) deletes sessions past their 30-day lifetime, audit rows older than 365 days, trusted devices unseen for 180 days, anonymises newsletter deliveries 365 days after the send, and scrubs customer details from shop orders after 3 years while keeping amounts and line items for accounting. Login and invitation tokens are purged 24 hours after use or expiry.
- **Consent** - analytics and ad pixels on the public sites load only after the visitor accepts the banner.
- **Logs** - container stdout is capped by the compose logging driver (5 x 20 MB).

## Dropbox Backups

Rotating, encrypted offsite backups to a Dropbox App Folder, managed from the
dashboard's admin-only Backups page. The archive contains a consistent SQLite
snapshot (`VACUUM INTO`), the `docs/` and `website/` asset directories, and
optionally `releases/`. It deliberately **excludes** `private.pem`,
`db_secret.bin`, and `jwt_secret.bin`, so one leaked backup key cannot
collapse every layer of key separation - keep those three files offline
separately, you need them for a restore. Workspace files and recordings are not
part of the archive either.

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
failure; a manual run is refused while another is in progress. Rotation is
grandfather-father-son - newest archive per day/week/month up to the configured
counts (default 7/4/12), and nothing younger than 48 h is ever deleted. The
OAuth refresh token is stored sealed with the DB at-rest key; access tokens are
minted per run and never persisted.

Restore:

```bash
# Download the archive from Dropbox (Apps/<app name>/), then:
susi-server decrypt-backup prod-backup-20260706-030000.tar.gz.enc --key <SUSI_BACKUP_KEY>
tar -xzf prod-backup-20260706-030000.tar.gz   # unpack into a fresh /data volume
# then copy private.pem, db_secret.bin and jwt_secret.bin from your offline copy
```

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/admin/backup/status` | Admin | Settings, connection state, quota, run history |
| `PUT` | `/api/v1/admin/backup/settings` | Admin | Schedule, retention counts, include releases |
| `GET` | `/api/v1/admin/backup/connect-url` | Admin | Dropbox consent URL |
| `POST` | `/api/v1/admin/backup/connect` | Admin | Exchange pasted code for a refresh token |
| `POST` | `/api/v1/admin/backup/disconnect` | Admin | Revoke + forget the connection |
| `POST` | `/api/v1/admin/backup/run` | Admin | Trigger a manual backup |

## Deploying to AWS Lightsail

The project includes a Dockerfile, two compose files, and a deploy script for one-command deployment to an AWS Lightsail (or any EC2/VPS) instance. The image is built locally and shipped to the host - the 2 GB Lightsail box cannot build the server without swapping.

### 1. Create a Lightsail instance

1. Go to [AWS Lightsail Console](https://lightsail.aws.amazon.com/)
2. Create an instance: **Linux/Unix** -> **OS Only** -> **Ubuntu 22.04 LTS** (or 24.04)
3. Choose a plan - **$5/mo (1 GB RAM, 1 vCPU)** runs it; 2 GB is more comfortable
4. Under **Networking**, open **22, 80, 443** only. The containers bind to loopback and are reached through nginx (step 8)

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

From your **local machine** (on Windows: from WSL, since Git Bash lacks rsync), in the susi project root:

```bash
# Production (port 3100, volume susi-data, compose file docker-compose.yml, env /opt/susi/.env)
./deploy.sh ubuntu@<YOUR_INSTANCE_IP> ~/.ssh/LightsailDefaultKey-*.pem

# Staging (port 3101, volume susi-data-staging, compose file docker-compose.staging.yml, env /opt/susi/.env.staging)
./deploy.sh ubuntu@<YOUR_INSTANCE_IP> ~/.ssh/LightsailDefaultKey-*.pem --staging
```

The script will:
1. Build the `susi:latest` image locally, `docker save | gzip` it, and `scp` it to the host
2. Copy only the two compose files to `/opt/susi` and create an empty `.env` / `.env.staging` on first deploy
3. Generate a **4096-bit RSA keypair** if none exists in the data volume
4. `docker load` the image and `docker compose up -d --force-recreate` with the matching env file

Both environments ship the same image; they differ only in compose file, env file, port, and data volume. Deploy to staging first, verify, then deploy to production.

On first run, the server creates an `admin` owner with a random one-time password printed once to the server log (`docker compose logs`). Log in and change the password immediately.

### 3a. Configure environment variables

The container reads integrations from `/opt/susi/.env` (production) or `/opt/susi/.env.staging`. The deploy script creates an empty file on first deploy; add settings as needed. Staging keeps its own file on purpose: the lower-trust instance must not carry live Stripe keys or the production backup key, and its compose file blanks every newsletter transport.

```bash
# /opt/susi/.env  (chmod 600)

# Sign-in code / password-reset / invitation / order / contact mail (Gmail SMTP relay shown)
SUSI_SMTP_HOST=smtp.gmail.com
SUSI_SMTP_PORT=587
SUSI_SMTP_USER=you@example.com
SUSI_SMTP_PASSWORD=<google-app-password>
SUSI_SMTP_FROM_NAME=Susi
SUSI_SMTP_FROM_ADDR=noreply@example.com
# Public dashboard origin, used in every emailed link. Empty disables the
# sign-in code and newsletter sending.
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
# convention as the per-site Stripe keys. No cross-site fallback. The compose
# file must pass the variables through - add a block for each new site.
SUSI_NEWSLETTER_SMTP_HOST_KLAUS=smtp.example.com
SUSI_NEWSLETTER_SMTP_USER_KLAUS=news@klaus.example.com
SUSI_NEWSLETTER_SMTP_PASSWORD_KLAUS=<app-password>
SUSI_NEWSLETTER_SMTP_FROM_ADDR_KLAUS=news@klaus.example.com

# Gmail connector (optional alternative to SUSI_NEWSLETTER_SMTP_USER/_PASSWORD).
# With these set, an owner connects a Google Workspace account from the
# Newsletter page and campaign mail goes out over Gmail with OAuth - no app
# password on the host. Static credentials above take precedence if both exist.
SUSI_GOOGLE_CLIENT_ID=<id>.apps.googleusercontent.com
SUSI_GOOGLE_CLIENT_SECRET=<secret>

# Accounts promoted to the `owner` role on every start (comma-separated).
# Owner is the only role that can send newsletters, create sites, or grant
# ownership, and it can only be granted by an existing owner - so this is how
# the first one exists on a database that predates the role, and the way back
# in if the last owner is ever lost. Applied idempotently on each boot.
SUSI_OWNER_EMAILS=you@example.com,you@other-domain.com

# Shop (leave empty to disable checkout - product pages still render).
# Bare keys serve the default site. Other sites read STRIPE_SECRET_KEY_{SITE} /
# STRIPE_WEBHOOK_SECRET_{SITE}; the compose files map the LPR shop from
# STRIPE_*_LPR_LIVE (production) and STRIPE_*_LPR_TEST (staging) so a sandbox
# key can never reach production. Keys can also be entered per shop in the
# dashboard, which takes precedence over the environment.
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_SECRET_KEY_LPR_LIVE=sk_live_...
STRIPE_WEBHOOK_SECRET_LPR_LIVE=whsec_...
SUSI_SHOP_BASE_URL=https://susi.example.com
SUSI_SHOP_NOTIFY_ADDR=orders@example.com

# Contact form (empty recipient disables unless the site has a contact_email;
# turnstile keys are optional)
SUSI_CONTACT_TO_ADDR=hello@example.com
SUSI_TURNSTILE_SECRET=...
SUSI_TURNSTILE_SITE_KEY=...

# FusionHub relay URL handed to workspace members on federation fetch.
# Empty disables the relay (hubs reach each other directly).
SUSI_RELAY_URL=wss://fusionhub.example.com/api/relay

# S3 for workspace recordings. Empty bucket disables the recording endpoints.
SUSI_S3_BUCKET=
SUSI_S3_REGION=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=

# Dropbox backups (see Dropbox Backups). All three empty = feature disabled.
SUSI_DROPBOX_APP_KEY=
SUSI_DROPBOX_APP_SECRET=
SUSI_BACKUP_KEY=<64 hex chars>
SUSI_BACKUP_PREFIX=prod

# CIDRs whose X-Forwarded-For / X-Real-IP headers are trusted. Empty =
# loopback plus all private IPv4 ranges (covers the Docker bridge nginx
# proxies through).
SUSI_TRUSTED_PROXIES=
```

Re-run `docker compose --env-file <env> -f <file> up -d` after editing the file to pick up changes.

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
curl https://<dashboard host>/health
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

Use the web dashboard at `https://<dashboard host>/` to create licenses and manage users. Or use the API:

```bash
SERVER="https://<dashboard host>"

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
| Private key | Docker volume `susi-data` -> `/data/private.pem` |
| Public key | Docker volume `susi-data` -> `/data/public.pem` |
| At-rest secrets | Docker volume `susi-data` -> `/data/jwt_secret.bin`, `/data/db_secret.bin` |
| Database | Docker volume `susi-data` -> `/data/licenses.db` |
| Release assets | Docker volume `susi-data` -> `/data/releases/{tag}/` |
| Doc pages + assets | Docker volume `susi-data` -> `/data/docs/{tag}/` (default product) or `/data/docs/{product}/{tag}/` |
| Website assets | Docker volume `susi-data` -> `/data/website/assets/{site}/` |
| Workspace files + docs | Docker volume `susi-data` -> `/data/workspaces/{id}/` |
| Env files | `/opt/susi/.env` (prod), `/opt/susi/.env.staging` |
| nginx vhosts | `nginx/*.conf` in the repo, copied to `/etc/nginx/conf.d/` on the box |
| Dashboard | `https://<dashboard host>/` (prod `:3100`, staging `:3101` behind nginx) |
| Public websites | each site's hosts, e.g. `https://xikaku.com/` (nginx rewrites `/{slug}` to `/site/{slug}`) |
| Documentation | `https://<dashboard host>/docs` |
| Shop | `https://<site host>/shop` |
| Default login | `admin` / random one-time password from the server log (must change on first login) |
| Logs | `docker compose logs -f` in `/opt/susi` |
| Health check | `GET /health` |

## Building

```bash
cargo build --workspace --release
```

Binaries are output to `target/release/`:
- `susi-admin` - CLI management tool
- `susi-server` - HTTP server
- `susi-helper` - end-user utility for fingerprinting and USB serial lookup

The Docker image only builds `susi-server` (`rust:1.95` builder, `debian:bookworm-slim` runtime, `--locked` against the committed `Cargo.lock`).

## Testing

```bash
cargo test --workspace
cargo test -p susi_core --features db      # the SQLite tests are feature-gated
cargo test -p susi_server --test integration
```

The integration suite starts the real `susi-server` binary on an ephemeral port per test and drives it through the Rust client, raw HTTP, and (when Conan is available) the C++ `PackageTest` binary. It covers licensing, workspaces, docs, website, newsletter, shop (with synthetic signed Stripe webhooks), backups (against a mock Dropbox endpoint), and auth. GitHub Actions runs `cargo build` and `cargo test` on every push and pull request to `main`.

## Dependencies

Key dependencies:
- [`rsa`](https://crates.io/crates/rsa) - RSA key generation, signing, verification
- [`sha2`](https://crates.io/crates/sha2) - SHA-256 hashing
- [`aes-gcm`](https://crates.io/crates/aes-gcm) - AES-256-GCM for USB tokens, sealed secrets, and backup archives
- [`hkdf`](https://crates.io/crates/hkdf) - HKDF-SHA256 key derivation for USB tokens
- [`axum`](https://crates.io/crates/axum) / [`tower-http`](https://crates.io/crates/tower-http) - HTTP server, multipart, CORS, security headers, path normalisation (susi_server only)
- [`rusqlite`](https://crates.io/crates/rusqlite) - SQLite storage (bundled; server/admin only) behind a poison-free [`parking_lot`](https://crates.io/crates/parking_lot) mutex
- [`argon2`](https://crates.io/crates/argon2), [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken), [`totp-rs`](https://crates.io/crates/totp-rs) - password hashing, sessions and tickets, TOTP 2FA (susi_server only)
- [`x509-cert`](https://crates.io/crates/x509-cert) / [`ring`](https://crates.io/crates/ring) - signing-certificate chain pinning on activate / verify (susi_server only)
- [`lettre`](https://crates.io/crates/lettre) - SMTP client for all outbound mail, including XOAUTH2 for the Gmail connector (susi_server only)
- [`pulldown-cmark`](https://crates.io/crates/pulldown-cmark) / [`ammonia`](https://crates.io/crates/ammonia) - Markdown rendering and HTML sanitising for pages, docs, newsletters, and email (susi_server only)
- [`hmac`](https://crates.io/crates/hmac) - Stripe webhook signature verification (susi_server only)
- [`printpdf`](https://crates.io/crates/printpdf) - paid-invoice PDF generation (susi_server only)
- [`aws-sdk-s3`](https://crates.io/crates/aws-sdk-s3) - presigned URLs for workspace recordings (susi_server only)
- [`tar`](https://crates.io/crates/tar) / [`flate2`](https://crates.io/crates/flate2) - backup archives (susi_server only)
- [`reqwest`](https://crates.io/crates/reqwest) - HTTP client for online refresh, Stripe, Turnstile, Dropbox, IndexNow, and oEmbed

The `susi_client` crate is intentionally lightweight - it only pulls in the crypto and HTTP dependencies needed for verification and the workspace API client.

## License

MIT
