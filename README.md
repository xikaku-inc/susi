# susi

*Susi* (Tagalog for "key") — a self-hosted backend platform written in Rust. It started as a software-licensing server and has grown to bundle everything a small product company needs around a downloadable application: signed licensing, release distribution, a documentation knowledge base, a public website, a Stripe-backed shop, and a contact form — all served from a single binary with a SQLite store.

## Features

### Licensing
- **RSA-SHA256 signed license files** — tamper-proof, offline-verifiable
- **Node-locked licenses** — bind licenses to specific machines via hardware fingerprint
- **Feature flags, expiry dates, machine limits** — fine-grained per-license policy
- **Lease-based seat management** — time-limited activations that expire automatically, preventing unauthorized concurrent usage
- **USB hardware tokens** — bind a license to a physical USB stick instead of a machine
- **Rust + C++ client libraries** — drop-in verification for both ecosystems

### Releases & workspaces
- **Workspaces** — group licenses, releases, configs, and docs per product/team with member roles (`owner` / `editor` / `viewer`)
- **Versioned config revisions** — push, fetch, and roll back JSON configs per workspace
- **Binary release channel** — upload signed installers/binaries; clients fetch via license-key-protected `/api/v1/updates`

### Documentation & website
- **Documentation knowledge base** — per-release doc sets at `/docs`, with Markdown editor, asset uploads, bulk import, and origin tagging (pipeline-generated vs. user-edited pages)
- **Public marketing website** — `/site` with in-browser Markdown editor, asset library, page revision history, and per-page SEO (`robots.txt`, `sitemap.xml`, `llms.txt`)

### Commerce
- **Stripe-backed shop** — products, shipping rates, automatic-tax checkout, branded order confirmations with PDF invoices, and an admin fulfillment workflow
- **Public contact form** — Cloudflare Turnstile + honeypot + per-IP rate limit, served at the `/site` chrome

### Auth & ops
- **Multi-user dashboard** with Argon2id passwords, **TOTP 2FA + backup codes**, **magic-link login**, **trusted-device list**, **password reset via email**, and **API tokens** for headless clients
- **Optional activation server** — HTTP server for online activation, lease renewal, and machine management
- **One-command deploy** — Docker + Compose with separate production / staging environments
- **Cross-platform clients** — Linux, Windows, macOS

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
| `susi_server` | Binary | HTTP server with SQLite backend — licensing, releases, docs, website, shop, contact |
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
# Time-limited license with lease enforcement (default: 7-day lease, 24h grace)
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
        eprintln!("Lease expired at {} — must renew to continue", lease_expired_at);
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
        // Lease expired but still in grace period — trigger renewal
        break;
    case SusiClient::LicenseStatus::Expired:
        // License has expired
        break;
    case SusiClient::LicenseStatus::LeaseExpired:
        // Lease and grace period both expired — must renew
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

- `expires` — `null` for perpetual licenses
- `lease_expires` — omitted when lease enforcement is disabled (`lease_duration = 0`). When present, the client must renew before this time or the license stops working (after the grace period).

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

Instead of binding a license to a specific machine, you can bind it to a physical USB stick. The license file is stored on the USB drive, encrypted with a key derived from the device's hardware serial number. Plug the stick into any machine and the software is licensed — remove it and it's not. Copying the file to a different USB stick fails because the serial number won't match.

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

## Susi Helper

`susi-helper` is a small end-user utility that helps customers provide the information needed to activate a license. It requires no database or private key — it is safe to ship to end users alongside your product.

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

On first run, the server creates an `admin` user with password `changeme`. Open the dashboard in your browser to log in and manage users.

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
| `DELETE` | `/api/v1/licenses/{key}/machines/{code}` | JWT | Deactivate a machine |
| `DELETE` | `/api/v1/licenses/{key}/machines/{code}/tombstone` | JWT | Clear the deactivation tombstone (allow re-activation) |
| `GET` | `/health` | None | Health check |

Admin endpoints require JWT authentication (see below).

### Web Dashboard

The server includes a built-in web dashboard at the root URL (`http://localhost:3100/`). It provides a browser-based interface for managing licenses, viewing activations, and administering users — no API calls required.

### Authentication & Multi-User Support

The server uses JWT-based authentication with multi-user support. Each team member gets their own account with independent credentials and optional 2FA.

**Default credentials** — on first run, the server seeds an `admin` user with password `changeme`. This must be changed on first login.

#### Auth Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | None | Login with username + password (+ TOTP if enabled) |
| `POST` | `/api/v1/auth/magic` | None | Exchange a magic-link token for a JWT |
| `POST` | `/api/v1/auth/forgot-password` | None | Request a password-reset email (accepts username or email) |
| `POST` | `/api/v1/auth/reset-password` | None | Submit a new password against a reset token |
| `GET` | `/api/v1/auth/status` | JWT | Check session status, get username and 2FA/password state |
| `POST` | `/api/v1/auth/change-password` | JWT | Change own password |
| `POST` | `/api/v1/auth/setup-2fa` | JWT | Generate TOTP secret and QR code |
| `POST` | `/api/v1/auth/verify-2fa` | JWT | Verify TOTP code to enable 2FA |
| `POST` | `/api/v1/auth/disable-2fa` | JWT | Disable 2FA (requires valid TOTP code) |
| `POST` | `/api/v1/auth/regenerate-backup-codes` | JWT | Issue a fresh set of one-shot backup codes |
| `PUT` | `/api/v1/auth/me/email` | JWT | Set own contact email (used for magic-link / reset) |
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

- Passwords are hashed with **Argon2id**
- Sessions use **HS256 JWT tokens** with 24-hour expiry
- 2FA uses **TOTP** with one-shot **backup codes**, plus **trusted-device fingerprints** so a known browser doesn't re-prompt every login
- **Magic-link** login lets a user authenticate by clicking a link sent to their registered email (15-minute TTL); enabled when SMTP is configured
- **Password reset** sends a time-limited token to the user's email
- New users and password resets force a password change on next login
- Login, shop checkout, Stripe webhook, and the contact form are each rate-limited per source IP (sliding window). When fronted by the on-host nginx proxy, `X-Forwarded-For` is honoured so the limiter sees the real client

#### API tokens (`susi_pat_…`) and 2FA

API tokens are long-lived bearers for headless clients (CI, scripts) and **bypass interactive 2FA**. The trade-off is deliberate: requiring a TOTP seed alongside an API token in CI raises attack surface without raising the bar — anyone with access to the bearer would also have access to the seed.

Operational consequences:

- Treat each API token as equivalent to a password + 2FA. Store it in a secret manager, never check it into git.
- Tokens are SHA-256-hashed at rest and revocable from the dashboard. Rotate them on any suspected compromise and on every team-member departure.
- For day-to-day admin work in the browser, use a JWT login — TOTP is enforced on every admin write that uses a JWT principal.
- Limit API tokens to the smallest set of users that need them, and audit `/api/v1/auth/api-tokens/all` periodically (admin-only).

### Activate a license

```bash
curl -X POST http://localhost:3100/api/v1/activate \
  -H "Content-Type: application/json" \
  -d '{"license_key": "XXXXX-XXXXX-XXXXX-XXXXX", "machine_code": "a1b2c3...", "friendly_name": "Server-1"}'
```

Returns a `SignedLicense` JSON that can be saved to disk for offline verification. The response includes a `lease_expires` timestamp — the client must call activate or verify again before this time to renew the lease.

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
    "lease_duration_hours": 168,
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
    // Lease expired or in grace period — try again soon
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
  // Lease expired or in grace period — try again soon
}
```

Call `verify_and_refresh`/`checkLicenseAndRefresh` periodically (e.g. at startup and every few hours) to keep the lease alive. The server will renew the lease on each successful call.

## Lease System

Leases prevent customers from running more concurrent machines than they've paid for. Instead of permanent machine activations that require manual deactivation, each activation now has a time-limited lease that must be renewed periodically.

### How It Works

```
Customer activates on Machine A:
  → Server grants a 7-day lease
  → Client stores the signed license (includes lease_expires timestamp)
  → Client calls /activate or /verify periodically to renew

Customer wants to move to Machine B:
  → They stop running on Machine A
  → After 7 days, Machine A's lease expires and is cleaned up
  → Machine B can now activate (the seat is freed)

Customer tries to run on both:
  → Machine A has an active lease
  → Machine B tries to activate → "Machine limit reached"
  → Enforced automatically — no trust required
```

### Configuration

| Parameter | Default | Description |
|---|---|---|
| `--lease-duration` | `168` (7 days) | Lease duration in hours. `0` disables lease enforcement. |
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

Workspaces are the unit of grouping for everything customer-facing: licenses, releases, doc sets, and config revisions can all be scoped to a workspace. Each workspace has a `name`, `product`, optional `description`, a `created_by` user, and a member list with one of three roles:

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

## Releases

Upload signed binaries (installers, archives, etc.) and let licensed clients fetch them through an authenticated update channel. Releases can be tagged, pinned to a workspace, and gated by workspace membership.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/updates/releases` | License key | List releases the caller can download |
| `GET` | `/api/v1/updates/download/{tag}/{asset}` | License key, JWT, or `?ticket=` | Stream a release asset to the caller |
| `POST` | `/api/v1/updates/download-ticket` | License key or JWT | Mint a 60 s single-asset ticket for the download URL |
| `GET` | `/api/v1/releases` | JWT | List all releases (admin view) |
| `POST` | `/api/v1/releases` | JWT | Upload a new release (multipart, up to 500 MB) |
| `PUT` / `DELETE` | `/api/v1/releases/{tag}` | JWT | Update metadata / delete |
| `POST` | `/api/v1/releases/{tag}/move` | JWT | Re-assign to another workspace |
| `GET` | `/api/v1/workspaces/{id}/releases` | JWT | List releases scoped to a workspace |

When a binary upload creates a new release, the latest workspace doc set is **seeded forward** so that user-edited docs carry over automatically.

## Documentation Knowledge Base

The `/docs` page is a per-release documentation site with an in-browser editor (EasyMDE, vendored). Each release has its own collection of pages and assets, addressed by tag.

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

> **Editing rule:** never `PUT` a full page from outside the dashboard — fetch first, then send a targeted patch to `body_md`. Wholesale overwrites trash user edits.

## Public Website

A small CMS that powers the marketing site at `/site`. Pages are Markdown, edited through the dashboard, and served with per-page SEO meta. There's no release concept here — all content is hand-authored.

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
- Field length caps + minimum body length
- Sender email syntactically validated; outbound mail body is plain text

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/contact/config` | None | Returns whether the form is enabled and the public Turnstile site key |
| `POST` | `/api/v1/contact` | None | Submit a contact-form message |

## Deploying to AWS Lightsail

The project includes a Dockerfile, docker-compose.yml, and a deploy script for one-command deployment to an AWS Lightsail (or any EC2/VPS) instance.

### 1. Create a Lightsail instance

1. Go to [AWS Lightsail Console](https://lightsail.aws.amazon.com/)
2. Create an instance: **Linux/Unix** → **OS Only** → **Ubuntu 22.04 LTS** (or 24.04)
3. Choose a plan — **$5/mo (1 GB RAM, 1 vCPU)** is sufficient
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

On first run, the server creates an `admin` user with password `changeme`. Log in at `http://<YOUR_INSTANCE_IP>:3100/` and change the password immediately.

### 3a. Configure environment variables

The container reads optional integrations from `/opt/susi/.env`. The deploy script seeds it with `SUSI_ADMIN_KEY`; add the rest manually as needed:

```bash
# /opt/susi/.env  (chmod 600)
SUSI_ADMIN_KEY=<generated-by-deploy.sh>

# Magic-link / password-reset / outbound mail (Gmail SMTP relay shown)
SUSI_SMTP_HOST=smtp.gmail.com
SUSI_SMTP_PORT=587
SUSI_SMTP_USER=you@example.com
SUSI_SMTP_PASSWORD=<google-app-password>
SUSI_SMTP_FROM_NAME=Susi
SUSI_SMTP_FROM_ADDR=noreply@example.com
SUSI_MAGIC_LINK_BASE_URL=https://susi.example.com

# Shop (leave empty to disable checkout — product pages still render)
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
    "lease_duration_hours": 168,
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

Save the activation response as `license.json` — it contains the signed license with lease timestamp.

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

The containers bind to `127.0.0.1:3100` (prod) and `127.0.0.1:3101` (staging) —
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

`X-Forwarded-For` is required — the Rust login rate-limiter reads it to
identify the real client when the TCP peer is loopback (nginx). Without it,
every request looks like it's coming from `127.0.0.1` and the per-IP limit
becomes a per-box limit.

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
| Default login | `admin` / `changeme` (must change on first login) |
| Logs | `docker compose logs -f` in `/opt/susi` |
| Health check | `GET http://<IP>:3100/health` |

## Building

```bash
cargo build --workspace --release
```

Binaries are output to `target/release/`:
- `susi-admin` — CLI management tool
- `susi-server` — HTTP activation server
- `susi-helper` — end-user utility for fingerprinting and USB serial lookup

## Testing

```bash
cargo test --workspace
```

## Dependencies

Key dependencies:
- [`rsa`](https://crates.io/crates/rsa) — RSA key generation, signing, verification
- [`sha2`](https://crates.io/crates/sha2) — SHA-256 hashing
- [`aes-gcm`](https://crates.io/crates/aes-gcm) — AES-256-GCM encryption for USB tokens
- [`hkdf`](https://crates.io/crates/hkdf) — HKDF-SHA256 key derivation for USB tokens
- [`axum`](https://crates.io/crates/axum) — HTTP server with multipart support (susi_server only)
- [`tower-http`](https://crates.io/crates/tower-http) — CORS middleware (susi_server only)
- [`argon2`](https://crates.io/crates/argon2) — Argon2id password hashing (susi_server only)
- [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken) — JWT session tokens (susi_server only)
- [`totp-rs`](https://crates.io/crates/totp-rs) — TOTP 2FA (susi_server only)
- [`lettre`](https://crates.io/crates/lettre) — SMTP client for magic-link / order / contact email (susi_server only)
- [`hmac`](https://crates.io/crates/hmac) — Stripe webhook signature verification (susi_server only)
- [`printpdf`](https://crates.io/crates/printpdf) — paid-invoice PDF generation (susi_server only)
- [`ammonia`](https://crates.io/crates/ammonia) — HTML sanitizer for admin-authored content in customer email (susi_server only)
- [`rusqlite`](https://crates.io/crates/rusqlite) — SQLite storage (server/admin only, bundled)
- [`reqwest`](https://crates.io/crates/reqwest) — HTTP client for online refresh, Stripe API, Turnstile siteverify

The `susi_client` crate is intentionally lightweight — it only pulls in the crypto and HTTP dependencies needed for verification and the workspace/release/docs API client.

## License

MIT
