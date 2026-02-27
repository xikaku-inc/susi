# susi

*Susi* (Tagalog for "key") — a self-hosted software licensing system built in Rust. Generate, sign, and verify node-locked license files using RSA-SHA256 cryptography — no cloud dependency required.

## Features

- **RSA-SHA256 signed license files** — tamper-proof, offline-verifiable
- **Node-locked licenses** — bind licenses to specific machines via hardware fingerprint
- **Feature flags** — control which product features each license unlocks
- **Expiry dates or perpetual** — time-limited or never-expiring licenses
- **Machine limits** — control how many machines a single license can activate
- **Optional activation server** — HTTP server for online activation and management
- **Cross-platform** — Linux and Windows support
- **C++ client library** — drop-in header+source for C++ projects (OpenSSL-based)

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  susi_admin      │     │  susi_server      │     │  susi_client        │
│  (CLI tool)      │     │  (HTTP server)    │     │  (library)          │
│                  │     │                   │     │                     │
│  keygen          │     │  POST /activate   │     │  verify signature   │
│  create license  │     │  POST /verify     │     │  check expiry       │
│  export / list   │     │  POST /deactivate │     │  check machine      │
│  revoke          │     │  GET  /licenses   │     │  check features     │
└────────┬─────────┘     └────────┬──────────┘     └─────────────────────┘
         │                        │
         └────────┬───────────────┘
                  ▼
         ┌────────────────┐
         │  susi_core      │
         │  (shared lib)   │
         │                 │
         │  data models    │
         │  RSA sign/verify│
         │  HW fingerprint │
         │  SQLite storage │
         └─────────────────┘
```

| Crate | Type | Description |
|---|---|---|
| `susi_core` | Library | Shared types, RSA crypto, hardware fingerprinting, SQLite storage |
| `susi_client` | Library | Lightweight verification library to embed in your application |
| `susi_admin` | Binary | CLI tool for key generation, license creation, and management |
| `susi_server` | Binary | HTTP activation server with SQLite backend |
| `cpp/` | C++ Library | Standalone verification client for C++ applications |

## Quick Start

### 1. Generate a keypair

```bash
susi-admin keygen --output-dir ./keys/
```

This creates `private.pem` (keep secret) and `public.pem` (distribute with your application).

### 2. Create a license

```bash
# Time-limited license
susi-admin create \
  --customer "Acme Corp" \
  --product "MyApp" \
  --days 365 \
  --features "pro,analytics" \
  --max-machines 3

# Perpetual license
susi-admin create \
  --customer "Acme Corp" \
  --perpetual \
  --features "pro"
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
    LicenseStatus::Expired { expired_at } => {
        eprintln!("License expired on {}", expired_at.format("%Y-%m-%d"));
    }
    LicenseStatus::InvalidMachine { .. } => {
        eprintln!("License not valid for this machine");
    }
    LicenseStatus::InvalidSignature => {
        eprintln!("License file has been tampered with");
    }
    other => eprintln!("License error: {:?}", other),
}
```

### 5. Verify in your C++ application

The `cpp/` directory contains a standalone C++ client (`susi.h` + `susi.cpp`) that uses OpenSSL for verification. Add it to your CMake project:

```cmake
add_subdirectory(susi/cpp)
target_link_libraries(your_target PRIVATE susi)
```

Then use it:

```cpp
#include <susi.h>

SusiClient susi;

// Pass the "LicenseInfo" section of your config as JSON:
bool valid = susi.checkLicense(R"({"LicenseFile": "license.json"})");

if (valid) {
    if (susi.hasFeature("pro")) {
        // enable pro features
    }
}
```

Before building for production, paste your public key (from `susi-admin keygen`) into the `DEFAULT_PUBLIC_KEY` constant in `susi.cpp`. When the key is empty, license checks are skipped (development mode).

To use your own logging framework instead of `fprintf`, define `SUSI_LOG` before including `susi.cpp`:

```cpp
#define SUSI_LOG(fmt, ...) my_logger("susi", fmt, ##__VA_ARGS__)
```

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
  "machine_codes": ["a1b2c3d4..."]
}
```

For perpetual licenses, the `expires` field is `null`.

## Hardware Fingerprinting

Machine identity is computed from:
- **Network interfaces** — sorted MAC addresses (excluding loopback/virtual)
- **Hostname**

Combined and hashed with SHA-256 to produce a stable fingerprint. Print the current machine's fingerprint with:

```bash
susi-admin fingerprint
```

## Activation Server

For online license management, run the activation server:

```bash
susi-server \
  --private-key ./keys/private.pem \
  --db licenses.db \
  --listen 0.0.0.0:3100 \
  --admin-key "your-secret-admin-key"
```

### API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/activate` | Public | Activate a license on a machine |
| `POST` | `/api/v1/verify` | Public | Verify and download a signed license |
| `POST` | `/api/v1/deactivate` | Public | Remove a machine activation |
| `GET` | `/api/v1/licenses` | Admin | List all licenses |
| `GET` | `/health` | None | Health check |

Admin endpoints require `Authorization: Bearer <admin-key>` header.

### Activate a license

```bash
curl -X POST http://localhost:3100/api/v1/activate \
  -H "Content-Type: application/json" \
  -d '{"license_key": "XXXXX-XXXXX-XXXXX-XXXXX", "machine_code": "a1b2c3...", "friendly_name": "Server-1"}'
```

Returns a `SignedLicense` JSON that can be saved to disk for offline verification.

## Client Library with Online Refresh

The client library can optionally contact the server to refresh the license, falling back to the cached local file if the server is unreachable:

```rust
let client = LicenseClient::with_server(
    include_str!("public.pem"),
    "http://license.example.com/api/v1".to_string(),
).unwrap();

let status = client.verify_and_refresh(
    Path::new("license.json"),
    "XXXXX-XXXXX-XXXXX-XXXXX",
);
```

## Managing Licenses

```bash
# List all licenses
susi-admin list

# Revoke a license
susi-admin revoke --key "XXXXX-XXXXX-XXXXX-XXXXX"

# Deactivate a machine
susi-admin deactivate --key "XXXXX-XXXXX-XXXXX-XXXXX" --machine-code "a1b2c3..."
```

## Building

```bash
cargo build --workspace --release
```

Binaries are output to `target/release/`:
- `susi-admin` — CLI management tool
- `susi-server` — HTTP activation server

## Testing

```bash
cargo test --workspace
```

## Dependencies

Key dependencies:
- [`rsa`](https://crates.io/crates/rsa) — RSA key generation, signing, verification
- [`sha2`](https://crates.io/crates/sha2) — SHA-256 hashing
- [`axum`](https://crates.io/crates/axum) — HTTP server (susi_server only)
- [`rusqlite`](https://crates.io/crates/rusqlite) — SQLite storage (server/admin only, bundled)
- [`reqwest`](https://crates.io/crates/reqwest) — HTTP client for online refresh (susi_client only)

The `susi_client` crate is intentionally lightweight — it only pulls in the crypto and HTTP dependencies needed for verification.

## License

MIT
