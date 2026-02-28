# susi

*Susi* (Tagalog for "key") — a self-hosted software licensing system built in Rust. Generate, sign, and verify node-locked license files using RSA-SHA256 cryptography — no cloud dependency required.

## Features

- **RSA-SHA256 signed license files** — tamper-proof, offline-verifiable
- **Node-locked licenses** — bind licenses to specific machines via hardware fingerprint
- **Feature flags** — control which product features each license unlocks
- **Expiry dates or perpetual** — time-limited or never-expiring licenses
- **Machine limits** — control how many machines a single license can activate
- **Lease-based seat management** — time-limited activations that expire automatically, preventing unauthorized concurrent usage
- **Optional activation server** — HTTP server for online activation and management
- **Web dashboard** — browser-based management UI with multi-user authentication and 2FA
- **USB hardware tokens** — bind a license to a physical USB stick instead of a machine
- **Cross-platform** — Linux and Windows support
- **C++ client library** — drop-in header+source for C++ projects (OpenSSL-based)

## Architecture

```
┌──────────────────┐     ┌───────────────────┐     ┌─────────────────────┐
│  susi_admin      │     │  susi_server      │     │  susi_client        │
│  (CLI tool)      │     │  (HTTP server)    │     │  (library)          │
│                  │     │                   │     │                     │
│  keygen          │     │  POST /activate   │     │  verify signature   │
│  create license  │     │  POST /verify     │     │  check expiry       │
│  export / list   │     │  POST /deactivate │     │  check machine      │
│  export-token    │     │  GET  /licenses   │     │  check features     │
│  revoke          │     │                   │     │  check lease        │
│                  │     │                   │     │  verify USB token   │
└────────┬─────────┘     └────────┬──────────┘     └─────────────────────┘
         │                        │
         └────────┬───────────────┘
                  ▼
         ┌─────────────────┐
         │  susi_core      │
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
    if (susi.isInGracePeriod()) {
        // lease expired but still in grace period — trigger renewal
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
  "machine_codes": ["a1b2c3d4..."],
  "lease_expires": "2025-01-22T00:00:00Z"
}
```

- `expires` — `null` for perpetual licenses
- `lease_expires` — omitted when lease enforcement is disabled (`lease_duration = 0`). When present, the client must renew before this time or the license stops working (after the grace period).

## Hardware Fingerprinting

Machine identity is computed from:
- **Network interfaces** — sorted MAC addresses (excluding loopback/virtual)
- **Hostname**

Combined and hashed with SHA-256 to produce a stable fingerprint. Print the current machine's fingerprint with:

```bash
susi-admin fingerprint
```

## USB Hardware Tokens

Instead of binding a license to a specific machine, you can bind it to a physical USB stick. The license file is stored on the USB drive, encrypted with a key derived from the device's hardware serial number. Plug the stick into any machine and the software is licensed — remove it and it's not. Copying the file to a different USB stick fails because the serial number won't match.

### How it works

1. The admin exports a license to a USB stick via `susi-admin export-token`
2. The signed license is encrypted with `AES-256-GCM` using a key derived from `HKDF-SHA256(usb_serial_number)`
3. The encrypted blob is written to `<usb_mount>/.susi/license.bin`
4. At runtime, the client scans connected USB drives for this file, decrypts it using the device's serial, and verifies the RSA signature as usual

Token-bound licenses have empty `machine_codes`, so they are not tied to any specific machine.

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
    println!("Licensed via USB token");
    if status.has_feature("pro") {
        // enable pro features
    }
}
```

### Verify from a USB token (C++)

```cpp
SusiClient susi;
if (susi.checkLicenseToken()) {
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

## Activation Server

For online license management, run the activation server:

```bash
susi-server \
  --private-key ./keys/private.pem \
  --db licenses.db \
  --listen 0.0.0.0:3100
```

On first run, the server creates an `admin` user with password `changeme`. Open the dashboard in your browser to log in and manage users.

### API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/activate` | Public | Activate a license on a machine (grants/renews lease) |
| `POST` | `/api/v1/verify` | Public | Verify a license and renew its lease (heartbeat) |
| `POST` | `/api/v1/deactivate` | Public | Remove a machine activation |
| `GET` | `/api/v1/licenses` | JWT | List all licenses |
| `POST` | `/api/v1/licenses` | JWT | Create a new license |
| `GET` | `/api/v1/licenses/{key}` | JWT | Get a specific license |
| `POST` | `/api/v1/licenses/{key}/revoke` | JWT | Revoke a license |
| `POST` | `/api/v1/licenses/{key}/export` | JWT | Export a signed license file |
| `DELETE` | `/api/v1/licenses/{key}/machines/{code}` | JWT | Deactivate a machine |
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
| `GET` | `/api/v1/auth/status` | JWT | Check session status, get username and 2FA/password state |
| `POST` | `/api/v1/auth/change-password` | JWT | Change own password |
| `POST` | `/api/v1/auth/setup-2fa` | JWT | Generate TOTP secret and QR code |
| `POST` | `/api/v1/auth/verify-2fa` | JWT | Verify TOTP code to enable 2FA |
| `POST` | `/api/v1/auth/disable-2fa` | JWT | Disable 2FA (requires valid TOTP code) |
| `GET` | `/api/v1/auth/users` | JWT | List all users |
| `POST` | `/api/v1/auth/users` | JWT | Create a new user |
| `DELETE` | `/api/v1/auth/users/{username}` | JWT | Delete a user (cannot delete self or last user) |
| `POST` | `/api/v1/auth/users/{username}/reset-password` | JWT | Reset a user's password (forces change on next login) |

#### Security

- Passwords are hashed with **Argon2id**
- Sessions use **HS256 JWT tokens** with 24-hour expiry
- 2FA uses **TOTP** (compatible with Google Authenticator, Authy, etc.)
- New users and password resets force a password change on next login

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

The client library can optionally contact the server to refresh the license and renew the lease, falling back to the cached local file if the server is unreachable:

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

Call `verify_and_refresh` periodically (e.g. at startup and every few hours) to keep the lease alive. The server will renew the lease on each successful call.

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
./deploy.sh ubuntu@<YOUR_INSTANCE_IP> ~/.ssh/LightsailDefaultKey-*.pem
```

The script will:
1. Create `/opt/susi` on the server and sync project files
2. Generate a **4096-bit RSA keypair** if none exists
3. Build the Docker image and start the container

On first run, the server creates an `admin` user with password `changeme`. Log in at `http://<YOUR_INSTANCE_IP>:3100/` and change the password immediately.

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

### 8. Optional: HTTPS with a custom domain

1. In Lightsail → **Networking** → attach a **static IP** to your instance
2. Point a DNS record (e.g. `license.yourdomain.com`) to that static IP
3. Set up nginx as a reverse proxy with Let's Encrypt:

```bash
sudo apt-get install -y nginx certbot python3-certbot-nginx

sudo tee /etc/nginx/sites-available/susi <<'EOF'
server {
    listen 80;
    server_name license.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:3100;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/susi /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d license.yourdomain.com
```

Then open port **443** and close port **3100** from public access in your Lightsail firewall.

### Quick reference

| Item | Location |
|---|---|
| Server binary | Docker container `susi-server` |
| Private key | Docker volume `susi-data` → `/data/private.pem` |
| Public key | Docker volume `susi-data` → `/data/public.pem` |
| Database | Docker volume `susi-data` → `/data/licenses.db` |
| Dashboard | `http://<IP>:3100/` |
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
- [`axum`](https://crates.io/crates/axum) — HTTP server (susi_server only)
- [`argon2`](https://crates.io/crates/argon2) — Argon2id password hashing (susi_server only)
- [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken) — JWT session tokens (susi_server only)
- [`totp-rs`](https://crates.io/crates/totp-rs) — TOTP 2FA (susi_server only)
- [`rusqlite`](https://crates.io/crates/rusqlite) — SQLite storage (server/admin only, bundled)
- [`reqwest`](https://crates.io/crates/reqwest) — HTTP client for online refresh (susi_client only)

The `susi_client` crate is intentionally lightweight — it only pulls in the crypto and HTTP dependencies needed for verification.

## License

MIT
