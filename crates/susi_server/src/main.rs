use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use argon2::{self, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use clap::Parser;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use susi_core::crypto::{private_key_from_pem, sign_license};
use susi_core::db::LicenseDb;
use susi_core::{License, DEFAULT_LEASE_DURATION_HOURS, DEFAULT_LEASE_GRACE_HOURS};
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
#[derive(Parser)]
#[command(name = "susi-server", about = "Susi License Server")]
struct Cli {
    /// Path to private key PEM file
    #[arg(long, default_value = "private.pem")]
    private_key: String,

    /// Path to SQLite database
    #[arg(long, default_value = "licenses.db")]
    db: String,

    /// Listen address
    #[arg(long, default_value = "0.0.0.0:3100")]
    listen: String,

    /// Directory for persistent data (keys, database, release assets)
    #[arg(long, default_value = "/data")]
    data_dir: String,
}

struct AppState {
    db: Mutex<LicenseDb>,
    private_key: RsaPrivateKey,
    jwt_secret: [u8; 32],
    data_dir: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iat: i64,
    exp: i64,
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ActivateRequest {
    license_key: String,
    machine_code: String,
    #[serde(default)]
    friendly_name: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    license_key: String,
    machine_code: String,
}

#[derive(Deserialize)]
struct DeactivateRequest {
    license_key: String,
    machine_code: String,
}

#[derive(Deserialize)]
struct CreateLicenseRequest {
    #[serde(default = "default_product")]
    product: String,
    customer: String,
    /// Expiry date as "YYYY-MM-DD", or null/missing for perpetual
    #[serde(default)]
    expires: Option<String>,
    /// Days until expiry (alternative to `expires`)
    #[serde(default)]
    days: Option<i64>,
    /// If true, license never expires
    #[serde(default)]
    perpetual: bool,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default = "default_max_machines")]
    max_machines: u32,
    /// Lease duration in hours. 0 = no lease enforcement. Default: 168 (7 days).
    #[serde(default = "default_lease_duration")]
    lease_duration_hours: u32,
    /// Grace period in hours after lease expires. Default: 24.
    #[serde(default = "default_lease_grace")]
    lease_grace_hours: u32,
}

fn default_product() -> String {
    "FusionHub".to_string()
}
fn default_max_machines() -> u32 {
    1
}
fn default_lease_duration() -> u32 {
    DEFAULT_LEASE_DURATION_HOURS
}
fn default_lease_grace() -> u32 {
    DEFAULT_LEASE_GRACE_HOURS
}

#[derive(Deserialize)]
struct UpdateLicenseRequest {
    #[serde(default)]
    customer: Option<String>,
    #[serde(default)]
    product: Option<String>,
    /// "YYYY-MM-DD", "perpetual", or null to leave unchanged
    #[serde(default)]
    expires: Option<String>,
    #[serde(default)]
    features: Option<Vec<String>>,
    #[serde(default)]
    max_machines: Option<u32>,
}

#[derive(Deserialize)]
struct ExportRequest {
    machine_code: String,
    #[serde(default)]
    friendly_name: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct LicenseSummary {
    id: String,
    license_key: String,
    product: String,
    customer: String,
    created: String,
    expires: String,
    features: Vec<String>,
    max_machines: u32,
    lease_duration_hours: u32,
    lease_grace_hours: u32,
    active_machine_count: usize,
    total_machine_count: usize,
    machines: Vec<MachineSummary>,
    revoked: bool,
}

#[derive(Serialize)]
struct MachineSummary {
    machine_code: String,
    friendly_name: String,
    activated_at: String,
    lease_expires_at: Option<String>,
    lease_active: bool,
}

fn license_to_summary(lic: &License) -> LicenseSummary {
    let now = Utc::now();
    LicenseSummary {
        id: lic.id.clone(),
        license_key: lic.license_key.clone(),
        product: lic.product.clone(),
        customer: lic.customer.clone(),
        created: lic.created.to_rfc3339(),
        expires: lic
            .expires
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "perpetual".to_string()),
        features: lic.features.clone(),
        max_machines: lic.max_machines,
        lease_duration_hours: lic.lease_duration_hours,
        lease_grace_hours: lic.lease_grace_hours,
        active_machine_count: lic.active_machine_count(),
        total_machine_count: lic.machines.len(),
        machines: lic
            .machines
            .iter()
            .map(|m| MachineSummary {
                machine_code: m.machine_code.clone(),
                friendly_name: m.friendly_name.clone(),
                activated_at: m.activated_at.to_rfc3339(),
                lease_expires_at: m.lease_expires_at.map(|dt| dt.to_rfc3339()),
                lease_active: m.is_lease_active(now),
            })
            .collect(),
        revoked: lic.revoked,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn error_response(status: StatusCode, msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: msg.to_string(),
        }),
    )
}

fn create_jwt(secret: &[u8; 32], username: &str) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: username.into(),
        iat: now,
        exp: now + 86400, // 24h
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
}

fn validate_jwt(
    headers: &HeaderMap,
    jwt_secret: &[u8; 32],
) -> Result<Claims, (StatusCode, Json<ErrorResponse>)> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth.strip_prefix("Bearer ").unwrap_or("");
    if token.is_empty() {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Missing authentication token"));
    }
    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    decode::<Claims>(token, &DecodingKey::from_secret(jwt_secret), &validation)
        .map(|data| data.claims)
        .map_err(|e| {
            let msg = match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => "Token expired",
                _ => "Invalid token",
            };
            error_response(StatusCode::UNAUTHORIZED, msg)
        })
}

fn require_password_changed(
    state: &AppState,
    username: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();
    if db.user_must_change_password(username).unwrap_or(true) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "Password change required before accessing admin features",
        ));
    }
    Ok(())
}

fn require_admin(
    state: &AppState,
    username: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();
    let role = db.get_user_role(username).unwrap_or_default();
    if role != "admin" {
        return Err(error_response(StatusCode::FORBIDDEN, "Admin access required"));
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
}

fn verify_password(
    password: &str,
    hash: &str,
) -> Result<bool, (StatusCode, Json<ErrorResponse>)> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

// ---------------------------------------------------------------------------
// Auth endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    totp_code: Option<String>,
}

async fn handle_login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();
    let hash = db
        .get_user_password_hash(&req.username)
        .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "Invalid credentials"))?;

    if !verify_password(&req.password, &hash)? {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }

    let totp_enabled = db.user_totp_enabled(&req.username).unwrap_or(false);
    if totp_enabled {
        match &req.totp_code {
            None => {
                return Ok(Json(serde_json::json!({
                    "error": "TOTP code required",
                    "totp_required": true
                })));
            }
            Some(code) => {
                let secret_b32 = db
                    .get_user_totp_secret(&req.username)
                    .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
                    .ok_or_else(|| error_response(StatusCode::INTERNAL_SERVER_ERROR, "TOTP secret missing"))?;
                let secret_bytes = Secret::Encoded(secret_b32)
                    .to_bytes()
                    .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
                let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes,
                    Some("Susi License Server".into()), req.username.clone().into())
                    .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
                if !totp.check_current(code).unwrap_or(false) {
                    return Err(error_response(StatusCode::UNAUTHORIZED, "Invalid TOTP code"));
                }
            }
        }
    }

    let must_change = db.user_must_change_password(&req.username).unwrap_or(false);
    let role = db.get_user_role(&req.username).unwrap_or_else(|_| "user".into());
    drop(db);

    let token = create_jwt(&state.jwt_secret, &req.username)?;
    Ok(Json(serde_json::json!({
        "token": token,
        "must_change_password": must_change,
        "totp_enabled": totp_enabled,
        "role": role
    })))
}

async fn handle_auth_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    let db = state.db.lock().unwrap();
    let must_change = db.user_must_change_password(&claims.sub).unwrap_or(false);
    let totp_enabled = db.user_totp_enabled(&claims.sub).unwrap_or(false);
    let role = db.get_user_role(&claims.sub).unwrap_or_else(|_| "user".into());
    Ok(Json(serde_json::json!({
        "must_change_password": must_change,
        "totp_enabled": totp_enabled,
        "username": claims.sub,
        "role": role
    })))
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

async fn handle_change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;

    if req.new_password.len() < 8 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Password must be at least 8 characters"));
    }

    let db = state.db.lock().unwrap();
    let hash = db
        .get_user_password_hash(&claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    if !verify_password(&req.current_password, &hash)? {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Current password is incorrect"));
    }

    let new_hash = hash_password(&req.new_password)?;
    db.update_user_password(&claims.sub, &new_hash)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

async fn handle_setup_2fa(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;

    let secret_bytes: [u8; 20] = rand::thread_rng().gen();
    let secret = Secret::Raw(secret_bytes.to_vec());
    let secret_b32 = secret.to_encoded().to_string();

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes.to_vec(),
        Some("Susi License Server".into()), claims.sub.clone().into())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let qr_code = totp
        .get_qr_base64()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let db = state.db.lock().unwrap();
    db.set_user_totp_secret(&claims.sub, &secret_b32)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({
        "secret": secret_b32,
        "qr_code": format!("data:image/png;base64,{}", qr_code),
        "otpauth_uri": totp.get_url()
    })))
}

#[derive(Deserialize)]
struct TotpCodeRequest {
    totp_code: String,
}

async fn handle_verify_2fa(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TotpCodeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;

    let db = state.db.lock().unwrap();
    let secret_b32 = db
        .get_user_totp_secret(&claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "No 2FA setup in progress"))?;

    let secret = Secret::Encoded(secret_b32)
        .to_bytes()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret,
        Some("Susi License Server".into()), claims.sub.clone().into())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    if !totp.check_current(&req.totp_code).unwrap_or(false) {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid TOTP code"));
    }

    db.enable_user_totp(&claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

async fn handle_disable_2fa(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TotpCodeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;

    let db = state.db.lock().unwrap();
    let secret_b32 = db
        .get_user_totp_secret(&claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "2FA is not enabled"))?;

    let secret = Secret::Encoded(secret_b32)
        .to_bytes()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret,
        Some("Susi License Server".into()), claims.sub.clone().into())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    if !totp.check_current(&req.totp_code).unwrap_or(false) {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Invalid TOTP code"));
    }

    db.disable_user_totp(&claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Public endpoints (client-facing)
// ---------------------------------------------------------------------------

fn compute_lease_expires(license: &License) -> Option<DateTime<Utc>> {
    if license.lease_duration_hours == 0 {
        None
    } else {
        Some(Utc::now() + Duration::hours(license.lease_duration_hours as i64))
    }
}

async fn handle_activate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ActivateRequest>,
) -> Result<Json<susi_core::SignedLicense>, (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();

    let license = db
        .get_license_by_key(&req.license_key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    if license.revoked {
        return Err(error_response(StatusCode::FORBIDDEN, "License has been revoked"));
    }

    if license.is_expired() {
        return Err(error_response(StatusCode::FORBIDDEN, "License has expired"));
    }

    if !license.is_machine_activated(&req.machine_code) && !license.can_add_machine() {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            &format!("Machine limit reached (max {})", license.max_machines),
        ));
    }

    let name = if req.friendly_name.is_empty() {
        "Unknown".to_string()
    } else {
        req.friendly_name.clone()
    };

    let lease_expires = compute_lease_expires(&license);
    db.add_machine_activation(&license.id, &req.machine_code, &name, lease_expires)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let license = db
        .get_license_by_key(&req.license_key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .unwrap();

    let payload = license.to_payload_for(Some(&req.machine_code));
    let signed = sign_license(&state.private_key, &payload)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(signed))
}

async fn handle_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<susi_core::SignedLicense>, (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();

    let license = db
        .get_license_by_key(&req.license_key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    if license.revoked {
        return Err(error_response(StatusCode::FORBIDDEN, "License has been revoked"));
    }

    if license.is_expired() {
        return Err(error_response(StatusCode::FORBIDDEN, "License has expired"));
    }

    if !license.is_machine_activated(&req.machine_code) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "Machine not authorized for this license",
        ));
    }

    // Renew the lease on verify (acts as heartbeat)
    if license.uses_leases() {
        let lease_expires = compute_lease_expires(&license);
        let activation = license.machines.iter().find(|m| m.machine_code == req.machine_code);
        let name = activation.map(|a| a.friendly_name.as_str()).unwrap_or("Unknown");
        db.add_machine_activation(&license.id, &req.machine_code, name, lease_expires)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }

    // Re-fetch to get updated lease
    let license = db
        .get_license_by_key(&req.license_key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .unwrap();

    let payload = license.to_payload_for(Some(&req.machine_code));
    let signed = sign_license(&state.private_key, &payload)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(signed))
}

async fn handle_deactivate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeactivateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();

    let license = db
        .get_license_by_key(&req.license_key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    db.remove_machine_activation(&license.id, &req.machine_code)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "deactivated" })))
}

#[derive(Serialize)]
struct PublicLicenseStatus {
    license_key: String,
    product: String,
    customer: String,
    expires: String,
    features: Vec<String>,
    max_machines: u32,
    active_machines: Vec<PublicMachineSummary>,
    revoked: bool,
}

#[derive(Serialize)]
struct PublicMachineSummary {
    machine_code: String,
    friendly_name: String,
    lease_expires_at: Option<String>,
    lease_active: bool,
}

async fn handle_license_status(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<Json<PublicLicenseStatus>, (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();

    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    let now = Utc::now();
    Ok(Json(PublicLicenseStatus {
        license_key: license.license_key.clone(),
        product: license.product.clone(),
        customer: license.customer.clone(),
        expires: license
            .expires
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "perpetual".to_string()),
        features: license.features.clone(),
        max_machines: license.max_machines,
        active_machines: license
            .machines
            .iter()
            .filter(|m| m.is_lease_active(now))
            .map(|m| PublicMachineSummary {
                machine_code: m.machine_code.clone(),
                friendly_name: m.friendly_name.clone(),
                lease_expires_at: m.lease_expires_at.map(|dt| dt.to_rfc3339()),
                lease_active: m.is_lease_active(now),
            })
            .collect(),
        revoked: license.revoked,
    }))
}

// ---------------------------------------------------------------------------
// Admin endpoints
// ---------------------------------------------------------------------------

async fn handle_list_licenses(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<LicenseSummary>>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    let licenses = db
        .list_licenses()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let summaries: Vec<LicenseSummary> = licenses.iter().map(license_to_summary).collect();
    Ok(Json(summaries))
}

async fn handle_get_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<LicenseSummary>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    Ok(Json(license_to_summary(&license)))
}

async fn handle_create_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateLicenseRequest>,
) -> Result<(StatusCode, Json<LicenseSummary>), (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let expires_dt = if req.perpetual {
        None
    } else {
        Some(match (req.expires, req.days) {
            (Some(date_str), _) => {
                let date = NaiveDate::parse_from_str(&date_str, "%Y-%m-%d")
                    .map_err(|_| error_response(StatusCode::BAD_REQUEST, &format!("Invalid date format: {}. Use YYYY-MM-DD.", date_str)))?;
                date.and_hms_opt(23, 59, 59)
                    .unwrap()
                    .and_utc()
            }
            (_, Some(d)) => Utc::now() + Duration::days(d),
            _ => Utc::now() + Duration::days(365),
        })
    };

    let mut license = License::new(
        req.product,
        req.customer,
        expires_dt,
        req.features,
        req.max_machines,
    );
    license.lease_duration_hours = req.lease_duration_hours;
    license.lease_grace_hours = req.lease_grace_hours;

    let db = state.db.lock().unwrap();
    db.insert_license(&license)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok((StatusCode::CREATED, Json(license_to_summary(&license))))
}

async fn handle_revoke_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    let revoked = db
        .revoke_license(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    if !revoked {
        return Err(error_response(StatusCode::NOT_FOUND, "License key not found"));
    }

    Ok(Json(serde_json::json!({ "status": "revoked" })))
}

async fn handle_delete_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    let deleted = db
        .delete_license(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    if !deleted {
        return Err(error_response(StatusCode::NOT_FOUND, "License key not found"));
    }

    Ok(Json(serde_json::json!({ "status": "deleted" })))
}

async fn handle_update_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(req): Json<UpdateLicenseRequest>,
) -> Result<Json<LicenseSummary>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    let customer = req.customer.as_deref().unwrap_or(&license.customer);
    let product = req.product.as_deref().unwrap_or(&license.product);
    let features = req.features.as_deref().unwrap_or(&license.features);
    let max_machines = req.max_machines.unwrap_or(license.max_machines);

    let expires_rfc = if let Some(ref exp) = req.expires {
        if exp == "perpetual" {
            None
        } else {
            let date = NaiveDate::parse_from_str(exp, "%Y-%m-%d")
                .map_err(|_| error_response(StatusCode::BAD_REQUEST, &format!("Invalid date: {}. Use YYYY-MM-DD.", exp)))?;
            Some(date.and_hms_opt(23, 59, 59).unwrap().and_utc().to_rfc3339())
        }
    } else {
        license.expires.map(|dt| dt.to_rfc3339())
    };

    db.update_license(&key, customer, product, expires_rfc.as_deref(), features, max_machines)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let updated = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License not found after update"))?;

    Ok(Json(license_to_summary(&updated)))
}

async fn handle_export_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(req): Json<ExportRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    if license.revoked {
        return Err(error_response(StatusCode::FORBIDDEN, "License has been revoked"));
    }

    if license.is_expired() {
        return Err(error_response(StatusCode::FORBIDDEN, "License has expired"));
    }

    if !license.is_machine_activated(&req.machine_code) && !license.can_add_machine() {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            &format!("Machine limit reached (max {})", license.max_machines),
        ));
    }

    let name = if req.friendly_name.is_empty() {
        "Unknown".to_string()
    } else {
        req.friendly_name.clone()
    };

    let lease_expires = compute_lease_expires(&license);
    db.add_machine_activation(&license.id, &req.machine_code, &name, lease_expires)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    // Re-fetch with the activation
    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .unwrap();

    let payload = license.to_payload_for(Some(&req.machine_code));
    let signed = sign_license(&state.private_key, &payload)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let json = serde_json::to_string_pretty(&signed)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"license.json\"",
            ),
        ],
        json,
    ))
}

async fn handle_deactivate_machine(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((key, machine_code)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    db.remove_machine_activation(&license.id, &machine_code)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "deactivated" })))
}

// ---------------------------------------------------------------------------
// User management endpoints
// ---------------------------------------------------------------------------

async fn handle_list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<susi_core::db::UserInfo>>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;
    let db = state.db.lock().unwrap();
    let users = db
        .list_users()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(users))
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    #[serde(default = "default_user_role")]
    role: String,
}

fn default_user_role() -> String {
    "user".to_string()
}

async fn handle_create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let username = req.username.trim();
    if username.is_empty() || username.len() > 64 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Username must be 1-64 characters"));
    }
    if req.password.len() < 8 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Password must be at least 8 characters"));
    }
    if !matches!(req.role.as_str(), "admin" | "user") {
        return Err(error_response(StatusCode::BAD_REQUEST, "Role must be admin or user"));
    }

    let pw_hash = hash_password(&req.password)?;
    let db = state.db.lock().unwrap();
    db.create_user(username, &pw_hash, &req.role)
        .map_err(|e| error_response(StatusCode::CONFLICT, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK", "username": username, "role": req.role })))
}

async fn handle_delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    if claims.sub == username {
        return Err(error_response(StatusCode::BAD_REQUEST, "Cannot delete your own account"));
    }

    let db = state.db.lock().unwrap();
    db.delete_user(&username)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

#[derive(Deserialize)]
struct RenameUserRequest {
    new_username: String,
}

async fn handle_rename_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(req): Json<RenameUserRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let new = req.new_username.trim().to_string();
    if new.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Username cannot be empty"));
    }
    if new == username {
        return Err(error_response(StatusCode::BAD_REQUEST, "New username is the same"));
    }

    let db = state.db.lock().unwrap();
    if db.user_exists(&new).unwrap_or(false) {
        return Err(error_response(StatusCode::CONFLICT, "Username already taken"));
    }
    db.rename_user(&username, &new)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

#[derive(Deserialize)]
struct ResetPasswordRequest {
    new_password: String,
}

async fn handle_reset_user_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    if req.new_password.len() < 8 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Password must be at least 8 characters"));
    }

    let pw_hash = hash_password(&req.new_password)?;
    let db = state.db.lock().unwrap();
    db.reset_user_password(&username, &pw_hash)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Release endpoints
// ---------------------------------------------------------------------------

fn validate_license_key(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let key = headers
        .get("x-license-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if key.is_empty() {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Missing X-License-Key header"));
    }

    let db = state.db.lock().unwrap();
    let license = db
        .get_license_by_key(key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "Invalid license key"))?;

    if license.revoked {
        return Err(error_response(StatusCode::FORBIDDEN, "License has been revoked"));
    }
    if license.is_expired() {
        return Err(error_response(StatusCode::FORBIDDEN, "License has expired"));
    }

    Ok(())
}

fn releases_dir(state: &AppState) -> std::path::PathBuf {
    std::path::Path::new(&state.data_dir).join("releases")
}

/// List releases — available to licensed clients or authenticated users
async fn handle_get_releases(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // Accept either license key or bearer token
    if validate_license_key(&state, &headers).is_err() {
        validate_jwt(&headers, &state.jwt_secret)?;
    }

    let db = state.db.lock().unwrap();
    let rows = db.list_releases()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let mut releases = Vec::new();
    for (id, tag, name, body, prerelease, created_at, _workspace_id) in &rows {
        let assets = db.get_release_assets(*id).unwrap_or_default();
        releases.push(serde_json::json!({
            "tag": tag,
            "name": name,
            "body": body,
            "published_at": created_at,
            "prerelease": prerelease,
            "assets": assets.iter().map(|(name, size)| serde_json::json!({
                "name": name,
                "size": size,
            })).collect::<Vec<_>>(),
        }));
    }

    Ok(Json(serde_json::json!({ "releases": releases })))
}

/// Download a release asset — available to licensed clients or logged-in users
async fn handle_download_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, asset_name)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Allow either license key or JWT auth
    let license_ok = validate_license_key(&state, &headers).is_ok();
    let jwt_ok = validate_jwt(&headers, &state.jwt_secret).is_ok();
    if !license_ok && !jwt_ok {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Authentication required"));
    }

    let file_path = releases_dir(&state).join(&tag).join(&asset_name);
    if !file_path.exists() {
        return Err(error_response(StatusCode::NOT_FOUND, "Asset not found"));
    }

    let bytes = std::fs::read(&file_path)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Read error: {}", e)))?;

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::CONTENT_TYPE, "application/octet-stream".parse().unwrap());
    resp_headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}\"", asset_name).parse().unwrap(),
    );
    resp_headers.insert(header::CONTENT_LENGTH, bytes.len().into());

    Ok((resp_headers, bytes))
}

/// List releases — admin view (JWT)
async fn handle_list_releases_admin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    let rows = db.list_releases()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let mut releases = Vec::new();
    for (id, tag, name, body, prerelease, created_at, workspace_id) in &rows {
        let assets = db.get_release_assets(*id).unwrap_or_default();
        releases.push(serde_json::json!({
            "tag": tag,
            "name": name,
            "body": body,
            "published_at": created_at,
            "prerelease": prerelease,
            "workspace_id": workspace_id,
            "assets": assets.iter().map(|(name, size)| serde_json::json!({
                "name": name,
                "size": size,
            })).collect::<Vec<_>>(),
        }));
    }

    Ok(Json(serde_json::json!({ "releases": releases })))
}

/// Upload a new release — admin only (JWT)
async fn handle_upload_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let mut tag = String::new();
    let mut name = String::new();
    let mut body = String::new();
    let mut prerelease = false;
    let mut workspace_id: Option<String> = None;
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();

    while let Some(field) = multipart.next_field().await
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("Multipart error: {}", e)))?
    {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "tag" => {
                tag = field.text().await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
            }
            "name" => {
                name = field.text().await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
            }
            "body" => {
                body = field.text().await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
            }
            "prerelease" => {
                let val = field.text().await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
                prerelease = val == "true" || val == "1";
            }
            "workspace_id" => {
                let val = field.text().await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
                if !val.is_empty() {
                    workspace_id = Some(val);
                }
            }
            "file" => {
                let file_name = field.file_name().unwrap_or("unknown").to_string();
                let data = field.bytes().await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("File read error: {}", e)))?;
                files.push((file_name, data.to_vec()));
            }
            _ => {}
        }
    }

    if tag.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Missing 'tag' field"));
    }
    if files.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "No files uploaded"));
    }

    // Save to database
    let release_id = {
        let db = state.db.lock().unwrap();
        if db.get_release_by_tag(&tag)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .is_some()
        {
            return Err(error_response(StatusCode::CONFLICT, &format!("Release {} already exists", tag)));
        }
        db.insert_release(&tag, &name, &body, prerelease, workspace_id.as_deref())
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };

    // Save files to disk
    let tag_dir = releases_dir(&state).join(&tag);
    std::fs::create_dir_all(&tag_dir)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Cannot create dir: {}", e)))?;

    let mut asset_names = Vec::new();
    for (file_name, data) in &files {
        let file_path = tag_dir.join(file_name);
        std::fs::write(&file_path, data)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Write error: {}", e)))?;

        let db = state.db.lock().unwrap();
        db.add_release_asset(release_id, file_name, data.len() as u64)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        asset_names.push(file_name.clone());
    }

    log::info!("Release {} created with assets: {}", tag, asset_names.join(", "));

    Ok(Json(serde_json::json!({
        "status": "OK",
        "tag": tag,
        "assets": asset_names,
    })))
}

/// Delete a release — admin only (JWT)
async fn handle_delete_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tag): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    if !db.delete_release(&tag)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    {
        return Err(error_response(StatusCode::NOT_FOUND, "Release not found"));
    }
    drop(db);

    // Remove files from disk
    let tag_dir = releases_dir(&state).join(&tag);
    let _ = std::fs::remove_dir_all(&tag_dir);

    log::info!("Release {} deleted", tag);

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Workspace endpoints (JWT-protected)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateWorkspaceRequest {
    name: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct UpdateWorkspaceRequest {
    name: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct AddMemberRequest {
    username: String,
    #[serde(default = "default_member_role")]
    role: String,
}

fn default_member_role() -> String {
    "viewer".to_string()
}

#[derive(Deserialize)]
struct PushConfigRequest {
    config_json: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct UpdateConfigRequest {
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    config_json: Option<String>,
}

async fn handle_create_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateWorkspaceRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    if req.name.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Workspace name is required"));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let db = state.db.lock().unwrap();
    db.create_workspace(&id, &req.name, &req.product, &req.description, &claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    log::info!("Workspace '{}' ({}) created by {}", req.name, id, claims.sub);

    Ok((StatusCode::CREATED, Json(serde_json::json!({
        "id": id,
        "name": req.name,
        "product": req.product,
        "description": req.description,
        "created_by": claims.sub,
    }))))
}

async fn handle_list_workspaces(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    let rows = db.list_workspaces_for_user(&claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let workspaces: Vec<_> = rows.iter().map(|(id, name, product, desc, created_by, created_at, updated_at, role)| {
        serde_json::json!({
            "id": id,
            "name": name,
            "product": product,
            "description": desc,
            "created_by": created_by,
            "created_at": created_at,
            "updated_at": updated_at,
            "role": role,
        })
    }).collect();

    Ok(Json(serde_json::json!({ "workspaces": workspaces })))
}

async fn handle_get_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    let role = db.get_workspace_member_role(&id, &claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let ws = db.get_workspace(&id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Workspace not found"))?;

    let members = db.list_workspace_members(&id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({
        "id": ws.0,
        "name": ws.1,
        "product": ws.2,
        "description": ws.3,
        "created_by": ws.4,
        "created_at": ws.5,
        "updated_at": ws.6,
        "role": role,
        "members": members.iter().map(|(u, r, a)| serde_json::json!({
            "username": u, "role": r, "added_at": a,
        })).collect::<Vec<_>>(),
    })))
}

async fn handle_update_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UpdateWorkspaceRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    let role = db.get_workspace_member_role(&id, &claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    if role != "owner" && role != "editor" {
        return Err(error_response(StatusCode::FORBIDDEN, "Insufficient permissions"));
    }

    db.update_workspace(&id, &req.name, &req.product, &req.description)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

async fn handle_delete_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    db.delete_workspace(&id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    log::info!("Workspace {} deleted by {}", id, claims.sub);
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Workspace member endpoints
// ---------------------------------------------------------------------------

async fn handle_add_workspace_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();

    if !matches!(req.role.as_str(), "owner" | "editor" | "viewer") {
        return Err(error_response(StatusCode::BAD_REQUEST, "Role must be owner, editor, or viewer"));
    }

    if !db.user_exists(&req.username).unwrap_or(false) {
        return Err(error_response(StatusCode::NOT_FOUND, "User does not exist"));
    }

    db.add_workspace_member(&workspace_id, &req.username, &req.role)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

async fn handle_remove_workspace_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, username)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;
    require_admin(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    db.remove_workspace_member(&workspace_id, &username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Config revision endpoints
// ---------------------------------------------------------------------------

async fn handle_push_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(req): Json<PushConfigRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    let role = db.get_workspace_member_role(&workspace_id, &claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    if role == "viewer" {
        return Err(error_response(StatusCode::FORBIDDEN, "Viewers cannot push configs"));
    }

    // Validate JSON
    serde_json::from_str::<serde_json::Value>(&req.config_json)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e)))?;

    let id = db.push_config_revision(&workspace_id, &req.config_json, &req.name, &req.description, &claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok((StatusCode::CREATED, Json(serde_json::json!({
        "id": id,
        "workspace_id": workspace_id,
    }))))
}

async fn handle_list_configs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    db.get_workspace_member_role(&workspace_id, &claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let rows = db.list_config_revisions(&workspace_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let configs: Vec<_> = rows.iter().map(|(id, name, desc, author, created_at)| {
        serde_json::json!({
            "id": id,
            "name": name,
            "description": desc,
            "author": author,
            "created_at": created_at,
        })
    }).collect();

    Ok(Json(serde_json::json!({ "configs": configs })))
}

async fn handle_get_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, config_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    db.get_workspace_member_role(&workspace_id, &claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let rev = db.get_config_revision(&workspace_id, config_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Config revision not found"))?;

    Ok(Json(serde_json::json!({
        "id": rev.0,
        "config_json": rev.1,
        "name": rev.2,
        "description": rev.3,
        "author": rev.4,
        "created_at": rev.5,
    })))
}

async fn handle_get_latest_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    db.get_workspace_member_role(&workspace_id, &claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let rev = db.get_latest_config_revision(&workspace_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "No config revisions in this workspace"))?;

    Ok(Json(serde_json::json!({
        "id": rev.0,
        "config_json": rev.1,
        "name": rev.2,
        "description": rev.3,
        "author": rev.4,
        "created_at": rev.5,
    })))
}

async fn handle_update_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, config_id)): Path<(String, i64)>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    let role = db.get_workspace_member_role(&workspace_id, &claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    if role == "viewer" {
        return Err(error_response(StatusCode::FORBIDDEN, "Viewers cannot edit configs"));
    }

    let updated = db.update_config_revision(&workspace_id, config_id, &req.name, &req.description, req.config_json.as_deref())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if !updated {
        return Err(error_response(StatusCode::NOT_FOUND, "Config revision not found"));
    }

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

async fn handle_delete_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, config_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    let role = db.get_workspace_member_role(&workspace_id, &claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    if role == "viewer" {
        return Err(error_response(StatusCode::FORBIDDEN, "Viewers cannot delete configs"));
    }

    let deleted = db.delete_config_revision(&workspace_id, config_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if !deleted {
        return Err(error_response(StatusCode::NOT_FOUND, "Config revision not found"));
    }

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

/// List releases visible to a workspace (workspace-specific + global).
async fn handle_workspace_releases(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(&headers, &state.jwt_secret)?;
    require_password_changed(&state, &claims.sub)?;

    let db = state.db.lock().unwrap();
    db.get_workspace_member_role(&workspace_id, &claims.sub)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let rows = db.list_releases_for_workspace(&workspace_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let mut releases = Vec::new();
    for (id, tag, name, body, prerelease, created_at) in &rows {
        let assets = db.get_release_assets(*id).unwrap_or_default();
        releases.push(serde_json::json!({
            "tag": tag,
            "name": name,
            "body": body,
            "published_at": created_at,
            "prerelease": prerelease,
            "assets": assets.iter().map(|(name, size)| serde_json::json!({
                "name": name,
                "size": size,
            })).collect::<Vec<_>>(),
        }));
    }

    Ok(Json(serde_json::json!({ "releases": releases })))
}

// ---------------------------------------------------------------------------
// Dashboard (embedded HTML)
// ---------------------------------------------------------------------------

async fn handle_dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

async fn handle_health() -> &'static str {
    "OK"
}

async fn handle_features() -> Json<Vec<susi_core::features::FeatureInfo>> {
    Json(susi_core::features::ALL_FEATURES.to_vec())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    log::info!("Loading private key from {}", cli.private_key);
    let priv_pem = std::fs::read_to_string(&cli.private_key)
        .with_context(|| format!("Failed to read private key from {}", cli.private_key))?;
    let private_key = private_key_from_pem(&priv_pem)
        .context("Failed to parse private key")?;

    log::info!("Opening database at {}", cli.db);
    let db = LicenseDb::open(&cli.db).context("Failed to open database")?;

    let default_hash = hash_password("changeme")
        .map_err(|_| anyhow::anyhow!("Failed to hash default password"))?;
    if db.seed_admin(&default_hash).context("Failed to seed admin")? {
        log::info!("Default admin user created (password: changeme)");
    }
    if db.user_must_change_password("admin").unwrap_or(false) {
        log::warn!("=== Default admin password is active. Change it at the dashboard! ===");
    }

    let jwt_secret: [u8; 32] = rand::random();

    // Ensure releases asset directory exists
    let releases_dir = std::path::Path::new(&cli.data_dir).join("releases");
    std::fs::create_dir_all(&releases_dir)
        .with_context(|| format!("Failed to create releases dir at {}", releases_dir.display()))?;

    let state = Arc::new(AppState {
        db: Mutex::new(db),
        private_key,
        jwt_secret,
        data_dir: cli.data_dir,
    });

    let app = Router::new()
        // Dashboard
        .route("/", get(handle_dashboard))
        // Health
        .route("/health", get(handle_health))
        // Available license features
        .route("/api/v1/features", get(handle_features))
        // Auth endpoints
        .route("/api/v1/auth/login", post(handle_login))
        .route("/api/v1/auth/status", get(handle_auth_status))
        .route("/api/v1/auth/change-password", post(handle_change_password))
        .route("/api/v1/auth/setup-2fa", post(handle_setup_2fa))
        .route("/api/v1/auth/verify-2fa", post(handle_verify_2fa))
        .route("/api/v1/auth/disable-2fa", post(handle_disable_2fa))
        // User management
        .route("/api/v1/auth/users", get(handle_list_users))
        .route("/api/v1/auth/users", post(handle_create_user))
        .route("/api/v1/auth/users/{username}", axum::routing::delete(handle_delete_user))
        .route("/api/v1/auth/users/{username}/rename", post(handle_rename_user))
        .route("/api/v1/auth/users/{username}/reset-password", post(handle_reset_user_password))
        // Public client endpoints
        .route("/api/v1/activate", post(handle_activate))
        .route("/api/v1/verify", post(handle_verify))
        .route("/api/v1/deactivate", post(handle_deactivate))
        .route("/api/v1/licenses/{key}/status", get(handle_license_status))
        // Admin endpoints (JWT-protected)
        .route("/api/v1/licenses", get(handle_list_licenses))
        .route("/api/v1/licenses", post(handle_create_license))
        .route("/api/v1/licenses/{key}", get(handle_get_license).put(handle_update_license).delete(handle_delete_license))
        .route("/api/v1/licenses/{key}/revoke", post(handle_revoke_license))
        .route("/api/v1/licenses/{key}/export", post(handle_export_license))
        .route(
            "/api/v1/licenses/{key}/machines/{machine_code}",
            axum::routing::delete(handle_deactivate_machine),
        )
        // Releases — client endpoints (license-key protected)
        .route("/api/v1/updates/releases", get(handle_get_releases))
        .route("/api/v1/updates/download/{tag}/{asset}", get(handle_download_asset))
        // Releases — admin endpoints (JWT protected)
        .route("/api/v1/releases", get(handle_list_releases_admin))
        .merge(
            Router::new()
                .route("/api/v1/releases", post(handle_upload_release))
                .layer(DefaultBodyLimit::max(500 * 1024 * 1024))
        )
        .route("/api/v1/releases/{tag}", axum::routing::delete(handle_delete_release))
        // Workspace endpoints (JWT protected)
        .route("/api/v1/workspaces", get(handle_list_workspaces).post(handle_create_workspace))
        .route("/api/v1/workspaces/{id}", get(handle_get_workspace).put(handle_update_workspace).delete(handle_delete_workspace))
        .route("/api/v1/workspaces/{id}/members", post(handle_add_workspace_member))
        .route("/api/v1/workspaces/{id}/members/{username}", axum::routing::delete(handle_remove_workspace_member))
        // Config revision endpoints (JWT protected)
        .route("/api/v1/workspaces/{id}/configs", get(handle_list_configs).post(handle_push_config))
        .route("/api/v1/workspaces/{id}/configs/latest", get(handle_get_latest_config))
        .route("/api/v1/workspaces/{id}/configs/{config_id}", get(handle_get_config).put(handle_update_config).delete(handle_delete_config))
        .route("/api/v1/workspaces/{id}/releases", get(handle_workspace_releases))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cli.listen)
        .await
        .with_context(|| format!("Failed to bind to {}", cli.listen))?;

    log::info!("License server listening on {}", cli.listen);
    log::info!("Dashboard: http://{}", cli.listen);
    axum::serve(listener, app)
        .await
        .context("Server error")?;

    Ok(())
}
