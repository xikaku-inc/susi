//! Rotating encrypted offsite backups to Dropbox.
//!
//! A scheduled (or manually triggered) run snapshots the SQLite DB with
//! `VACUUM INTO`, tars it together with the signing key, the two secret
//! files and `docs/` (optionally `releases/`), encrypts the archive with
//! chunked AES-256-GCM under `SUSI_BACKUP_KEY`, uploads it to the app's
//! Dropbox App Folder via upload sessions, and prunes old archives with a
//! grandfather-father-son retention scheme (daily/weekly/monthly).
//!
//! Dropbox auth: scoped app (app-folder access) + offline OAuth. The admin
//! pastes the one-time authorization code into the dashboard; the resulting
//! refresh token is stored sealed with the DB at-rest key. Access tokens are
//! minted per run and never persisted.
//!
//! Restore: `susi-server decrypt-backup <archive> --key <hex>` then untar
//! into a fresh /data volume.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Datelike, Duration, NaiveDateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use susi_core::db::LicenseDb;
use susi_core::error::LicenseError;

use crate::{audit, error_response, require_admin_full, validate_principal, AppState, ErrorResponse};

fn db_err(e: LicenseError) -> (StatusCode, Json<ErrorResponse>) {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Database error: {}", e))
}

// ---------------------------------------------------------------------------
// Config (from CLI/env, fixed for the process lifetime)
// ---------------------------------------------------------------------------

pub(crate) struct BackupConfig {
    pub app_key: String,
    pub app_secret: String,
    /// 32-byte archive encryption key (SUSI_BACKUP_KEY, hex). None = feature off.
    pub archive_key: Option<[u8; 32]>,
    /// Archive name prefix; lets prod and staging share one app folder.
    pub prefix: String,
    /// Path of the license-signing key PEM, included in every archive.
    pub private_key_path: String,
    pub api_base: String,
    pub content_base: String,
    /// Dedicated client: uploads need a far longer per-request timeout than
    /// the shared 15 s `AppState::http` client allows.
    pub http: reqwest::Client,
}

impl BackupConfig {
    pub fn configured(&self) -> bool {
        !self.app_key.is_empty() && !self.app_secret.is_empty() && self.archive_key.is_some()
    }
}

/// Parse SUSI_BACKUP_KEY (64 hex chars). Empty = feature disabled.
pub(crate) fn parse_archive_key(hex_key: &str) -> Result<Option<[u8; 32]>> {
    if hex_key.is_empty() {
        return Ok(None);
    }
    let bytes = hex::decode(hex_key).context("SUSI_BACKUP_KEY is not valid hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("SUSI_BACKUP_KEY must be 64 hex chars (32 bytes)"))?;
    Ok(Some(arr))
}

// ---------------------------------------------------------------------------
// Settings (admin-editable, stored in backup_state)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy)]
pub(crate) struct BackupSettings {
    pub enabled: bool,
    pub hour_utc: u8,
    pub include_releases: bool,
    pub keep_daily: u32,
    pub keep_weekly: u32,
    pub keep_monthly: u32,
}

impl Default for BackupSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            hour_utc: 3,
            include_releases: false,
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 12,
        }
    }
}

impl BackupSettings {
    fn load(db: &LicenseDb) -> Self {
        let d = Self::default();
        let get = |k: &str| db.get_backup_state(k).ok().flatten();
        Self {
            enabled: get("enabled").map(|v| v == "1").unwrap_or(d.enabled),
            hour_utc: get("hour_utc").and_then(|v| v.parse().ok()).unwrap_or(d.hour_utc),
            include_releases: get("include_releases").map(|v| v == "1").unwrap_or(d.include_releases),
            keep_daily: get("keep_daily").and_then(|v| v.parse().ok()).unwrap_or(d.keep_daily),
            keep_weekly: get("keep_weekly").and_then(|v| v.parse().ok()).unwrap_or(d.keep_weekly),
            keep_monthly: get("keep_monthly").and_then(|v| v.parse().ok()).unwrap_or(d.keep_monthly),
        }
    }

    fn save(&self, db: &LicenseDb) -> Result<(), LicenseError> {
        db.set_backup_state("enabled", if self.enabled { "1" } else { "0" })?;
        db.set_backup_state("hour_utc", &self.hour_utc.to_string())?;
        db.set_backup_state("include_releases", if self.include_releases { "1" } else { "0" })?;
        db.set_backup_state("keep_daily", &self.keep_daily.to_string())?;
        db.set_backup_state("keep_weekly", &self.keep_weekly.to_string())?;
        db.set_backup_state("keep_monthly", &self.keep_monthly.to_string())?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Archive encryption: chunked AES-256-GCM
//
// Layout: magic "SUSIBKP1" | 4-byte random nonce prefix | chunks.
// Each chunk: u32 LE ciphertext length | AES-256-GCM ciphertext.
// Nonce = prefix || u64 LE chunk counter; AAD = [is_final_chunk]. The bound
// counter defeats reordering, the final flag defeats truncation.
// ---------------------------------------------------------------------------

const BACKUP_MAGIC: &[u8; 8] = b"SUSIBKP1";
const CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Read until `buf` is full or EOF; returns bytes read.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(m) => n += m,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

pub(crate) fn encrypt_stream(key: &[u8; 32], r: &mut impl Read, w: &mut impl Write) -> Result<()> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use rand::RngCore;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("AES init: {}", e))?;
    w.write_all(BACKUP_MAGIC)?;
    let mut prefix = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut prefix);
    w.write_all(&prefix)?;

    let mut counter: u64 = 0;
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = read_full(r, &mut buf)?;
        let is_final = n < CHUNK_SIZE;
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&prefix);
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &buf[..n], aad: &[is_final as u8] })
            .map_err(|_| anyhow!("AES encrypt failed"))?;
        w.write_all(&(ct.len() as u32).to_le_bytes())?;
        w.write_all(&ct)?;
        counter += 1;
        if is_final {
            break;
        }
    }
    w.flush()?;
    Ok(())
}

pub(crate) fn decrypt_stream(key: &[u8; 32], r: &mut impl Read, w: &mut impl Write) -> Result<()> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("AES init: {}", e))?;
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic).context("archive too short")?;
    if &magic != BACKUP_MAGIC {
        bail!("not a susi backup archive (bad magic)");
    }
    let mut prefix = [0u8; 4];
    r.read_exact(&mut prefix).context("archive too short")?;

    let mut counter: u64 = 0;
    loop {
        let mut len_buf = [0u8; 4];
        match r.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                bail!("archive is truncated (missing final chunk)");
            }
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > CHUNK_SIZE + 16 {
            bail!("corrupt archive (chunk length {} out of range)", len);
        }
        let mut ct = vec![0u8; len];
        r.read_exact(&mut ct).context("archive is truncated mid-chunk")?;

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&prefix);
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce);

        if let Ok(pt) = cipher.decrypt(nonce, Payload { msg: &ct, aad: &[0u8] }) {
            w.write_all(&pt)?;
        } else if let Ok(pt) = cipher.decrypt(nonce, Payload { msg: &ct, aad: &[1u8] }) {
            w.write_all(&pt)?;
            let mut probe = [0u8; 1];
            if r.read(&mut probe)? != 0 {
                bail!("corrupt archive (data after final chunk)");
            }
            w.flush()?;
            return Ok(());
        } else {
            bail!("decryption failed (wrong key or corrupt archive)");
        }
        counter += 1;
    }
}

fn encrypt_file(key: &[u8; 32], input: &Path, output: &Path) -> Result<()> {
    let mut r = BufReader::new(File::open(input)?);
    let mut w = BufWriter::new(File::create(output)?);
    encrypt_stream(key, &mut r, &mut w)
}

/// `susi-server decrypt-backup` entry point.
pub(crate) fn cli_decrypt(input: &str, output: Option<&str>, hex_key: &str) -> Result<()> {
    let key = parse_archive_key(hex_key)?.ok_or_else(|| anyhow!("--key is required"))?;
    let out = match output {
        Some(o) => o.to_string(),
        None => input
            .strip_suffix(".enc")
            .map(str::to_string)
            .unwrap_or_else(|| format!("{}.tar.gz", input)),
    };
    let mut r = BufReader::new(File::open(input).with_context(|| format!("open {}", input))?);
    let mut w = BufWriter::new(File::create(&out).with_context(|| format!("create {}", out))?);
    decrypt_stream(&key, &mut r, &mut w)?;
    println!("Decrypted to {} - unpack with: tar -xzf {}", out, out);
    Ok(())
}

// ---------------------------------------------------------------------------
// Archive building
// ---------------------------------------------------------------------------

fn build_archive(
    data_dir: &Path,
    _private_key_path: &Path,
    snapshot: &Path,
    include_releases: bool,
    out: &Path,
) -> Result<()> {
    let gz = flate2::write::GzEncoder::new(
        BufWriter::new(File::create(out)?),
        flate2::Compression::default(),
    );
    let mut tar = tar::Builder::new(gz);
    tar.append_path_with_name(snapshot, "licenses.db")
        .context("tar: db snapshot")?;
    // Deliberately NOT archived: private.pem, db_secret.bin, jwt_secret.bin.
    // Bundling the at-rest key (which decrypts the TOTP seeds in the DB), the
    // signing key and the JWT secret next to the personal-data DB would let
    // one leaked SUSI_BACKUP_KEY collapse every layer of key separation. Keep
    // an offline copy of those three files when provisioning the host; a
    // restore needs them from that copy.
    let mut dirs = vec!["docs", "website"];
    if include_releases {
        dirs.push("releases");
    }
    for dir in dirs {
        let p = data_dir.join(dir);
        if p.is_dir() {
            tar.append_dir_all(dir, &p).with_context(|| format!("tar: {}/", dir))?;
        }
    }
    let gz = tar.into_inner()?;
    gz.finish()?.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Archive naming + GFS rotation
// ---------------------------------------------------------------------------

fn archive_name(prefix: &str, at: DateTime<Utc>) -> String {
    format!("{}-backup-{}.tar.gz.enc", prefix, at.format("%Y%m%d-%H%M%S"))
}

fn parse_archive_time(prefix: &str, name: &str) -> Option<DateTime<Utc>> {
    let stamp = name
        .strip_prefix(prefix)?
        .strip_prefix("-backup-")?
        .strip_suffix(".tar.gz.enc")?;
    NaiveDateTime::parse_from_str(stamp, "%Y%m%d-%H%M%S")
        .ok()
        .map(|t| t.and_utc())
}

/// GFS selection: given all archives (of this instance), return the names to
/// delete. Keeps the newest archive per calendar day / ISO week / calendar
/// month up to the configured counts, plus everything younger than 48 h so a
/// just-made manual backup never vanishes in the same night's rotation.
fn select_deletions(
    mut entries: Vec<(String, DateTime<Utc>)>,
    now: DateTime<Utc>,
    keep_daily: u32,
    keep_weekly: u32,
    keep_monthly: u32,
) -> Vec<String> {
    entries.sort_by(|a, b| b.1.cmp(&a.1));
    let mut keep: HashSet<&str> = HashSet::new();
    let mut days: Vec<chrono::NaiveDate> = Vec::new();
    let mut weeks: Vec<(i32, u32)> = Vec::new();
    let mut months: Vec<(i32, u32)> = Vec::new();

    for (name, t) in &entries {
        if now.signed_duration_since(*t) < Duration::hours(48) {
            keep.insert(name);
        }
        let day = t.date_naive();
        if !days.contains(&day) && (days.len() as u32) < keep_daily {
            days.push(day);
            keep.insert(name);
        }
        let week = (t.iso_week().year(), t.iso_week().week());
        if !weeks.contains(&week) && (weeks.len() as u32) < keep_weekly {
            weeks.push(week);
            keep.insert(name);
        }
        let month = (t.year(), t.month());
        if !months.contains(&month) && (months.len() as u32) < keep_monthly {
            months.push(month);
            keep.insert(name);
        }
    }

    entries
        .iter()
        .filter(|(name, _)| !keep.contains(name.as_str()))
        .map(|(name, _)| name.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Dropbox HTTP client (plain reqwest; no SDK)
// ---------------------------------------------------------------------------

async fn token_request(cfg: &BackupConfig, form: &[(&str, &str)]) -> Result<Value> {
    let resp = cfg
        .http
        .post(format!("{}/oauth2/token", cfg.api_base))
        .form(form)
        .send()
        .await
        .context("Dropbox token endpoint unreachable")?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("Dropbox token request failed ({}): {}", status, body);
    }
    serde_json::from_str(&body).context("Dropbox token response is not JSON")
}

/// One-time exchange of the pasted authorization code for a refresh token.
async fn exchange_code(cfg: &BackupConfig, code: &str) -> Result<String> {
    let v = token_request(
        cfg,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &cfg.app_key),
            ("client_secret", &cfg.app_secret),
        ],
    )
    .await?;
    v["refresh_token"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("Dropbox response is missing refresh_token"))
}

async fn access_token(cfg: &BackupConfig, refresh_token: &str) -> Result<String> {
    let v = token_request(
        cfg,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &cfg.app_key),
            ("client_secret", &cfg.app_secret),
        ],
    )
    .await?;
    v["access_token"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("Dropbox response is missing access_token"))
}

/// JSON-RPC style call against api.dropboxapi.com.
async fn api_rpc(cfg: &BackupConfig, token: &str, endpoint: &str, body: Value) -> Result<Value> {
    let resp = cfg
        .http
        .post(format!("{}/2/{}", cfg.api_base, endpoint))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("Dropbox {} unreachable", endpoint))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("Dropbox {} failed ({}): {}", endpoint, status, text);
    }
    serde_json::from_str(&text).with_context(|| format!("Dropbox {}: bad JSON", endpoint))
}

/// Content upload call (upload / upload_session/*). `arg` goes in the
/// Dropbox-API-Arg header, bytes in the body.
async fn content_call(
    cfg: &BackupConfig,
    token: &str,
    endpoint: &str,
    arg: &Value,
    body: Vec<u8>,
) -> Result<Value> {
    let resp = cfg
        .http
        .post(format!("{}/2/{}", cfg.content_base, endpoint))
        .bearer_auth(token)
        .header("Dropbox-API-Arg", arg.to_string())
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .with_context(|| format!("Dropbox {} unreachable", endpoint))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("Dropbox {} failed ({}): {}", endpoint, status, text);
    }
    if text.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&text).with_context(|| format!("Dropbox {}: bad JSON", endpoint))
}

/// Session-based upload in 32 MiB parts; works for any file size and keeps
/// peak memory bounded on the small Lightsail box.
const UPLOAD_PART: usize = 32 * 1024 * 1024;

async fn upload_file(cfg: &BackupConfig, token: &str, local: &Path, remote_name: &str) -> Result<()> {
    let mut f = tokio::fs::File::open(local).await?;

    let mut first = vec![0u8; UPLOAD_PART];
    let n = read_full_async(&mut f, &mut first).await?;
    first.truncate(n);
    let v = content_call(cfg, token, "files/upload_session/start", &json!({"close": false}), first)
        .await?;
    let session_id = v["session_id"]
        .as_str()
        .ok_or_else(|| anyhow!("upload_session/start: missing session_id"))?
        .to_string();
    let mut offset = n as u64;

    loop {
        let mut part = vec![0u8; UPLOAD_PART];
        let n = read_full_async(&mut f, &mut part).await?;
        if n == 0 {
            break;
        }
        part.truncate(n);
        content_call(
            cfg,
            token,
            "files/upload_session/append_v2",
            &json!({"cursor": {"session_id": session_id, "offset": offset}, "close": false}),
            part,
        )
        .await?;
        offset += n as u64;
    }

    content_call(
        cfg,
        token,
        "files/upload_session/finish",
        &json!({
            "cursor": {"session_id": session_id, "offset": offset},
            "commit": {"path": format!("/{}", remote_name), "mode": "overwrite", "mute": true}
        }),
        Vec::new(),
    )
    .await?;
    Ok(())
}

async fn read_full_async(f: &mut tokio::fs::File, buf: &mut [u8]) -> Result<usize> {
    use tokio::io::AsyncReadExt;
    let mut n = 0;
    while n < buf.len() {
        let m = f.read(&mut buf[n..]).await?;
        if m == 0 {
            break;
        }
        n += m;
    }
    Ok(n)
}

/// All files in the app folder root: (name, size).
async fn list_files(cfg: &BackupConfig, token: &str) -> Result<Vec<(String, u64)>> {
    let mut out = Vec::new();
    let mut v = api_rpc(cfg, token, "files/list_folder", json!({"path": "", "recursive": false}))
        .await?;
    loop {
        if let Some(entries) = v["entries"].as_array() {
            for e in entries {
                if e[".tag"] == "file" {
                    if let Some(name) = e["name"].as_str() {
                        out.push((name.to_string(), e["size"].as_u64().unwrap_or(0)));
                    }
                }
            }
        }
        if !v["has_more"].as_bool().unwrap_or(false) {
            break;
        }
        let cursor = v["cursor"].as_str().unwrap_or_default().to_string();
        v = api_rpc(cfg, token, "files/list_folder/continue", json!({"cursor": cursor})).await?;
    }
    Ok(out)
}

async fn delete_file(cfg: &BackupConfig, token: &str, name: &str) -> Result<()> {
    api_rpc(cfg, token, "files/delete_v2", json!({"path": format!("/{}", name)})).await?;
    Ok(())
}

async fn account_email(cfg: &BackupConfig, token: &str) -> Result<String> {
    let v = api_rpc(cfg, token, "users/get_current_account", Value::Null).await?;
    Ok(v["email"].as_str().unwrap_or("(unknown)").to_string())
}

/// Best-effort (used, allocated) in bytes for the dashboard quota bar.
async fn space_usage(cfg: &BackupConfig, token: &str) -> Option<(u64, u64)> {
    let v = api_rpc(cfg, token, "users/get_space_usage", Value::Null).await.ok()?;
    Some((
        v["used"].as_u64()?,
        v["allocation"]["allocated"].as_u64().unwrap_or(0),
    ))
}

// ---------------------------------------------------------------------------
// Backup run
// ---------------------------------------------------------------------------

/// Clears the running flag when a run ends, however it ends.
struct RunGuard(Arc<AppState>);
impl Drop for RunGuard {
    fn drop(&mut self) {
        self.0.backup_running.store(false, Ordering::SeqCst);
    }
}

pub(crate) async fn run_backup(state: Arc<AppState>, source: &str) -> Result<()> {
    let cfg = &state.backup;
    let key = cfg
        .archive_key
        .ok_or_else(|| anyhow!("Backups are not configured (SUSI_BACKUP_KEY missing)"))?;
    if !cfg.configured() {
        bail!("Backups are not configured (Dropbox app key/secret missing)");
    }
    let refresh = {
        let db = state.db.lock();
        db.get_backup_refresh_token()
            .map_err(|e| anyhow!("{}", e))?
            .ok_or_else(|| anyhow!("Dropbox is not connected"))?
    };
    if state
        .backup_running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        bail!("A backup is already running");
    }
    let _guard = RunGuard(Arc::clone(&state));

    let (run_id, settings) = {
        let db = state.db.lock();
        (
            db.insert_backup_run(source).map_err(|e| anyhow!("{}", e))?,
            BackupSettings::load(&db),
        )
    };
    log::info!("Backup started ({})", source);
    let started = std::time::Instant::now();
    let name = archive_name(&cfg.prefix, Utc::now());

    let result = do_backup(&state, &key, &settings, &refresh, &name).await;

    {
        let db = state.db.lock();
        let _ = db.prune_backup_runs(50);
        match &result {
            Ok(size) => {
                let _ = db.finish_backup_run(run_id, "ok", &name, *size as i64, "");
            }
            Err(e) => {
                let _ = db.finish_backup_run(run_id, "error", &name, 0, &format!("{:#}", e));
            }
        }
    }
    match &result {
        Ok(size) => log::info!(
            "Backup finished: {} ({} bytes) in {:.1} s",
            name,
            size,
            started.elapsed().as_secs_f32()
        ),
        Err(e) => log::error!("Backup failed: {:#}", e),
    }
    result.map(|_| ())
}

async fn do_backup(
    state: &Arc<AppState>,
    key: &[u8; 32],
    settings: &BackupSettings,
    refresh: &str,
    name: &str,
) -> Result<u64> {
    let cfg = &state.backup;
    let tmp = Path::new(&state.data_dir).join("backup_tmp");

    // Snapshot + tar + encrypt on a blocking thread.
    let enc_path: PathBuf = {
        let state = Arc::clone(state);
        let key = *key;
        let include_releases = settings.include_releases;
        let name = name.to_string();
        let tmp = tmp.clone();
        tokio::task::spawn_blocking(move || -> Result<PathBuf> {
            if tmp.exists() {
                std::fs::remove_dir_all(&tmp).context("clear backup_tmp")?;
            }
            std::fs::create_dir_all(&tmp).context("create backup_tmp")?;

            let snapshot = tmp.join("licenses.db");
            {
                let db = state.db.lock();
                db.vacuum_into(snapshot.to_str().context("snapshot path")?)
                    .map_err(|e| anyhow!("DB snapshot: {}", e))?;
            }
            let tar_path = tmp.join("backup.tar.gz");
            build_archive(
                Path::new(&state.data_dir),
                Path::new(&state.backup.private_key_path),
                &snapshot,
                include_releases,
                &tar_path,
            )?;
            std::fs::remove_file(&snapshot).ok();

            let enc = tmp.join(&name);
            encrypt_file(&key, &tar_path, &enc)?;
            std::fs::remove_file(&tar_path).ok();
            Ok(enc)
        })
        .await
        .context("backup worker panicked")??
    };

    let size = std::fs::metadata(&enc_path)?.len();
    let upload = async {
        let token = access_token(cfg, refresh).await?;
        upload_file(cfg, &token, &enc_path, name).await?;

        // Rotation: only archives carrying our own prefix participate.
        let files = list_files(cfg, &token).await?;
        let entries: Vec<(String, DateTime<Utc>)> = files
            .into_iter()
            .filter_map(|(n, _)| parse_archive_time(&cfg.prefix, &n).map(|t| (n, t)))
            .collect();
        let deletions = select_deletions(
            entries,
            Utc::now(),
            settings.keep_daily,
            settings.keep_weekly,
            settings.keep_monthly,
        );
        for del in &deletions {
            if let Err(e) = delete_file(cfg, &token, del).await {
                log::warn!("Backup rotation: failed to delete {}: {:#}", del, e);
            } else {
                log::info!("Backup rotation: deleted {}", del);
            }
        }

        if let Some((used, allocated)) = space_usage(cfg, &token).await {
            let db = state.db.lock();
            let _ = db.set_backup_state("space_used", &used.to_string());
            let _ = db.set_backup_state("space_allocated", &allocated.to_string());
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;

    std::fs::remove_dir_all(&tmp).ok();
    upload?;
    Ok(size)
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

/// Nightly backup at `hour_utc`; on failure, retries hourly until the run
/// succeeds (each calendar day becomes due again regardless).
pub(crate) fn spawn_scheduler(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        tick.tick().await; // skip immediate fire
        loop {
            tick.tick().await;
            if !scheduled_run_due(&state) {
                continue;
            }
            {
                let db = state.db.lock();
                let _ = db.set_backup_state("last_scheduled_attempt", &Utc::now().to_rfc3339());
                let _ = db.set_backup_state("last_scheduled_ok", "0");
            }
            if let Err(e) = run_backup(Arc::clone(&state), "scheduled").await {
                log::error!("Scheduled backup failed: {:#}", e);
            } else {
                let db = state.db.lock();
                let _ = db.set_backup_state("last_scheduled_ok", "1");
            }
        }
    });
}

fn scheduled_run_due(state: &Arc<AppState>) -> bool {
    if !state.backup.configured() || state.backup_running.load(Ordering::SeqCst) {
        return false;
    }
    let db = state.db.lock();
    let settings = BackupSettings::load(&db);
    if !settings.enabled {
        return false;
    }
    match db.get_backup_refresh_token() {
        Ok(Some(_)) => {}
        _ => return false,
    }
    let now = Utc::now();
    let due_at = match now.with_hour(settings.hour_utc as u32).and_then(|t| t.with_minute(0)).and_then(|t| t.with_second(0)) {
        Some(t) => t,
        None => return false,
    };
    if now < due_at {
        return false;
    }
    let last_attempt = db
        .get_backup_state("last_scheduled_attempt")
        .ok()
        .flatten()
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|t| t.with_timezone(&Utc));
    let last_ok = db
        .get_backup_state("last_scheduled_ok")
        .ok()
        .flatten()
        .map(|v| v == "1")
        .unwrap_or(true);
    match last_attempt {
        None => true,
        Some(t) if t < due_at => true,
        // Attempted since today's due time but failed: retry hourly.
        Some(t) => !last_ok && now.signed_duration_since(t) >= Duration::hours(1),
    }
}

// ---------------------------------------------------------------------------
// Admin API handlers
// ---------------------------------------------------------------------------

pub async fn handle_backup_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let db = state.db.lock();
    let settings = BackupSettings::load(&db);
    let connected = db.get_backup_refresh_token().ok().flatten().is_some();
    let account = db.get_backup_state("dropbox_account").ok().flatten();
    let space_used = db.get_backup_state("space_used").ok().flatten().and_then(|v| v.parse::<u64>().ok());
    let space_allocated = db.get_backup_state("space_allocated").ok().flatten().and_then(|v| v.parse::<u64>().ok());
    let history = db.list_backup_runs(20).map_err(db_err)?;
    Ok(Json(json!({
        "configured": state.backup.configured(),
        "connected": connected,
        "account": account,
        "prefix": state.backup.prefix,
        "running": state.backup_running.load(Ordering::SeqCst),
        "settings": settings,
        "space_used": space_used,
        "space_allocated": space_allocated,
        "history": history,
    })))
}

#[derive(Deserialize)]
pub struct UpdateBackupSettingsRequest {
    pub enabled: bool,
    pub hour_utc: u8,
    pub include_releases: bool,
    pub keep_daily: u32,
    pub keep_weekly: u32,
    pub keep_monthly: u32,
}

pub async fn handle_backup_put_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<UpdateBackupSettingsRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    if req.hour_utc > 23 {
        return Err(error_response(StatusCode::BAD_REQUEST, "hour_utc must be 0-23"));
    }
    if req.keep_daily < 1 || req.keep_daily > 60 {
        return Err(error_response(StatusCode::BAD_REQUEST, "keep_daily must be 1-60"));
    }
    if req.keep_weekly > 52 || req.keep_monthly > 120 {
        return Err(error_response(StatusCode::BAD_REQUEST, "keep_weekly max 52, keep_monthly max 120"));
    }
    let settings = BackupSettings {
        enabled: req.enabled,
        hour_utc: req.hour_utc,
        include_releases: req.include_releases,
        keep_daily: req.keep_daily,
        keep_weekly: req.keep_weekly,
        keep_monthly: req.keep_monthly,
    };
    {
        let db = state.db.lock();
        settings.save(&db).map_err(db_err)?;
    }
    audit(
        &state,
        &p.username,
        "backup.settings",
        "dropbox",
        &format!(
            "enabled={} hour_utc={} include_releases={} keep={}d/{}w/{}m",
            settings.enabled, settings.hour_utc, settings.include_releases,
            settings.keep_daily, settings.keep_weekly, settings.keep_monthly
        ),
    );
    Ok(Json(json!({ "status": "OK" })))
}

pub async fn handle_backup_connect_url(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    if !state.backup.configured() {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Backups are not configured on this server (SUSI_DROPBOX_APP_KEY / SUSI_DROPBOX_APP_SECRET / SUSI_BACKUP_KEY)",
        ));
    }
    // No redirect_uri: Dropbox shows the user a code to copy-paste into the
    // dashboard, which avoids registering per-environment redirect URLs.
    let url = format!(
        "https://www.dropbox.com/oauth2/authorize?client_id={}&response_type=code&token_access_type=offline",
        urlencode(&state.backup.app_key)
    );
    Ok(Json(json!({ "url": url })))
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[derive(Deserialize)]
pub struct BackupConnectRequest {
    pub code: String,
}

pub async fn handle_backup_connect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BackupConnectRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    if !state.backup.configured() {
        return Err(error_response(StatusCode::SERVICE_UNAVAILABLE, "Backups are not configured on this server"));
    }
    let code = req.code.trim();
    if code.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Authorization code is required"));
    }
    let refresh = exchange_code(&state.backup, code)
        .await
        .map_err(|e| error_response(StatusCode::BAD_GATEWAY, &format!("{:#}", e)))?;
    let token = access_token(&state.backup, &refresh)
        .await
        .map_err(|e| error_response(StatusCode::BAD_GATEWAY, &format!("{:#}", e)))?;
    let email = account_email(&state.backup, &token)
        .await
        .unwrap_or_else(|_| "(unknown)".into());
    let space = space_usage(&state.backup, &token).await;
    {
        let db = state.db.lock();
        db.set_backup_refresh_token(&refresh).map_err(db_err)?;
        db.set_backup_state("dropbox_account", &email).map_err(db_err)?;
        if let Some((used, allocated)) = space {
            let _ = db.set_backup_state("space_used", &used.to_string());
            let _ = db.set_backup_state("space_allocated", &allocated.to_string());
        }
    }
    audit(&state, &p.username, "backup.connect", "dropbox", &email);
    Ok(Json(json!({ "status": "OK", "account": email })))
}

pub async fn handle_backup_disconnect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let refresh = {
        let db = state.db.lock();
        db.get_backup_refresh_token().ok().flatten()
    };
    // Best-effort server-side revocation; local state is cleared regardless.
    if let Some(refresh) = refresh {
        if let Ok(token) = access_token(&state.backup, &refresh).await {
            let _ = api_rpc(&state.backup, &token, "auth/token/revoke", Value::Null).await;
        }
    }
    {
        let db = state.db.lock();
        db.delete_backup_state("dropbox_refresh_token").map_err(db_err)?;
        db.delete_backup_state("dropbox_account").map_err(db_err)?;
        db.delete_backup_state("space_used").map_err(db_err)?;
        db.delete_backup_state("space_allocated").map_err(db_err)?;
    }
    audit(&state, &p.username, "backup.disconnect", "dropbox", "");
    Ok(Json(json!({ "status": "OK" })))
}

pub async fn handle_backup_run(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    if !state.backup.configured() {
        return Err(error_response(StatusCode::SERVICE_UNAVAILABLE, "Backups are not configured on this server"));
    }
    let connected = {
        let db = state.db.lock();
        db.get_backup_refresh_token().ok().flatten().is_some()
    };
    if !connected {
        return Err(error_response(StatusCode::CONFLICT, "Dropbox is not connected"));
    }
    if state.backup_running.load(Ordering::SeqCst) {
        return Err(error_response(StatusCode::CONFLICT, "A backup is already running"));
    }
    audit(&state, &p.username, "backup.run", "dropbox", "manual trigger");
    let bg = Arc::clone(&state);
    tokio::spawn(async move {
        let _ = run_backup(bg, "manual").await;
    });
    Ok(Json(json!({ "status": "started" })))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn key() -> [u8; 32] {
        [42u8; 32]
    }

    fn roundtrip(data: &[u8]) -> Vec<u8> {
        let mut enc = Vec::new();
        encrypt_stream(&key(), &mut &data[..], &mut enc).unwrap();
        let mut dec = Vec::new();
        decrypt_stream(&key(), &mut &enc[..], &mut dec).unwrap();
        dec
    }

    #[test]
    fn test_encrypt_roundtrip_small() {
        let data = b"hello backup world";
        assert_eq!(roundtrip(data), data);
    }

    #[test]
    fn test_encrypt_roundtrip_empty() {
        assert_eq!(roundtrip(b""), b"");
    }

    #[test]
    fn test_encrypt_roundtrip_multi_chunk() {
        // Cross the chunk boundary and hit an exact multiple as well.
        let sizes = [CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 2 * CHUNK_SIZE + 12345];
        for size in sizes {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            assert_eq!(roundtrip(&data), data, "size {}", size);
        }
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let mut enc = Vec::new();
        encrypt_stream(&key(), &mut &b"secret"[..], &mut enc).unwrap();
        let wrong = [43u8; 32];
        let mut out = Vec::new();
        assert!(decrypt_stream(&wrong, &mut &enc[..], &mut out).is_err());
    }

    #[test]
    fn test_decrypt_truncation_detected() {
        let data: Vec<u8> = (0..CHUNK_SIZE + 100).map(|i| (i % 256) as u8).collect();
        let mut enc = Vec::new();
        encrypt_stream(&key(), &mut &data[..], &mut enc).unwrap();
        // Drop the final chunk entirely: chop off the last chunk's bytes.
        let cut = 8 + 4 + 4 + (CHUNK_SIZE + 16); // header + first chunk
        let mut out = Vec::new();
        assert!(decrypt_stream(&key(), &mut &enc[..cut], &mut out).is_err());
    }

    #[test]
    fn test_decrypt_bad_magic() {
        let mut out = Vec::new();
        assert!(decrypt_stream(&key(), &mut &b"NOTABKUP12345678"[..], &mut out).is_err());
    }

    #[test]
    fn test_archive_name_roundtrip() {
        let t = Utc.with_ymd_and_hms(2026, 7, 6, 3, 0, 17).unwrap();
        let name = archive_name("prod", t);
        assert_eq!(name, "prod-backup-20260706-030017.tar.gz.enc");
        assert_eq!(parse_archive_time("prod", &name), Some(t));
        // Foreign prefixes and non-archive files never parse.
        assert_eq!(parse_archive_time("staging", &name), None);
        assert_eq!(parse_archive_time("prod", "prod-backup-garbage.tar.gz.enc"), None);
        assert_eq!(parse_archive_time("prod", "notes.txt"), None);
    }

    fn entry(prefix: &str, y: i32, m: u32, d: u32, h: u32) -> (String, DateTime<Utc>) {
        let t = Utc.with_ymd_and_hms(y, m, d, h, 0, 0).unwrap();
        (archive_name(prefix, t), t)
    }

    #[test]
    fn test_gfs_keeps_recent_dailies() {
        let now = Utc.with_ymd_and_hms(2026, 7, 10, 12, 0, 0).unwrap();
        // 10 consecutive nightly backups; keep 7 daily, 0 weekly, 0 monthly.
        let entries: Vec<_> = (1..=10).map(|d| entry("p", 2026, 7, d, 3)).collect();
        let dels = select_deletions(entries.clone(), now, 7, 0, 0);
        // Days 10..4 kept (7 dailies), days 3, 2, 1 deleted.
        let deleted: HashSet<_> = dels.iter().cloned().collect();
        for d in 4..=10 {
            assert!(!deleted.contains(&entries[d - 1].0), "day {} should be kept", d);
        }
        for d in 1..=3 {
            assert!(deleted.contains(&entries[d - 1].0), "day {} should be deleted", d);
        }
    }

    #[test]
    fn test_gfs_weekly_monthly_tiers() {
        let now = Utc.with_ymd_and_hms(2026, 7, 10, 12, 0, 0).unwrap();
        // Daily backups over ~3 months.
        let mut entries = Vec::new();
        for m in 5..=7u32 {
            for d in 1..=28u32 {
                if m == 7 && d > 10 {
                    break;
                }
                entries.push(entry("p", 2026, m, d, 3));
            }
        }
        let dels: HashSet<_> = select_deletions(entries.clone(), now, 7, 4, 12).into_iter().collect();
        let kept: Vec<_> = entries.iter().filter(|(n, _)| !dels.contains(n)).collect();
        // Newest per month is kept for every month present.
        assert!(kept.iter().any(|(_, t)| t.month() == 5 && t.day() == 28));
        assert!(kept.iter().any(|(_, t)| t.month() == 6 && t.day() == 28));
        // Last 7 days of dailies are all kept.
        for d in 4..=10 {
            assert!(kept.iter().any(|(_, t)| t.month() == 7 && t.day() == d), "july {} kept", d);
        }
        // Something actually got rotated out.
        assert!(!dels.is_empty());
        // Early-June middle-of-week days are gone (not daily, weekly or monthly picks).
        assert!(dels.iter().any(|n| n.contains("202606")));
    }

    #[test]
    fn test_gfs_never_deletes_younger_than_48h() {
        let now = Utc.with_ymd_and_hms(2026, 7, 10, 12, 0, 0).unwrap();
        // Two manual backups today + the nightly one; keep_daily=1 would
        // normally drop the older two, but they're younger than 48 h.
        let entries = vec![
            entry("p", 2026, 7, 10, 3),
            entry("p", 2026, 7, 10, 8),
            entry("p", 2026, 7, 10, 11),
        ];
        let dels = select_deletions(entries, now, 1, 0, 0);
        assert!(dels.is_empty());
    }

    #[test]
    fn test_gfs_keeps_multiple_same_day_only_newest_when_old() {
        let now = Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap();
        // Two backups on the same long-past day: only the newest survives
        // (as that day's daily/weekly/monthly representative).
        let entries = vec![
            entry("p", 2026, 8, 1, 3),
            entry("p", 2026, 8, 1, 15),
            entry("p", 2026, 8, 19, 3),
        ];
        let dels = select_deletions(entries, now, 7, 4, 12);
        assert_eq!(dels, vec![archive_name("p", Utc.with_ymd_and_hms(2026, 8, 1, 3, 0, 0).unwrap())]);
    }

    #[test]
    fn test_build_archive_and_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        std::fs::write(data_dir.join("db_secret.bin"), [1u8; 32]).unwrap();
        std::fs::write(data_dir.join("jwt_secret.bin"), [2u8; 32]).unwrap();
        std::fs::write(data_dir.join("private.pem"), "PEM").unwrap();
        std::fs::create_dir_all(data_dir.join("docs")).unwrap();
        std::fs::write(data_dir.join("docs/page.md"), "# hi").unwrap();
        std::fs::create_dir_all(data_dir.join("releases")).unwrap();
        std::fs::write(data_dir.join("releases/app.bin"), [9u8; 128]).unwrap();
        let snapshot = data_dir.join("snap.db");
        std::fs::write(&snapshot, b"sqlite-bytes").unwrap();

        let tar_path = data_dir.join("out.tar.gz");
        build_archive(data_dir, &data_dir.join("private.pem"), &snapshot, false, &tar_path).unwrap();
        let enc_path = data_dir.join("out.enc");
        encrypt_file(&key(), &tar_path, &enc_path).unwrap();

        // Decrypt + list tar entries.
        let mut dec = Vec::new();
        decrypt_stream(&key(), &mut BufReader::new(File::open(&enc_path).unwrap()), &mut dec).unwrap();
        let gz = flate2::read::GzDecoder::new(&dec[..]);
        let mut ar = tar::Archive::new(gz);
        let names: HashSet<String> = ar
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().replace('\\', "/"))
            .collect();
        assert!(names.contains("licenses.db"));
        // Key material must not ride along with the personal-data DB.
        assert!(!names.contains("private.pem"));
        assert!(!names.contains("db_secret.bin"));
        assert!(!names.contains("jwt_secret.bin"));
        assert!(names.contains("docs/page.md"));
        assert!(!names.iter().any(|n| n.starts_with("releases")));

        // With releases included the binary shows up too.
        build_archive(data_dir, &data_dir.join("private.pem"), &snapshot, true, &tar_path).unwrap();
        let gz = flate2::read::GzDecoder::new(File::open(&tar_path).unwrap());
        let mut ar = tar::Archive::new(gz);
        let names: HashSet<String> = ar
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().replace('\\', "/"))
            .collect();
        assert!(names.contains("releases/app.bin"));
    }
}
