use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::error::LicenseError;
use crate::license::{License, MachineActivation};

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub username: String,
    pub role: String,
    pub totp_enabled: bool,
    pub must_change_password: bool,
    pub created_at: String,
    pub email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceInfo {
    pub fingerprint: String,
    pub label: String,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug)]
pub struct LoginTokenRow {
    pub username: String,
    pub device_fp: String,
    pub device_label: String,
}

/// Minimal info needed to authorize a request via an API token.
#[derive(Debug)]
pub struct ApiTokenAuthRow {
    pub id: i64,
    pub username: String,
    pub revoked: bool,
}

/// Public-facing metadata about a token. Never includes the hash or raw token —
/// `prefix` is enough for humans to spot which token a row refers to.
#[derive(Debug, Serialize)]
pub struct ApiTokenInfo {
    pub id: i64,
    pub username: String,
    pub name: String,
    pub token_prefix: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

pub struct LicenseDb {
    conn: Connection,
}

impl LicenseDb {
    pub fn open(path: &str) -> Result<Self, LicenseError> {
        let conn =
            Connection::open(path).map_err(|e| LicenseError::Other(format!("DB open: {}", e)))?;
        let db = Self { conn };
        db.init_tables()?;
        Ok(db)
    }

    fn init_tables(&self) -> Result<(), LicenseError> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS licenses (
                id TEXT PRIMARY KEY,
                product TEXT NOT NULL,
                customer TEXT NOT NULL,
                license_key TEXT NOT NULL UNIQUE,
                created TEXT NOT NULL,
                expires TEXT NOT NULL,
                features TEXT NOT NULL,
                max_machines INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0,
                lease_duration_hours INTEGER NOT NULL DEFAULT 168,
                lease_grace_hours INTEGER NOT NULL DEFAULT 24
            );

            CREATE TABLE IF NOT EXISTS machine_activations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_id TEXT NOT NULL,
                machine_code TEXT NOT NULL,
                friendly_name TEXT NOT NULL DEFAULT '',
                activated_at TEXT NOT NULL,
                lease_expires_at TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (license_id) REFERENCES licenses(id),
                UNIQUE(license_id, machine_code)
            );

            CREATE TABLE IF NOT EXISTS machine_tombstones (
                license_id TEXT NOT NULL,
                machine_code TEXT NOT NULL,
                removed_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (license_id, machine_code),
                FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_license_key ON licenses(license_key);
            CREATE INDEX IF NOT EXISTS idx_activations_license ON machine_activations(license_id);
            CREATE INDEX IF NOT EXISTS idx_tombstones_expiry ON machine_tombstones(expires_at);

            CREATE TABLE IF NOT EXISTS releases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tag TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL DEFAULT '',
                body TEXT NOT NULL DEFAULT '',
                prerelease INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS release_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                release_id INTEGER NOT NULL,
                file_name TEXT NOT NULL,
                file_size INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (release_id) REFERENCES releases(id) ON DELETE CASCADE,
                UNIQUE(release_id, file_name)
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                must_change_password INTEGER NOT NULL DEFAULT 1,
                totp_secret TEXT,
                totp_enabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                product TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS workspace_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                added_at TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                UNIQUE(workspace_id, username)
            );
            CREATE INDEX IF NOT EXISTS idx_workspace_members_user ON workspace_members(username);

            CREATE TABLE IF NOT EXISTS config_revisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                config_json TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                author TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                UNIQUE(workspace_id, version)
            );
            CREATE INDEX IF NOT EXISTS idx_config_revisions_workspace ON config_revisions(workspace_id);

            CREATE TABLE IF NOT EXISTS doc_pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                release_id INTEGER NOT NULL,
                slug TEXT NOT NULL,
                title TEXT NOT NULL,
                body_md TEXT NOT NULL DEFAULT '',
                parent_slug TEXT,
                ord INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                origin TEXT NOT NULL DEFAULT 'user',
                FOREIGN KEY (release_id) REFERENCES releases(id) ON DELETE CASCADE,
                UNIQUE(release_id, slug)
            );
            CREATE INDEX IF NOT EXISTS idx_doc_pages_release ON doc_pages(release_id);
            CREATE INDEX IF NOT EXISTS idx_doc_pages_parent ON doc_pages(release_id, parent_slug);

            CREATE TABLE IF NOT EXISTS doc_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                release_id INTEGER NOT NULL,
                file_name TEXT NOT NULL,
                file_size INTEGER NOT NULL DEFAULT 0,
                origin TEXT NOT NULL DEFAULT 'user',
                FOREIGN KEY (release_id) REFERENCES releases(id) ON DELETE CASCADE,
                UNIQUE(release_id, file_name)
            );
            CREATE INDEX IF NOT EXISTS idx_doc_assets_release ON doc_assets(release_id);

            CREATE TABLE IF NOT EXISTS website_pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slug TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                body_md TEXT NOT NULL DEFAULT '',
                parent_slug TEXT,
                ord INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_website_pages_parent ON website_pages(parent_slug);

            CREATE TABLE IF NOT EXISTS website_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL UNIQUE,
                file_size INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS known_devices (
                username TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                PRIMARY KEY (username, fingerprint)
            );
            CREATE INDEX IF NOT EXISTS idx_known_devices_user ON known_devices(username);

            CREATE TABLE IF NOT EXISTS login_tokens (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                device_fp TEXT NOT NULL,
                device_label TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_login_tokens_expires ON login_tokens(expires_at);

            CREATE TABLE IF NOT EXISTS totp_backup_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_totp_backup_user ON totp_backup_codes(username);

            CREATE TABLE IF NOT EXISTS api_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                token_prefix TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(username);",
            )
            .map_err(|e| LicenseError::Other(format!("DB init: {}", e)))?;
        self.migrate()?;
        Ok(())
    }

    fn migrate(&self) -> Result<(), LicenseError> {
        // Add lease columns to existing databases
        let _ = self.conn.execute_batch(
            "ALTER TABLE licenses ADD COLUMN lease_duration_hours INTEGER NOT NULL DEFAULT 168;
             ALTER TABLE licenses ADD COLUMN lease_grace_hours INTEGER NOT NULL DEFAULT 24;
             ALTER TABLE machine_activations ADD COLUMN lease_expires_at TEXT NOT NULL DEFAULT '';"
        );
        // Add workspace_id to releases for per-workspace scoping
        let _ = self.conn.execute_batch(
            "ALTER TABLE releases ADD COLUMN workspace_id TEXT DEFAULT NULL;"
        );

        // Add name column to config_revisions
        let _ = self.conn.execute_batch(
            "ALTER TABLE config_revisions ADD COLUMN name TEXT NOT NULL DEFAULT '';"
        );

        // Add role column to users (existing users default to admin)
        let _ = self.conn.execute_batch(
            "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';"
        );

        // Tag doc pages / assets with their origin so a new release tag can
        // inherit hand-authored pages from the prior release without dragging
        // along the pipeline-regenerated ones. Existing rows default to 'user'
        // — safe because it keeps them in the carry-over set; next pipeline run
        // re-stamps its own pages as 'pipeline'.
        let _ = self.conn.execute_batch(
            "ALTER TABLE doc_pages ADD COLUMN origin TEXT NOT NULL DEFAULT 'user';
             ALTER TABLE doc_assets ADD COLUMN origin TEXT NOT NULL DEFAULT 'user';"
        );

        // Add email column to users (nullable — admin sets it per user)
        let _ = self.conn.execute_batch(
            "ALTER TABLE users ADD COLUMN email TEXT;"
        );

        // Migrate single-admin table to multi-user table
        let has_admin_user: bool = self.conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='admin_user'",
                [], |r| r.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if has_admin_user {
            let _ = self.conn.execute_batch(
                "INSERT OR IGNORE INTO users (username, password_hash, must_change_password, totp_secret, totp_enabled, created_at, updated_at)
                 SELECT 'admin', password_hash, must_change_password, totp_secret, totp_enabled, created_at, updated_at FROM admin_user WHERE id = 1;
                 DROP TABLE admin_user;"
            );
        }
        Ok(())
    }

    /// Delete machine activations whose lease has expired (cleanup on access).
    pub fn cleanup_expired_leases(&self, license_id: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "DELETE FROM machine_activations
                 WHERE license_id = ?1 AND lease_expires_at != '' AND lease_expires_at < ?2",
                params![license_id, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB cleanup: {}", e)))?;
        Ok(())
    }

    pub fn insert_license(&self, license: &License) -> Result<(), LicenseError> {
        let features_json = serde_json::to_string(&license.features)?;
        let expires_str = license
            .expires
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        self.conn
            .execute(
                "INSERT INTO licenses (id, product, customer, license_key, created, expires, features, max_machines, revoked, lease_duration_hours, lease_grace_hours)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    license.id,
                    license.product,
                    license.customer,
                    license.license_key,
                    license.created.to_rfc3339(),
                    expires_str,
                    features_json,
                    license.max_machines,
                    license.revoked as i32,
                    license.lease_duration_hours,
                    license.lease_grace_hours,
                ],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
        Ok(())
    }

    pub fn get_license_by_key(&self, license_key: &str) -> Result<Option<License>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, product, customer, license_key, created, expires, features, max_machines, revoked, lease_duration_hours, lease_grace_hours
             FROM licenses WHERE license_key = ?1",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;

        let mut rows = stmt
            .query(params![license_key])
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;

        let row = match rows
            .next()
            .map_err(|e| LicenseError::Other(format!("DB next: {}", e)))?
        {
            Some(r) => r,
            None => return Ok(None),
        };

        let id: String = row
            .get(0)
            .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?;
        let features_json: String = row
            .get(6)
            .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?;
        let features: Vec<String> = serde_json::from_str(&features_json)?;

        let created_str: String = row
            .get(4)
            .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?;
        let expires_str: String = row
            .get(5)
            .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?;

        let created = DateTime::parse_from_rfc3339(&created_str)
            .map_err(|e| LicenseError::Other(format!("Date parse: {}", e)))?
            .with_timezone(&Utc);
        let expires = if expires_str.is_empty() {
            None
        } else {
            Some(
                DateTime::parse_from_rfc3339(&expires_str)
                    .map_err(|e| LicenseError::Other(format!("Date parse: {}", e)))?
                    .with_timezone(&Utc),
            )
        };

        let lease_duration_hours: u32 = row
            .get(9)
            .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?;

        // Cleanup expired leases immediately
        self.cleanup_expired_leases(&id)?;

        let mut license = License {
            id: id.clone(),
            product: row
                .get(1)
                .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?,
            customer: row
                .get(2)
                .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?,
            license_key: row
                .get(3)
                .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?,
            created,
            expires,
            features,
            max_machines: row
                .get::<_, u32>(7)
                .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?,
            lease_duration_hours,
            lease_grace_hours: row
                .get(10)
                .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?,
            machines: Vec::new(),
            revoked: row
                .get::<_, i32>(8)
                .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?
                != 0,
        };

        license.machines = self.get_machine_activations(&id)?;
        Ok(Some(license))
    }

    fn get_machine_activations(
        &self,
        license_id: &str,
    ) -> Result<Vec<MachineActivation>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT machine_code, friendly_name, activated_at, lease_expires_at
             FROM machine_activations WHERE license_id = ?1",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;

        let activations = stmt
            .query_map(params![license_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .filter_map(|(machine_code, friendly_name, activated_str, lease_str)| {
                let activated_at = DateTime::parse_from_rfc3339(&activated_str)
                    .ok()?
                    .with_timezone(&Utc);
                let lease_expires_at = if lease_str.is_empty() {
                    None
                } else {
                    Some(
                        DateTime::parse_from_rfc3339(&lease_str)
                            .ok()?
                            .with_timezone(&Utc),
                    )
                };
                Some(MachineActivation {
                    machine_code,
                    friendly_name,
                    activated_at,
                    lease_expires_at,
                })
            })
            .collect();

        Ok(activations)
    }

    pub fn add_machine_activation(
        &self,
        license_id: &str,
        machine_code: &str,
        friendly_name: &str,
        lease_expires_at: Option<DateTime<Utc>>,
    ) -> Result<(), LicenseError> {
        let lease_str = lease_expires_at
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        self.conn
            .execute(
                "INSERT INTO machine_activations (license_id, machine_code, friendly_name, activated_at, lease_expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(license_id, machine_code) DO UPDATE SET
                friendly_name = excluded.friendly_name,
                activated_at = excluded.activated_at,
                lease_expires_at = excluded.lease_expires_at",
                params![
                    license_id,
                    machine_code,
                    friendly_name,
                    Utc::now().to_rfc3339(),
                    lease_str,
                ],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
        Ok(())
    }

    pub fn remove_machine_activation(
        &self,
        license_id: &str,
        machine_code: &str,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "DELETE FROM machine_activations WHERE license_id = ?1 AND machine_code = ?2",
                params![license_id, machine_code],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(())
    }

    /// Record a tombstone so the given machine cannot silently self-reactivate
    /// for `ttl_hours` after an admin removal. An existing tombstone is
    /// overwritten (the expiry refreshes).
    pub fn add_machine_tombstone(
        &self,
        license_id: &str,
        machine_code: &str,
        ttl_hours: i64,
    ) -> Result<(), LicenseError> {
        let now = Utc::now();
        let expires = now + Duration::hours(ttl_hours.max(0));
        self.conn
            .execute(
                "INSERT INTO machine_tombstones (license_id, machine_code, removed_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(license_id, machine_code) DO UPDATE SET
                    removed_at = excluded.removed_at,
                    expires_at = excluded.expires_at",
                params![
                    license_id,
                    machine_code,
                    now.to_rfc3339(),
                    expires.to_rfc3339(),
                ],
            )
            .map_err(|e| LicenseError::Other(format!("DB tombstone insert: {}", e)))?;
        Ok(())
    }

    /// Return the tombstone expiry if the machine is currently tombstoned.
    /// Expired tombstones are pruned opportunistically and return `None`.
    pub fn machine_tombstone_expires_at(
        &self,
        license_id: &str,
        machine_code: &str,
    ) -> Result<Option<DateTime<Utc>>, LicenseError> {
        let now = Utc::now();
        self.conn
            .execute(
                "DELETE FROM machine_tombstones WHERE expires_at < ?1",
                params![now.to_rfc3339()],
            )
            .map_err(|e| LicenseError::Other(format!("DB tombstone prune: {}", e)))?;

        let expires: Option<String> = self
            .conn
            .query_row(
                "SELECT expires_at FROM machine_tombstones WHERE license_id = ?1 AND machine_code = ?2",
                params![license_id, machine_code],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB tombstone query: {}", e)))?;

        Ok(expires.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))))
    }

    /// Drop a tombstone, e.g. when an admin re-adds the machine.
    pub fn clear_machine_tombstone(
        &self,
        license_id: &str,
        machine_code: &str,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "DELETE FROM machine_tombstones WHERE license_id = ?1 AND machine_code = ?2",
                params![license_id, machine_code],
            )
            .map_err(|e| LicenseError::Other(format!("DB tombstone delete: {}", e)))?;
        Ok(())
    }

    pub fn revoke_license(&self, license_key: &str) -> Result<bool, LicenseError> {
        let rows = self
            .conn
            .execute(
                "UPDATE licenses SET revoked = 1 WHERE license_key = ?1",
                params![license_key],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(rows > 0)
    }

    pub fn delete_license(&self, license_key: &str) -> Result<bool, LicenseError> {
        let id: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM licenses WHERE license_key = ?1",
                params![license_key],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        let Some(id) = id else { return Ok(false) };
        self.conn
            .execute("DELETE FROM machine_activations WHERE license_id = ?1", params![id])
            .map_err(|e| LicenseError::Other(format!("DB delete machines: {}", e)))?;
        let rows = self
            .conn
            .execute(
                "DELETE FROM licenses WHERE license_key = ?1",
                params![license_key],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(rows > 0)
    }

    pub fn update_license(
        &self,
        license_key: &str,
        customer: &str,
        product: &str,
        expires: Option<&str>,
        features: &[String],
        max_machines: u32,
    ) -> Result<bool, LicenseError> {
        let features_json = serde_json::to_string(features)?;
        let expires_str = expires.unwrap_or("");
        let rows = self
            .conn
            .execute(
                "UPDATE licenses SET customer = ?1, product = ?2, expires = ?3, features = ?4, max_machines = ?5 WHERE license_key = ?6",
                params![customer, product, expires_str, features_json, max_machines, license_key],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(rows > 0)
    }

    // -----------------------------------------------------------------------
    // User management
    // -----------------------------------------------------------------------

    pub fn seed_admin(&self, password_hash: &str) -> Result<bool, LicenseError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        if count > 0 {
            return Ok(false);
        }
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO users (username, password_hash, role, must_change_password, totp_enabled, created_at, updated_at)
                 VALUES ('admin', ?1, 'admin', 1, 0, ?2, ?2)",
                params![password_hash, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
        Ok(true)
    }

    pub fn get_user_password_hash(&self, username: &str) -> Result<String, LicenseError> {
        self.conn
            .query_row(
                "SELECT password_hash FROM users WHERE username = ?1",
                params![username],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    pub fn user_must_change_password(&self, username: &str) -> Result<bool, LicenseError> {
        let v: i32 = self
            .conn
            .query_row(
                "SELECT must_change_password FROM users WHERE username = ?1",
                params![username],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(v != 0)
    }

    pub fn user_totp_enabled(&self, username: &str) -> Result<bool, LicenseError> {
        let v: i32 = self
            .conn
            .query_row(
                "SELECT totp_enabled FROM users WHERE username = ?1",
                params![username],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(v != 0)
    }

    pub fn get_user_totp_secret(&self, username: &str) -> Result<Option<String>, LicenseError> {
        self.conn
            .query_row(
                "SELECT totp_secret FROM users WHERE username = ?1",
                params![username],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    pub fn update_user_password(&self, username: &str, new_hash: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE users SET password_hash = ?1, must_change_password = 0, updated_at = ?2 WHERE username = ?3",
                params![new_hash, now, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    pub fn set_user_totp_secret(&self, username: &str, secret: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE users SET totp_secret = ?1, totp_enabled = 0, updated_at = ?2 WHERE username = ?3",
                params![secret, now, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    pub fn enable_user_totp(&self, username: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE users SET totp_enabled = 1, updated_at = ?1 WHERE username = ?2",
                params![now, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    pub fn disable_user_totp(&self, username: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE users SET totp_secret = NULL, totp_enabled = 0, updated_at = ?1 WHERE username = ?2",
                params![now, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    pub fn list_users(&self) -> Result<Vec<UserInfo>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT username, role, totp_enabled, must_change_password, created_at, email FROM users ORDER BY created_at")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let users = stmt
            .query_map([], |r| {
                Ok(UserInfo {
                    username: r.get(0)?,
                    role: r.get(1)?,
                    totp_enabled: r.get::<_, i32>(2)? != 0,
                    must_change_password: r.get::<_, i32>(3)? != 0,
                    created_at: r.get(4)?,
                    email: r.get(5)?,
                })
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(users)
    }

    pub fn get_user_email(&self, username: &str) -> Result<Option<String>, LicenseError> {
        self.conn
            .query_row(
                "SELECT email FROM users WHERE username = ?1",
                params![username],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    pub fn set_user_email(&self, username: &str, email: Option<&str>) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE users SET email = ?1, updated_at = ?2 WHERE username = ?3",
                params![email, now, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Known devices (trusted-device gate for login)
    // -----------------------------------------------------------------------

    pub fn is_device_known(&self, username: &str, fingerprint: &str) -> Result<bool, LicenseError> {
        let count: i64 = self.conn
            .query_row(
                "SELECT COUNT(*) FROM known_devices WHERE username = ?1 AND fingerprint = ?2",
                params![username, fingerprint],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(count > 0)
    }

    /// Insert a new trusted-device row, or refresh last_seen + label if it already exists.
    pub fn register_device(
        &self,
        username: &str,
        fingerprint: &str,
        label: &str,
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO known_devices (username, fingerprint, label, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(username, fingerprint) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    label = CASE WHEN excluded.label != '' THEN excluded.label ELSE known_devices.label END",
                params![username, fingerprint, label, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert: {}", e)))?;
        Ok(())
    }

    pub fn touch_device(&self, username: &str, fingerprint: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE known_devices SET last_seen = ?1 WHERE username = ?2 AND fingerprint = ?3",
                params![now, username, fingerprint],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    pub fn list_devices(&self, username: &str) -> Result<Vec<DeviceInfo>, LicenseError> {
        let mut stmt = self.conn
            .prepare("SELECT fingerprint, label, first_seen, last_seen FROM known_devices WHERE username = ?1 ORDER BY last_seen DESC")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![username], |r| {
                Ok(DeviceInfo {
                    fingerprint: r.get(0)?,
                    label: r.get(1)?,
                    first_seen: r.get(2)?,
                    last_seen: r.get(3)?,
                })
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn revoke_device(&self, username: &str, fingerprint: &str) -> Result<bool, LicenseError> {
        let n = self.conn
            .execute(
                "DELETE FROM known_devices WHERE username = ?1 AND fingerprint = ?2",
                params![username, fingerprint],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(n > 0)
    }

    // -----------------------------------------------------------------------
    // Magic-link login tokens
    // -----------------------------------------------------------------------

    pub fn insert_login_token(
        &self,
        token_hash: &str,
        username: &str,
        device_fp: &str,
        device_label: &str,
        ttl_seconds: i64,
    ) -> Result<(), LicenseError> {
        let now = Utc::now();
        let expires = now + Duration::seconds(ttl_seconds);
        self.conn
            .execute(
                "INSERT INTO login_tokens (token_hash, username, device_fp, device_label, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![token_hash, username, device_fp, device_label, now.to_rfc3339(), expires.to_rfc3339()],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
        Ok(())
    }

    /// Look up a magic-link token WITHOUT consuming it. Returns the row only
    /// if it is unknown-unused AND still within its TTL — the same validity
    /// rules `consume_login_token` applies, minus the mark-as-used step.
    ///
    /// This exists because magic-link exchange may require a second input
    /// (e.g. a TOTP code) before the server has enough to issue a JWT. If we
    /// consumed up-front, a legitimate user who missed the TOTP prompt would
    /// be stuck with a spent token.
    pub fn peek_login_token(&self, token_hash: &str) -> Result<Option<LoginTokenRow>, LicenseError> {
        let row: Option<(String, String, String, String, Option<String>)> = self
            .conn
            .query_row(
                "SELECT username, device_fp, device_label, expires_at, used_at FROM login_tokens WHERE token_hash = ?1",
                params![token_hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        let Some((username, device_fp, device_label, expires_at, used_at)) = row else {
            return Ok(None);
        };
        if used_at.is_some() {
            return Ok(None);
        }
        let expires: DateTime<Utc> = DateTime::parse_from_rfc3339(&expires_at)
            .map_err(|e| LicenseError::Other(format!("Bad token expires_at: {}", e)))?
            .with_timezone(&Utc);
        if Utc::now() > expires {
            return Ok(None);
        }
        Ok(Some(LoginTokenRow { username, device_fp, device_label }))
    }

    /// Validate a magic-link token and mark it as consumed.
    ///
    /// Returns the (username, device_fp, device_label) on success. Returns
    /// `Ok(None)` if the token is unknown, already used, or expired. The token
    /// is single-use — once consumed, subsequent lookups return `None`.
    pub fn consume_login_token(&self, token_hash: &str) -> Result<Option<LoginTokenRow>, LicenseError> {
        let row: Option<(String, String, String, String, Option<String>)> = self
            .conn
            .query_row(
                "SELECT username, device_fp, device_label, expires_at, used_at FROM login_tokens WHERE token_hash = ?1",
                params![token_hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;

        let Some((username, device_fp, device_label, expires_at, used_at)) = row else {
            return Ok(None);
        };
        if used_at.is_some() {
            return Ok(None);
        }
        let expires: DateTime<Utc> = DateTime::parse_from_rfc3339(&expires_at)
            .map_err(|e| LicenseError::Other(format!("Bad token expires_at: {}", e)))?
            .with_timezone(&Utc);
        if Utc::now() > expires {
            return Ok(None);
        }

        let now = Utc::now().to_rfc3339();
        let n = self.conn
            .execute(
                "UPDATE login_tokens SET used_at = ?1 WHERE token_hash = ?2 AND used_at IS NULL",
                params![now, token_hash],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        if n == 0 {
            // Race — another consumer beat us to it.
            return Ok(None);
        }
        Ok(Some(LoginTokenRow { username, device_fp, device_label }))
    }

    // -----------------------------------------------------------------------
    // TOTP backup codes
    // -----------------------------------------------------------------------

    /// Replace the set of backup codes for a user. Atomic: wipes previous rows
    /// (used or not) before inserting the new hashes. The caller is expected
    /// to keep the raw codes only until they've been shown to the user.
    pub fn replace_backup_codes(
        &self,
        username: &str,
        hashes: &[String],
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        let tx = self.conn.unchecked_transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;
        tx.execute("DELETE FROM totp_backup_codes WHERE username = ?1", params![username])
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        for h in hashes {
            tx.execute(
                "INSERT INTO totp_backup_codes (username, code_hash, created_at) VALUES (?1, ?2, ?3)",
                params![username, h, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert backup: {}", e)))?;
        }
        tx.commit().map_err(|e| LicenseError::Other(format!("DB commit: {}", e)))?;
        Ok(())
    }

    pub fn clear_backup_codes(&self, username: &str) -> Result<(), LicenseError> {
        self.conn
            .execute("DELETE FROM totp_backup_codes WHERE username = ?1", params![username])
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(())
    }

    pub fn list_unused_backup_codes(
        &self,
        username: &str,
    ) -> Result<Vec<(i64, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, code_hash FROM totp_backup_codes WHERE username = ?1 AND used_at IS NULL",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![username], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn count_unused_backup_codes(&self, username: &str) -> Result<usize, LicenseError> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM totp_backup_codes WHERE username = ?1 AND used_at IS NULL",
                params![username],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(n as usize)
    }

    /// Mark a backup-code row used. Returns true iff a previously-unused row
    /// was flipped — false for already-used or unknown IDs (guards against race).
    pub fn consume_backup_code(&self, id: i64) -> Result<bool, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let n = self
            .conn
            .execute(
                "UPDATE totp_backup_codes SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL",
                params![now, id],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(n > 0)
    }

    // -----------------------------------------------------------------------
    // API tokens (long-lived bearer tokens for service accounts)
    // -----------------------------------------------------------------------

    pub fn insert_api_token(
        &self,
        username: &str,
        name: &str,
        token_hash: &str,
        token_prefix: &str,
    ) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO api_tokens (username, name, token_hash, token_prefix, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![username, name, token_hash, token_prefix, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Lookup by hash, returning the minimum needed to authorize a request.
    /// Auth-hot path — must be cheap.
    pub fn find_api_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<ApiTokenAuthRow>, LicenseError> {
        self.conn
            .query_row(
                "SELECT id, username, revoked_at FROM api_tokens WHERE token_hash = ?1",
                params![token_hash],
                |r| {
                    Ok(ApiTokenAuthRow {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        revoked: r.get::<_, Option<String>>(2)?.is_some(),
                    })
                },
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    /// Update last_used_at. Called on every authenticated request — best-effort,
    /// callers ignore errors so a transient DB hiccup doesn't 500 the request.
    pub fn touch_api_token_used(&self, id: i64) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute("UPDATE api_tokens SET last_used_at = ?1 WHERE id = ?2", params![now, id])
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    pub fn list_api_tokens_for_user(&self, username: &str) -> Result<Vec<ApiTokenInfo>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, username, name, token_prefix, created_at, last_used_at, revoked_at
                 FROM api_tokens WHERE username = ?1 ORDER BY created_at DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![username], row_to_api_token_info)
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn list_all_api_tokens(&self) -> Result<Vec<ApiTokenInfo>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, username, name, token_prefix, created_at, last_used_at, revoked_at
                 FROM api_tokens ORDER BY username, created_at DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], row_to_api_token_info)
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Mark token revoked. Returns true if a previously-unrevoked row was
    /// flipped, false if the row was unknown or already revoked.
    pub fn revoke_api_token(&self, id: i64) -> Result<bool, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let n = self.conn
            .execute(
                "UPDATE api_tokens SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
                params![now, id],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(n > 0)
    }

    /// Look up just the owning username — used for permission checks (e.g.
    /// "is this token-id owned by the caller before they revoke it").
    pub fn get_api_token_owner(&self, id: i64) -> Result<Option<String>, LicenseError> {
        self.conn
            .query_row(
                "SELECT username FROM api_tokens WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    /// Delete expired or consumed tokens older than 24h. Housekeeping; safe to ignore errors.
    pub fn purge_old_login_tokens(&self) -> Result<(), LicenseError> {
        let cutoff = (Utc::now() - Duration::hours(24)).to_rfc3339();
        self.conn
            .execute(
                "DELETE FROM login_tokens WHERE expires_at < ?1 OR (used_at IS NOT NULL AND used_at < ?1)",
                params![cutoff],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(())
    }

    pub fn create_user(&self, username: &str, password_hash: &str, role: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO users (username, password_hash, role, must_change_password, totp_enabled, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 1, 0, ?4, ?4)",
                params![username, password_hash, role, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
        Ok(())
    }

    pub fn delete_user(&self, username: &str) -> Result<(), LicenseError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        if count <= 1 {
            return Err(LicenseError::Other("Cannot delete the last user".into()));
        }
        self.conn
            .execute("DELETE FROM users WHERE username = ?1", params![username])
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(())
    }

    pub fn get_user_role(&self, username: &str) -> Result<String, LicenseError> {
        self.conn
            .query_row(
                "SELECT role FROM users WHERE username = ?1",
                params![username],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    pub fn user_exists(&self, username: &str) -> Result<bool, LicenseError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE username = ?1",
                params![username],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(count > 0)
    }

    pub fn rename_user(&self, old_username: &str, new_username: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE users SET username = ?1, updated_at = ?2 WHERE username = ?3",
                params![new_username, now, old_username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        self.conn
            .execute(
                "UPDATE workspace_members SET username = ?1 WHERE username = ?2",
                params![new_username, old_username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        self.conn
            .execute(
                "UPDATE workspaces SET created_by = ?1 WHERE created_by = ?2",
                params![new_username, old_username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    pub fn reset_user_password(&self, username: &str, new_hash: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE users SET password_hash = ?1, must_change_password = 1, updated_at = ?2 WHERE username = ?3",
                params![new_hash, now, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Workspaces
    // -----------------------------------------------------------------------

    pub fn create_workspace(
        &self,
        id: &str,
        name: &str,
        product: &str,
        description: &str,
        created_by: &str,
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO workspaces (id, name, product, description, created_by, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                params![id, name, product, description, created_by, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert workspace: {}", e)))?;
        // Add creator as owner
        self.conn
            .execute(
                "INSERT INTO workspace_members (workspace_id, username, role, added_at)
                 VALUES (?1, ?2, 'owner', ?3)",
                params![id, created_by, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert workspace member: {}", e)))?;
        Ok(())
    }

    pub fn get_workspace(
        &self,
        id: &str,
    ) -> Result<Option<(String, String, String, String, String, String, String)>, LicenseError> {
        match self.conn.query_row(
            "SELECT id, name, product, description, created_by, created_at, updated_at
             FROM workspaces WHERE id = ?1",
            params![id],
            |r| Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
            )),
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    pub fn list_workspaces_for_user(
        &self,
        username: &str,
    ) -> Result<Vec<(String, String, String, String, String, String, String, String)>, LicenseError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT w.id, w.name, w.product, w.description, w.created_by, w.created_at, w.updated_at, wm.role
                 FROM workspaces w
                 JOIN workspace_members wm ON w.id = wm.workspace_id
                 WHERE wm.username = ?1
                 ORDER BY w.name"
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![username], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn update_workspace(
        &self,
        id: &str,
        name: &str,
        product: &str,
        description: &str,
    ) -> Result<bool, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let rows = self.conn
            .execute(
                "UPDATE workspaces SET name = ?1, product = ?2, description = ?3, updated_at = ?4 WHERE id = ?5",
                params![name, product, description, now, id],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(rows > 0)
    }

    pub fn delete_workspace(&self, id: &str) -> Result<bool, LicenseError> {
        let rows = self.conn
            .execute("DELETE FROM workspaces WHERE id = ?1", params![id])
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(rows > 0)
    }

    // -----------------------------------------------------------------------
    // Workspace members
    // -----------------------------------------------------------------------

    pub fn add_workspace_member(
        &self,
        workspace_id: &str,
        username: &str,
        role: &str,
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO workspace_members (workspace_id, username, role, added_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(workspace_id, username) DO UPDATE SET role = excluded.role",
                params![workspace_id, username, role, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert member: {}", e)))?;
        Ok(())
    }

    pub fn remove_workspace_member(
        &self,
        workspace_id: &str,
        username: &str,
    ) -> Result<bool, LicenseError> {
        let rows = self.conn
            .execute(
                "DELETE FROM workspace_members WHERE workspace_id = ?1 AND username = ?2",
                params![workspace_id, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete member: {}", e)))?;
        Ok(rows > 0)
    }

    pub fn list_workspace_members(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<(String, String, String)>, LicenseError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT username, role, added_at FROM workspace_members WHERE workspace_id = ?1 ORDER BY added_at"
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![workspace_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn get_workspace_member_role(
        &self,
        workspace_id: &str,
        username: &str,
    ) -> Result<Option<String>, LicenseError> {
        match self.conn.query_row(
            "SELECT role FROM workspace_members WHERE workspace_id = ?1 AND username = ?2",
            params![workspace_id, username],
            |r| r.get(0),
        ) {
            Ok(role) => Ok(Some(role)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    // -----------------------------------------------------------------------
    // Config revisions
    // -----------------------------------------------------------------------

    pub fn push_config_revision(
        &self,
        workspace_id: &str,
        config_json: &str,
        name: &str,
        description: &str,
        author: &str,
    ) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let next_version: i64 = self.conn
            .query_row(
                "SELECT COALESCE(MAX(version), -1) + 1 FROM config_revisions WHERE workspace_id = ?1",
                params![workspace_id],
                |row| row.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query max version: {}", e)))?;
        self.conn
            .execute(
                "INSERT INTO config_revisions (workspace_id, version, config_json, name, description, author, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![workspace_id, next_version, config_json, name, description, author, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert config: {}", e)))?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_config_revisions(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<(i64, String, String, String, String)>, LicenseError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT id, name, description, author, created_at
                 FROM config_revisions WHERE workspace_id = ?1
                 ORDER BY id DESC"
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![workspace_id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn get_config_revision(
        &self,
        workspace_id: &str,
        id: i64,
    ) -> Result<Option<(i64, String, String, String, String, String)>, LicenseError> {
        match self.conn.query_row(
            "SELECT id, config_json, name, description, author, created_at
             FROM config_revisions WHERE workspace_id = ?1 AND id = ?2",
            params![workspace_id, id],
            |r| Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            )),
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    pub fn get_latest_config_revision(
        &self,
        workspace_id: &str,
    ) -> Result<Option<(i64, String, String, String, String, String)>, LicenseError> {
        match self.conn.query_row(
            "SELECT id, config_json, name, description, author, created_at
             FROM config_revisions WHERE workspace_id = ?1
             ORDER BY id DESC LIMIT 1",
            params![workspace_id],
            |r| Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            )),
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    pub fn update_config_revision(
        &self,
        workspace_id: &str,
        id: i64,
        name: &str,
        description: &str,
        config_json: Option<&str>,
    ) -> Result<bool, LicenseError> {
        let affected = if let Some(cj) = config_json {
            self.conn.execute(
                "UPDATE config_revisions SET name = ?1, description = ?2, config_json = ?3
                 WHERE workspace_id = ?4 AND id = ?5",
                params![name, description, cj, workspace_id, id],
            )
        } else {
            self.conn.execute(
                "UPDATE config_revisions SET name = ?1, description = ?2
                 WHERE workspace_id = ?3 AND id = ?4",
                params![name, description, workspace_id, id],
            )
        }.map_err(|e| LicenseError::Other(format!("DB update config: {}", e)))?;
        Ok(affected > 0)
    }

    pub fn delete_config_revision(
        &self,
        workspace_id: &str,
        id: i64,
    ) -> Result<bool, LicenseError> {
        let affected = self.conn
            .execute(
                "DELETE FROM config_revisions WHERE workspace_id = ?1 AND id = ?2",
                params![workspace_id, id],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete config: {}", e)))?;
        Ok(affected > 0)
    }

    // -----------------------------------------------------------------------
    // Releases (with workspace scoping)
    // -----------------------------------------------------------------------

    pub fn insert_release(
        &self,
        tag: &str,
        name: &str,
        body: &str,
        prerelease: bool,
        workspace_id: Option<&str>,
    ) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO releases (tag, name, body, prerelease, created_at, workspace_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![tag, name, body, prerelease as i32, now, workspace_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert release: {}", e)))?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn add_release_asset(
        &self,
        release_id: i64,
        file_name: &str,
        file_size: u64,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT INTO release_assets (release_id, file_name, file_size) VALUES (?1, ?2, ?3)
                 ON CONFLICT(release_id, file_name) DO UPDATE SET file_size = excluded.file_size",
                params![release_id, file_name, file_size as i64],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert asset: {}", e)))?;
        Ok(())
    }

    /// Update metadata of an existing release without touching its id (so
    /// FKs from doc_pages / release_assets remain intact).
    pub fn update_release_metadata(
        &self,
        release_id: i64,
        name: &str,
        body: &str,
        prerelease: bool,
        workspace_id: Option<&str>,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "UPDATE releases SET name = ?1, body = ?2, prerelease = ?3, workspace_id = ?4 WHERE id = ?5",
                params![name, body, prerelease as i32, workspace_id, release_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB update release: {}", e)))?;
        Ok(())
    }

    pub fn list_releases(&self) -> Result<Vec<(i64, String, String, String, bool, String, Option<String>)>, LicenseError> {
        let mut stmt = self.conn
            .prepare("SELECT id, tag, name, body, prerelease, created_at, workspace_id FROM releases ORDER BY id DESC")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i32>(4)? != 0,
                    r.get::<_, String>(5)?,
                    r.get::<_, Option<String>>(6)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// List releases visible to a workspace (workspace-specific + global).
    pub fn list_releases_for_workspace(&self, workspace_id: &str) -> Result<Vec<(i64, String, String, String, bool, String)>, LicenseError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT id, tag, name, body, prerelease, created_at FROM releases
                 WHERE workspace_id = ?1 OR workspace_id IS NULL
                 ORDER BY id DESC"
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![workspace_id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i32>(4)? != 0,
                    r.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn get_release_assets(&self, release_id: i64) -> Result<Vec<(String, u64)>, LicenseError> {
        let mut stmt = self.conn
            .prepare("SELECT file_name, file_size FROM release_assets WHERE release_id = ?1")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![release_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn get_release_by_tag(&self, tag: &str) -> Result<Option<i64>, LicenseError> {
        match self.conn.query_row(
            "SELECT id FROM releases WHERE tag = ?1",
            params![tag],
            |r| r.get(0),
        ) {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    pub fn delete_release(&self, tag: &str) -> Result<bool, LicenseError> {
        let rows = self.conn
            .execute("DELETE FROM releases WHERE tag = ?1", params![tag])
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(rows > 0)
    }

    // -----------------------------------------------------------------------
    // License listing
    // -----------------------------------------------------------------------

    pub fn list_licenses(&self) -> Result<Vec<License>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, product, customer, license_key, created, expires, features, max_machines, revoked, lease_duration_hours, lease_grace_hours
             FROM licenses ORDER BY created DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, u32>(7)?,
                    row.get::<_, i32>(8)?,
                    row.get::<_, u32>(9)?,
                    row.get::<_, u32>(10)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;

        let mut licenses = Vec::new();
        for row in rows {
            let (
                id,
                product,
                customer,
                license_key,
                created_str,
                expires_str,
                features_json,
                max_machines,
                revoked,
                lease_duration_hours,
                lease_grace_hours,
            ) = row.map_err(|e| LicenseError::Other(format!("DB row: {}", e)))?;

            let features: Vec<String> = serde_json::from_str(&features_json).unwrap_or_default();
            let created = DateTime::parse_from_rfc3339(&created_str)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let expires = if expires_str.is_empty() {
                None
            } else {
                Some(
                    DateTime::parse_from_rfc3339(&expires_str)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                )
            };

            // Cleanup expired leases
            let _ = self.cleanup_expired_leases(&id);

            let machines = self.get_machine_activations(&id).unwrap_or_default();

            licenses.push(License {
                id,
                product,
                customer,
                license_key,
                created,
                expires,
                features,
                max_machines,
                lease_duration_hours,
                lease_grace_hours,
                machines,
                revoked: revoked != 0,
            });
        }

        Ok(licenses)
    }

    // -----------------------------------------------------------------------
    // Documentation pages (per-release knowledge base)
    // -----------------------------------------------------------------------

    /// Upsert a single page authored via the editor. Always marks the row as
    /// `origin='user'` — even if a prior pipeline run had planted the slug.
    /// Manual edits imply ownership: next pipeline run will skip it.
    pub fn upsert_doc_page(
        &self,
        release_id: i64,
        slug: &str,
        title: &str,
        body_md: &str,
        parent_slug: Option<&str>,
        ord: i64,
    ) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO doc_pages (release_id, slug, title, body_md, parent_slug, ord, updated_at, origin)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'user')
                 ON CONFLICT(release_id, slug) DO UPDATE SET
                   title = excluded.title,
                   body_md = excluded.body_md,
                   parent_slug = excluded.parent_slug,
                   ord = excluded.ord,
                   updated_at = excluded.updated_at,
                   origin = 'user'",
                params![release_id, slug, title, body_md, parent_slug, ord, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert doc page: {}", e)))?;
        let id = self.conn
            .query_row(
                "SELECT id FROM doc_pages WHERE release_id = ?1 AND slug = ?2",
                params![release_id, slug],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB lookup doc page: {}", e)))?;
        Ok(id)
    }

    /// List all pages of a release as (slug, title, parent_slug, ord, updated_at).
    pub fn list_doc_pages(
        &self,
        release_id: i64,
    ) -> Result<Vec<(String, String, Option<String>, i64, String)>, LicenseError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT slug, title, parent_slug, ord, updated_at FROM doc_pages
                 WHERE release_id = ?1 ORDER BY parent_slug NULLS FIRST, ord, title",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![release_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Fetch a single page (title, body_md, parent_slug, ord, updated_at).
    pub fn get_doc_page(
        &self,
        release_id: i64,
        slug: &str,
    ) -> Result<Option<(String, String, Option<String>, i64, String)>, LicenseError> {
        match self.conn.query_row(
            "SELECT title, body_md, parent_slug, ord, updated_at FROM doc_pages
             WHERE release_id = ?1 AND slug = ?2",
            params![release_id, slug],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    pub fn delete_doc_page(&self, release_id: i64, slug: &str) -> Result<bool, LicenseError> {
        let n = self.conn
            .execute(
                "DELETE FROM doc_pages WHERE release_id = ?1 AND slug = ?2",
                params![release_id, slug],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(n > 0)
    }

    /// Rename a page's slug atomically. Cascades to any child pages whose
    /// `parent_slug` pointed at the old value. Returns Ok(false) if the source
    /// page doesn't exist; Err on UNIQUE conflict (target slug already taken).
    pub fn rename_doc_page(
        &mut self,
        release_id: i64,
        old_slug: &str,
        new_slug: &str,
    ) -> Result<bool, LicenseError> {
        if old_slug == new_slug {
            return Ok(true);
        }
        let tx = self.conn.transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;
        let n = tx.execute(
            "UPDATE doc_pages SET slug = ?1 WHERE release_id = ?2 AND slug = ?3",
            params![new_slug, release_id, old_slug],
        ).map_err(|e| LicenseError::Other(format!("DB rename: {}", e)))?;
        if n == 0 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE doc_pages SET parent_slug = ?1 WHERE release_id = ?2 AND parent_slug = ?3",
            params![new_slug, release_id, old_slug],
        ).map_err(|e| LicenseError::Other(format!("DB rename cascade: {}", e)))?;
        tx.commit().map_err(|e| LicenseError::Other(format!("DB tx commit: {}", e)))?;
        Ok(true)
    }

    /// Bulk-upsert pages originating from the auto-generated pipeline. Within
    /// a single transaction: for each slug, if an existing row is
    /// `origin='user'` (i.e. the user has taken ownership via the editor) the
    /// page is left untouched and its slug is returned in the skipped list.
    /// Everything else is inserted or refreshed as `origin='pipeline'`.
    /// Returns (written_count, skipped_user_slugs).
    pub fn upsert_doc_pages(
        &mut self,
        release_id: i64,
        pages: &[(String, String, String, Option<String>, i64)],
    ) -> Result<(usize, Vec<String>), LicenseError> {
        let now = Utc::now().to_rfc3339();
        let tx = self.conn.transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;
        let mut written = 0usize;
        let mut skipped: Vec<String> = Vec::new();
        for (slug, title, body_md, parent_slug, ord) in pages {
            let existing_origin: Option<String> = tx
                .query_row(
                    "SELECT origin FROM doc_pages WHERE release_id = ?1 AND slug = ?2",
                    params![release_id, slug],
                    |r| r.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| LicenseError::Other(format!("DB origin probe {}: {}", slug, e)))?;
            if existing_origin.as_deref() == Some("user") {
                skipped.push(slug.clone());
                continue;
            }
            tx.execute(
                "INSERT INTO doc_pages (release_id, slug, title, body_md, parent_slug, ord, updated_at, origin)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pipeline')
                 ON CONFLICT(release_id, slug) DO UPDATE SET
                   title = excluded.title,
                   body_md = excluded.body_md,
                   parent_slug = excluded.parent_slug,
                   ord = excluded.ord,
                   updated_at = excluded.updated_at,
                   origin = 'pipeline'",
                params![release_id, slug, title, body_md, parent_slug.as_deref(), ord, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert page {}: {}", slug, e)))?;
            written += 1;
        }
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB commit: {}", e)))?;
        Ok((written, skipped))
    }

    /// Upsert an asset uploaded via the editor — always marks origin='user',
    /// including when overwriting a prior pipeline-planted row.
    pub fn upsert_doc_asset(
        &self,
        release_id: i64,
        file_name: &str,
        file_size: u64,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT INTO doc_assets (release_id, file_name, file_size, origin)
                 VALUES (?1, ?2, ?3, 'user')
                 ON CONFLICT(release_id, file_name) DO UPDATE SET
                   file_size = excluded.file_size,
                   origin = 'user'",
                params![release_id, file_name, file_size as i64],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert asset: {}", e)))?;
        Ok(())
    }

    /// Pipeline-side asset upsert. Skips rows whose existing origin='user' so
    /// hand-uploaded assets aren't clobbered. Returns true if written.
    pub fn upsert_doc_asset_pipeline(
        &self,
        release_id: i64,
        file_name: &str,
        file_size: u64,
    ) -> Result<bool, LicenseError> {
        let existing: Option<String> = self.conn
            .query_row(
                "SELECT origin FROM doc_assets WHERE release_id = ?1 AND file_name = ?2",
                params![release_id, file_name],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB asset origin probe: {}", e)))?;
        if existing.as_deref() == Some("user") {
            return Ok(false);
        }
        self.conn
            .execute(
                "INSERT INTO doc_assets (release_id, file_name, file_size, origin)
                 VALUES (?1, ?2, ?3, 'pipeline')
                 ON CONFLICT(release_id, file_name) DO UPDATE SET
                   file_size = excluded.file_size,
                   origin = 'pipeline'",
                params![release_id, file_name, file_size as i64],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert asset: {}", e)))?;
        Ok(true)
    }

    pub fn list_doc_assets(
        &self,
        release_id: i64,
    ) -> Result<Vec<(String, u64)>, LicenseError> {
        let mut stmt = self.conn
            .prepare("SELECT file_name, file_size FROM doc_assets WHERE release_id = ?1 ORDER BY file_name")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![release_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn delete_doc_asset(&self, release_id: i64, file_name: &str) -> Result<bool, LicenseError> {
        let n = self.conn
            .execute(
                "DELETE FROM doc_assets WHERE release_id = ?1 AND file_name = ?2",
                params![release_id, file_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(n > 0)
    }

    /// Releases that contain at least one doc page (newest first).
    /// Returns (id, tag, name, created_at, page_count).
    pub fn list_doc_releases(&self) -> Result<Vec<(i64, String, String, String, i64)>, LicenseError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT r.id, r.tag, r.name, r.created_at, COUNT(p.id)
                 FROM releases r
                 INNER JOIN doc_pages p ON p.release_id = r.id
                 GROUP BY r.id
                 ORDER BY r.id DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Ensure a release row exists for the given tag — used by bulk doc import
    /// when the docs ship before the binary release. Returns the release id.
    pub fn ensure_release(
        &self,
        tag: &str,
        name: &str,
    ) -> Result<i64, LicenseError> {
        Ok(self.ensure_release_created(tag, name)?.0)
    }

    /// Same as `ensure_release` but also signals whether the row was created
    /// (true) or already existed (false). Callers use the boolean to trigger
    /// one-shot seeding (e.g. copying hand-authored doc pages forward).
    pub fn ensure_release_created(
        &self,
        tag: &str,
        name: &str,
    ) -> Result<(i64, bool), LicenseError> {
        if let Some(id) = self.get_release_by_tag(tag)? {
            return Ok((id, false));
        }
        let id = self.insert_release(tag, name, "", false, None)?;
        Ok((id, true))
    }

    /// Return (id, tag) of the most recent release that has at least one
    /// `origin='user'` doc page, excluding a given release id. Used to seed a
    /// brand-new release tag with hand-authored content from the prior one.
    pub fn latest_prior_release_with_user_docs(
        &self,
        exclude_id: i64,
    ) -> Result<Option<(i64, String)>, LicenseError> {
        self.conn
            .query_row(
                "SELECT r.id, r.tag FROM releases r
                 WHERE r.id != ?1
                   AND EXISTS (
                       SELECT 1 FROM doc_pages p
                       WHERE p.release_id = r.id AND p.origin = 'user'
                   )
                 ORDER BY r.id DESC LIMIT 1",
                params![exclude_id],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB prior release: {}", e)))
    }

    /// Clone all `origin='user'` doc pages from `src_release_id` into
    /// `dst_release_id`. Slugs that already exist in the destination are left
    /// untouched (which shouldn't happen for a freshly created release, but
    /// makes the helper idempotent). Returns the number of pages inserted.
    pub fn copy_user_doc_pages(
        &mut self,
        src_release_id: i64,
        dst_release_id: i64,
    ) -> Result<usize, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let n = self.conn
            .execute(
                "INSERT OR IGNORE INTO doc_pages
                   (release_id, slug, title, body_md, parent_slug, ord, updated_at, origin)
                 SELECT ?1, slug, title, body_md, parent_slug, ord, ?2, 'user'
                 FROM doc_pages
                 WHERE release_id = ?3 AND origin = 'user'",
                params![dst_release_id, now, src_release_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB copy user pages: {}", e)))?;
        Ok(n)
    }

    /// Clone `origin='user'` asset rows between releases. Returns the list of
    /// file names so the caller can copy the backing files on disk (the DB
    /// only knows about metadata).
    pub fn copy_user_doc_asset_rows(
        &self,
        src_release_id: i64,
        dst_release_id: i64,
    ) -> Result<Vec<String>, LicenseError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT file_name, file_size FROM doc_assets
                 WHERE release_id = ?1 AND origin = 'user'",
            )
            .map_err(|e| LicenseError::Other(format!("DB prep: {}", e)))?;
        let rows: Vec<(String, i64)> = stmt
            .query_map(params![src_release_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        let mut copied = Vec::with_capacity(rows.len());
        for (name, size) in rows {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO doc_assets (release_id, file_name, file_size, origin)
                     VALUES (?1, ?2, ?3, 'user')",
                    params![dst_release_id, name, size],
                )
                .map_err(|e| LicenseError::Other(format!("DB insert asset: {}", e)))?;
            copied.push(name);
        }
        Ok(copied)
    }

    // -----------------------------------------------------------------------
    // Website pages / assets (single-site public page store, no releases)
    // -----------------------------------------------------------------------

    pub fn upsert_website_page(
        &self,
        slug: &str,
        title: &str,
        body_md: &str,
        parent_slug: Option<&str>,
        ord: i64,
    ) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO website_pages (slug, title, body_md, parent_slug, ord, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(slug) DO UPDATE SET
                   title = excluded.title,
                   body_md = excluded.body_md,
                   parent_slug = excluded.parent_slug,
                   ord = excluded.ord,
                   updated_at = excluded.updated_at",
                params![slug, title, body_md, parent_slug, ord, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert website page: {}", e)))?;
        let id = self.conn
            .query_row(
                "SELECT id FROM website_pages WHERE slug = ?1",
                params![slug],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB lookup website page: {}", e)))?;
        Ok(id)
    }

    pub fn list_website_pages(
        &self,
    ) -> Result<Vec<(String, String, Option<String>, i64, String)>, LicenseError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT slug, title, parent_slug, ord, updated_at FROM website_pages
                 ORDER BY parent_slug NULLS FIRST, ord, title",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn get_website_page(
        &self,
        slug: &str,
    ) -> Result<Option<(String, String, Option<String>, i64, String)>, LicenseError> {
        match self.conn.query_row(
            "SELECT title, body_md, parent_slug, ord, updated_at FROM website_pages
             WHERE slug = ?1",
            params![slug],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    pub fn delete_website_page(&self, slug: &str) -> Result<bool, LicenseError> {
        let n = self.conn
            .execute(
                "DELETE FROM website_pages WHERE slug = ?1",
                params![slug],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(n > 0)
    }

    /// Rename a website page slug, cascading `parent_slug` references.
    /// Returns Ok(false) if the source slug doesn't exist; Err on UNIQUE conflict.
    pub fn rename_website_page(
        &mut self,
        old_slug: &str,
        new_slug: &str,
    ) -> Result<bool, LicenseError> {
        if old_slug == new_slug {
            return Ok(true);
        }
        let tx = self.conn.transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;
        let n = tx.execute(
            "UPDATE website_pages SET slug = ?1 WHERE slug = ?2",
            params![new_slug, old_slug],
        ).map_err(|e| LicenseError::Other(format!("DB rename: {}", e)))?;
        if n == 0 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE website_pages SET parent_slug = ?1 WHERE parent_slug = ?2",
            params![new_slug, old_slug],
        ).map_err(|e| LicenseError::Other(format!("DB rename cascade: {}", e)))?;
        tx.commit().map_err(|e| LicenseError::Other(format!("DB tx commit: {}", e)))?;
        Ok(true)
    }

    pub fn upsert_website_asset(
        &self,
        file_name: &str,
        file_size: u64,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT INTO website_assets (file_name, file_size)
                 VALUES (?1, ?2)
                 ON CONFLICT(file_name) DO UPDATE SET file_size = excluded.file_size",
                params![file_name, file_size as i64],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert website asset: {}", e)))?;
        Ok(())
    }

    pub fn list_website_assets(&self) -> Result<Vec<(String, i64)>, LicenseError> {
        let mut stmt = self.conn
            .prepare("SELECT file_name, file_size FROM website_assets ORDER BY file_name")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn delete_website_asset(&self, file_name: &str) -> Result<bool, LicenseError> {
        let n = self.conn
            .execute(
                "DELETE FROM website_assets WHERE file_name = ?1",
                params![file_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete website asset: {}", e)))?;
        Ok(n > 0)
    }
}

fn row_to_api_token_info(r: &rusqlite::Row<'_>) -> rusqlite::Result<ApiTokenInfo> {
    Ok(ApiTokenInfo {
        id: r.get(0)?,
        username: r.get(1)?,
        name: r.get(2)?,
        token_prefix: r.get(3)?,
        created_at: r.get(4)?,
        last_used_at: r.get(5)?,
        revoked_at: r.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use crate::license::DEFAULT_LEASE_DURATION_HOURS;

    fn test_db() -> LicenseDb {
        LicenseDb::open(":memory:").unwrap()
    }

    fn lease_expires(hours: i64) -> Option<DateTime<Utc>> {
        Some(Utc::now() + Duration::hours(hours))
    }

    #[test]
    fn test_user_email_roundtrip() {
        let db = test_db();
        db.seed_admin("hash").unwrap();
        assert_eq!(db.get_user_email("admin").unwrap(), None);
        db.set_user_email("admin", Some("klaus@lp-research.com")).unwrap();
        assert_eq!(db.get_user_email("admin").unwrap().as_deref(), Some("klaus@lp-research.com"));
        db.set_user_email("admin", None).unwrap();
        assert_eq!(db.get_user_email("admin").unwrap(), None);
    }

    #[test]
    fn test_known_device_lifecycle() {
        let db = test_db();
        db.seed_admin("hash").unwrap();
        assert!(!db.is_device_known("admin", "fp1").unwrap());
        db.register_device("admin", "fp1", "Chrome / Linux").unwrap();
        assert!(db.is_device_known("admin", "fp1").unwrap());

        // Upsert on repeat — last_seen should update but no duplicate row.
        db.register_device("admin", "fp1", "").unwrap();
        let devices = db.list_devices("admin").unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].label, "Chrome / Linux");

        // Revoke
        assert!(db.revoke_device("admin", "fp1").unwrap());
        assert!(!db.is_device_known("admin", "fp1").unwrap());
        assert!(!db.revoke_device("admin", "fp1").unwrap());
    }

    #[test]
    fn test_login_token_consume_once() {
        let db = test_db();
        db.seed_admin("hash").unwrap();
        db.insert_login_token("hash1", "admin", "fp1", "Chrome", 900).unwrap();

        let row = db.consume_login_token("hash1").unwrap().expect("token valid");
        assert_eq!(row.username, "admin");
        assert_eq!(row.device_fp, "fp1");
        assert_eq!(row.device_label, "Chrome");

        // Second consume returns None (single-use).
        assert!(db.consume_login_token("hash1").unwrap().is_none());
    }

    #[test]
    fn test_peek_does_not_consume() {
        let db = test_db();
        db.seed_admin("hash").unwrap();
        db.insert_login_token("hashP", "admin", "fp1", "", 900).unwrap();
        // Peek twice — token should still be consumable after.
        assert!(db.peek_login_token("hashP").unwrap().is_some());
        assert!(db.peek_login_token("hashP").unwrap().is_some());
        assert!(db.consume_login_token("hashP").unwrap().is_some());
        // After consume, both peek and consume see nothing.
        assert!(db.peek_login_token("hashP").unwrap().is_none());
        assert!(db.consume_login_token("hashP").unwrap().is_none());
    }

    #[test]
    fn test_login_token_expired() {
        let db = test_db();
        db.seed_admin("hash").unwrap();
        // Insert with -1 TTL → already expired.
        db.insert_login_token("hash2", "admin", "fp1", "", -1).unwrap();
        assert!(db.consume_login_token("hash2").unwrap().is_none());
    }

    #[test]
    fn test_api_token_lifecycle() {
        let db = test_db();
        db.seed_admin("hash").unwrap();

        let id = db.insert_api_token("admin", "ci-bot", "h-abcdef", "susi_pat_ab").unwrap();
        let row = db.find_api_token_by_hash("h-abcdef").unwrap().expect("present");
        assert_eq!(row.id, id);
        assert_eq!(row.username, "admin");
        assert!(!row.revoked);

        let listed = db.list_api_tokens_for_user("admin").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "ci-bot");
        assert_eq!(listed[0].token_prefix, "susi_pat_ab");
        assert!(listed[0].last_used_at.is_none());

        db.touch_api_token_used(id).unwrap();
        let after = db.list_api_tokens_for_user("admin").unwrap();
        assert!(after[0].last_used_at.is_some());

        // Revoke flips once, returns false on second attempt.
        assert!(db.revoke_api_token(id).unwrap());
        assert!(!db.revoke_api_token(id).unwrap());

        // Lookup still finds it but reports revoked=true so the auth path can reject.
        let row = db.find_api_token_by_hash("h-abcdef").unwrap().expect("present");
        assert!(row.revoked);
    }

    #[test]
    fn test_api_token_unknown_hash_returns_none() {
        let db = test_db();
        db.seed_admin("hash").unwrap();
        assert!(db.find_api_token_by_hash("nope").unwrap().is_none());
    }

    #[test]
    fn test_api_token_get_owner() {
        let db = test_db();
        db.seed_admin("hash").unwrap();
        let id = db.insert_api_token("admin", "x", "h-x", "p-x").unwrap();
        assert_eq!(db.get_api_token_owner(id).unwrap().as_deref(), Some("admin"));
        assert_eq!(db.get_api_token_owner(999).unwrap(), None);
    }

    #[test]
    fn test_backup_codes_replace_and_consume() {
        let db = test_db();
        db.seed_admin("hash").unwrap();
        assert_eq!(db.count_unused_backup_codes("admin").unwrap(), 0);

        let hashes: Vec<String> = (0..8).map(|i| format!("hash-{}", i)).collect();
        db.replace_backup_codes("admin", &hashes).unwrap();
        assert_eq!(db.count_unused_backup_codes("admin").unwrap(), 8);

        let unused = db.list_unused_backup_codes("admin").unwrap();
        let id = unused[0].0;
        assert!(db.consume_backup_code(id).unwrap());
        assert_eq!(db.count_unused_backup_codes("admin").unwrap(), 7);
        // Double-consume returns false — race protection.
        assert!(!db.consume_backup_code(id).unwrap());

        // Replace wipes old rows (including used ones).
        let new_hashes: Vec<String> = (0..8).map(|i| format!("new-{}", i)).collect();
        db.replace_backup_codes("admin", &new_hashes).unwrap();
        assert_eq!(db.count_unused_backup_codes("admin").unwrap(), 8);
    }

    #[test]
    fn test_login_token_unknown_returns_none() {
        let db = test_db();
        db.seed_admin("hash").unwrap();
        assert!(db.consume_login_token("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_create_and_get_license() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test Corp".to_string(),
            Some(Utc::now() + Duration::days(365)),
            vec!["full_fusion".to_string()],
            3,
        );

        db.insert_license(&license).unwrap();

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.id, license.id);
        assert_eq!(retrieved.product, "FusionHub");
        assert_eq!(retrieved.customer, "Test Corp");
        assert_eq!(retrieved.features, vec!["full_fusion"]);
        assert_eq!(retrieved.max_machines, 3);
        assert_eq!(retrieved.lease_duration_hours, DEFAULT_LEASE_DURATION_HOURS);
        assert!(!retrieved.revoked);
    }

    #[test]
    fn test_machine_activations() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            2,
        );
        db.insert_license(&license).unwrap();

        let lease = lease_expires(168);
        db.add_machine_activation(&license.id, "machine1", "ECU-1", lease)
            .unwrap();
        db.add_machine_activation(&license.id, "machine2", "ECU-2", lease)
            .unwrap();

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.machines.len(), 2);
        assert!(retrieved.machines[0].lease_expires_at.is_some());

        db.remove_machine_activation(&license.id, "machine1")
            .unwrap();
        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.machines.len(), 1);
        assert_eq!(retrieved.machines[0].machine_code, "machine2");
    }

    #[test]
    fn test_machine_tombstone_lifecycle() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            2,
        );
        db.insert_license(&license).unwrap();

        // Nothing tombstoned initially
        assert!(db
            .machine_tombstone_expires_at(&license.id, "mX")
            .unwrap()
            .is_none());

        // Add tombstone — present with a future expiry
        db.add_machine_tombstone(&license.id, "mX", 24).unwrap();
        let exp = db
            .machine_tombstone_expires_at(&license.id, "mX")
            .unwrap()
            .expect("tombstone should be active");
        assert!(exp > Utc::now());

        // Clearing removes it
        db.clear_machine_tombstone(&license.id, "mX").unwrap();
        assert!(db
            .machine_tombstone_expires_at(&license.id, "mX")
            .unwrap()
            .is_none());
    }

    // --- Regression tests for "removed machine keeps coming back" bug ---
    //
    // Prior to the tombstone mechanism, a running client would call /activate
    // on every startup and immediately reclaim the slot an admin had just
    // removed. These tests replay the full sequence at the DB layer (which is
    // what the server's handle_activate / handle_deactivate_machine handlers
    // drive) so future refactors cannot silently break the invariant.

    /// Mirrors the relevant slice of `handle_activate`: tombstone check comes
    /// before the activation upsert. Returns Ok when the client would be
    /// allowed to activate, Err when the server would reject it.
    fn sim_client_activate(
        db: &LicenseDb,
        license_id: &str,
        machine_code: &str,
        friendly_name: &str,
    ) -> Result<(), String> {
        if let Some(exp) = db
            .machine_tombstone_expires_at(license_id, machine_code)
            .map_err(|e| e.to_string())?
        {
            return Err(format!("tombstoned until {}", exp));
        }
        db.add_machine_activation(license_id, machine_code, friendly_name, None)
            .map_err(|e| e.to_string())
    }

    /// Mirrors `handle_deactivate_machine` (admin path): remove + tombstone.
    fn sim_admin_remove(db: &LicenseDb, license_id: &str, machine_code: &str) {
        db.remove_machine_activation(license_id, machine_code).unwrap();
        db.add_machine_tombstone(license_id, machine_code, 24).unwrap();
    }

    /// Mirrors `handle_deactivate` (public client path): remove only, NO tombstone.
    fn sim_client_self_deactivate(db: &LicenseDb, license_id: &str, machine_code: &str) {
        db.remove_machine_activation(license_id, machine_code).unwrap();
    }

    #[test]
    fn regression_admin_remove_blocks_silent_reactivation() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            3,
        );
        db.insert_license(&license).unwrap();

        // Client activates on startup.
        sim_client_activate(&db, &license.id, "mc-laptop", "nico-lpLaptop").unwrap();
        assert_eq!(
            db.get_license_by_key(&license.license_key).unwrap().unwrap().machines.len(),
            1
        );

        // Admin removes the machine via the admin UI.
        sim_admin_remove(&db, &license.id, "mc-laptop");
        assert_eq!(
            db.get_license_by_key(&license.license_key).unwrap().unwrap().machines.len(),
            0
        );

        // Client restarts and tries to activate again. This MUST be blocked —
        // otherwise the admin's removal is effectively a no-op, which is the
        // exact bug we are guarding against.
        let err = sim_client_activate(&db, &license.id, "mc-laptop", "nico-lpLaptop").unwrap_err();
        assert!(err.contains("tombstoned"), "expected tombstone rejection, got: {}", err);
        assert_eq!(
            db.get_license_by_key(&license.license_key).unwrap().unwrap().machines.len(),
            0,
            "machine must NOT reappear after admin removal"
        );
    }

    #[test]
    fn regression_client_self_deactivate_does_not_tombstone() {
        // A user who hits "Remove THIS machine" in their own FusionHub UI is
        // explicitly resetting the install — they must be able to re-activate
        // immediately. Only *admin* removal is sticky.
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            1,
        );
        db.insert_license(&license).unwrap();

        sim_client_activate(&db, &license.id, "mc-1", "laptop").unwrap();
        sim_client_self_deactivate(&db, &license.id, "mc-1");
        // No tombstone should have been written.
        assert!(db.machine_tombstone_expires_at(&license.id, "mc-1").unwrap().is_none());
        // Re-activate must succeed right away.
        sim_client_activate(&db, &license.id, "mc-1", "laptop").unwrap();
        assert_eq!(
            db.get_license_by_key(&license.license_key).unwrap().unwrap().machines.len(),
            1
        );
    }

    #[test]
    fn regression_admin_clear_tombstone_unblocks_reactivation() {
        // Escape hatch: if an admin removes a machine by mistake, they can
        // clear the tombstone so the client re-activates on its next try.
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            1,
        );
        db.insert_license(&license).unwrap();

        sim_client_activate(&db, &license.id, "mc-oops", "laptop").unwrap();
        sim_admin_remove(&db, &license.id, "mc-oops");
        assert!(sim_client_activate(&db, &license.id, "mc-oops", "laptop").is_err());

        db.clear_machine_tombstone(&license.id, "mc-oops").unwrap();
        sim_client_activate(&db, &license.id, "mc-oops", "laptop").unwrap();
        assert_eq!(
            db.get_license_by_key(&license.license_key).unwrap().unwrap().machines.len(),
            1
        );
    }

    #[test]
    fn regression_stable_fingerprint_never_creates_duplicate_slots() {
        // The root cause of the ghost-slot buildup was the *same* machine
        // producing *different* fingerprints across restarts. With a stable
        // fingerprint, repeated activations of the same machine_code must
        // upsert into a single slot, never accumulate. (Locks in the
        // `UNIQUE(license_id, machine_code)` + ON CONFLICT behavior.)
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            5,
        );
        db.insert_license(&license).unwrap();

        for i in 0..10 {
            let name = format!("run-{}", i);
            sim_client_activate(&db, &license.id, "stable-mc", &name).unwrap();
        }
        let retrieved = db.get_license_by_key(&license.license_key).unwrap().unwrap();
        assert_eq!(retrieved.machines.len(), 1, "stable fingerprint must map to one slot");
        // Latest friendly name wins (upsert semantics).
        assert_eq!(retrieved.machines[0].friendly_name, "run-9");
    }

    #[test]
    fn test_machine_tombstone_auto_prunes_expired() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            1,
        );
        db.insert_license(&license).unwrap();

        // Insert an already-expired tombstone directly
        let past = (Utc::now() - Duration::hours(1)).to_rfc3339();
        db.conn
            .execute(
                "INSERT INTO machine_tombstones (license_id, machine_code, removed_at, expires_at) VALUES (?1, ?2, ?3, ?3)",
                params![&license.id, "stale", &past],
            )
            .unwrap();

        // Querying should both report None and prune the row
        assert!(db
            .machine_tombstone_expires_at(&license.id, "stale")
            .unwrap()
            .is_none());
        let count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM machine_tombstones WHERE license_id = ?1",
                params![&license.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_expired_lease_cleaned_on_access() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            1,
        );
        db.insert_license(&license).unwrap();

        // Add a machine with an already-expired lease
        let expired_lease = Some(Utc::now() - Duration::hours(1));
        db.add_machine_activation(&license.id, "old_machine", "Old", expired_lease)
            .unwrap();

        // Access triggers cleanup
        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.machines.len(), 0);
    }

    #[test]
    fn test_lease_renewal_updates_expiry() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            1,
        );
        db.insert_license(&license).unwrap();

        let lease1 = Some(Utc::now() + Duration::hours(1));
        db.add_machine_activation(&license.id, "machine1", "M1", lease1)
            .unwrap();

        // Renew with longer lease
        let lease2 = Some(Utc::now() + Duration::hours(168));
        db.add_machine_activation(&license.id, "machine1", "M1", lease2)
            .unwrap();

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.machines.len(), 1);
        // The lease should have been updated (closer to 168h than 1h from now)
        let lease_dt = retrieved.machines[0].lease_expires_at.unwrap();
        let hours_remaining = (lease_dt - Utc::now()).num_hours();
        assert!(hours_remaining > 100);
    }

    #[test]
    fn test_no_lease_activation() {
        let db = test_db();
        let mut license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            1,
        );
        license.lease_duration_hours = 0;
        db.insert_license(&license).unwrap();

        db.add_machine_activation(&license.id, "machine1", "M1", None)
            .unwrap();

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.machines.len(), 1);
        assert!(retrieved.machines[0].lease_expires_at.is_none());
    }

    #[test]
    fn test_revoke_license() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            0,
        );
        db.insert_license(&license).unwrap();

        let revoked = db.revoke_license(&license.license_key).unwrap();
        assert!(revoked);

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert!(retrieved.revoked);
    }

    #[test]
    fn test_list_licenses() {
        let db = test_db();
        for i in 0..3 {
            let license = License::new(
                "FusionHub".to_string(),
                format!("Customer {}", i),
                Some(Utc::now() + Duration::days(30)),
                vec![],
                0,
            );
            db.insert_license(&license).unwrap();
        }

        let all = db.list_licenses().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_get_nonexistent_license() {
        let db = test_db();
        let result = db.get_license_by_key("NONEXISTENT").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_perpetual_license_roundtrip() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Perpetual Corp".to_string(),
            None,
            vec!["full_fusion".to_string()],
            0,
        );
        db.insert_license(&license).unwrap();

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert!(retrieved.expires.is_none());
        assert!(!retrieved.is_expired());
    }

    #[test]
    fn test_duplicate_machine_renews() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            0,
        );
        db.insert_license(&license).unwrap();

        let lease = lease_expires(168);
        db.add_machine_activation(&license.id, "machine1", "M1", lease)
            .unwrap();
        db.add_machine_activation(&license.id, "machine1", "M1 again", lease)
            .unwrap();

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.machines.len(), 1);
        assert_eq!(retrieved.machines[0].friendly_name, "M1 again");
    }

    // -----------------------------------------------------------------------
    // Workspace tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_and_get_workspace() {
        let db = test_db();
        db.create_workspace("ws-1", "Test Workspace", "FusionHub", "A test", "admin").unwrap();

        let ws = db.get_workspace("ws-1").unwrap().unwrap();
        assert_eq!(ws.0, "ws-1");
        assert_eq!(ws.1, "Test Workspace");
        assert_eq!(ws.2, "FusionHub");
        assert_eq!(ws.3, "A test");
        assert_eq!(ws.4, "admin");
    }

    #[test]
    fn test_workspace_creator_is_owner() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();

        let role = db.get_workspace_member_role("ws-1", "admin").unwrap();
        assert_eq!(role, Some("owner".to_string()));
    }

    #[test]
    fn test_list_workspaces_for_user() {
        let db = test_db();
        db.create_workspace("ws-1", "One", "", "", "admin").unwrap();
        db.create_workspace("ws-2", "Two", "", "", "admin").unwrap();
        db.create_workspace("ws-3", "Three", "", "", "other").unwrap();

        let list = db.list_workspaces_for_user("admin").unwrap();
        assert_eq!(list.len(), 2);

        let list = db.list_workspaces_for_user("other").unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_workspace_members() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();

        db.add_workspace_member("ws-1", "user1", "editor").unwrap();
        db.add_workspace_member("ws-1", "user2", "viewer").unwrap();

        let members = db.list_workspace_members("ws-1").unwrap();
        assert_eq!(members.len(), 3); // admin + user1 + user2

        assert_eq!(db.get_workspace_member_role("ws-1", "user1").unwrap(), Some("editor".to_string()));
        assert_eq!(db.get_workspace_member_role("ws-1", "user2").unwrap(), Some("viewer".to_string()));
        assert_eq!(db.get_workspace_member_role("ws-1", "nobody").unwrap(), None);

        // Update role via upsert
        db.add_workspace_member("ws-1", "user2", "editor").unwrap();
        assert_eq!(db.get_workspace_member_role("ws-1", "user2").unwrap(), Some("editor".to_string()));

        // Remove member
        db.remove_workspace_member("ws-1", "user1").unwrap();
        let members = db.list_workspace_members("ws-1").unwrap();
        assert_eq!(members.len(), 2);
    }

    #[test]
    fn test_update_workspace() {
        let db = test_db();
        db.create_workspace("ws-1", "Old Name", "P", "D", "admin").unwrap();

        let updated = db.update_workspace("ws-1", "New Name", "NewP", "NewD").unwrap();
        assert!(updated);

        let ws = db.get_workspace("ws-1").unwrap().unwrap();
        assert_eq!(ws.1, "New Name");
        assert_eq!(ws.2, "NewP");
    }

    #[test]
    fn test_delete_workspace_cascades() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        db.add_workspace_member("ws-1", "user1", "viewer").unwrap();
        db.push_config_revision("ws-1", "{}", "init", "", "admin").unwrap();

        db.delete_workspace("ws-1").unwrap();

        assert!(db.get_workspace("ws-1").unwrap().is_none());
        assert_eq!(db.list_workspace_members("ws-1").unwrap().len(), 0);
        assert_eq!(db.list_config_revisions("ws-1").unwrap().len(), 0);
    }

    // -----------------------------------------------------------------------
    // Config revision tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_push_and_list_configs() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();

        let v1 = db.push_config_revision("ws-1", r#"{"a":1}"#, "first", "", "admin").unwrap();
        let v2 = db.push_config_revision("ws-1", r#"{"a":2}"#, "second", "", "admin").unwrap();
        assert_eq!(v1, 1);
        assert_eq!(v2, 2);

        let list = db.list_config_revisions("ws-1").unwrap();
        assert_eq!(list.len(), 2);
        // Newest first (field .1 = name)
        assert_eq!(list[0].1, "second");
        assert_eq!(list[1].1, "first");
    }

    #[test]
    fn test_get_config_revision() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        db.push_config_revision("ws-1", r#"{"key":"value"}"#, "test", "", "admin").unwrap();

        let rev = db.get_config_revision("ws-1", 1).unwrap().unwrap();
        assert_eq!(rev.1, r#"{"key":"value"}"#); // config_json
        assert_eq!(rev.2, "test"); // name

        assert!(db.get_config_revision("ws-1", 99).unwrap().is_none());
    }

    #[test]
    fn test_get_latest_config() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();

        assert!(db.get_latest_config_revision("ws-1").unwrap().is_none());

        db.push_config_revision("ws-1", r#"{"v":1}"#, "v1", "", "admin").unwrap();
        db.push_config_revision("ws-1", r#"{"v":2}"#, "v2", "", "admin").unwrap();

        let latest = db.get_latest_config_revision("ws-1").unwrap().unwrap();
        assert_eq!(latest.1, r#"{"v":2}"#); // config_json
        assert_eq!(latest.2, "v2"); // name
    }

    #[test]
    fn test_doc_pages_crud_and_bulk_upsert() {
        let mut db = test_db();
        let rid = db.insert_release("v1.0", "FusionHub 1.0", "", false, None).unwrap();

        // Editor upsert marks as user
        db.upsert_doc_page(rid, "imu", "IMU Source", "# IMU", Some("sources"), 1).unwrap();
        let page = db.get_doc_page(rid, "imu").unwrap().unwrap();
        assert_eq!(page.0, "IMU Source");
        assert_eq!(page.1, "# IMU");
        assert_eq!(page.2.as_deref(), Some("sources"));

        db.upsert_doc_page(rid, "imu", "IMU Source v2", "# v2", Some("sources"), 2).unwrap();
        let page = db.get_doc_page(rid, "imu").unwrap().unwrap();
        assert_eq!(page.0, "IMU Source v2");
        assert_eq!(page.3, 2);

        db.upsert_doc_page(rid, "sources", "Sources", "Index", None, 0).unwrap();
        assert_eq!(db.list_doc_pages(rid).unwrap().len(), 2);

        // Bulk (pipeline) upsert: skips user-owned `imu`, writes new slugs as pipeline.
        let new_pages = vec![
            ("imu".to_string(), "Pipeline IMU".to_string(), "pipe".to_string(), Some("sources".to_string()), 5),
            ("a".to_string(), "A".to_string(), "body a".to_string(), None, 0),
            ("b".to_string(), "B".to_string(), "body b".to_string(), Some("a".to_string()), 1),
        ];
        let (written, skipped) = db.upsert_doc_pages(rid, &new_pages).unwrap();
        assert_eq!(written, 2);
        assert_eq!(skipped, vec!["imu".to_string()]);
        // imu is still the user's edit, untouched.
        let imu = db.get_doc_page(rid, "imu").unwrap().unwrap();
        assert_eq!(imu.0, "IMU Source v2");
        assert_eq!(db.list_doc_pages(rid).unwrap().len(), 4);

        // Cascade delete with release
        assert!(db.delete_release("v1.0").unwrap());
        assert!(db.get_doc_page(rid, "a").unwrap().is_none());
    }

    #[test]
    fn test_doc_page_origin_tracking() {
        let mut db = test_db();
        let rid = db.insert_release("v1.0", "", "", false, None).unwrap();

        // Pipeline bulk plants a page.
        db.upsert_doc_pages(rid, &[(
            "imu".into(), "IMU".into(), "pipe body".into(), None, 0,
        )]).unwrap();
        let origin: String = db.conn.query_row(
            "SELECT origin FROM doc_pages WHERE release_id = ?1 AND slug = ?2",
            params![rid, "imu"], |r| r.get(0),
        ).unwrap();
        assert_eq!(origin, "pipeline");

        // Editor edit on the same slug promotes it to user.
        db.upsert_doc_page(rid, "imu", "IMU (edited)", "user body", None, 0).unwrap();
        let origin: String = db.conn.query_row(
            "SELECT origin FROM doc_pages WHERE release_id = ?1 AND slug = ?2",
            params![rid, "imu"], |r| r.get(0),
        ).unwrap();
        assert_eq!(origin, "user");

        // Pipeline re-run now skips the user page.
        let (written, skipped) = db.upsert_doc_pages(rid, &[(
            "imu".into(), "IMU".into(), "pipe again".into(), None, 0,
        )]).unwrap();
        assert_eq!(written, 0);
        assert_eq!(skipped, vec!["imu".to_string()]);
        let body = db.get_doc_page(rid, "imu").unwrap().unwrap().1;
        assert_eq!(body, "user body");
    }

    #[test]
    fn test_copy_user_docs_to_new_release() {
        let mut db = test_db();
        let old = db.insert_release("v1.0", "", "", false, None).unwrap();

        // Mixed origins under the old release.
        db.upsert_doc_pages(old, &[
            ("imu".into(), "IMU".into(), "pipe".into(), Some("sources".into()), 0),
            ("sources".into(), "Sources".into(), "auto".into(), None, 10),
        ]).unwrap();
        db.upsert_doc_page(old, "general", "General", "# General\nHand-authored", None, 0).unwrap();
        db.upsert_doc_page(old, "getting-started", "Getting Started", "guide", Some("general"), 1).unwrap();

        // Brand-new release tag.
        let (new_id, created) = db.ensure_release_created("v1.1", "FusionHub 1.1").unwrap();
        assert!(created);

        let prior = db.latest_prior_release_with_user_docs(new_id).unwrap();
        assert_eq!(prior.as_ref().map(|p| p.1.as_str()), Some("v1.0"));
        let (src_id, _src_tag) = prior.unwrap();

        let n = db.copy_user_doc_pages(src_id, new_id).unwrap();
        assert_eq!(n, 2); // general + getting-started

        let pages: Vec<String> = db.list_doc_pages(new_id).unwrap()
            .into_iter().map(|p| p.0).collect();
        assert!(pages.contains(&"general".to_string()));
        assert!(pages.contains(&"getting-started".to_string()));
        assert!(!pages.contains(&"imu".to_string()));
        assert!(!pages.contains(&"sources".to_string()));

        // All carried pages retain origin='user'.
        for slug in &pages {
            let o: String = db.conn.query_row(
                "SELECT origin FROM doc_pages WHERE release_id = ?1 AND slug = ?2",
                params![new_id, slug], |r| r.get(0),
            ).unwrap();
            assert_eq!(o, "user", "slug {} should be user", slug);
        }

        // Re-ensuring the existing tag reports not-newly-created.
        let (_, created) = db.ensure_release_created("v1.1", "").unwrap();
        assert!(!created);
    }

    #[test]
    fn test_doc_releases_filters_to_releases_with_pages() {
        let db = test_db();
        let r1 = db.insert_release("v1.0", "with docs", "", false, None).unwrap();
        let _r2 = db.insert_release("v1.1", "no docs", "", false, None).unwrap();
        db.upsert_doc_page(r1, "intro", "Intro", "...", None, 0).unwrap();

        let releases = db.list_doc_releases().unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].1, "v1.0");
        assert_eq!(releases[0].4, 1); // page count
    }

    #[test]
    fn test_ensure_release_is_idempotent() {
        let db = test_db();
        let id1 = db.ensure_release("v2.0", "FusionHub 2.0").unwrap();
        let id2 = db.ensure_release("v2.0", "different name").unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_releases_with_workspace_scoping() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();

        db.insert_release("v1.0", "Global", "", false, None).unwrap();
        db.insert_release("v1.1", "Scoped", "", false, Some("ws-1")).unwrap();

        // Global list shows all
        let all = db.list_releases().unwrap();
        assert_eq!(all.len(), 2);

        // Workspace list shows global + workspace-specific
        let ws_releases = db.list_releases_for_workspace("ws-1").unwrap();
        assert_eq!(ws_releases.len(), 2);

        // Different workspace only sees global
        let other = db.list_releases_for_workspace("ws-other").unwrap();
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].1, "v1.0");
    }
}
