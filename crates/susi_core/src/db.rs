use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::Serialize;

use crate::error::LicenseError;
use crate::license::{License, MachineActivation};

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub username: String,
    pub totp_enabled: bool,
    pub must_change_password: bool,
    pub created_at: String,
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

            CREATE INDEX IF NOT EXISTS idx_license_key ON licenses(license_key);
            CREATE INDEX IF NOT EXISTS idx_activations_license ON machine_activations(license_id);

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
                description TEXT NOT NULL DEFAULT '',
                author TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                UNIQUE(workspace_id, version)
            );
            CREATE INDEX IF NOT EXISTS idx_config_revisions_workspace ON config_revisions(workspace_id);",
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
                "INSERT INTO users (username, password_hash, must_change_password, totp_enabled, created_at, updated_at)
                 VALUES ('admin', ?1, 1, 0, ?2, ?2)",
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
            .prepare("SELECT username, totp_enabled, must_change_password, created_at FROM users ORDER BY created_at")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let users = stmt
            .query_map([], |r| {
                Ok(UserInfo {
                    username: r.get(0)?,
                    totp_enabled: r.get::<_, i32>(1)? != 0,
                    must_change_password: r.get::<_, i32>(2)? != 0,
                    created_at: r.get(3)?,
                })
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(users)
    }

    pub fn create_user(&self, username: &str, password_hash: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO users (username, password_hash, must_change_password, totp_enabled, created_at, updated_at)
                 VALUES (?1, ?2, 1, 0, ?3, ?3)",
                params![username, password_hash, now],
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
        description: &str,
        author: &str,
    ) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        // Auto-increment version per workspace
        let next_version: i64 = self.conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM config_revisions WHERE workspace_id = ?1",
                params![workspace_id],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        self.conn
            .execute(
                "INSERT INTO config_revisions (workspace_id, version, config_json, description, author, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![workspace_id, next_version, config_json, description, author, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert config: {}", e)))?;
        Ok(next_version)
    }

    pub fn list_config_revisions(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<(i64, i64, String, String, String)>, LicenseError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT id, version, description, author, created_at
                 FROM config_revisions WHERE workspace_id = ?1
                 ORDER BY version DESC"
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![workspace_id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
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
        version: i64,
    ) -> Result<Option<(i64, i64, String, String, String, String)>, LicenseError> {
        match self.conn.query_row(
            "SELECT id, version, config_json, description, author, created_at
             FROM config_revisions WHERE workspace_id = ?1 AND version = ?2",
            params![workspace_id, version],
            |r| Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
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
    ) -> Result<Option<(i64, i64, String, String, String, String)>, LicenseError> {
        match self.conn.query_row(
            "SELECT id, version, config_json, description, author, created_at
             FROM config_revisions WHERE workspace_id = ?1
             ORDER BY version DESC LIMIT 1",
            params![workspace_id],
            |r| Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
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
                "INSERT INTO release_assets (release_id, file_name, file_size) VALUES (?1, ?2, ?3)",
                params![release_id, file_name, file_size as i64],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert asset: {}", e)))?;
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
        db.push_config_revision("ws-1", "{}", "init", "admin").unwrap();

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

        let v1 = db.push_config_revision("ws-1", r#"{"a":1}"#, "first", "admin").unwrap();
        let v2 = db.push_config_revision("ws-1", r#"{"a":2}"#, "second", "admin").unwrap();
        assert_eq!(v1, 1);
        assert_eq!(v2, 2);

        let list = db.list_config_revisions("ws-1").unwrap();
        assert_eq!(list.len(), 2);
        // Newest first
        assert_eq!(list[0].1, 2);
        assert_eq!(list[1].1, 1);
    }

    #[test]
    fn test_get_config_revision() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        db.push_config_revision("ws-1", r#"{"key":"value"}"#, "test", "admin").unwrap();

        let rev = db.get_config_revision("ws-1", 1).unwrap().unwrap();
        assert_eq!(rev.1, 1); // version
        assert_eq!(rev.2, r#"{"key":"value"}"#); // config_json
        assert_eq!(rev.3, "test"); // description

        assert!(db.get_config_revision("ws-1", 99).unwrap().is_none());
    }

    #[test]
    fn test_get_latest_config() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();

        assert!(db.get_latest_config_revision("ws-1").unwrap().is_none());

        db.push_config_revision("ws-1", r#"{"v":1}"#, "v1", "admin").unwrap();
        db.push_config_revision("ws-1", r#"{"v":2}"#, "v2", "admin").unwrap();

        let latest = db.get_latest_config_revision("ws-1").unwrap().unwrap();
        assert_eq!(latest.1, 2);
        assert_eq!(latest.2, r#"{"v":2}"#);
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
