use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::error::LicenseError;
use crate::license::{License, MachineActivation};

/// Default product slug. Every pre-existing release and every release created
/// through a non-product-aware code path (binary uploads, workspace docs)
/// belongs to this product, so the migration and the back-compat routes can
/// rely on it.
pub const DEFAULT_PRODUCT: &str = "fusionhub";

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

/// Public-facing metadata about a token. Never includes the hash or raw token -
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

#[derive(Debug, Serialize)]
pub struct SessionRow {
    pub id: i64,
    pub jti: String,
    pub username: String,
    pub created_at: String,
    pub last_seen: String,
    pub device_label: String,
    pub ip: String,
}

#[derive(Debug, Serialize)]
pub struct AuditRow {
    pub id: i64,
    pub at: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub details: String,
}

#[derive(Debug, Serialize)]
pub struct BackupRunRow {
    pub id: i64,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: String,
    pub source: String,
    pub archive_name: String,
    pub size_bytes: i64,
    pub error: String,
}

#[derive(Debug, Serialize)]
pub struct RecordingRow {
    pub id: i64,
    pub workspace_id: String,
    pub s3_key: String,
    pub file_name: String,
    pub description: String,
    pub file_size: i64,
    pub status: String,
    pub author: String,
    pub created_at: String,
    pub completed_at: Option<String>,
}

pub struct LicenseDb {
    conn: Connection,
    /// AES-256-GCM key for at-rest encryption of stored secrets (TOTP seeds,
    /// federation channel secrets). None = read/write plaintext (CLI tools,
    /// tests); the server always sets one via `set_at_rest_key`.
    at_rest_key: Option<[u8; 32]>,
}

/// Marker prefix for at-rest-encrypted secret values:
/// "enc1:" + base64(nonce(12) || AES-256-GCM ciphertext).
const AT_REST_PREFIX: &str = "enc1:";

impl LicenseDb {
    pub fn open(path: &str) -> Result<Self, LicenseError> {
        let conn =
            Connection::open(path).map_err(|e| LicenseError::Other(format!("DB open: {}", e)))?;
        // WAL: readers don't block writers (and vice versa); synchronous=NORMAL is
        // safe with WAL and skips per-commit fsyncs; busy_timeout retries instead
        // of returning SQLITE_BUSY when a write lock is briefly held; 256 MiB mmap
        // lets the kernel page-cache satisfy reads without copying.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\n\
             PRAGMA synchronous=NORMAL;\n\
             PRAGMA busy_timeout=5000;\n\
             PRAGMA temp_store=MEMORY;\n\
             PRAGMA mmap_size=268435456;\n\
             PRAGMA foreign_keys=ON;",
        )
        .map_err(|e| LicenseError::Other(format!("DB pragma: {}", e)))?;
        let db = Self { conn, at_rest_key: None };
        db.init_tables()?;
        Ok(db)
    }

    /// Enable at-rest encryption of stored secrets with the given key, then
    /// encrypt any legacy plaintext rows in place (returns how many were
    /// converted). Reads accept both forms, so rows written before the key
    /// existed keep working until the sweep converts them.
    pub fn set_at_rest_key(&mut self, key: [u8; 32]) -> Result<usize, LicenseError> {
        self.at_rest_key = Some(key);
        self.encrypt_plaintext_secrets()
    }

    fn seal_secret(&self, plaintext: &str) -> Result<String, LicenseError> {
        let Some(key) = &self.at_rest_key else {
            return Ok(plaintext.to_string());
        };
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use base64::Engine as _;
        use rand::RngCore;
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| LicenseError::Other(format!("At-rest AES init: {}", e)))?;
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
            .map_err(|e| LicenseError::Other(format!("At-rest encrypt: {}", e)))?;
        let mut blob = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);
        Ok(format!(
            "{}{}",
            AT_REST_PREFIX,
            base64::engine::general_purpose::STANDARD.encode(blob)
        ))
    }

    fn open_secret(&self, stored: &str) -> Result<String, LicenseError> {
        let Some(b64) = stored.strip_prefix(AT_REST_PREFIX) else {
            // Legacy plaintext row (or encryption disabled).
            return Ok(stored.to_string());
        };
        let Some(key) = &self.at_rest_key else {
            return Err(LicenseError::Other(
                "Stored secret is encrypted but no at-rest key is configured".into(),
            ));
        };
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use base64::Engine as _;
        let blob = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| LicenseError::Other(format!("At-rest decode: {}", e)))?;
        if blob.len() < 12 + 16 {
            return Err(LicenseError::Other("At-rest blob too short".into()));
        }
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| LicenseError::Other(format!("At-rest AES init: {}", e)))?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&blob[..12]), &blob[12..])
            .map_err(|_| LicenseError::Other("At-rest decrypt failed (wrong db_secret.bin?)".into()))?;
        String::from_utf8(plaintext)
            .map_err(|e| LicenseError::Other(format!("At-rest utf8: {}", e)))
    }

    /// One-time sweep converting plaintext secret columns to the encrypted
    /// form. Idempotent: already-encrypted rows carry the prefix and are
    /// skipped.
    fn encrypt_plaintext_secrets(&self) -> Result<usize, LicenseError> {
        let mut converted = 0usize;

        let totp_rows: Vec<(String, String)> = {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT username, totp_secret FROM users
                     WHERE totp_secret IS NOT NULL AND totp_secret != ''
                       AND totp_secret NOT LIKE 'enc1:%'",
                )
                .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
            let rows: Vec<(String, String)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
                .filter_map(|r| r.ok())
                .collect();
            rows
        };
        for (username, secret) in totp_rows {
            let sealed = self.seal_secret(&secret)?;
            self.conn
                .execute(
                    "UPDATE users SET totp_secret = ?1 WHERE username = ?2",
                    params![sealed, username],
                )
                .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
            converted += 1;
        }

        let fed_rows: Vec<(String, String)> = {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT workspace_id, channel_secret FROM workspace_federation
                     WHERE channel_secret NOT LIKE 'enc1:%'",
                )
                .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
            let rows: Vec<(String, String)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
                .filter_map(|r| r.ok())
                .collect();
            rows
        };
        for (workspace_id, secret) in fed_rows {
            let sealed = self.seal_secret(&secret)?;
            self.conn
                .execute(
                    "UPDATE workspace_federation SET channel_secret = ?1 WHERE workspace_id = ?2",
                    params![sealed, workspace_id],
                )
                .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
            converted += 1;
        }

        Ok(converted)
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
                lease_duration_hours INTEGER NOT NULL DEFAULT 72,
                lease_grace_hours INTEGER NOT NULL DEFAULT 24,
                require_signed_binary INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS machine_activations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_id TEXT NOT NULL,
                machine_code TEXT NOT NULL,
                friendly_name TEXT NOT NULL DEFAULT '',
                activated_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL DEFAULT '',
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

            -- License <-> portal-user association. A row means the user can
            -- see the license in their self-serve view (key, machines,
            -- offline export). Many-to-many: a company license is visible to
            -- several contacts, a user may hold licenses for several products.
            CREATE TABLE IF NOT EXISTS license_users (
                license_id TEXT NOT NULL,
                username TEXT NOT NULL,
                added_at TEXT NOT NULL,
                PRIMARY KEY (license_id, username),
                FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_license_users_user ON license_users(username);

            CREATE TABLE IF NOT EXISTS products (
                slug TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                ord INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS releases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tag TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                body TEXT NOT NULL DEFAULT '',
                prerelease INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                -- Vestigial: workspace-scoped releases were replaced by
                -- workspace_files / workspace_doc_pages; always NULL after the
                -- startup migration. Kept because older migrations reference it.
                workspace_id TEXT DEFAULT NULL,
                product TEXT NOT NULL DEFAULT 'fusionhub',
                kind TEXT NOT NULL DEFAULT 'software',
                UNIQUE(product, tag)
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
                token_version INTEGER NOT NULL DEFAULT 1,
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

            -- Workspace-scoped federation channel secret. Members of the same
            -- workspace share this opaque base64 string; FusionHub instances
            -- derive their ChaCha20Poly1305 data-plane key from it. Lazily
            -- created on first read so existing workspaces just work.
            CREATE TABLE IF NOT EXISTS workspace_federation (
                workspace_id TEXT PRIMARY KEY,
                channel_secret TEXT NOT NULL,
                created_at TEXT NOT NULL,
                rotated_at TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );

            -- One node-graph per workspace. Source of truth for the
            -- distributed pipeline shared by every member fusionhub:
            -- `graph_version` is the optimistic-lock counter (PUT must echo
            -- the value it loaded; mismatch ⇒ 409), `config` is the raw JSON
            -- the editor exports. NULL row ⇒ workspace has no graph yet
            -- (first peer to save seeds it).
            CREATE TABLE IF NOT EXISTS workspace_graphs (
                workspace_id  TEXT PRIMARY KEY,
                graph_version INTEGER NOT NULL,
                config        TEXT NOT NULL,
                updated_by    TEXT NOT NULL,
                updated_at    TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );

            -- Workspace peer registry. Each FusionHub instance that logs into
            -- a workspace registers its externally-reachable URL here. Other
            -- members poll this list to populate their peer set without mDNS.
            -- `network_id` is a peer-side scope string - peers only federate
            -- with others sharing the same value (workspace membership is
            -- necessary but not sufficient). Empty string means isolated.
            CREATE TABLE IF NOT EXISTS workspace_peers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                url TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                network_id TEXT NOT NULL DEFAULT '',
                registered_by TEXT NOT NULL,
                registered_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                UNIQUE(workspace_id, host_id)
            );
            CREATE INDEX IF NOT EXISTS idx_workspace_peers_ws ON workspace_peers(workspace_id);

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
                updated_at TEXT NOT NULL,
                meta_description TEXT NOT NULL DEFAULT '',
                hidden INTEGER NOT NULL DEFAULT 0,
                page_kind TEXT NOT NULL DEFAULT 'page',
                published_at TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_website_pages_parent ON website_pages(parent_slug);

            CREATE TABLE IF NOT EXISTS website_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL UNIQUE,
                file_size INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS website_page_revisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slug TEXT NOT NULL,
                title TEXT NOT NULL,
                body_md TEXT NOT NULL DEFAULT '',
                parent_slug TEXT,
                ord INTEGER NOT NULL DEFAULT 0,
                captured_at TEXT NOT NULL,
                author TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_website_page_revisions_slug
                ON website_page_revisions(slug, captured_at DESC);

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

            -- One row per issued session JWT (keyed by its jti claim) so
            -- users can list and revoke their active sessions. Rows for
            -- expired JWTs are purged by the background cleanup task.
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                jti TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                device_label TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '',
                revoked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(username);

            -- Append-only admin audit trail: who did what to which object.
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_audit_log_at ON audit_log(at DESC);

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
            CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(username);

            CREATE TABLE IF NOT EXISTS shop_products (
                sku             TEXT PRIMARY KEY,
                title           TEXT NOT NULL,
                description_md  TEXT NOT NULL DEFAULT '',
                price_cents     INTEGER NOT NULL,
                currency        TEXT NOT NULL DEFAULT 'usd',
                image_asset     TEXT,
                tax_code        TEXT NOT NULL DEFAULT 'txcd_99999999',
                active          INTEGER NOT NULL DEFAULT 1,
                ord             INTEGER NOT NULL DEFAULT 0,
                updated_at      TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_shop_products_active_ord
                ON shop_products(active, ord);

            CREATE TABLE IF NOT EXISTS shop_shipping_rates (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                label             TEXT NOT NULL,
                amount_cents      INTEGER NOT NULL,
                currency          TEXT NOT NULL DEFAULT 'usd',
                delivery_min_days INTEGER,
                delivery_max_days INTEGER,
                regions           TEXT NOT NULL DEFAULT '[\"*\"]',
                active            INTEGER NOT NULL DEFAULT 1,
                ord               INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_shop_shipping_rates_active_ord
                ON shop_shipping_rates(active, ord);

            -- Shadow of completed Stripe Checkout Sessions. Stripe remains the
            -- source of truth for payment + customer details; we keep a local
            -- row so the admin UI can list / drive fulfillment without a
            -- round-trip per request, plus columns Stripe doesn't track for us
            -- (shipped_at, tracking_number, ...).
            CREATE TABLE IF NOT EXISTS shop_orders (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                stripe_session_id   TEXT NOT NULL UNIQUE,
                created_at          TEXT NOT NULL,
                customer_email      TEXT NOT NULL DEFAULT '',
                customer_name       TEXT NOT NULL DEFAULT '',
                amount_total_cents  INTEGER NOT NULL DEFAULT 0,
                currency            TEXT NOT NULL DEFAULT 'usd',
                status              TEXT NOT NULL DEFAULT 'paid',
                ship_to_json        TEXT NOT NULL DEFAULT '{}',
                line_items_json     TEXT NOT NULL DEFAULT '[]',
                tracking_carrier    TEXT NOT NULL DEFAULT '',
                tracking_number     TEXT NOT NULL DEFAULT '',
                shipped_at          TEXT,
                notes               TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_shop_orders_status_created
                ON shop_orders(status, created_at DESC);

            -- Free-form key/value config for the shop. Lets the admin UI
            -- store recipient lists, copy strings, toggles, etc. without a
            -- migration each time we add another setting.
            CREATE TABLE IF NOT EXISTS shop_settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            -- Site-wide key/value config (analytics IDs, etc.). Distinct from
            -- shop_settings so site-level concerns don't bleed into the shop
            -- admin namespace.
            CREATE TABLE IF NOT EXISTS site_settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            -- Workspace-scoped recording files. Susi stores only metadata +
            -- the S3 object key; bytes live in the configured bucket under
            -- `workspaces/{id}/recordings/{uuid}`. Two-phase upload: a row is
            -- created with status='pending' alongside a presigned PUT URL,
            -- then a /complete call flips it to 'uploaded' once the client
            -- finishes its PUT.
            CREATE TABLE IF NOT EXISTS workspace_recordings (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT    NOT NULL,
                s3_key       TEXT    NOT NULL UNIQUE,
                file_name    TEXT    NOT NULL,
                description  TEXT    NOT NULL DEFAULT '',
                file_size    INTEGER NOT NULL DEFAULT 0,
                status       TEXT    NOT NULL DEFAULT 'pending',
                author       TEXT    NOT NULL,
                created_at   TEXT    NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_workspace_recordings_ws
                ON workspace_recordings(workspace_id, created_at DESC);

            -- Flat per-workspace file share. Bytes live on disk under
            -- data_dir/workspaces/{id}/files; rows hold metadata only.
            CREATE TABLE IF NOT EXISTS workspace_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_size INTEGER NOT NULL DEFAULT 0,
                author TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                UNIQUE(workspace_id, file_name)
            );
            CREATE INDEX IF NOT EXISTS idx_workspace_files_ws
                ON workspace_files(workspace_id, created_at DESC);

            -- Workspace documentation: one flat page tree per workspace. The
            -- release-tag dimension only exists for global product docs
            -- (doc_pages); workspace docs are continuous, so no origin column
            -- and no seeding-forward machinery either.
            CREATE TABLE IF NOT EXISTS workspace_doc_pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT NOT NULL,
                slug TEXT NOT NULL,
                title TEXT NOT NULL,
                body_md TEXT NOT NULL DEFAULT '',
                parent_slug TEXT,
                ord INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                UNIQUE(workspace_id, slug)
            );
            CREATE INDEX IF NOT EXISTS idx_ws_doc_pages_ws ON workspace_doc_pages(workspace_id);

            CREATE TABLE IF NOT EXISTS workspace_doc_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_size INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                UNIQUE(workspace_id, file_name)
            );

            -- Dropbox backup config/state (schedule, retention, sealed OAuth
            -- refresh token). KV so new settings don't need a migration.
            CREATE TABLE IF NOT EXISTS backup_state (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            -- One row per backup attempt (scheduled or manual).
            CREATE TABLE IF NOT EXISTS backup_runs (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at   TEXT    NOT NULL,
                finished_at  TEXT,
                status       TEXT    NOT NULL DEFAULT 'running',
                source       TEXT    NOT NULL DEFAULT 'manual',
                archive_name TEXT    NOT NULL DEFAULT '',
                size_bytes   INTEGER NOT NULL DEFAULT 0,
                error        TEXT    NOT NULL DEFAULT ''
            );",
            )
            .map_err(|e| LicenseError::Other(format!("DB init: {}", e)))?;
        self.migrate()?;
        Ok(())
    }

    fn migrate(&self) -> Result<(), LicenseError> {
        // Add lease columns to existing databases
        let _ = self.conn.execute_batch(
            "ALTER TABLE licenses ADD COLUMN lease_duration_hours INTEGER NOT NULL DEFAULT 72;
             ALTER TABLE licenses ADD COLUMN lease_grace_hours INTEGER NOT NULL DEFAULT 24;
             ALTER TABLE machine_activations ADD COLUMN lease_expires_at TEXT NOT NULL DEFAULT '';",
        );
        // Add workspace_id to releases for per-workspace scoping
        let _ = self
            .conn
            .execute_batch("ALTER TABLE releases ADD COLUMN workspace_id TEXT DEFAULT NULL;");

        // Add name column to config_revisions
        let _ = self.conn.execute_batch(
            "ALTER TABLE config_revisions ADD COLUMN name TEXT NOT NULL DEFAULT '';",
        );

        // Add role column to users (existing users default to admin)
        let _ = self
            .conn
            .execute_batch("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';");

        // Tag doc pages / assets with their origin so a new release tag can
        // inherit hand-authored pages from the prior release without dragging
        // along the pipeline-regenerated ones. Existing rows default to 'user'
        // - safe because it keeps them in the carry-over set; next pipeline run
        // re-stamps its own pages as 'pipeline'.
        let _ = self.conn.execute_batch(
            "ALTER TABLE doc_pages ADD COLUMN origin TEXT NOT NULL DEFAULT 'user';
             ALTER TABLE doc_assets ADD COLUMN origin TEXT NOT NULL DEFAULT 'user';",
        );

        // Add email column to users (nullable - admin sets it per user)
        let _ = self
            .conn
            .execute_batch("ALTER TABLE users ADD COLUMN email TEXT;");

        // SEO: per-page meta description override (empty = auto-derive from body_md)
        let _ = self.conn.execute_batch(
            "ALTER TABLE website_pages ADD COLUMN meta_description TEXT NOT NULL DEFAULT '';",
        );

        // Hide pages from the public site (nav, SSR, sitemap) without deleting
        let _ = self.conn.execute_batch(
            "ALTER TABLE website_pages ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0;",
        );

        // Session-revocation counter: every issued JWT embeds the value at
        // issue time and is rejected once they diverge. Bumped on password
        // change/reset so a stolen token can be evicted.
        let _ = self.conn.execute_batch(
            "ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1;",
        );

        // Distinguish device-trust magic links from password-reset links so a
        // sign-in token can't be replayed against the reset endpoint to take
        // over an account.
        let _ = self.conn.execute_batch(
            "ALTER TABLE login_tokens ADD COLUMN kind TEXT NOT NULL DEFAULT 'device';",
        );

        // Peer-side federation scope string. Empty default keeps existing rows
        // valid; the application layer treats empty as "isolated" so prior
        // workspace setups must explicitly set a value on each peer to opt
        // back into federation.
        let _ = self.conn.execute_batch(
            "ALTER TABLE workspace_peers ADD COLUMN network_id TEXT NOT NULL DEFAULT '';",
        );

        // Workspace member roles (viewer/editor/owner) were retired: membership
        // alone grants full read+write, management stays site-admin-only. Drop
        // the now-unused column. The error on a fresh DB (no such column) is
        // ignored.
        let _ = self
            .conn
            .execute_batch("ALTER TABLE workspace_members DROP COLUMN role;");

        // Migrate single-admin table to multi-user table
        let has_admin_user: bool = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='admin_user'",
                [],
                |r| r.get::<_, i64>(0),
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

        // Add require binary signing to licenses table
        let _ = self.conn.execute_batch(
            "ALTER TABLE licenses ADD COLUMN require_signed_binary INTEGER NOT NULL DEFAULT 0;",
        );

        // Per-product scoping for releases (docs + binaries). Existing rows
        // default to the FusionHub product so every current release, doc page,
        // and asset stays addressable. The unique key moves from `tag` alone to
        // `(product, tag)` so a second product can reuse version tags.
        let _ = self
            .conn
            .execute_batch("ALTER TABLE releases ADD COLUMN product TEXT NOT NULL DEFAULT 'fusionhub';");

        // The old schema declared `tag TEXT NOT NULL UNIQUE`, whose implicit
        // unique index SQLite can't ALTER away. Rebuild the table once to swap
        // that for the composite `UNIQUE(product, tag)`. Guard on the stored
        // schema so this runs exactly once and never on a fresh DB (whose
        // CREATE already carries the composite key).
        let releases_sql: String = self
            .conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='releases'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_default();
        if !releases_sql.contains("UNIQUE(product, tag)") {
            self.conn
                .execute_batch(
                    "PRAGMA foreign_keys=OFF;
                     BEGIN;
                     CREATE TABLE releases_new (
                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                         tag TEXT NOT NULL,
                         name TEXT NOT NULL DEFAULT '',
                         body TEXT NOT NULL DEFAULT '',
                         prerelease INTEGER NOT NULL DEFAULT 0,
                         created_at TEXT NOT NULL,
                         workspace_id TEXT DEFAULT NULL,
                         product TEXT NOT NULL DEFAULT 'fusionhub',
                         UNIQUE(product, tag)
                     );
                     INSERT INTO releases_new (id, tag, name, body, prerelease, created_at, workspace_id, product)
                         SELECT id, tag, name, body, prerelease, created_at, workspace_id, product FROM releases;
                     DROP TABLE releases;
                     ALTER TABLE releases_new RENAME TO releases;
                     COMMIT;
                     PRAGMA foreign_keys=ON;",
                )
                .map_err(|e| LicenseError::Other(format!("DB releases rebuild: {}", e)))?;
        }

        // Seed the default product row so the admin UI lists it and FK-style
        // lookups resolve. Idempotent.
        let _ = self.conn.execute(
            "INSERT OR IGNORE INTO products (slug, name, description, ord, created_at)
             VALUES ('fusionhub', 'FusionHub', '', 0, ?1)",
            params![Utc::now().to_rfc3339()],
        );

        // Track last server contact separately from the first activation.
        // Existing rows fall back to activated_at, which the old code
        // refreshed on every renewal.
        let _ = self.conn.execute_batch(
            "ALTER TABLE machine_activations ADD COLUMN last_seen_at TEXT NOT NULL DEFAULT '';",
        );

        // Distinguish doc-only collections ('docs') from software releases
        // ('software') so release listings can exclude them. Backfill runs
        // exactly once, when the column is first added: existing doc-only
        // rows carry pages or doc assets but no binaries.
        if self
            .conn
            .execute_batch("ALTER TABLE releases ADD COLUMN kind TEXT NOT NULL DEFAULT 'software';")
            .is_ok()
        {
            let _ = self.conn.execute_batch(
                "UPDATE releases SET kind = 'docs'
                 WHERE NOT EXISTS (SELECT 1 FROM release_assets a WHERE a.release_id = releases.id)
                   AND (EXISTS (SELECT 1 FROM doc_pages p WHERE p.release_id = releases.id)
                        OR EXISTS (SELECT 1 FROM doc_assets d WHERE d.release_id = releases.id));",
            );
        }

        // Public-download flag: a product's *global* releases can be fetched
        // with no license or login (the free FusionHub installer linked from
        // xikaku.com so sensor users replacing LpmsControl can grab it). The
        // one-time enable of the default product runs only when the column is
        // first added, so an admin later toggling it off in the Products page
        // is not clobbered on the next restart.
        if self
            .conn
            .execute_batch("ALTER TABLE products ADD COLUMN download_public INTEGER NOT NULL DEFAULT 0;")
            .is_ok()
        {
            let _ = self.conn.execute(
                "UPDATE products SET download_public = 1 WHERE slug = ?1",
                params![DEFAULT_PRODUCT],
            );
        }

        // Blog posts live in website_pages: kind 'post' plus a publish date
        // (YYYY-MM-DD). Regular pages keep kind 'page' and an empty date.
        let _ = self.conn.execute_batch(
            "ALTER TABLE website_pages ADD COLUMN page_kind TEXT NOT NULL DEFAULT 'page';
             ALTER TABLE website_pages ADD COLUMN published_at TEXT NOT NULL DEFAULT '';",
        );

        // >> Add new migrations as own execute_batch statements here <<
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
                "INSERT INTO licenses (id, product, customer, license_key, created, expires, features, max_machines, revoked, lease_duration_hours, lease_grace_hours, require_signed_binary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
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
                    license.require_signed_binary as i32,
                ],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
        Ok(())
    }

    pub fn get_license_by_key(&self, license_key: &str) -> Result<Option<License>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, product, customer, license_key, created, expires, features, max_machines, revoked, lease_duration_hours, lease_grace_hours, require_signed_binary
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

        // Lease-expired activations are kept as history (they stop counting
        // toward the seat limit via is_lease_active), so no cleanup here.

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
            require_signed_binary: row
                .get::<_, i32>(11)
                .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?
                != 0,
        };

        license.machines = self.get_machine_activations(&id)?;
        Ok(Some(license))
    }

    /// Batch variant of `get_machine_activations` for list endpoints. One
    /// query covers every license id, with rows grouped into the returned
    /// map by license_id. Avoids the per-license N+1 in `list_licenses`.
    pub fn get_machine_activations_for_licenses(
        &self,
        license_ids: &[String],
    ) -> Result<std::collections::HashMap<String, Vec<MachineActivation>>, LicenseError> {
        let mut out: std::collections::HashMap<String, Vec<MachineActivation>> =
            std::collections::HashMap::with_capacity(license_ids.len());
        if license_ids.is_empty() {
            return Ok(out);
        }
        let placeholders = std::iter::repeat("?")
            .take(license_ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT license_id, machine_code, friendly_name, activated_at, last_seen_at, lease_expires_at
             FROM machine_activations WHERE license_id IN ({})",
            placeholders,
        );
        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let params_iter: Vec<&dyn rusqlite::ToSql> = license_ids
            .iter()
            .map(|s| s as &dyn rusqlite::ToSql)
            .collect();
        let rows = stmt
            .query_map(&params_iter[..], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        for r in rows.flatten() {
            let (license_id, machine_code, friendly_name, activated_str, seen_str, lease_str) = r;
            let Some(activated_at) = DateTime::parse_from_rfc3339(&activated_str)
                .ok()
                .map(|d| d.with_timezone(&Utc))
            else {
                continue;
            };
            let last_seen_at = DateTime::parse_from_rfc3339(&seen_str)
                .ok()
                .map(|d| d.with_timezone(&Utc))
                .or(Some(activated_at));
            let lease_expires_at = if lease_str.is_empty() {
                None
            } else {
                DateTime::parse_from_rfc3339(&lease_str)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            };
            out.entry(license_id).or_default().push(MachineActivation {
                machine_code,
                friendly_name,
                activated_at,
                last_seen_at,
                lease_expires_at,
            });
        }
        Ok(out)
    }

    fn get_machine_activations(
        &self,
        license_id: &str,
    ) -> Result<Vec<MachineActivation>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT machine_code, friendly_name, activated_at, last_seen_at, lease_expires_at
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
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .filter_map(|(machine_code, friendly_name, activated_str, seen_str, lease_str)| {
                let activated_at = DateTime::parse_from_rfc3339(&activated_str)
                    .ok()?
                    .with_timezone(&Utc);
                let last_seen_at = DateTime::parse_from_rfc3339(&seen_str)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
                    .or(Some(activated_at));
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
                    last_seen_at,
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
        // Renewal keeps activated_at (first activation) and bumps last_seen_at.
        self.conn
            .execute(
                "INSERT INTO machine_activations (license_id, machine_code, friendly_name, activated_at, last_seen_at, lease_expires_at)
             VALUES (?1, ?2, ?3, ?4, ?4, ?5)
             ON CONFLICT(license_id, machine_code) DO UPDATE SET
                friendly_name = excluded.friendly_name,
                last_seen_at = excluded.last_seen_at,
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

        Ok(expires.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        }))
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
            .execute(
                "DELETE FROM machine_activations WHERE license_id = ?1",
                params![id],
            )
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
        require_signed_binary: bool,
    ) -> Result<bool, LicenseError> {
        let features_json = serde_json::to_string(features)?;
        let expires_str = expires.unwrap_or("");
        let rows = self
            .conn
            .execute(
                "UPDATE licenses SET customer = ?1, product = ?2, expires = ?3, features = ?4, max_machines = ?5, require_signed_binary = ?6 WHERE license_key = ?7",
                params![customer, product, expires_str, features_json, max_machines, require_signed_binary as i32, license_key],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(rows > 0)
    }

}

mod assignments;
mod users;
mod devices;
mod login_tokens;
mod backup_codes;
mod api_tokens;
mod workspaces;
mod workspace_members;
mod federation;
mod workspace_graph;
mod config_revisions;
mod recordings;
mod workspace_files;
mod releases;
mod products;
mod license_listing;
mod docs;
mod website;
mod shop;
mod sessions;
mod audit;
mod backup;


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
    use crate::license::DEFAULT_LEASE_DURATION_HOURS;
    use chrono::Duration;

    fn test_db() -> LicenseDb {
        LicenseDb::open(":memory:").unwrap()
    }

    /// TOTP + federation secrets round-trip through at-rest encryption, the
    /// raw column carries only ciphertext, and legacy plaintext rows are
    /// converted by the sweep and stay readable.
    #[test]
    fn test_at_rest_secret_encryption() {
        let mut db = test_db();
        db.create_user("alice", "hash", "user").unwrap();
        // Legacy plaintext row, written before the key existed.
        db.set_user_totp_secret("alice", "PLAINSEED").unwrap();

        let n = db.set_at_rest_key([7u8; 32]).unwrap();
        assert_eq!(n, 1, "sweep must convert the plaintext row");
        assert_eq!(db.get_user_totp_secret("alice").unwrap().as_deref(), Some("PLAINSEED"));

        // New writes land encrypted and round-trip.
        db.set_user_totp_secret("alice", "NEWSEED").unwrap();
        assert_eq!(db.get_user_totp_secret("alice").unwrap().as_deref(), Some("NEWSEED"));
        let raw: String = db
            .conn
            .query_row("SELECT totp_secret FROM users WHERE username = 'alice'", [], |r| r.get(0))
            .unwrap();
        assert!(raw.starts_with("enc1:"), "raw column must be ciphertext, got: {}", raw);
        assert!(!raw.contains("NEWSEED"));

        // Federation channel secret: created encrypted, read back decrypted.
        db.create_workspace("ws-enc", "WS", "", "", "admin").unwrap();
        let secret = db.get_or_create_workspace_federation_secret("ws-enc").unwrap();
        assert_eq!(
            db.get_or_create_workspace_federation_secret("ws-enc").unwrap(),
            secret
        );
        let raw: String = db
            .conn
            .query_row(
                "SELECT channel_secret FROM workspace_federation WHERE workspace_id = 'ws-enc'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(raw.starts_with("enc1:"));
        assert!(!raw.contains(&secret));

        // Rotation stays encrypted and returns a fresh plaintext secret.
        let rotated = db.rotate_workspace_federation_secret("ws-enc").unwrap();
        assert_ne!(rotated, secret);
        assert_eq!(
            db.get_or_create_workspace_federation_secret("ws-enc").unwrap(),
            rotated
        );
    }

    /// Build an old-schema database (releases keyed by a global-unique `tag`,
    /// no product column) with a release + a doc page, then reopen it through
    /// `LicenseDb::open` to exercise the product migration + table rebuild.
    #[test]
    fn test_product_migration_rebuilds_releases() {
        let path = std::env::temp_dir()
            .join(format!("susi_migtest_{}.db", std::process::id()));
        let p = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path);

        // Pre-migration shape: tag is globally UNIQUE, no product column.
        {
            let conn = Connection::open(&p).unwrap();
            conn.execute_batch(
                "CREATE TABLE releases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tag TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL DEFAULT '',
                    body TEXT NOT NULL DEFAULT '',
                    prerelease INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    workspace_id TEXT DEFAULT NULL
                );
                 CREATE TABLE doc_pages (
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
                 INSERT INTO releases (id, tag, name, created_at) VALUES (1, 'v1.0', 'Old', '2020-01-01T00:00:00Z');
                 INSERT INTO doc_pages (release_id, slug, title, updated_at) VALUES (1, 'intro', 'Intro', '2020-01-01T00:00:00Z');",
            )
            .unwrap();
        }

        // Reopen - runs init_tables + migrate (adds product, rebuilds releases).
        let db = LicenseDb::open(&p).unwrap();

        // Existing release is preserved and now belongs to the default product.
        let rid = db
            .get_release_by_product_tag(DEFAULT_PRODUCT, "v1.0")
            .unwrap();
        assert_eq!(rid, Some(1), "release row must survive the rebuild");

        // FK-linked doc page survived (id preserved across the rebuild).
        let pages = db.list_doc_pages(1).unwrap();
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].0, "intro");

        // Composite (product, tag) now lets another product reuse the same tag.
        let other = db
            .insert_release("lpvr", "v1.0", "LPVR", "", false, "software")
            .unwrap();
        assert_ne!(other, 1);
        assert_eq!(
            db.get_release_by_product_tag("lpvr", "v1.0").unwrap(),
            Some(other)
        );

        // The default product row was seeded.
        assert!(db.product_exists(DEFAULT_PRODUCT).unwrap());

        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    fn lease_expires(hours: i64) -> Option<DateTime<Utc>> {
        Some(Utc::now() + Duration::hours(hours))
    }

    #[test]
    fn test_user_email_roundtrip() {
        let db = test_db();
        db.seed_admin("hash").unwrap();
        assert_eq!(db.get_user_email("admin").unwrap(), None);
        db.set_user_email("admin", Some("klaus@lp-research.com"))
            .unwrap();
        assert_eq!(
            db.get_user_email("admin").unwrap().as_deref(),
            Some("klaus@lp-research.com")
        );
        db.set_user_email("admin", None).unwrap();
        assert_eq!(db.get_user_email("admin").unwrap(), None);
    }

    #[test]
    fn test_known_device_lifecycle() {
        let db = test_db();
        db.seed_admin("hash").unwrap();
        assert!(!db.is_device_known("admin", "fp1").unwrap());
        db.register_device("admin", "fp1", "Chrome / Linux")
            .unwrap();
        assert!(db.is_device_known("admin", "fp1").unwrap());

        // Upsert on repeat - last_seen should update but no duplicate row.
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
        db.insert_login_token("hash1", "admin", "fp1", "Chrome", 900)
            .unwrap();

        let row = db
            .consume_login_token("hash1")
            .unwrap()
            .expect("token valid");
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
        db.insert_login_token("hashP", "admin", "fp1", "", 900)
            .unwrap();
        // Peek twice - token should still be consumable after.
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
        db.insert_login_token("hash2", "admin", "fp1", "", -1)
            .unwrap();
        assert!(db.consume_login_token("hash2").unwrap().is_none());
    }

    #[test]
    fn test_api_token_lifecycle() {
        let db = test_db();
        db.seed_admin("hash").unwrap();

        let id = db
            .insert_api_token("admin", "ci-bot", "h-abcdef", "susi_pat_ab")
            .unwrap();
        let row = db
            .find_api_token_by_hash("h-abcdef")
            .unwrap()
            .expect("present");
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
        let row = db
            .find_api_token_by_hash("h-abcdef")
            .unwrap()
            .expect("present");
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
        assert_eq!(
            db.get_api_token_owner(id).unwrap().as_deref(),
            Some("admin")
        );
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
        // Double-consume returns false - race protection.
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

        // Add tombstone - present with a future expiry
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
        db.remove_machine_activation(license_id, machine_code)
            .unwrap();
        db.add_machine_tombstone(license_id, machine_code, 24)
            .unwrap();
    }

    /// Mirrors `handle_deactivate` (public client path): remove only, NO tombstone.
    fn sim_client_self_deactivate(db: &LicenseDb, license_id: &str, machine_code: &str) {
        db.remove_machine_activation(license_id, machine_code)
            .unwrap();
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
            db.get_license_by_key(&license.license_key)
                .unwrap()
                .unwrap()
                .machines
                .len(),
            1
        );

        // Admin removes the machine via the admin UI.
        sim_admin_remove(&db, &license.id, "mc-laptop");
        assert_eq!(
            db.get_license_by_key(&license.license_key)
                .unwrap()
                .unwrap()
                .machines
                .len(),
            0
        );

        // Client restarts and tries to activate again. This MUST be blocked -
        // otherwise the admin's removal is effectively a no-op, which is the
        // exact bug we are guarding against.
        let err = sim_client_activate(&db, &license.id, "mc-laptop", "nico-lpLaptop").unwrap_err();
        assert!(
            err.contains("tombstoned"),
            "expected tombstone rejection, got: {}",
            err
        );
        assert_eq!(
            db.get_license_by_key(&license.license_key)
                .unwrap()
                .unwrap()
                .machines
                .len(),
            0,
            "machine must NOT reappear after admin removal"
        );
    }

    #[test]
    fn regression_client_self_deactivate_does_not_tombstone() {
        // A user who hits "Remove THIS machine" in their own FusionHub UI is
        // explicitly resetting the install - they must be able to re-activate
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
        assert!(db
            .machine_tombstone_expires_at(&license.id, "mc-1")
            .unwrap()
            .is_none());
        // Re-activate must succeed right away.
        sim_client_activate(&db, &license.id, "mc-1", "laptop").unwrap();
        assert_eq!(
            db.get_license_by_key(&license.license_key)
                .unwrap()
                .unwrap()
                .machines
                .len(),
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
            db.get_license_by_key(&license.license_key)
                .unwrap()
                .unwrap()
                .machines
                .len(),
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
        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(
            retrieved.machines.len(),
            1,
            "stable fingerprint must map to one slot"
        );
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
    fn test_expired_lease_kept_as_history_and_frees_seat() {
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

        // The row persists as history but no longer counts as active or
        // toward the seat limit.
        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.machines.len(), 1);
        assert_eq!(retrieved.active_machine_count(), 0);
        assert!(!retrieved.is_machine_activated("old_machine"));
        assert!(retrieved.can_add_machine());

        // A returning machine renews in place instead of inserting a new row.
        let fresh_lease = Some(Utc::now() + Duration::hours(168));
        db.add_machine_activation(&license.id, "old_machine", "Old", fresh_lease)
            .unwrap();
        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.machines.len(), 1);
        assert_eq!(retrieved.active_machine_count(), 1);
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

    #[test]
    fn test_renewal_keeps_activated_at_and_bumps_last_seen() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            None,
            vec![],
            0,
        );
        db.insert_license(&license).unwrap();

        db.add_machine_activation(&license.id, "machine1", "M1", lease_expires(168))
            .unwrap();

        // Backdate both timestamps to simulate an old activation.
        let old = (Utc::now() - Duration::days(30)).to_rfc3339();
        db.conn
            .execute(
                "UPDATE machine_activations SET activated_at = ?1, last_seen_at = ?1",
                params![old],
            )
            .unwrap();

        db.add_machine_activation(&license.id, "machine1", "M1", lease_expires(168))
            .unwrap();

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        let m = &retrieved.machines[0];
        assert!((Utc::now() - m.activated_at).num_days() >= 29);
        assert!((Utc::now() - m.last_seen()).num_minutes() < 5);
    }

    #[test]
    fn test_last_seen_falls_back_to_activated_at() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            None,
            vec![],
            0,
        );
        db.insert_license(&license).unwrap();

        db.add_machine_activation(&license.id, "machine1", "M1", None)
            .unwrap();
        // Simulate a pre-migration row with an empty last_seen_at.
        db.conn
            .execute("UPDATE machine_activations SET last_seen_at = ''", [])
            .unwrap();

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        let m = &retrieved.machines[0];
        assert_eq!(m.last_seen(), m.activated_at);
    }

    // -----------------------------------------------------------------------
    // Workspace tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_and_get_workspace() {
        let db = test_db();
        db.create_workspace("ws-1", "Test Workspace", "FusionHub", "A test", "admin")
            .unwrap();

        let ws = db.get_workspace("ws-1").unwrap().unwrap();
        assert_eq!(ws.0, "ws-1");
        assert_eq!(ws.1, "Test Workspace");
        assert_eq!(ws.2, "FusionHub");
        assert_eq!(ws.3, "A test");
        assert_eq!(ws.4, "admin");
    }

    #[test]
    fn test_workspace_creator_is_member() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();

        assert!(db.workspace_access("ws-1", "admin").unwrap().is_some());
    }

    #[test]
    fn test_list_workspaces_for_user() {
        let db = test_db();
        db.create_workspace("ws-1", "One", "", "", "admin").unwrap();
        db.create_workspace("ws-2", "Two", "", "", "admin").unwrap();
        db.create_workspace("ws-3", "Three", "", "", "other")
            .unwrap();

        let list = db.list_workspaces_for_user("admin").unwrap();
        assert_eq!(list.len(), 2);

        let list = db.list_workspaces_for_user("other").unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_workspace_members() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();

        db.add_workspace_member("ws-1", "user1").unwrap();
        db.add_workspace_member("ws-1", "user2").unwrap();

        let members = db.list_workspace_members("ws-1").unwrap();
        assert_eq!(members.len(), 3); // admin + user1 + user2

        assert!(db.workspace_access("ws-1", "user1").unwrap().is_some());
        assert!(db.workspace_access("ws-1", "user2").unwrap().is_some());
        assert!(db.workspace_access("ws-1", "nobody").unwrap().is_none());

        // Adding an existing member is idempotent.
        db.add_workspace_member("ws-1", "user2").unwrap();
        assert_eq!(db.list_workspace_members("ws-1").unwrap().len(), 3);

        // Remove member
        db.remove_workspace_member("ws-1", "user1").unwrap();
        let members = db.list_workspace_members("ws-1").unwrap();
        assert_eq!(members.len(), 2);
        assert!(db.workspace_access("ws-1", "user1").unwrap().is_none());
    }

    #[test]
    fn test_update_workspace() {
        let db = test_db();
        db.create_workspace("ws-1", "Old Name", "P", "D", "admin")
            .unwrap();

        let updated = db
            .update_workspace("ws-1", "New Name", "NewP", "NewD", None)
            .unwrap();
        assert!(updated);

        let ws = db.get_workspace("ws-1").unwrap().unwrap();
        assert_eq!(ws.1, "New Name");
        assert_eq!(ws.2, "NewP");
    }

    #[test]
    fn test_delete_workspace_cascades() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        db.add_workspace_member("ws-1", "user1").unwrap();
        db.push_config_revision("ws-1", "{}", "init", "", "admin")
            .unwrap();

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

        let v1 = db
            .push_config_revision("ws-1", r#"{"a":1}"#, "first", "", "admin")
            .unwrap();
        let v2 = db
            .push_config_revision("ws-1", r#"{"a":2}"#, "second", "", "admin")
            .unwrap();
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
        db.push_config_revision("ws-1", r#"{"key":"value"}"#, "test", "", "admin")
            .unwrap();

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

        db.push_config_revision("ws-1", r#"{"v":1}"#, "v1", "", "admin")
            .unwrap();
        db.push_config_revision("ws-1", r#"{"v":2}"#, "v2", "", "admin")
            .unwrap();

        let latest = db.get_latest_config_revision("ws-1").unwrap().unwrap();
        assert_eq!(latest.1, r#"{"v":2}"#); // config_json
        assert_eq!(latest.2, "v2"); // name
    }

    #[test]
    fn test_release_asset_add_and_delete() {
        let db = test_db();
        let rid = db.insert_release(DEFAULT_PRODUCT, "v9.9", "Test", "", false, "software").unwrap();

        db.add_release_asset(rid, "a.bin", 11).unwrap();
        db.add_release_asset(rid, "b.bin", 22).unwrap();
        let assets = db.get_release_assets(rid).unwrap();
        assert_eq!(assets.len(), 2);

        // Upsert keeps the same row count and updates size in place.
        db.add_release_asset(rid, "a.bin", 33).unwrap();
        let assets = db.get_release_assets(rid).unwrap();
        assert_eq!(assets.len(), 2);
        let a = assets.iter().find(|(n, _)| n == "a.bin").unwrap();
        assert_eq!(a.1, 33);

        // Delete one - the other remains.
        assert!(db.delete_release_asset(rid, "a.bin").unwrap());
        let remaining = db.get_release_assets(rid).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0, "b.bin");

        // Deleting again is a no-op (returns false).
        assert!(!db.delete_release_asset(rid, "a.bin").unwrap());
    }

    #[test]
    fn test_doc_pages_crud_and_bulk_upsert() {
        let mut db = test_db();
        let rid = db
            .insert_release(DEFAULT_PRODUCT, "v1.0", "FusionHub 1.0", "", false, "software")
            .unwrap();

        // Editor upsert marks as user
        db.upsert_doc_page(rid, "imu", "IMU Source", "# IMU", Some("sources"), 1)
            .unwrap();
        let page = db.get_doc_page(rid, "imu").unwrap().unwrap();
        assert_eq!(page.0, "IMU Source");
        assert_eq!(page.1, "# IMU");
        assert_eq!(page.2.as_deref(), Some("sources"));

        db.upsert_doc_page(rid, "imu", "IMU Source v2", "# v2", Some("sources"), 2)
            .unwrap();
        let page = db.get_doc_page(rid, "imu").unwrap().unwrap();
        assert_eq!(page.0, "IMU Source v2");
        assert_eq!(page.3, 2);

        db.upsert_doc_page(rid, "sources", "Sources", "Index", None, 0)
            .unwrap();
        assert_eq!(db.list_doc_pages(rid).unwrap().len(), 2);

        // Bulk (pipeline) upsert: skips user-owned `imu`, writes new slugs as pipeline.
        let new_pages = vec![
            (
                "imu".to_string(),
                "Pipeline IMU".to_string(),
                "pipe".to_string(),
                Some("sources".to_string()),
                5,
            ),
            (
                "a".to_string(),
                "A".to_string(),
                "body a".to_string(),
                None,
                0,
            ),
            (
                "b".to_string(),
                "B".to_string(),
                "body b".to_string(),
                Some("a".to_string()),
                1,
            ),
        ];
        let (written, skipped) = db.upsert_doc_pages(rid, &new_pages).unwrap();
        assert_eq!(written, 2);
        assert_eq!(skipped, vec!["imu".to_string()]);
        // imu is still the user's edit, untouched.
        let imu = db.get_doc_page(rid, "imu").unwrap().unwrap();
        assert_eq!(imu.0, "IMU Source v2");
        assert_eq!(db.list_doc_pages(rid).unwrap().len(), 4);

        // Cascade delete with release
        assert!(db.delete_release(DEFAULT_PRODUCT, "v1.0").unwrap());
        assert!(db.get_doc_page(rid, "a").unwrap().is_none());
    }

    #[test]
    fn test_doc_page_origin_tracking() {
        let mut db = test_db();
        let rid = db.insert_release(DEFAULT_PRODUCT, "v1.0", "", "", false, "software").unwrap();

        // Pipeline bulk plants a page.
        db.upsert_doc_pages(
            rid,
            &[("imu".into(), "IMU".into(), "pipe body".into(), None, 0)],
        )
        .unwrap();
        let origin: String = db
            .conn
            .query_row(
                "SELECT origin FROM doc_pages WHERE release_id = ?1 AND slug = ?2",
                params![rid, "imu"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(origin, "pipeline");

        // Editor edit on the same slug promotes it to user.
        db.upsert_doc_page(rid, "imu", "IMU (edited)", "user body", None, 0)
            .unwrap();
        let origin: String = db
            .conn
            .query_row(
                "SELECT origin FROM doc_pages WHERE release_id = ?1 AND slug = ?2",
                params![rid, "imu"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(origin, "user");

        // Pipeline re-run now skips the user page.
        let (written, skipped) = db
            .upsert_doc_pages(
                rid,
                &[("imu".into(), "IMU".into(), "pipe again".into(), None, 0)],
            )
            .unwrap();
        assert_eq!(written, 0);
        assert_eq!(skipped, vec!["imu".to_string()]);
        let body = db.get_doc_page(rid, "imu").unwrap().unwrap().1;
        assert_eq!(body, "user body");
    }

    #[test]
    fn test_copy_user_docs_to_new_release() {
        let mut db = test_db();
        let old = db.insert_release(DEFAULT_PRODUCT, "v1.0", "", "", false, "software").unwrap();

        // Mixed origins under the old release.
        db.upsert_doc_pages(
            old,
            &[
                (
                    "imu".into(),
                    "IMU".into(),
                    "pipe".into(),
                    Some("sources".into()),
                    0,
                ),
                ("sources".into(), "Sources".into(), "auto".into(), None, 10),
            ],
        )
        .unwrap();
        db.upsert_doc_page(
            old,
            "general",
            "General",
            "# General\nHand-authored",
            None,
            0,
        )
        .unwrap();
        db.upsert_doc_page(
            old,
            "getting-started",
            "Getting Started",
            "guide",
            Some("general"),
            1,
        )
        .unwrap();

        // Brand-new release tag.
        let (new_id, created) = db.ensure_release_created("v1.1", "FusionHub 1.1").unwrap();
        assert!(created);

        let prior = db
            .latest_prior_release_with_user_docs(new_id, DEFAULT_PRODUCT)
            .unwrap();
        assert_eq!(prior.as_ref().map(|p| p.1.as_str()), Some("v1.0"));
        let (src_id, _src_tag) = prior.unwrap();

        let n = db.copy_user_doc_pages(src_id, new_id).unwrap();
        assert_eq!(n, 2); // general + getting-started

        let pages: Vec<String> = db
            .list_doc_pages(new_id)
            .unwrap()
            .into_iter()
            .map(|p| p.0)
            .collect();
        assert!(pages.contains(&"general".to_string()));
        assert!(pages.contains(&"getting-started".to_string()));
        assert!(!pages.contains(&"imu".to_string()));
        assert!(!pages.contains(&"sources".to_string()));

        // All carried pages retain origin='user'.
        for slug in &pages {
            let o: String = db
                .conn
                .query_row(
                    "SELECT origin FROM doc_pages WHERE release_id = ?1 AND slug = ?2",
                    params![new_id, slug],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(o, "user", "slug {} should be user", slug);
        }

        // Re-ensuring the existing tag reports not-newly-created.
        let (_, created) = db.ensure_release_created("v1.1", "").unwrap();
        assert!(!created);
    }

    #[test]
    fn test_doc_releases_filters_to_releases_with_pages() {
        let db = test_db();
        let r1 = db
            .insert_release(DEFAULT_PRODUCT, "v1.0", "with docs", "", false, "software")
            .unwrap();
        let _r2 = db
            .insert_release(DEFAULT_PRODUCT, "v1.1", "no docs", "", false, "software")
            .unwrap();
        db.upsert_doc_page(r1, "intro", "Intro", "...", None, 0)
            .unwrap();

        let releases = db.list_doc_releases(DEFAULT_PRODUCT).unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].1, "v1.0");
        assert_eq!(releases[0].4, 1); // page count
    }

    #[test]
    fn test_delete_user_removes_dependent_rows() {
        let db = test_db();
        db.create_user("bob", "hash", "user").unwrap();
        db.create_user("keeper", "hash", "user").unwrap();
        db.create_workspace("ws-del", "WS", "", "", "keeper").unwrap();
        db.add_workspace_member("ws-del", "bob").unwrap();
        db.add_workspace_member("ws-del", "keeper").unwrap();

        db.delete_user("bob").unwrap();

        // The deleted account must not linger as a workspace member; the
        // other member is untouched.
        let members: Vec<String> = db
            .list_workspace_members("ws-del")
            .unwrap()
            .into_iter()
            .map(|(u, _)| u)
            .collect();
        assert!(!members.contains(&"bob".to_string()));
        assert!(members.contains(&"keeper".to_string()));
    }

    #[test]
    fn test_ws_doc_pages_are_workspace_separated() {
        let mut db = test_db();
        db.create_workspace("ws-a", "A", "", "", "admin").unwrap();
        db.create_workspace("ws-b", "B", "", "", "admin").unwrap();

        db.upsert_ws_doc_page("ws-a", "guide", "Guide A", "a body", None, 0)
            .unwrap();
        db.upsert_ws_doc_page("ws-b", "guide", "Guide B", "b body", None, 0)
            .unwrap();
        db.upsert_ws_doc_page("ws-a", "child", "Child", "c", Some("guide"), 1)
            .unwrap();

        // Same slug lives independently per workspace.
        let a = db.get_ws_doc_page("ws-a", "guide").unwrap().unwrap();
        assert_eq!(a.1, "a body");
        let b = db.get_ws_doc_page("ws-b", "guide").unwrap().unwrap();
        assert_eq!(b.1, "b body");
        assert_eq!(db.list_ws_doc_pages("ws-a").unwrap().len(), 2);
        assert_eq!(db.list_ws_doc_pages("ws-b").unwrap().len(), 1);

        // Rename cascades to children within the workspace only.
        assert!(db.rename_ws_doc_page("ws-a", "guide", "manual").unwrap());
        let child = db.get_ws_doc_page("ws-a", "child").unwrap().unwrap();
        assert_eq!(child.2.as_deref(), Some("manual"));
        assert!(db.get_ws_doc_page("ws-b", "guide").unwrap().is_some());

        // Delete affects only the addressed workspace.
        assert!(db.delete_ws_doc_page("ws-a", "manual").unwrap());
        assert!(!db.delete_ws_doc_page("ws-a", "manual").unwrap());
        assert!(db.get_ws_doc_page("ws-b", "guide").unwrap().is_some());

        // Assets: upsert overwrites size, listing is per-workspace.
        db.upsert_ws_doc_asset("ws-a", "shot.png", 10).unwrap();
        db.upsert_ws_doc_asset("ws-a", "shot.png", 20).unwrap();
        assert_eq!(db.list_ws_doc_assets("ws-a").unwrap(), vec![("shot.png".to_string(), 20)]);
        assert!(db.list_ws_doc_assets("ws-b").unwrap().is_empty());
        assert!(db.delete_ws_doc_asset("ws-a", "shot.png").unwrap());
    }

    #[test]
    fn test_migrate_workspace_release_rows() {
        let db = test_db();
        db.create_workspace("ws-a", "A", "", "", "admin").unwrap();

        // Two legacy workspace-scoped releases sharing a slug and a file name;
        // the newer release (higher id) must win both.
        let old = db
            .insert_release(DEFAULT_PRODUCT, "v0.9", "old", "", false, "software")
            .unwrap();
        let new = db
            .insert_release(DEFAULT_PRODUCT, "v1.0", "new", "", false, "software")
            .unwrap();
        db.conn
            .execute("UPDATE releases SET workspace_id = 'ws-a'", [])
            .unwrap();
        for (rid, body) in [(old, "old body"), (new, "new body")] {
            db.upsert_doc_page(rid, "guide", "Guide", body, None, 0).unwrap();
            db.upsert_doc_asset(rid, "shot.png", 5).unwrap();
        }

        // Newest first, so the caller migrates `new` before `old`.
        let scoped = db.list_workspace_scoped_releases().unwrap();
        assert_eq!(
            scoped.iter().map(|r| r.1.as_str()).collect::<Vec<_>>(),
            vec!["v1.0", "v0.9"],
        );

        for (rid, tag, ..) in &scoped {
            let assets = db.migrate_release_docs_to_workspace(*rid, "ws-a").unwrap();
            assert_eq!(assets, vec!["shot.png".to_string()], "release {}", tag);
            db.delete_release_by_id(*rid).unwrap();
        }

        // The newer release's page content won; rows exist exactly once.
        let page = db.get_ws_doc_page("ws-a", "guide").unwrap().unwrap();
        assert_eq!(page.1, "new body");
        assert_eq!(db.list_ws_doc_pages("ws-a").unwrap().len(), 1);
        assert_eq!(db.list_ws_doc_assets("ws-a").unwrap().len(), 1);

        // Release rows and their children are gone; nothing left to migrate.
        assert!(db.list_workspace_scoped_releases().unwrap().is_empty());
        assert!(db.get_release_by_product_tag(DEFAULT_PRODUCT, "v1.0").unwrap().is_none());
        assert!(db.get_doc_page(new, "guide").unwrap().is_none());
    }

    #[test]
    fn test_ensure_release_is_idempotent() {
        let db = test_db();
        let id1 = db.ensure_release("v2.0", "FusionHub 2.0").unwrap();
        let id2 = db.ensure_release("v2.0", "different name").unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_workspace_files_crud() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        db.create_workspace("ws-2", "WS2", "", "", "admin").unwrap();

        db.upsert_workspace_file("ws-1", "build.zip", 100, "alice").unwrap();
        db.upsert_workspace_file("ws-2", "build.zip", 7, "bob").unwrap();
        assert!(db.workspace_file_exists("ws-1", "build.zip").unwrap());
        assert!(!db.workspace_file_exists("ws-1", "other.zip").unwrap());

        // Re-upload overwrites size + author in place.
        db.upsert_workspace_file("ws-1", "build.zip", 200, "carol").unwrap();
        let files = db.list_workspace_files("ws-1").unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "build.zip");
        assert_eq!(files[0].1, 200);
        assert_eq!(files[0].2, "carol");

        // Workspaces stay separated; delete only hits the addressed row.
        assert_eq!(db.list_workspace_files("ws-2").unwrap()[0].1, 7);
        assert!(db.delete_workspace_file("ws-1", "build.zip").unwrap());
        assert!(!db.delete_workspace_file("ws-1", "build.zip").unwrap());
        assert_eq!(db.list_workspace_files("ws-2").unwrap().len(), 1);
    }

    #[test]
    fn test_doc_collections_hidden_from_release_lists() {
        let db = test_db();

        db.insert_release(DEFAULT_PRODUCT, "v1.0", "Software", "", false, "software")
            .unwrap();
        let doc_id = db
            .insert_release(DEFAULT_PRODUCT, "sales-manual", "Sales Manual", "", false, "docs")
            .unwrap();

        // Doc-only collections never surface in software release lists.
        let all = db.list_releases().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].1, "v1.0");

        // Attaching binaries promotes the collection to a software release.
        db.set_release_kind(doc_id, "software").unwrap();
        assert_eq!(db.list_releases().unwrap().len(), 2);

        // The docs insert path creates 'docs' rows that stay hidden.
        let (_, created) = db
            .ensure_release_created_for(DEFAULT_PRODUCT, "manual-2", "Manual 2")
            .unwrap();
        assert!(created);
        assert!(db.list_releases().unwrap().iter().all(|r| r.1 != "manual-2"));
    }

    #[test]
    fn test_release_kind_migration_backfill() {
        let path = std::env::temp_dir()
            .join(format!("susi_kindtest_{}.db", std::process::id()));
        let p = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path);
        {
            let db = LicenseDb::open(&p).unwrap();
            // Simulate a pre-`kind` schema: drop the column, leaving one
            // doc-only row (pages, no binaries) and one software row.
            db.conn
                .execute_batch("ALTER TABLE releases DROP COLUMN kind;")
                .unwrap();
            db.conn
                .execute_batch(
                    "INSERT INTO releases (id, tag, name, created_at) VALUES
                         (1, 'manual', 'Manual', '2020-01-01T00:00:00Z'),
                         (2, 'v1.0', 'Release', '2020-01-01T00:00:00Z');
                     INSERT INTO doc_pages (release_id, slug, title, updated_at)
                         VALUES (1, 'intro', 'Intro', '2020-01-01T00:00:00Z');
                     INSERT INTO release_assets (release_id, file_name, file_size)
                         VALUES (2, 'setup.msi', 123);",
                )
                .unwrap();
        }

        // Reopen - migration adds `kind` and backfills doc-only rows.
        let db = LicenseDb::open(&p).unwrap();
        let all = db.list_releases().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].1, "v1.0");

        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_federation_secret_idempotent_per_workspace() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        db.create_workspace("ws-2", "WS2", "", "", "admin").unwrap();

        let s1a = db
            .get_or_create_workspace_federation_secret("ws-1")
            .unwrap();
        let s1b = db
            .get_or_create_workspace_federation_secret("ws-1")
            .unwrap();
        assert_eq!(s1a, s1b, "same workspace must return same secret");
        assert!(!s1a.is_empty());
        // base64 of 32 bytes → 44 chars (with padding).
        assert_eq!(s1a.len(), 44);

        let s2 = db
            .get_or_create_workspace_federation_secret("ws-2")
            .unwrap();
        assert_ne!(s1a, s2, "different workspaces must get different secrets");
    }

    #[test]
    fn test_federation_secret_rotation() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();

        let before = db
            .get_or_create_workspace_federation_secret("ws-1")
            .unwrap();
        let rotated = db.rotate_workspace_federation_secret("ws-1").unwrap();
        assert_ne!(before, rotated, "rotation must produce a new secret");

        // Subsequent reads return the rotated value.
        let after = db
            .get_or_create_workspace_federation_secret("ws-1")
            .unwrap();
        assert_eq!(after, rotated);

        // Rotating on a workspace that never had a secret should still work
        // (treat as create).
        db.create_workspace("ws-fresh", "F", "", "", "admin")
            .unwrap();
        let fresh = db.rotate_workspace_federation_secret("ws-fresh").unwrap();
        assert_eq!(fresh.len(), 44);
        assert_eq!(
            db.get_or_create_workspace_federation_secret("ws-fresh")
                .unwrap(),
            fresh
        );
    }

    #[test]
    fn test_workspace_peer_upsert_and_list() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        db.create_workspace("ws-2", "WS2", "", "", "admin").unwrap();

        // Register two peers in ws-1 and one in ws-2.
        db.upsert_workspace_peer(
            "ws-1",
            "hostA",
            "https://a.local:443",
            "Laptop A",
            "",
            "alice",
        )
        .unwrap();
        db.upsert_workspace_peer(
            "ws-1",
            "hostB",
            "https://b.local:443",
            "Laptop B",
            "",
            "alice",
        )
        .unwrap();
        db.upsert_workspace_peer("ws-2", "hostA", "https://other.local", "", "", "bob")
            .unwrap();

        let peers_ws1 = db.list_workspace_peers("ws-1").unwrap();
        assert_eq!(peers_ws1.len(), 2);
        let host_ids: Vec<&str> = peers_ws1.iter().map(|p| p.0.as_str()).collect();
        assert!(host_ids.contains(&"hostA"));
        assert!(host_ids.contains(&"hostB"));

        let peers_ws2 = db.list_workspace_peers("ws-2").unwrap();
        assert_eq!(peers_ws2.len(), 1);
        assert_eq!(peers_ws2[0].1, "https://other.local");

        // Re-register hostA with a new URL - must update in place.
        std::thread::sleep(std::time::Duration::from_millis(5));
        db.upsert_workspace_peer(
            "ws-1",
            "hostA",
            "https://a.new:443",
            "Laptop A v2",
            "",
            "alice",
        )
        .unwrap();
        let after = db.list_workspace_peers("ws-1").unwrap();
        assert_eq!(after.len(), 2, "upsert must not create duplicate row");
        let row_a = after.iter().find(|p| p.0 == "hostA").unwrap();
        assert_eq!(row_a.1, "https://a.new:443");
        assert_eq!(row_a.2, "Laptop A v2");
    }

    #[test]
    fn test_workspace_peer_carries_network_id_through_upsert() {
        // Peers register their network_id; re-registration updates it in
        // place so flipping the setting on a live instance propagates to
        // other workspace members at their next federation poll.
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        db.upsert_workspace_peer("ws-1", "hostA", "https://a", "A", "lab-east", "alice")
            .unwrap();
        db.upsert_workspace_peer("ws-1", "hostB", "https://b", "B", "lab-west", "alice")
            .unwrap();
        let rows = db.list_workspace_peers("ws-1").unwrap();
        let a = rows.iter().find(|r| r.0 == "hostA").unwrap();
        let b = rows.iter().find(|r| r.0 == "hostB").unwrap();
        assert_eq!(a.3, "lab-east", "network_id stored on initial insert");
        assert_eq!(b.3, "lab-west");
        // Flip hostA's network_id; re-register must update the row.
        db.upsert_workspace_peer("ws-1", "hostA", "https://a", "A", "lab-west", "alice")
            .unwrap();
        let rows2 = db.list_workspace_peers("ws-1").unwrap();
        let a2 = rows2.iter().find(|r| r.0 == "hostA").unwrap();
        assert_eq!(a2.3, "lab-west", "network_id updated on re-register");
    }

    #[test]
    fn test_workspace_graph_first_save_seeds_v1() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        assert!(db.get_workspace_graph("ws-1").unwrap().is_none());
        assert!(db.get_workspace_graph_version("ws-1").unwrap().is_none());

        let v = db
            .upsert_workspace_graph("ws-1", None, r#"{"sources":{}}"#, "alice")
            .unwrap();
        assert_eq!(v, 1);
        let row = db.get_workspace_graph("ws-1").unwrap().expect("row exists");
        assert_eq!(row.0, 1);
        assert_eq!(row.1, r#"{"sources":{}}"#);
        assert_eq!(row.2, "alice");
        assert_eq!(db.get_workspace_graph_version("ws-1").unwrap(), Some(1));
    }

    #[test]
    fn test_workspace_graph_optimistic_lock_bumps_on_match() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        db.upsert_workspace_graph("ws-1", None, r#"{"a":1}"#, "alice")
            .unwrap();

        let v2 = db
            .upsert_workspace_graph("ws-1", Some(1), r#"{"a":2}"#, "bob")
            .unwrap();
        assert_eq!(v2, 2);
        let row = db.get_workspace_graph("ws-1").unwrap().unwrap();
        assert_eq!(row.0, 2);
        assert_eq!(row.1, r#"{"a":2}"#);
        assert_eq!(row.2, "bob");
    }

    #[test]
    fn test_workspace_graph_stale_version_rejected() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        db.upsert_workspace_graph("ws-1", None, r#"{"v":1}"#, "alice")
            .unwrap();
        db.upsert_workspace_graph("ws-1", Some(1), r#"{"v":2}"#, "alice")
            .unwrap();
        // Caller still thinks it's at v1 - must fail with current=2.
        let err = db
            .upsert_workspace_graph("ws-1", Some(1), r#"{"v":3}"#, "bob")
            .unwrap_err();
        match err {
            crate::error::LicenseError::GraphConflict { current } => assert_eq!(current, 2),
            other => panic!("expected GraphConflict, got {:?}", other),
        }
        // Stored row unchanged after the rejected write.
        assert_eq!(
            db.get_workspace_graph("ws-1").unwrap().unwrap().1,
            r#"{"v":2}"#
        );
    }

    #[test]
    fn test_workspace_graph_no_expected_version_after_first_save_conflicts() {
        // Once a row exists, `expected_version = None` must NOT silently
        // overwrite - that would be the same "forgot to load" footgun.
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        db.upsert_workspace_graph("ws-1", None, r#"{"v":1}"#, "alice")
            .unwrap();
        let err = db
            .upsert_workspace_graph("ws-1", None, r#"{"v":2}"#, "bob")
            .unwrap_err();
        assert!(matches!(
            err,
            crate::error::LicenseError::GraphConflict { current: 1 }
        ));
    }

    #[test]
    fn test_workspace_graph_cascade_deletes_with_workspace() {
        // Dropping the parent workspace must take the graph with it (FK ON DELETE CASCADE).
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        db.upsert_workspace_graph("ws-1", None, "{}", "alice")
            .unwrap();
        db.delete_workspace("ws-1").unwrap();
        assert!(db.get_workspace_graph("ws-1").unwrap().is_none());
    }

    #[test]
    fn test_workspace_peer_delete() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        db.upsert_workspace_peer("ws-1", "hostA", "https://a", "", "", "alice")
            .unwrap();

        assert!(db.delete_workspace_peer("ws-1", "hostA").unwrap());
        assert_eq!(db.list_workspace_peers("ws-1").unwrap().len(), 0);
        // Second delete returns false.
        assert!(!db.delete_workspace_peer("ws-1", "hostA").unwrap());
        // Wrong workspace also false.
        db.upsert_workspace_peer("ws-1", "hostA", "https://a", "", "", "alice")
            .unwrap();
        assert!(!db.delete_workspace_peer("ws-other", "hostA").unwrap());
        assert_eq!(db.list_workspace_peers("ws-1").unwrap().len(), 1);
    }

    #[test]
    fn test_invitation_token_roundtrip() {
        let db = test_db();
        db.seed_admin("hash").unwrap();
        db.create_user("alice", "unusable-random-hash", "user")
            .unwrap();

        assert!(!db.has_pending_invitation("alice").unwrap());
        db.insert_invitation_token("inv-1", "alice", 7 * 24 * 3600)
            .unwrap();
        assert!(db.has_pending_invitation("alice").unwrap());

        // Same consume function handles both kinds - invitee uses the
        // existing /#/reset/<token> endpoint to pick their initial password.
        let user = db.consume_password_reset_token("inv-1").unwrap();
        assert_eq!(user.as_deref(), Some("alice"));

        // Single-use.
        assert!(db.consume_password_reset_token("inv-1").unwrap().is_none());
        // Consumed → no longer "pending".
        assert!(!db.has_pending_invitation("alice").unwrap());
    }

    #[test]
    fn test_resend_invalidates_prior_token() {
        let db = test_db();
        db.seed_admin("hash").unwrap();
        db.create_user("bob", "h", "user").unwrap();

        db.insert_invitation_token("old", "bob", 3600).unwrap();
        // Admin resends - must invalidate the old link before minting the new one.
        db.invalidate_setup_tokens("bob").unwrap();
        db.insert_invitation_token("new", "bob", 3600).unwrap();

        assert!(db.consume_password_reset_token("old").unwrap().is_none());
        assert_eq!(
            db.consume_password_reset_token("new").unwrap().as_deref(),
            Some("bob")
        );
    }

    #[test]
    fn test_invitation_expired_is_not_pending() {
        let db = test_db();
        db.seed_admin("hash").unwrap();
        db.create_user("carol", "h", "user").unwrap();

        db.insert_invitation_token("stale", "carol", -1).unwrap();
        assert!(!db.has_pending_invitation("carol").unwrap());
        assert!(db.consume_password_reset_token("stale").unwrap().is_none());
    }

    #[test]
    fn test_reset_token_still_works_via_consume() {
        // Sanity: the existing forgot-password path (kind='reset') keeps
        // working through the now-broader consume_password_reset_token.
        let db = test_db();
        db.seed_admin("hash").unwrap();
        db.create_user("dave", "h", "user").unwrap();

        db.insert_password_reset_token("rh", "dave", 600).unwrap();
        assert_eq!(
            db.consume_password_reset_token("rh").unwrap().as_deref(),
            Some("dave")
        );
    }

    #[test]
    fn test_workspace_delete_cascades_federation_and_peers() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        db.get_or_create_workspace_federation_secret("ws-1")
            .unwrap();
        db.upsert_workspace_peer("ws-1", "hostA", "https://a", "", "", "alice")
            .unwrap();
        assert_eq!(db.list_workspace_peers("ws-1").unwrap().len(), 1);

        db.delete_workspace("ws-1").unwrap();

        // FK cascade should have wiped both rows.
        assert_eq!(db.list_workspace_peers("ws-1").unwrap().len(), 0);
        // Re-creating the workspace must yield a fresh secret, not the old one.
        db.create_workspace("ws-1", "WS again", "", "", "admin")
            .unwrap();
        let fresh = db
            .get_or_create_workspace_federation_secret("ws-1")
            .unwrap();
        assert_eq!(fresh.len(), 44);
    }

    #[test]
    fn test_asset_usage_and_rename_covers_shop_products() {
        let mut db = test_db();
        db.upsert_website_asset("sensor.png", 123).unwrap();
        db.upsert_website_page("intro", "Intro", "![img](sensor.png)", None, 0, "", "page", "", None)
            .unwrap();
        db.upsert_product("lpms-b2", "LPMS-B2", "", 34900, "usd", Some("sensor.png"), "txcd", true, 0)
            .unwrap();

        let rows = db.list_website_assets_with_usage().unwrap();
        assert_eq!(rows.len(), 1);
        let (name, size, usage, pages_csv, products_csv) = rows[0].clone();
        assert_eq!(name, "sensor.png");
        assert_eq!(size, 123);
        assert_eq!(usage, 1);
        assert_eq!(pages_csv, "intro");
        assert_eq!(products_csv, "lpms-b2");

        // Rename rewrites both page markdown and the product image reference.
        let (ok, n_pages) = db.rename_website_asset("sensor.png", "imu.png").unwrap();
        assert!(ok);
        assert_eq!(n_pages, 1);
        let body = db.get_website_page("intro").unwrap().unwrap().1;
        assert!(body.contains("](imu.png)"), "page body not rewritten: {}", body);
        let img: Option<String> = db
            .conn
            .query_row("SELECT image_asset FROM shop_products WHERE sku = 'lpms-b2'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(img.as_deref(), Some("imu.png"));
    }

    #[test]
    fn test_website_page_hidden_flag() {
        let mut db = test_db();
        db.upsert_website_page("about", "About", "# About", None, 0, "", "page", "", None)
            .unwrap();

        // New pages default to visible.
        let pages = db.list_website_pages().unwrap();
        assert_eq!(pages.len(), 1);
        assert!(!pages[0].6, "new page must not be hidden");
        assert!(!db.get_website_page("about").unwrap().unwrap().6);

        // Hide, verify, and check that editing the page keeps it hidden.
        assert!(db.set_website_page_hidden("about", true).unwrap());
        assert!(db.get_website_page("about").unwrap().unwrap().6);
        db.upsert_website_page("about", "About v2", "# About v2", None, 0, "", "page", "", None)
            .unwrap();
        assert!(
            db.get_website_page("about").unwrap().unwrap().6,
            "editing a page must not reset the hidden flag"
        );

        // Show again.
        assert!(db.set_website_page_hidden("about", false).unwrap());
        assert!(!db.get_website_page("about").unwrap().unwrap().6);

        // Unknown slug reports not-found.
        assert!(!db.set_website_page_hidden("nope", true).unwrap());
    }
}
