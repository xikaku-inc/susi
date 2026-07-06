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
                lease_duration_hours INTEGER NOT NULL DEFAULT 168,
                lease_grace_hours INTEGER NOT NULL DEFAULT 24,
                require_signed_binary INTEGER NOT NULL DEFAULT 0
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
                workspace_id TEXT DEFAULT NULL,
                product TEXT NOT NULL DEFAULT 'fusionhub',
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
            -- `network_id` is a peer-side scope string — peers only federate
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
                meta_description TEXT NOT NULL DEFAULT ''
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
                ON workspace_recordings(workspace_id, created_at DESC);",
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
        // — safe because it keeps them in the carry-over set; next pipeline run
        // re-stamps its own pages as 'pipeline'.
        let _ = self.conn.execute_batch(
            "ALTER TABLE doc_pages ADD COLUMN origin TEXT NOT NULL DEFAULT 'user';
             ALTER TABLE doc_assets ADD COLUMN origin TEXT NOT NULL DEFAULT 'user';",
        );

        // Add email column to users (nullable — admin sets it per user)
        let _ = self
            .conn
            .execute_batch("ALTER TABLE users ADD COLUMN email TEXT;");

        // SEO: per-page meta description override (empty = auto-derive from body_md)
        let _ = self.conn.execute_batch(
            "ALTER TABLE website_pages ADD COLUMN meta_description TEXT NOT NULL DEFAULT '';",
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

        // >> Add new migrations as own execute_batch statements here <<
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

    /// Single sweep across every license. Returns the number of rows removed.
    /// Run periodically from a background task instead of on every license
    /// read — the per-row variant turned every heartbeat into a DELETE.
    pub fn cleanup_all_expired_leases(&self) -> Result<usize, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let n = self
            .conn
            .execute(
                "DELETE FROM machine_activations
                 WHERE lease_expires_at != '' AND lease_expires_at < ?1",
                params![now],
            )
            .map_err(|e| LicenseError::Other(format!("DB cleanup: {}", e)))?;
        Ok(n)
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

        // Lease cleanup runs in a background task (`cleanup_all_expired_leases`),
        // not on every read — issuing a DELETE on every heartbeat dominated the
        // verify path and competed for the write lock with no benefit.

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
            "SELECT license_id, machine_code, friendly_name, activated_at, lease_expires_at
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
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        for r in rows.flatten() {
            let (license_id, machine_code, friendly_name, activated_str, lease_str) = r;
            let Some(activated_at) = DateTime::parse_from_rfc3339(&activated_str)
                .ok()
                .map(|d| d.with_timezone(&Utc))
            else {
                continue;
            };
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

    // -----------------------------------------------------------------------
    // License <-> user assignment
    // -----------------------------------------------------------------------

    pub fn assign_license_user(&self, license_id: &str, username: &str) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO license_users (license_id, username, added_at) VALUES (?1, ?2, ?3)",
                params![license_id, username, Utc::now().to_rfc3339()],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
        Ok(())
    }

    pub fn unassign_license_user(
        &self,
        license_id: &str,
        username: &str,
    ) -> Result<bool, LicenseError> {
        let rows = self
            .conn
            .execute(
                "DELETE FROM license_users WHERE license_id = ?1 AND username = ?2",
                params![license_id, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(rows > 0)
    }

    pub fn list_license_users(&self, license_id: &str) -> Result<Vec<String>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT username FROM license_users WHERE license_id = ?1 ORDER BY username")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let users = stmt
            .query_map(params![license_id], |r| r.get(0))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(users)
    }

    pub fn is_license_assigned(
        &self,
        license_id: &str,
        username: &str,
    ) -> Result<bool, LicenseError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM license_users WHERE license_id = ?1 AND username = ?2",
                params![license_id, username],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(count > 0)
    }

    /// Every (username, license_key, product) assignment row. One query for
    /// the admin users list instead of a per-user lookup.
    pub fn list_all_license_assignments(
        &self,
    ) -> Result<Vec<(String, String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT lu.username, l.license_key, l.product
                 FROM license_users lu JOIN licenses l ON l.id = lu.license_id
                 ORDER BY lu.username, l.product",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
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
        let stored: Option<String> = self
            .conn
            .query_row(
                "SELECT totp_secret FROM users WHERE username = ?1",
                params![username],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        stored.map(|s| self.open_secret(&s)).transpose()
    }

    pub fn update_user_password(&self, username: &str, new_hash: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE users SET password_hash = ?1, must_change_password = 0,
                        token_version = token_version + 1, updated_at = ?2
                 WHERE username = ?3",
                params![new_hash, now, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    /// Current session-JWT version for a user; None when the user doesn't
    /// exist. A JWT is only valid while its embedded `tv` matches this value.
    pub fn get_user_token_version(&self, username: &str) -> Result<Option<i64>, LicenseError> {
        self.conn
            .query_row(
                "SELECT token_version FROM users WHERE username = ?1",
                params![username],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    /// Clear the must-change-password bootstrap flag without touching the
    /// hash. Used by invitation magic-login: the customer proved inbox
    /// control and stays passwordless (the stored hash is a random secret).
    pub fn clear_must_change_password(&self, username: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE users SET must_change_password = 0, updated_at = ?1 WHERE username = ?2",
                params![now, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    pub fn set_user_totp_secret(&self, username: &str, secret: &str) -> Result<(), LicenseError> {
        let sealed = self.seal_secret(secret)?;
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE users SET totp_secret = ?1, totp_enabled = 0, updated_at = ?2 WHERE username = ?3",
                params![sealed, now, username],
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

    /// Find a username by email (case-insensitive). Returns None if zero or
    /// multiple matches — ambiguous addresses shouldn't grant a password reset.
    pub fn find_unique_username_by_email(
        &self,
        email: &str,
    ) -> Result<Option<String>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT username FROM users WHERE LOWER(email) = LOWER(?1) LIMIT 2")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows: Vec<String> = stmt
            .query_map(params![email], |r| r.get::<_, String>(0))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        if rows.len() == 1 {
            Ok(Some(rows.into_iter().next().unwrap()))
        } else {
            Ok(None)
        }
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
        let count: i64 = self
            .conn
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
        let n = self
            .conn
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
    pub fn peek_login_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<LoginTokenRow>, LicenseError> {
        let row: Option<(String, String, String, String, Option<String>)> = self
            .conn
            .query_row(
                "SELECT username, device_fp, device_label, expires_at, used_at FROM login_tokens WHERE token_hash = ?1 AND kind = 'device'",
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
        Ok(Some(LoginTokenRow {
            username,
            device_fp,
            device_label,
        }))
    }

    /// Validate a magic-link token and mark it as consumed.
    ///
    /// Returns the (username, device_fp, device_label) on success. Returns
    /// `Ok(None)` if the token is unknown, already used, or expired. The token
    /// is single-use — once consumed, subsequent lookups return `None`.
    pub fn consume_login_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<LoginTokenRow>, LicenseError> {
        let row: Option<(String, String, String, String, Option<String>)> = self
            .conn
            .query_row(
                "SELECT username, device_fp, device_label, expires_at, used_at FROM login_tokens WHERE token_hash = ?1 AND kind = 'device'",
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
                "UPDATE login_tokens SET used_at = ?1 WHERE token_hash = ?2 AND used_at IS NULL AND kind = 'device'",
                params![now, token_hash],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        if n == 0 {
            // Race — another consumer beat us to it.
            return Ok(None);
        }
        Ok(Some(LoginTokenRow {
            username,
            device_fp,
            device_label,
        }))
    }

    pub fn insert_password_reset_token(
        &self,
        token_hash: &str,
        username: &str,
        ttl_seconds: i64,
    ) -> Result<(), LicenseError> {
        let now = Utc::now();
        let expires = now + Duration::seconds(ttl_seconds);
        self.conn
            .execute(
                "INSERT INTO login_tokens (token_hash, username, device_fp, device_label, created_at, expires_at, kind)
                 VALUES (?1, ?2, '', '', ?3, ?4, 'reset')",
                params![token_hash, username, now.to_rfc3339(), expires.to_rfc3339()],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
        Ok(())
    }

    /// Mint an admin-initiated invitation token. Same single-use semantics as
    /// a password-reset token, but stored with `kind = 'invite'` so welcome
    /// emails, longer TTLs, and pending-invite UI can be distinguished from
    /// user-initiated resets in audit.
    pub fn insert_invitation_token(
        &self,
        token_hash: &str,
        username: &str,
        ttl_seconds: i64,
    ) -> Result<(), LicenseError> {
        let now = Utc::now();
        let expires = now + Duration::seconds(ttl_seconds);
        self.conn
            .execute(
                "INSERT INTO login_tokens (token_hash, username, device_fp, device_label, created_at, expires_at, kind)
                 VALUES (?1, ?2, '', '', ?3, ?4, 'invite')",
                params![token_hash, username, now.to_rfc3339(), expires.to_rfc3339()],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
        Ok(())
    }

    /// Invalidate every outstanding emailed sign-in code for a user - called
    /// after too many wrong guesses so a live code can't be brute-forced for
    /// the rest of its TTL.
    pub fn invalidate_signin_codes(&self, username: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE login_tokens SET used_at = ?1
                 WHERE username = ?2 AND used_at IS NULL AND kind = 'device'",
                params![now, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    /// Invalidate every outstanding reset/invite token for a user — used
    /// when re-issuing an invitation so the previous link stops working.
    pub fn invalidate_setup_tokens(&self, username: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE login_tokens SET used_at = ?1
                 WHERE username = ?2 AND used_at IS NULL AND kind IN ('reset','invite')",
                params![now, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    /// True iff the user has at least one unused, unexpired invitation token.
    /// Used by the admin UI to show a "Pending invite" badge.
    /// Look up an invitation token WITHOUT consuming it. Same validity rules
    /// as the consume path (unused + within TTL), restricted to kind='invite'.
    /// Used by magic-login to check the invitee's role before consuming.
    pub fn peek_invitation_token(&self, token_hash: &str) -> Result<Option<String>, LicenseError> {
        let row: Option<(String, String, Option<String>)> = self
            .conn
            .query_row(
                "SELECT username, expires_at, used_at FROM login_tokens
                 WHERE token_hash = ?1 AND kind = 'invite'",
                params![token_hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        let Some((username, expires_at, used_at)) = row else {
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
        Ok(Some(username))
    }

    pub fn has_pending_invitation(&self, username: &str) -> Result<bool, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM login_tokens
                 WHERE username = ?1 AND kind = 'invite' AND used_at IS NULL AND expires_at > ?2",
                params![username, now],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(count > 0)
    }

    /// Validate a password-reset or invitation token and mark it consumed.
    /// Returns the username on success. Single-use; matches `kind IN
    /// ('reset','invite')` so the same `/#/reset/<token>` flow lets a new
    /// user set their initial password and a returning user reset theirs.
    pub fn consume_password_reset_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<String>, LicenseError> {
        let row: Option<(String, String, Option<String>)> = self
            .conn
            .query_row(
                "SELECT username, expires_at, used_at FROM login_tokens
                 WHERE token_hash = ?1 AND kind IN ('reset','invite')",
                params![token_hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;

        let Some((username, expires_at, used_at)) = row else {
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
        let n = self
            .conn
            .execute(
                "UPDATE login_tokens SET used_at = ?1
                 WHERE token_hash = ?2 AND used_at IS NULL AND kind IN ('reset','invite')",
                params![now, token_hash],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        if n == 0 {
            return Ok(None);
        }
        Ok(Some(username))
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
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;
        tx.execute(
            "DELETE FROM totp_backup_codes WHERE username = ?1",
            params![username],
        )
        .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        for h in hashes {
            tx.execute(
                "INSERT INTO totp_backup_codes (username, code_hash, created_at) VALUES (?1, ?2, ?3)",
                params![username, h, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert backup: {}", e)))?;
        }
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB commit: {}", e)))?;
        Ok(())
    }

    pub fn clear_backup_codes(&self, username: &str) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "DELETE FROM totp_backup_codes WHERE username = ?1",
                params![username],
            )
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
            .query_map(params![username], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })
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

    /// Combined `find + touch` for the auth hot path. Uses
    /// `UPDATE ... RETURNING` so we do exactly one round-trip to validate the
    /// bearer and bump `last_used_at` (instead of two distinct lock cycles).
    /// Returns `None` if the hash is unknown.
    pub fn find_and_touch_api_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<ApiTokenAuthRow>, LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .query_row(
                "UPDATE api_tokens SET last_used_at = ?1
                 WHERE token_hash = ?2
                 RETURNING id, username, revoked_at",
                params![now, token_hash],
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
            .execute(
                "UPDATE api_tokens SET last_used_at = ?1 WHERE id = ?2",
                params![now, id],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    pub fn list_api_tokens_for_user(
        &self,
        username: &str,
    ) -> Result<Vec<ApiTokenInfo>, LicenseError> {
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
        let n = self
            .conn
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

    pub fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
    ) -> Result<(), LicenseError> {
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
        self.conn
            .execute("DELETE FROM license_users WHERE username = ?1", params![username])
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

    pub fn set_user_role(&self, username: &str, role: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        let n = self
            .conn
            .execute(
                "UPDATE users SET role = ?2, updated_at = ?3 WHERE username = ?1",
                params![username, role, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        if n == 0 {
            return Err(LicenseError::Other("User not found".into()));
        }
        Ok(())
    }

    /// Single-row fetch of every user attribute the admin gate needs:
    /// (role, must_change_password, totp_enabled). Replaces the three
    /// separate `get_user_role` / `user_must_change_password` /
    /// `user_totp_enabled` calls — saves two SQLite round-trips and two
    /// extra mutex cycles per admin request. Returns `None` if the
    /// username doesn't exist (which the caller should treat as a denied
    /// auth, same as the unwrap-defaults the old helpers used).
    pub fn get_user_admin_check(
        &self,
        username: &str,
    ) -> Result<Option<(String, bool, bool)>, LicenseError> {
        self.conn
            .query_row(
                "SELECT role, must_change_password, totp_enabled FROM users WHERE username = ?1",
                params![username],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)? != 0,
                        r.get::<_, i64>(2)? != 0,
                    ))
                },
            )
            .optional()
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

    /// Rename a user across every username-keyed table, atomically. Tables
    /// with a uniqueness constraint on (x, username) can already hold rows
    /// under the new name (e.g. left over from an earlier partial rename, or
    /// memberships added by hand) - those are merged instead of renamed:
    /// duplicate membership rows are dropped. Without the merge a plain UPDATE aborts on the unique
    /// constraint and a non-transactional rename leaves half the tables on
    /// the old name.
    pub fn rename_user(&self, old_username: &str, new_username: &str) -> Result<(), LicenseError> {
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| LicenseError::Other(format!("DB begin: {}", e)))?;
        let result = self.rename_user_inner(old_username, new_username);
        if result.is_ok() {
            self.conn
                .execute_batch("COMMIT")
                .map_err(|e| LicenseError::Other(format!("DB commit: {}", e)))?;
        } else {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
        result
    }

    fn rename_user_inner(&self, old_username: &str, new_username: &str) -> Result<(), LicenseError> {
        let run = |sql: &str| {
            self.conn
                .execute(sql, params![new_username, old_username])
                .map(|_| ())
                .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))
        };
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE users SET username = ?1, updated_at = ?2 WHERE username = ?3",
                params![new_username, now, old_username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        // Workspace memberships: drop the now-duplicate row where the new name
        // is already a member, then rename the rest.
        run("DELETE FROM workspace_members WHERE username = ?2
             AND workspace_id IN (SELECT workspace_id FROM workspace_members WHERE username = ?1)")?;
        run("UPDATE workspace_members SET username = ?1 WHERE username = ?2")?;
        run("UPDATE workspaces SET created_by = ?1 WHERE created_by = ?2")?;
        // License assignments and trusted devices: same merge, no roles.
        run("DELETE FROM license_users WHERE username = ?2
             AND license_id IN (SELECT license_id FROM license_users WHERE username = ?1)")?;
        run("UPDATE license_users SET username = ?1 WHERE username = ?2")?;
        run("DELETE FROM known_devices WHERE username = ?2
             AND fingerprint IN (SELECT fingerprint FROM known_devices WHERE username = ?1)")?;
        run("UPDATE known_devices SET username = ?1 WHERE username = ?2")?;
        run("UPDATE login_tokens SET username = ?1 WHERE username = ?2")?;
        run("UPDATE totp_backup_codes SET username = ?1 WHERE username = ?2")?;
        run("UPDATE api_tokens SET username = ?1 WHERE username = ?2")?;
        // Attribution columns: keep authorship pointing at the live account.
        run("UPDATE config_revisions SET author = ?1 WHERE author = ?2")?;
        run("UPDATE workspace_graphs SET updated_by = ?1 WHERE updated_by = ?2")?;
        run("UPDATE workspace_peers SET registered_by = ?1 WHERE registered_by = ?2")?;
        run("UPDATE workspace_recordings SET author = ?1 WHERE author = ?2")?;
        run("UPDATE website_page_revisions SET author = ?1 WHERE author = ?2")?;
        Ok(())
    }

    pub fn reset_user_password(&self, username: &str, new_hash: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE users SET password_hash = ?1, must_change_password = 1,
                        token_version = token_version + 1, updated_at = ?2
                 WHERE username = ?3",
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
        // Add creator as a member
        self.conn
            .execute(
                "INSERT INTO workspace_members (workspace_id, username, added_at)
                 VALUES (?1, ?2, ?3)",
                params![id, created_by, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert workspace member: {}", e)))?;
        Ok(())
    }

    pub fn get_workspace(
        &self,
        id: &str,
    ) -> Result<Option<(String, String, String, String, String, String, String)>, LicenseError>
    {
        match self.conn.query_row(
            "SELECT id, name, product, description, created_by, created_at, updated_at
             FROM workspaces WHERE id = ?1",
            params![id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                ))
            },
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    pub fn list_workspaces_for_user(
        &self,
        username: &str,
    ) -> Result<
        Vec<(
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        )>,
        LicenseError,
    > {
        let mut stmt = self.conn
            .prepare(
                "SELECT w.id, w.name, w.product, w.description, w.created_by, w.created_at, w.updated_at
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
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// List every workspace (admin view).
    pub fn list_all_workspaces(
        &self,
    ) -> Result<
        Vec<(
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        )>,
        LicenseError,
    > {
        let mut stmt = self.conn
            .prepare(
                "SELECT id, name, product, description, created_by, created_at, updated_at
                 FROM workspaces
                 ORDER BY name"
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
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
        created_by: Option<&str>,
    ) -> Result<bool, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let rows = match created_by {
            Some(cb) => self.conn
                .execute(
                    "UPDATE workspaces SET name = ?1, product = ?2, description = ?3, created_by = ?4, updated_at = ?5 WHERE id = ?6",
                    params![name, product, description, cb, now, id],
                )
                .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?,
            None => self.conn
                .execute(
                    "UPDATE workspaces SET name = ?1, product = ?2, description = ?3, updated_at = ?4 WHERE id = ?5",
                    params![name, product, description, now, id],
                )
                .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?,
        };
        Ok(rows > 0)
    }

    pub fn delete_workspace(&self, id: &str) -> Result<bool, LicenseError> {
        let rows = self
            .conn
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
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO workspace_members (workspace_id, username, added_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(workspace_id, username) DO NOTHING",
                params![workspace_id, username, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert member: {}", e)))?;
        Ok(())
    }

    pub fn remove_workspace_member(
        &self,
        workspace_id: &str,
        username: &str,
    ) -> Result<bool, LicenseError> {
        let rows = self
            .conn
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
    ) -> Result<Vec<(String, String)>, LicenseError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT username, added_at FROM workspace_members WHERE workspace_id = ?1 ORDER BY added_at"
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![workspace_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// `Some(())` if the user may access this workspace: a site admin (admins
    /// can administer any workspace) or a member. `None` otherwise. Membership
    /// grants full read+write; management (add/remove members, delete) stays
    /// gated on site-admin in the handler layer.
    pub fn workspace_access(
        &self,
        workspace_id: &str,
        username: &str,
    ) -> Result<Option<()>, LicenseError> {
        if self.get_user_role(username).map(|r| r == "admin").unwrap_or(false) {
            return Ok(Some(()));
        }
        match self.conn.query_row(
            "SELECT 1 FROM workspace_members WHERE workspace_id = ?1 AND username = ?2",
            params![workspace_id, username],
            |_| Ok(()),
        ) {
            Ok(()) => Ok(Some(())),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    /// True when the user belongs to any workspace scoped to `product`. Used
    /// as a product-entitlement signal for global release downloads.
    pub fn user_in_product_workspace(
        &self,
        username: &str,
        product: &str,
    ) -> Result<bool, LicenseError> {
        self.conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM workspace_members wm
                     JOIN workspaces w ON w.id = wm.workspace_id
                     WHERE wm.username = ?1 AND w.product = ?2)",
                params![username, product],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    // -----------------------------------------------------------------------
    // Workspace federation: shared channel secret + peer registry
    // -----------------------------------------------------------------------

    /// Read the workspace's federation channel secret, creating one on first
    /// call. Members of the same workspace get the same secret on every call,
    /// so they all derive the same ChaCha20Poly1305 data-plane key.
    pub fn get_or_create_workspace_federation_secret(
        &self,
        workspace_id: &str,
    ) -> Result<String, LicenseError> {
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT channel_secret FROM workspace_federation WHERE workspace_id = ?1",
                params![workspace_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        if let Some(s) = existing {
            return self.open_secret(&s);
        }
        // Fresh 32 bytes of OS entropy, base64-encoded for transport.
        use base64::Engine as _;
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let secret = base64::engine::general_purpose::STANDARD.encode(&buf);
        let sealed = self.seal_secret(&secret)?;
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO workspace_federation (workspace_id, channel_secret, created_at, rotated_at)
                 VALUES (?1, ?2, ?3, ?3)",
                params![workspace_id, sealed, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert federation: {}", e)))?;
        Ok(secret)
    }

    /// Rotate the workspace's federation secret. Existing peers must re-fetch
    /// to keep encrypting on the wire; until they do their frames will fail to
    /// authenticate at the receiver and get dropped.
    pub fn rotate_workspace_federation_secret(
        &self,
        workspace_id: &str,
    ) -> Result<String, LicenseError> {
        use base64::Engine as _;
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let secret = base64::engine::general_purpose::STANDARD.encode(&buf);
        let sealed = self.seal_secret(&secret)?;
        let now = Utc::now().to_rfc3339();
        let updated = self
            .conn
            .execute(
                "UPDATE workspace_federation SET channel_secret = ?2, rotated_at = ?3
                 WHERE workspace_id = ?1",
                params![workspace_id, sealed, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB update federation: {}", e)))?;
        if updated == 0 {
            // No row yet — treat rotate as create.
            self.conn
                .execute(
                    "INSERT INTO workspace_federation (workspace_id, channel_secret, created_at, rotated_at)
                     VALUES (?1, ?2, ?3, ?3)",
                    params![workspace_id, sealed, now],
                )
                .map_err(|e| LicenseError::Other(format!("DB insert federation: {}", e)))?;
        }
        Ok(secret)
    }

    /// Insert or update a peer registration. Updates `url`, `label`,
    /// `network_id`, and `last_seen` on conflict so a peer that moved (new
    /// public URL, or changed its Network ID) refreshes in place rather than
    /// accumulating stale rows.
    pub fn upsert_workspace_peer(
        &self,
        workspace_id: &str,
        host_id: &str,
        url: &str,
        label: &str,
        network_id: &str,
        registered_by: &str,
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO workspace_peers
                    (workspace_id, host_id, url, label, network_id, registered_by, registered_at, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
                 ON CONFLICT(workspace_id, host_id) DO UPDATE SET
                    url = excluded.url,
                    label = excluded.label,
                    network_id = excluded.network_id,
                    last_seen = excluded.last_seen",
                params![workspace_id, host_id, url, label, network_id, registered_by, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert peer: {}", e)))?;
        Ok(())
    }

    /// List peers registered against a workspace. Returns
    /// `(host_id, url, label, network_id, registered_by, last_seen)`.
    pub fn list_workspace_peers(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<(String, String, String, String, String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT host_id, url, label, network_id, registered_by, last_seen
                 FROM workspace_peers
                 WHERE workspace_id = ?1
                 ORDER BY host_id",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows: Vec<_> = stmt
            .query_map(params![workspace_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Remove a peer registration. Returns true if a row was deleted.
    pub fn delete_workspace_peer(
        &self,
        workspace_id: &str,
        host_id: &str,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM workspace_peers WHERE workspace_id = ?1 AND host_id = ?2",
                params![workspace_id, host_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete peer: {}", e)))?;
        Ok(n > 0)
    }

    // -----------------------------------------------------------------------
    // Workspace graph (one shared node-graph per workspace, version-tracked)
    // -----------------------------------------------------------------------

    /// Fetch the workspace's current graph. Returns `(graph_version, config_json,
    /// updated_by, updated_at)` or `None` when no graph has been pushed yet.
    pub fn get_workspace_graph(
        &self,
        workspace_id: &str,
    ) -> Result<Option<(u32, String, String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT graph_version, config, updated_by, updated_at
                 FROM workspace_graphs WHERE workspace_id = ?1",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let row = stmt
            .query_row(params![workspace_id], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u32,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .ok();
        Ok(row)
    }

    /// Cheap version-only fetch for the federation poll response — avoids
    /// shipping the (potentially large) config blob on every poll cycle.
    /// `None` when no graph row exists yet.
    pub fn get_workspace_graph_version(
        &self,
        workspace_id: &str,
    ) -> Result<Option<u32>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT graph_version FROM workspace_graphs WHERE workspace_id = ?1")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let row = stmt
            .query_row(params![workspace_id], |r| r.get::<_, i64>(0))
            .ok()
            .map(|v| v as u32);
        Ok(row)
    }

    /// Upsert the workspace's graph with optimistic-lock semantics. The caller
    /// passes the version it loaded; we bump to `loaded + 1` only when the row
    /// is still at that version (or absent ⇒ seed at version 1). Returns the
    /// new version. `Err(GraphConflict { current })` when another writer raced
    /// us — caller surfaces this as HTTP 409 with the current version so the
    /// editor can refresh.
    ///
    /// `expected_version` is `None` only for the very first save of a
    /// workspace (or when the caller is deliberately overwriting; today we
    /// route deliberate overwrites through the same `Some(current)` path).
    pub fn upsert_workspace_graph(
        &self,
        workspace_id: &str,
        expected_version: Option<u32>,
        config_json: &str,
        updated_by: &str,
    ) -> Result<u32, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let current = self.get_workspace_graph_version(workspace_id)?;

        match (current, expected_version) {
            // First save: no existing row, no expected version → seed at v1.
            (None, None) => {
                self.conn
                    .execute(
                        "INSERT INTO workspace_graphs
                            (workspace_id, graph_version, config, updated_by, updated_at)
                         VALUES (?1, 1, ?2, ?3, ?4)",
                        params![workspace_id, config_json, updated_by, now],
                    )
                    .map_err(|e| LicenseError::Other(format!("DB insert graph: {}", e)))?;
                Ok(1)
            }
            // Update: expected matches current → bump to current+1.
            (Some(cur), Some(exp)) if cur == exp => {
                let next = cur + 1;
                self.conn
                    .execute(
                        "UPDATE workspace_graphs
                            SET graph_version = ?2, config = ?3, updated_by = ?4, updated_at = ?5
                          WHERE workspace_id = ?1 AND graph_version = ?6",
                        params![
                            workspace_id,
                            next as i64,
                            config_json,
                            updated_by,
                            now,
                            cur as i64
                        ],
                    )
                    .map_err(|e| LicenseError::Other(format!("DB update graph: {}", e)))?;
                Ok(next)
            }
            // Anything else is a conflict — surface the current version so the
            // editor can re-fetch and re-apply local changes on top.
            _ => Err(LicenseError::GraphConflict {
                current: current.unwrap_or(0),
            }),
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
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, name, description, author, created_at
                 FROM config_revisions WHERE workspace_id = ?1
                 ORDER BY id DESC",
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
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            },
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
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            },
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
        }
        .map_err(|e| LicenseError::Other(format!("DB update config: {}", e)))?;
        Ok(affected > 0)
    }

    pub fn delete_config_revision(
        &self,
        workspace_id: &str,
        id: i64,
    ) -> Result<bool, LicenseError> {
        let affected = self
            .conn
            .execute(
                "DELETE FROM config_revisions WHERE workspace_id = ?1 AND id = ?2",
                params![workspace_id, id],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete config: {}", e)))?;
        Ok(affected > 0)
    }

    // -----------------------------------------------------------------------
    // Workspace recordings (S3-backed; row stores metadata + key only)
    // -----------------------------------------------------------------------

    pub fn create_recording(
        &self,
        workspace_id: &str,
        s3_key: &str,
        file_name: &str,
        description: &str,
        author: &str,
    ) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO workspace_recordings
                 (workspace_id, s3_key, file_name, description, file_size, status, author, created_at)
                 VALUES (?1, ?2, ?3, ?4, 0, 'pending', ?5, ?6)",
                params![workspace_id, s3_key, file_name, description, author, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert recording: {}", e)))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Flip a recording row from pending to uploaded; records final size.
    pub fn complete_recording(
        &self,
        workspace_id: &str,
        id: i64,
        file_size: u64,
    ) -> Result<bool, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let affected = self
            .conn
            .execute(
                "UPDATE workspace_recordings
                 SET status = 'uploaded', file_size = ?1, completed_at = ?2
                 WHERE workspace_id = ?3 AND id = ?4",
                params![file_size as i64, now, workspace_id, id],
            )
            .map_err(|e| LicenseError::Other(format!("DB complete recording: {}", e)))?;
        Ok(affected > 0)
    }

    pub fn list_recordings(&self, workspace_id: &str) -> Result<Vec<RecordingRow>, LicenseError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT id, workspace_id, s3_key, file_name, description, file_size, status, author, created_at, completed_at
                 FROM workspace_recordings WHERE workspace_id = ?1
                 ORDER BY id DESC"
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare list_recordings: {}", e)))?;
        let rows = stmt
            .query_map(params![workspace_id], |r| {
                Ok(RecordingRow {
                    id: r.get(0)?,
                    workspace_id: r.get(1)?,
                    s3_key: r.get(2)?,
                    file_name: r.get(3)?,
                    description: r.get(4)?,
                    file_size: r.get(5)?,
                    status: r.get(6)?,
                    author: r.get(7)?,
                    created_at: r.get(8)?,
                    completed_at: r.get(9)?,
                })
            })
            .map_err(|e| LicenseError::Other(format!("DB query list_recordings: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn get_recording(
        &self,
        workspace_id: &str,
        id: i64,
    ) -> Result<Option<RecordingRow>, LicenseError> {
        match self.conn.query_row(
            "SELECT id, workspace_id, s3_key, file_name, description, file_size, status, author, created_at, completed_at
             FROM workspace_recordings WHERE workspace_id = ?1 AND id = ?2",
            params![workspace_id, id],
            |r| Ok(RecordingRow {
                id: r.get(0)?,
                workspace_id: r.get(1)?,
                s3_key: r.get(2)?,
                file_name: r.get(3)?,
                description: r.get(4)?,
                file_size: r.get(5)?,
                status: r.get(6)?,
                author: r.get(7)?,
                created_at: r.get(8)?,
                completed_at: r.get(9)?,
            }),
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query get_recording: {}", e))),
        }
    }

    /// Delete a recording row. Returns the s3_key so the caller can purge S3.
    pub fn delete_recording(
        &self,
        workspace_id: &str,
        id: i64,
    ) -> Result<Option<String>, LicenseError> {
        let key: Option<String> = self
            .conn
            .query_row(
                "SELECT s3_key FROM workspace_recordings WHERE workspace_id = ?1 AND id = ?2",
                params![workspace_id, id],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB lookup recording: {}", e)))?;
        let Some(k) = key else {
            return Ok(None);
        };
        self.conn
            .execute(
                "DELETE FROM workspace_recordings WHERE workspace_id = ?1 AND id = ?2",
                params![workspace_id, id],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete recording: {}", e)))?;
        Ok(Some(k))
    }

    // -----------------------------------------------------------------------
    // Releases (with workspace scoping)
    // -----------------------------------------------------------------------

    pub fn insert_release(
        &self,
        product: &str,
        tag: &str,
        name: &str,
        body: &str,
        prerelease: bool,
        workspace_id: Option<&str>,
    ) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO releases (product, tag, name, body, prerelease, created_at, workspace_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![product, tag, name, body, prerelease as i32, now, workspace_id],
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

    pub fn delete_release_asset(
        &self,
        release_id: i64,
        file_name: &str,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM release_assets WHERE release_id = ?1 AND file_name = ?2",
                params![release_id, file_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete asset: {}", e)))?;
        Ok(n > 0)
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
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE releases SET name = ?1, body = ?2, prerelease = ?3, workspace_id = ?4, created_at = ?5 WHERE id = ?6",
                params![name, body, prerelease as i32, workspace_id, now, release_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB update release: {}", e)))?;
        Ok(())
    }

    pub fn list_releases(
        &self,
    ) -> Result<Vec<(i64, String, String, String, bool, String, Option<String>, String)>, LicenseError>
    {
        let mut stmt = self.conn
            .prepare("SELECT id, tag, name, body, prerelease, created_at, workspace_id, product FROM releases ORDER BY id DESC")
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
                    r.get::<_, String>(7)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// List releases that belong to a single workspace. Global releases are
    /// excluded — those are reachable through the public/admin global release
    /// listing and don't belong on a workspace-specific surface.
    pub fn list_releases_for_workspace(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<(i64, String, String, String, bool, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, tag, name, body, prerelease, created_at FROM releases
                 WHERE workspace_id = ?1
                 ORDER BY id DESC",
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
        let mut stmt = self
            .conn
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

    /// Batch variant of `get_release_assets` for list endpoints. Returns one
    /// `release_id → assets` map after a single query, eliminating the
    /// per-release N+1 in `handle_list_releases_admin` / workspace listings.
    pub fn get_assets_for_releases(
        &self,
        release_ids: &[i64],
    ) -> Result<std::collections::HashMap<i64, Vec<(String, u64)>>, LicenseError> {
        let mut out: std::collections::HashMap<i64, Vec<(String, u64)>> =
            std::collections::HashMap::with_capacity(release_ids.len());
        if release_ids.is_empty() {
            return Ok(out);
        }
        let placeholders = std::iter::repeat("?")
            .take(release_ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT release_id, file_name, file_size FROM release_assets WHERE release_id IN ({})",
            placeholders,
        );
        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let params_iter: Vec<&dyn rusqlite::ToSql> = release_ids
            .iter()
            .map(|s| s as &dyn rusqlite::ToSql)
            .collect();
        let rows = stmt
            .query_map(&params_iter[..], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)? as u64,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        for (rid, name, size) in rows.flatten() {
            out.entry(rid).or_default().push((name, size));
        }
        Ok(out)
    }

    pub fn get_release_by_product_tag(
        &self,
        product: &str,
        tag: &str,
    ) -> Result<Option<i64>, LicenseError> {
        match self.conn.query_row(
            "SELECT id FROM releases WHERE product = ?1 AND tag = ?2",
            params![product, tag],
            |r| r.get(0),
        ) {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    /// Reassign a release to a different workspace (or to global with `None`).
    /// Doesn't touch any other column — doc pages, assets, and software files
    /// stay attached because they FK on release_id, not on workspace_id.
    pub fn set_release_workspace(
        &self,
        release_id: i64,
        workspace_id: Option<&str>,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "UPDATE releases SET workspace_id = ?1 WHERE id = ?2",
                params![workspace_id, release_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB move release: {}", e)))?;
        Ok(())
    }

    /// Return `Some(workspace_id_or_none)` if the (product, tag) exists, else
    /// `None`. Inner `Option` is `Some(ws_id)` for workspace-scoped, `None` for
    /// global.
    pub fn get_release_workspace_id(
        &self,
        product: &str,
        tag: &str,
    ) -> Result<Option<Option<String>>, LicenseError> {
        match self.conn.query_row(
            "SELECT workspace_id FROM releases WHERE product = ?1 AND tag = ?2",
            params![product, tag],
            |r| r.get::<_, Option<String>>(0),
        ) {
            Ok(ws) => Ok(Some(ws)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    pub fn delete_release(&self, product: &str, tag: &str) -> Result<bool, LicenseError> {
        let rows = self
            .conn
            .execute(
                "DELETE FROM releases WHERE product = ?1 AND tag = ?2",
                params![product, tag],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(rows > 0)
    }

    // -----------------------------------------------------------------------
    // Products (catalog dimension that scopes releases + docs)
    // -----------------------------------------------------------------------

    /// All products, ordered for display. Returns (slug, name, description, ord).
    pub fn list_release_products(
        &self,
    ) -> Result<Vec<(String, String, String, i64)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT slug, name, description, ord FROM products ORDER BY ord, name")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn product_exists(&self, slug: &str) -> Result<bool, LicenseError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM products WHERE slug = ?1",
                params![slug],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(count > 0)
    }

    /// Display name for a release-product slug, if the product exists.
    pub fn get_product_name(&self, slug: &str) -> Result<Option<String>, LicenseError> {
        self.conn
            .query_row(
                "SELECT name FROM products WHERE slug = ?1",
                params![slug],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    /// Insert or update a product. Slug is the immutable key.
    pub fn upsert_release_product(
        &self,
        slug: &str,
        name: &str,
        description: &str,
        ord: i64,
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO products (slug, name, description, ord, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(slug) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    ord = excluded.ord",
                params![slug, name, description, ord, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert product: {}", e)))?;
        Ok(())
    }

    /// Count releases attached to a product — callers reject deletion of a
    /// product that still owns releases.
    pub fn count_releases_for_product(&self, slug: &str) -> Result<i64, LicenseError> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM releases WHERE product = ?1",
                params![slug],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    pub fn delete_release_product(&self, slug: &str) -> Result<bool, LicenseError> {
        let rows = self
            .conn
            .execute("DELETE FROM products WHERE slug = ?1", params![slug])
            .map_err(|e| LicenseError::Other(format!("DB delete product: {}", e)))?;
        Ok(rows > 0)
    }

    // -----------------------------------------------------------------------
    // License listing
    // -----------------------------------------------------------------------

    pub fn list_licenses(&self) -> Result<Vec<License>, LicenseError> {
        self.collect_licenses(
            "SELECT id, product, customer, license_key, created, expires, features, max_machines, revoked, lease_duration_hours, lease_grace_hours, require_signed_binary
             FROM licenses ORDER BY created DESC",
            &[],
        )
    }

    /// Licenses assigned to `username` via `license_users`, machines included.
    pub fn list_licenses_for_user(&self, username: &str) -> Result<Vec<License>, LicenseError> {
        self.collect_licenses(
            "SELECT l.id, l.product, l.customer, l.license_key, l.created, l.expires, l.features, l.max_machines, l.revoked, l.lease_duration_hours, l.lease_grace_hours, l.require_signed_binary
             FROM licenses l JOIN license_users lu ON lu.license_id = l.id
             WHERE lu.username = ?1 ORDER BY l.created DESC",
            &[&username],
        )
    }

    fn collect_licenses(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<License>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;

        let rows = stmt
            .query_map(params, |row| {
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
                    row.get::<_, i32>(11)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;

        // Materialise the parent rows first so we can issue a single batch
        // query for activations instead of N round-trips. Lease cleanup runs
        // periodically in the background (`spawn_lease_cleanup_task`); doing
        // it here would issue another DELETE per license per list call.
        let parents: Vec<_> = rows.filter_map(|r| r.ok()).collect();
        let ids: Vec<String> = parents.iter().map(|r| r.0.clone()).collect();
        let mut machines_by_id = self
            .get_machine_activations_for_licenses(&ids)
            .unwrap_or_default();

        let mut licenses = Vec::with_capacity(parents.len());
        for (
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
            require_signed_binary,
        ) in parents
        {
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

            let machines = machines_by_id.remove(&id).unwrap_or_default();

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
                require_signed_binary: require_signed_binary != 0,
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
        let id = self
            .conn
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
        let mut stmt = self
            .conn
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
        let n = self
            .conn
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
        let tx = self
            .conn
            .transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;
        let n = tx
            .execute(
                "UPDATE doc_pages SET slug = ?1 WHERE release_id = ?2 AND slug = ?3",
                params![new_slug, release_id, old_slug],
            )
            .map_err(|e| LicenseError::Other(format!("DB rename: {}", e)))?;
        if n == 0 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE doc_pages SET parent_slug = ?1 WHERE release_id = ?2 AND parent_slug = ?3",
            params![new_slug, release_id, old_slug],
        )
        .map_err(|e| LicenseError::Other(format!("DB rename cascade: {}", e)))?;
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB tx commit: {}", e)))?;
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
        let tx = self
            .conn
            .transaction()
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
        let existing: Option<String> = self
            .conn
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

    pub fn list_doc_assets(&self, release_id: i64) -> Result<Vec<(String, u64)>, LicenseError> {
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
        let n = self
            .conn
            .execute(
                "DELETE FROM doc_assets WHERE release_id = ?1 AND file_name = ?2",
                params![release_id, file_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(n > 0)
    }

    /// Releases of one product that contain at least one doc page (newest
    /// first). Returns (id, tag, name, created_at, page_count).
    pub fn list_doc_releases(
        &self,
        product: &str,
    ) -> Result<Vec<(i64, String, String, String, i64)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT r.id, r.tag, r.name, r.created_at, COUNT(p.id)
                 FROM releases r
                 INNER JOIN doc_pages p ON p.release_id = r.id
                 WHERE r.workspace_id IS NULL AND r.product = ?1
                 GROUP BY r.id
                 ORDER BY r.id DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![product], |r| {
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

    /// List releases that belong to a specific workspace, regardless of whether
    /// they have any doc pages yet. Used by the workspace docs editor to show
    /// all workspace-scoped releases the user can author docs into.
    pub fn list_doc_releases_for_workspace(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<(i64, String, String, String, i64)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT r.id, r.tag, r.name, r.created_at,
                        (SELECT COUNT(*) FROM doc_pages p WHERE p.release_id = r.id)
                 FROM releases r
                 WHERE r.workspace_id = ?1
                 ORDER BY r.id DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![workspace_id], |r| {
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

    /// Ensure a release row exists for the given tag under the default product
    /// — used by bulk doc import when the docs ship before the binary release.
    /// Returns the release id.
    pub fn ensure_release(&self, tag: &str, name: &str) -> Result<i64, LicenseError> {
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
        self.ensure_release_created_scoped(DEFAULT_PRODUCT, tag, name, None)
    }

    /// Product- and workspace-aware variant. When `workspace_id` is `Some`, the
    /// release is created with that scope. If the (product, tag) already exists
    /// with a *different* scope (or none), returns the existing id without
    /// modifying it — a caller that cares should reject that case before
    /// calling.
    pub fn ensure_release_created_scoped(
        &self,
        product: &str,
        tag: &str,
        name: &str,
        workspace_id: Option<&str>,
    ) -> Result<(i64, bool), LicenseError> {
        if let Some(id) = self.get_release_by_product_tag(product, tag)? {
            return Ok((id, false));
        }
        let id = self.insert_release(product, tag, name, "", false, workspace_id)?;
        Ok((id, true))
    }

    /// Return (id, tag) of the most recent release that has at least one
    /// `origin='user'` doc page, excluding a given release id. Restricted to
    /// the same product and workspace scope (`Some(ws)` for a workspace
    /// release; `None` for a global release) so that user docs never seed
    /// across products or workspaces.
    pub fn latest_prior_release_with_user_docs(
        &self,
        exclude_id: i64,
        product: &str,
        workspace_id: Option<&str>,
    ) -> Result<Option<(i64, String)>, LicenseError> {
        let res = match workspace_id {
            Some(ws) => self.conn.query_row(
                "SELECT r.id, r.tag FROM releases r
                 WHERE r.id != ?1
                   AND r.product = ?3
                   AND r.workspace_id = ?2
                   AND EXISTS (
                       SELECT 1 FROM doc_pages p
                       WHERE p.release_id = r.id AND p.origin = 'user'
                   )
                 ORDER BY r.id DESC LIMIT 1",
                params![exclude_id, ws, product],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            ),
            None => self.conn.query_row(
                "SELECT r.id, r.tag FROM releases r
                 WHERE r.id != ?1
                   AND r.product = ?2
                   AND r.workspace_id IS NULL
                   AND EXISTS (
                       SELECT 1 FROM doc_pages p
                       WHERE p.release_id = r.id AND p.origin = 'user'
                   )
                 ORDER BY r.id DESC LIMIT 1",
                params![exclude_id, product],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            ),
        };
        res.optional()
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
        let n = self
            .conn
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
        let mut stmt = self
            .conn
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

    /// Upsert a website page. When the row already exists and its content
    /// actually differs from the incoming state, the prior state is captured
    /// into `website_page_revisions` so edits are recoverable.
    pub fn upsert_website_page(
        &mut self,
        slug: &str,
        title: &str,
        body_md: &str,
        parent_slug: Option<&str>,
        ord: i64,
        meta_description: &str,
        author: Option<&str>,
    ) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let tx = self
            .conn
            .transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;

        // Capture prior state as a revision if this is an update-with-change.
        let prior: Option<(String, String, Option<String>, i64)> = tx
            .query_row(
                "SELECT title, body_md, parent_slug, ord FROM website_pages WHERE slug = ?1",
                params![slug],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB read prior: {}", e)))?;
        if let Some((p_title, p_body, p_parent, p_ord)) = &prior {
            let unchanged = p_title == title
                && p_body == body_md
                && p_parent.as_deref() == parent_slug
                && *p_ord == ord;
            if !unchanged {
                tx.execute(
                    "INSERT INTO website_page_revisions
                       (slug, title, body_md, parent_slug, ord, captured_at, author)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![slug, p_title, p_body, p_parent, p_ord, now, author],
                )
                .map_err(|e| LicenseError::Other(format!("DB snapshot: {}", e)))?;
            }
        }

        tx.execute(
            "INSERT INTO website_pages (slug, title, body_md, parent_slug, ord, updated_at, meta_description)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(slug) DO UPDATE SET
               title = excluded.title,
               body_md = excluded.body_md,
               parent_slug = excluded.parent_slug,
               ord = excluded.ord,
               updated_at = excluded.updated_at,
               meta_description = excluded.meta_description",
            params![slug, title, body_md, parent_slug, ord, now, meta_description],
        )
        .map_err(|e| LicenseError::Other(format!("DB upsert website page: {}", e)))?;
        let id = tx
            .query_row(
                "SELECT id FROM website_pages WHERE slug = ?1",
                params![slug],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB lookup website page: {}", e)))?;
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB tx commit: {}", e)))?;
        Ok(id)
    }

    /// List revisions for a page, newest first. Body omitted for list brevity.
    pub fn list_page_revisions(
        &self,
        slug: &str,
    ) -> Result<Vec<(i64, String, Option<String>, String, i64)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, captured_at, author, title, LENGTH(body_md)
                 FROM website_page_revisions
                 WHERE slug = ?1
                 ORDER BY captured_at DESC, id DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![slug], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Fetch full content of a specific revision by id.
    pub fn get_page_revision(
        &self,
        slug: &str,
        revision_id: i64,
    ) -> Result<Option<(String, String, Option<String>, i64, String, Option<String>)>, LicenseError>
    {
        self.conn
            .query_row(
                "SELECT title, body_md, parent_slug, ord, captured_at, author
                 FROM website_page_revisions
                 WHERE slug = ?1 AND id = ?2",
                params![slug, revision_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    /// Assets with usage: (file_name, file_size, usage_count, pages_csv).
    /// A page is counted if its body contains the literal filename substring.
    pub fn list_website_assets_with_usage(
        &self,
    ) -> Result<Vec<(String, i64, i64, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT a.file_name, a.file_size,
                        (SELECT COUNT(*) FROM website_pages p
                           WHERE p.body_md LIKE '%' || a.file_name || '%') AS usage_count,
                        COALESCE(
                          (SELECT GROUP_CONCAT(p.slug, ',') FROM website_pages p
                             WHERE p.body_md LIKE '%' || a.file_name || '%'),
                          ''
                        ) AS pages_csv
                 FROM website_assets a
                 ORDER BY a.file_name",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Rename an asset file_name and rewrite every markdown reference in page
    /// bodies in the same transaction. Returns (renamed, pages_updated).
    pub fn rename_website_asset(
        &mut self,
        old_name: &str,
        new_name: &str,
    ) -> Result<(bool, usize), LicenseError> {
        if old_name == new_name {
            return Ok((true, 0));
        }
        let tx = self
            .conn
            .transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;
        // Reject if target already exists (would collide on UNIQUE).
        let exists: bool = tx
            .query_row(
                "SELECT 1 FROM website_assets WHERE file_name = ?1",
                params![new_name],
                |_| Ok(true),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB check: {}", e)))?
            .unwrap_or(false);
        if exists {
            return Err(LicenseError::Other("target filename already exists".into()));
        }
        let n_assets = tx
            .execute(
                "UPDATE website_assets SET file_name = ?1 WHERE file_name = ?2",
                params![new_name, old_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB rename asset: {}", e)))?;
        if n_assets == 0 {
            return Ok((false, 0));
        }
        // Rewrite markdown: match both `](old)` and `](old){...}` forms.
        let paren_old = format!("]({})", old_name);
        let paren_new = format!("]({})", new_name);
        let brace_old = format!("]({}){{", old_name);
        let brace_new = format!("]({}){{", new_name);
        let n_pages = tx
            .execute(
                "UPDATE website_pages
             SET body_md = REPLACE(REPLACE(body_md, ?1, ?2), ?3, ?4)
             WHERE body_md LIKE '%' || ?5 || '%'",
                params![brace_old, brace_new, paren_old, paren_new, old_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB rewrite body_md: {}", e)))?;
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB tx commit: {}", e)))?;
        Ok((true, n_pages))
    }

    pub fn list_website_pages(
        &self,
    ) -> Result<Vec<(String, String, Option<String>, i64, String, String)>, LicenseError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT slug, title, parent_slug, ord, updated_at, meta_description FROM website_pages
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
                    r.get::<_, String>(5)?,
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
    ) -> Result<Option<(String, String, Option<String>, i64, String, String)>, LicenseError> {
        match self.conn.query_row(
            "SELECT title, body_md, parent_slug, ord, updated_at, meta_description FROM website_pages
             WHERE slug = ?1",
            params![slug],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            },
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    pub fn delete_website_page(&self, slug: &str) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute("DELETE FROM website_pages WHERE slug = ?1", params![slug])
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
        let tx = self
            .conn
            .transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;
        let n = tx
            .execute(
                "UPDATE website_pages SET slug = ?1 WHERE slug = ?2",
                params![new_slug, old_slug],
            )
            .map_err(|e| LicenseError::Other(format!("DB rename: {}", e)))?;
        if n == 0 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE website_pages SET parent_slug = ?1 WHERE parent_slug = ?2",
            params![new_slug, old_slug],
        )
        .map_err(|e| LicenseError::Other(format!("DB rename cascade: {}", e)))?;
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB tx commit: {}", e)))?;
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

    /// Returns true if a website asset with the given file name is recorded.
    /// Used by shop product upsert to validate `image_asset` references a
    /// real upload before saving.
    pub fn website_asset_exists(&self, file_name: &str) -> Result<bool, LicenseError> {
        match self.conn.query_row(
            "SELECT 1 FROM website_assets WHERE file_name = ?1",
            params![file_name],
            |_| Ok(()),
        ) {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(LicenseError::Other(format!("DB asset exists: {}", e))),
        }
    }

    pub fn list_website_assets(&self) -> Result<Vec<(String, i64)>, LicenseError> {
        let mut stmt = self
            .conn
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
        let n = self
            .conn
            .execute(
                "DELETE FROM website_assets WHERE file_name = ?1",
                params![file_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete website asset: {}", e)))?;
        Ok(n > 0)
    }

    // ---------------------------------------------------------------------
    // Shop: products
    //
    // Tuple layout: (sku, title, description_md, price_cents, currency,
    //                image_asset, tax_code, active, ord, updated_at)
    // ---------------------------------------------------------------------

    pub fn list_products(
        &self,
        active_only: bool,
    ) -> Result<
        Vec<(
            String,
            String,
            String,
            i64,
            String,
            Option<String>,
            String,
            bool,
            i64,
            String,
        )>,
        LicenseError,
    > {
        let sql = if active_only {
            "SELECT sku, title, description_md, price_cents, currency, image_asset, tax_code, active, ord, updated_at
             FROM shop_products WHERE active = 1 ORDER BY ord, title"
        } else {
            "SELECT sku, title, description_md, price_cents, currency, image_asset, tax_code, active, ord, updated_at
             FROM shop_products ORDER BY ord, title"
        };
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7).map(|v| v != 0)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, String>(9)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Batch lookup. Returns a map of `sku → product row` for every requested
    /// SKU that exists. Use this for checkout / cart paths where a per-SKU
    /// `get_product` loop would issue one round-trip per item under the lock.
    pub fn get_products_by_skus(
        &self,
        skus: &[String],
    ) -> Result<
        std::collections::HashMap<
            String,
            (
                String,
                String,
                String,
                i64,
                String,
                Option<String>,
                String,
                bool,
                i64,
                String,
            ),
        >,
        LicenseError,
    > {
        let mut out = std::collections::HashMap::with_capacity(skus.len());
        if skus.is_empty() {
            return Ok(out);
        }
        // SQLite has no native array binding; build `?,?,?,…` placeholders.
        let placeholders = std::iter::repeat("?")
            .take(skus.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT sku, title, description_md, price_cents, currency, image_asset, tax_code, active, ord, updated_at
             FROM shop_products WHERE sku IN ({})",
            placeholders,
        );
        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let params_iter: Vec<&dyn rusqlite::ToSql> =
            skus.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let rows = stmt
            .query_map(&params_iter[..], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7).map(|v| v != 0)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, String>(9)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        for row in rows.flatten() {
            out.insert(row.0.clone(), row);
        }
        Ok(out)
    }

    pub fn get_product(
        &self,
        sku: &str,
    ) -> Result<
        Option<(
            String,
            String,
            String,
            i64,
            String,
            Option<String>,
            String,
            bool,
            i64,
            String,
        )>,
        LicenseError,
    > {
        match self.conn.query_row(
            "SELECT sku, title, description_md, price_cents, currency, image_asset, tax_code, active, ord, updated_at
             FROM shop_products WHERE sku = ?1",
            params![sku],
            |r| Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, i64>(7).map(|v| v != 0)?,
                r.get::<_, i64>(8)?,
                r.get::<_, String>(9)?,
            )),
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_product(
        &self,
        sku: &str,
        title: &str,
        description_md: &str,
        price_cents: i64,
        currency: &str,
        image_asset: Option<&str>,
        tax_code: &str,
        active: bool,
        ord: i64,
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO shop_products
               (sku, title, description_md, price_cents, currency, image_asset, tax_code, active, ord, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(sku) DO UPDATE SET
               title = excluded.title,
               description_md = excluded.description_md,
               price_cents = excluded.price_cents,
               currency = excluded.currency,
               image_asset = excluded.image_asset,
               tax_code = excluded.tax_code,
               active = excluded.active,
               ord = excluded.ord,
               updated_at = excluded.updated_at",
            params![
                sku, title, description_md, price_cents, currency,
                image_asset, tax_code, active as i64, ord, now,
            ],
        )
        .map_err(|e| LicenseError::Other(format!("DB upsert product: {}", e)))?;
        Ok(())
    }

    pub fn delete_product(&self, sku: &str) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute("DELETE FROM shop_products WHERE sku = ?1", params![sku])
            .map_err(|e| LicenseError::Other(format!("DB delete product: {}", e)))?;
        Ok(n > 0)
    }

    // ---------------------------------------------------------------------
    // Shop: shipping rates
    //
    // Tuple layout: (id, label, amount_cents, currency, delivery_min_days,
    //                delivery_max_days, regions_json, active, ord)
    // ---------------------------------------------------------------------

    pub fn list_shipping_rates(
        &self,
        active_only: bool,
    ) -> Result<
        Vec<(
            i64,
            String,
            i64,
            String,
            Option<i64>,
            Option<i64>,
            String,
            bool,
            i64,
        )>,
        LicenseError,
    > {
        let sql = if active_only {
            "SELECT id, label, amount_cents, currency, delivery_min_days, delivery_max_days, regions, active, ord
             FROM shop_shipping_rates WHERE active = 1 ORDER BY ord, amount_cents"
        } else {
            "SELECT id, label, amount_cents, currency, delivery_min_days, delivery_max_days, regions, active, ord
             FROM shop_shipping_rates ORDER BY ord, amount_cents"
        };
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7).map(|v| v != 0)?,
                    r.get::<_, i64>(8)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_shipping_rate(
        &self,
        label: &str,
        amount_cents: i64,
        currency: &str,
        delivery_min_days: Option<i64>,
        delivery_max_days: Option<i64>,
        regions_json: &str,
        active: bool,
        ord: i64,
    ) -> Result<i64, LicenseError> {
        self.conn.execute(
            "INSERT INTO shop_shipping_rates
               (label, amount_cents, currency, delivery_min_days, delivery_max_days, regions, active, ord)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                label, amount_cents, currency,
                delivery_min_days, delivery_max_days, regions_json,
                active as i64, ord,
            ],
        )
        .map_err(|e| LicenseError::Other(format!("DB insert shipping rate: {}", e)))?;
        Ok(self.conn.last_insert_rowid())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_shipping_rate(
        &self,
        id: i64,
        label: &str,
        amount_cents: i64,
        currency: &str,
        delivery_min_days: Option<i64>,
        delivery_max_days: Option<i64>,
        regions_json: &str,
        active: bool,
        ord: i64,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "UPDATE shop_shipping_rates
               SET label = ?2, amount_cents = ?3, currency = ?4,
                   delivery_min_days = ?5, delivery_max_days = ?6,
                   regions = ?7, active = ?8, ord = ?9
             WHERE id = ?1",
                params![
                    id,
                    label,
                    amount_cents,
                    currency,
                    delivery_min_days,
                    delivery_max_days,
                    regions_json,
                    active as i64,
                    ord,
                ],
            )
            .map_err(|e| LicenseError::Other(format!("DB update shipping rate: {}", e)))?;
        Ok(n > 0)
    }

    pub fn delete_shipping_rate(&self, id: i64) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute("DELETE FROM shop_shipping_rates WHERE id = ?1", params![id])
            .map_err(|e| LicenseError::Other(format!("DB delete shipping rate: {}", e)))?;
        Ok(n > 0)
    }

    // ---------------------------------------------------------------------
    // Shop: orders
    //
    // Tuple layout: (id, stripe_session_id, created_at, customer_email,
    //                customer_name, amount_total_cents, currency, status,
    //                ship_to_json, line_items_json, tracking_carrier,
    //                tracking_number, shipped_at, notes)
    // ---------------------------------------------------------------------

    /// Insert a shop order keyed on `stripe_session_id`. Returns `(id, inserted)`;
    /// `inserted == false` means the row already existed (Stripe webhook retry).
    /// Callers use that flag to skip side effects (emails) on retries.
    /// `status` is 'paid' for settled sessions, 'pending_payment' for delayed
    /// payment methods still awaiting settlement.
    pub fn insert_order_if_absent(
        &self,
        stripe_session_id: &str,
        created_at: &str,
        customer_email: &str,
        customer_name: &str,
        amount_total_cents: i64,
        currency: &str,
        status: &str,
        ship_to_json: &str,
        line_items_json: &str,
    ) -> Result<(i64, bool), LicenseError> {
        let n = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO shop_orders
               (stripe_session_id, created_at, customer_email, customer_name,
                amount_total_cents, currency, status, ship_to_json, line_items_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    stripe_session_id,
                    created_at,
                    customer_email,
                    customer_name,
                    amount_total_cents,
                    currency,
                    status,
                    ship_to_json,
                    line_items_json,
                ],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert order: {}", e)))?;
        let id = self
            .conn
            .query_row(
                "SELECT id FROM shop_orders WHERE stripe_session_id = ?1",
                params![stripe_session_id],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB lookup order: {}", e)))?;
        Ok((id, n > 0))
    }

    /// Conditionally flip an order's status from `from` to `to`, keyed by
    /// Stripe session id. Returns whether a row changed - false means the
    /// order is missing or already past `from` (e.g. a webhook retry), so
    /// side effects tied to the transition must be skipped.
    pub fn transition_order_status_by_session(
        &self,
        stripe_session_id: &str,
        from: &str,
        to: &str,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "UPDATE shop_orders SET status = ?3
                 WHERE stripe_session_id = ?1 AND status = ?2",
                params![stripe_session_id, from, to],
            )
            .map_err(|e| LicenseError::Other(format!("DB update order status: {}", e)))?;
        Ok(n > 0)
    }

    #[allow(clippy::type_complexity)]
    pub fn list_orders(
        &self,
        status_filter: Option<&str>,
    ) -> Result<
        Vec<(
            i64,
            String,
            String,
            String,
            String,
            i64,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            String,
        )>,
        LicenseError,
    > {
        let (sql, has_filter) = if status_filter.is_some() {
            (
                "SELECT id, stripe_session_id, created_at, customer_email, customer_name,
                        amount_total_cents, currency, status, ship_to_json, line_items_json,
                        tracking_carrier, tracking_number, shipped_at, notes
                 FROM shop_orders WHERE status = ?1 ORDER BY created_at DESC, id DESC",
                true,
            )
        } else {
            (
                "SELECT id, stripe_session_id, created_at, customer_email, customer_name,
                        amount_total_cents, currency, status, ship_to_json, line_items_json,
                        tracking_carrier, tracking_number, shipped_at, notes
                 FROM shop_orders ORDER BY created_at DESC, id DESC",
                false,
            )
        };
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let row_map = |r: &rusqlite::Row<'_>| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
                r.get::<_, String>(9)?,
                r.get::<_, String>(10)?,
                r.get::<_, String>(11)?,
                r.get::<_, Option<String>>(12)?,
                r.get::<_, String>(13)?,
            ))
        };
        let rows: Vec<_> = if has_filter {
            stmt.query_map(params![status_filter.unwrap()], row_map)
                .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
                .filter_map(|r| r.ok())
                .collect()
        } else {
            stmt.query_map([], row_map)
                .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
                .filter_map(|r| r.ok())
                .collect()
        };
        Ok(rows)
    }

    #[allow(clippy::type_complexity)]
    pub fn get_order(
        &self,
        id: i64,
    ) -> Result<
        Option<(
            i64,
            String,
            String,
            String,
            String,
            i64,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            String,
        )>,
        LicenseError,
    > {
        match self.conn.query_row(
            "SELECT id, stripe_session_id, created_at, customer_email, customer_name,
                    amount_total_cents, currency, status, ship_to_json, line_items_json,
                    tracking_carrier, tracking_number, shipped_at, notes
             FROM shop_orders WHERE id = ?1",
            params![id],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                    r.get::<_, String>(11)?,
                    r.get::<_, Option<String>>(12)?,
                    r.get::<_, String>(13)?,
                ))
            },
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    /// Mark an order as shipped, recording carrier + tracking number.
    /// Sets shipped_at to the provided RFC3339 timestamp.
    pub fn mark_order_shipped(
        &self,
        id: i64,
        carrier: &str,
        tracking_number: &str,
        shipped_at: &str,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "UPDATE shop_orders
               SET status = 'shipped',
                   tracking_carrier = ?2,
                   tracking_number  = ?3,
                   shipped_at       = ?4
             WHERE id = ?1",
                params![id, carrier, tracking_number, shipped_at],
            )
            .map_err(|e| LicenseError::Other(format!("DB mark shipped: {}", e)))?;
        Ok(n > 0)
    }

    pub fn update_order_notes(&self, id: i64, notes: &str) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "UPDATE shop_orders SET notes = ?2 WHERE id = ?1",
                params![id, notes],
            )
            .map_err(|e| LicenseError::Other(format!("DB update notes: {}", e)))?;
        Ok(n > 0)
    }

    // ---------------------------------------------------------------------
    // Shop: settings (key/value)
    // ---------------------------------------------------------------------

    pub fn get_shop_setting(&self, key: &str) -> Result<Option<String>, LicenseError> {
        match self.conn.query_row(
            "SELECT value FROM shop_settings WHERE key = ?1",
            params![key],
            |r| r.get::<_, String>(0),
        ) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB get setting: {}", e))),
        }
    }

    pub fn set_shop_setting(&self, key: &str, value: &str) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT INTO shop_settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(|e| LicenseError::Other(format!("DB set setting: {}", e)))?;
        Ok(())
    }

    pub fn list_shop_settings(&self) -> Result<Vec<(String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value FROM shop_settings ORDER BY key")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn get_site_setting(&self, key: &str) -> Result<Option<String>, LicenseError> {
        match self.conn.query_row(
            "SELECT value FROM site_settings WHERE key = ?1",
            params![key],
            |r| r.get::<_, String>(0),
        ) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB get site setting: {}", e))),
        }
    }

    pub fn set_site_setting(&self, key: &str, value: &str) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT INTO site_settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(|e| LicenseError::Other(format!("DB set site setting: {}", e)))?;
        Ok(())
    }

    pub fn list_site_settings(&self) -> Result<Vec<(String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value FROM site_settings ORDER BY key")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
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

        // Reopen — runs init_tables + migrate (adds product, rebuilds releases).
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
            .insert_release("lpvr", "v1.0", "LPVR", "", false, None)
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

        // Client restarts and tries to activate again. This MUST be blocked —
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
    fn test_expired_lease_cleaned_by_sweep() {
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

        // Reads no longer trigger cleanup — that ran on every heartbeat and
        // dominated the verify path. Background `cleanup_all_expired_leases`
        // is what now removes expired rows.
        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.machines.len(), 1);

        let removed = db.cleanup_all_expired_leases().unwrap();
        assert_eq!(removed, 1);

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
        let rid = db.insert_release(DEFAULT_PRODUCT, "v9.9", "Test", "", false, None).unwrap();

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

        // Delete one — the other remains.
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
            .insert_release(DEFAULT_PRODUCT, "v1.0", "FusionHub 1.0", "", false, None)
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
        let rid = db.insert_release(DEFAULT_PRODUCT, "v1.0", "", "", false, None).unwrap();

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
        let old = db.insert_release(DEFAULT_PRODUCT, "v1.0", "", "", false, None).unwrap();

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
            .latest_prior_release_with_user_docs(new_id, DEFAULT_PRODUCT, None)
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
            .insert_release(DEFAULT_PRODUCT, "v1.0", "with docs", "", false, None)
            .unwrap();
        let _r2 = db
            .insert_release(DEFAULT_PRODUCT, "v1.1", "no docs", "", false, None)
            .unwrap();
        db.upsert_doc_page(r1, "intro", "Intro", "...", None, 0)
            .unwrap();

        let releases = db.list_doc_releases(DEFAULT_PRODUCT).unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].1, "v1.0");
        assert_eq!(releases[0].4, 1); // page count
    }

    #[test]
    fn test_doc_release_listings_are_scope_separated() {
        let mut db = test_db();
        db.create_workspace("ws-a", "A", "", "", "admin").unwrap();
        db.create_workspace("ws-b", "B", "", "", "admin").unwrap();

        let g1 = db
            .insert_release(DEFAULT_PRODUCT, "g1.0", "global", "", false, None)
            .unwrap();
        let a1 = db
            .insert_release(DEFAULT_PRODUCT, "a1.0", "a-rel", "", false, Some("ws-a"))
            .unwrap();
        let b1 = db
            .insert_release(DEFAULT_PRODUCT, "b1.0", "b-rel", "", false, Some("ws-b"))
            .unwrap();
        for rid in [g1, a1, b1] {
            db.upsert_doc_page(rid, "intro", "Intro", "body", None, 0)
                .unwrap();
        }

        // Global list excludes workspace-scoped releases entirely.
        let global = db.list_doc_releases(DEFAULT_PRODUCT).unwrap();
        assert_eq!(global.len(), 1);
        assert_eq!(global[0].1, "g1.0");

        // Each workspace listing returns only its own releases (no cross-pollination).
        let a = db.list_doc_releases_for_workspace("ws-a").unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].1, "a1.0");

        let b = db.list_doc_releases_for_workspace("ws-b").unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].1, "b1.0");
    }

    #[test]
    fn test_seed_lookup_does_not_cross_workspace_boundaries() {
        let mut db = test_db();
        db.create_workspace("ws-a", "A", "", "", "admin").unwrap();
        db.create_workspace("ws-b", "B", "", "", "admin").unwrap();

        // Set up: a global release with user docs, plus ws-a release with its own user docs.
        let g_old = db.insert_release(DEFAULT_PRODUCT, "g0.9", "g old", "", false, None).unwrap();
        db.upsert_doc_page(g_old, "guide", "Guide", "global hand-authored", None, 0)
            .unwrap();

        let a_old = db
            .insert_release(DEFAULT_PRODUCT, "a0.9", "a old", "", false, Some("ws-a"))
            .unwrap();
        db.upsert_doc_page(a_old, "guide", "Guide", "ws-a hand-authored", None, 0)
            .unwrap();

        // New global release: prior must come from the global pool.
        let (g_new, _) = db
            .ensure_release_created_scoped(DEFAULT_PRODUCT, "g1.0", "g new", None)
            .unwrap();
        let prior = db.latest_prior_release_with_user_docs(g_new, DEFAULT_PRODUCT, None).unwrap();
        assert_eq!(prior.map(|p| p.1), Some("g0.9".to_string()));

        // New ws-a release: prior must come from ws-a's pool, not global, not ws-b.
        let (a_new, _) = db
            .ensure_release_created_scoped(DEFAULT_PRODUCT, "a1.0", "a new", Some("ws-a"))
            .unwrap();
        let prior = db
            .latest_prior_release_with_user_docs(a_new, DEFAULT_PRODUCT, Some("ws-a"))
            .unwrap();
        assert_eq!(prior.map(|p| p.1), Some("a0.9".to_string()));

        // New ws-b release: no prior in ws-b's scope, so seeding finds nothing
        // (it must NOT pull from ws-a or global).
        let (b_new, _) = db
            .ensure_release_created_scoped(DEFAULT_PRODUCT, "b1.0", "b new", Some("ws-b"))
            .unwrap();
        let prior = db
            .latest_prior_release_with_user_docs(b_new, DEFAULT_PRODUCT, Some("ws-b"))
            .unwrap();
        assert!(
            prior.is_none(),
            "ws-b must not see prior docs from ws-a or global"
        );
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

        db.insert_release(DEFAULT_PRODUCT, "v1.0", "Global", "", false, None)
            .unwrap();
        db.insert_release(DEFAULT_PRODUCT, "v1.1", "Scoped", "", false, Some("ws-1"))
            .unwrap();

        // Global list shows all releases regardless of scope.
        let all = db.list_releases().unwrap();
        assert_eq!(all.len(), 2);

        // Workspace list shows ONLY workspace-specific releases — global
        // releases are surfaced through the public/admin endpoints instead.
        let ws_releases = db.list_releases_for_workspace("ws-1").unwrap();
        assert_eq!(ws_releases.len(), 1);
        assert_eq!(ws_releases[0].1, "v1.1");

        // Different workspace sees none of these.
        let other = db.list_releases_for_workspace("ws-other").unwrap();
        assert_eq!(other.len(), 0);
    }

    #[test]
    fn test_get_release_workspace_id() {
        let db = test_db();
        db.create_workspace("ws-1", "WS", "", "", "admin").unwrap();
        db.insert_release(DEFAULT_PRODUCT, "v1.0", "Global", "", false, None)
            .unwrap();
        db.insert_release(DEFAULT_PRODUCT, "v1.1", "Scoped", "", false, Some("ws-1"))
            .unwrap();

        assert_eq!(db.get_release_workspace_id(DEFAULT_PRODUCT, "v1.0").unwrap(), Some(None));
        assert_eq!(
            db.get_release_workspace_id(DEFAULT_PRODUCT, "v1.1").unwrap(),
            Some(Some("ws-1".to_string()))
        );
        assert_eq!(db.get_release_workspace_id(DEFAULT_PRODUCT, "nonexistent").unwrap(), None);
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

        // Re-register hostA with a new URL — must update in place.
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
        // Caller still thinks it's at v1 — must fail with current=2.
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
        // overwrite — that would be the same "forgot to load" footgun.
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

        // Same consume function handles both kinds — invitee uses the
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
        // Admin resends — must invalidate the old link before minting the new one.
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
}
