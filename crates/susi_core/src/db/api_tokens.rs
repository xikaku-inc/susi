use super::*;

impl LicenseDb {
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
    /// Auth-hot path - must be cheap.
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

    /// Update last_used_at. Called on every authenticated request - best-effort,
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

    /// Look up just the owning username - used for permission checks (e.g.
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
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| LicenseError::Other(format!("DB begin: {}", e)))?;
        let result = self.delete_user_inner(username);
        if result.is_ok() {
            self.conn
                .execute_batch("COMMIT")
                .map_err(|e| LicenseError::Other(format!("DB commit: {}", e)))?;
        } else {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
        result
    }

    fn delete_user_inner(&self, username: &str) -> Result<(), LicenseError> {
        let run = |sql: &str| {
            self.conn
                .execute(sql, params![username])
                .map(|_| ())
                .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))
        };
        // Per-user rows go with the account. Attribution columns (revision
        // authors, recording uploaders, page editors) deliberately stay as
        // historical record.
        run("DELETE FROM users WHERE username = ?1")?;
        run("DELETE FROM license_users WHERE username = ?1")?;
        run("DELETE FROM workspace_members WHERE username = ?1")?;
        run("DELETE FROM sessions WHERE username = ?1")?;
        run("DELETE FROM known_devices WHERE username = ?1")?;
        run("DELETE FROM login_tokens WHERE username = ?1")?;
        run("DELETE FROM totp_backup_codes WHERE username = ?1")?;
        run("DELETE FROM api_tokens WHERE username = ?1")?;
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
    /// `user_totp_enabled` calls - saves two SQLite round-trips and two
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
        let _ = self
            .conn
            .execute("DELETE FROM sessions WHERE username = ?1", params![username]);
        Ok(())
    }

}
