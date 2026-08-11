use super::*;

impl LicenseDb {
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
                // Owner, not admin: ownership can only be granted by an
                // existing owner, so a fresh install would otherwise have no
                // way to ever produce one.
                "INSERT INTO users (username, password_hash, role, must_change_password, totp_enabled, created_at, updated_at)
                 VALUES ('admin', ?1, 'owner', 1, 0, ?2, ?2)",
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
        // The token_version bump just revoked every outstanding JWT - drop
        // their now-dead session rows. API tokens go too: a password change
        // must invalidate everything the old credential minted.
        let _ = self
            .conn
            .execute("DELETE FROM sessions WHERE username = ?1", params![username]);
        let _ = self.revoke_api_tokens_for_user(username);
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
            .prepare("SELECT username, role, totp_enabled, must_change_password, created_at, email, newsletter_opt_in, first_name, last_name FROM users ORDER BY created_at")
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
                    newsletter_opt_in: r.get::<_, i32>(6)? != 0,
                    first_name: r.get(7)?,
                    last_name: r.get(8)?,
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
    /// multiple matches - ambiguous addresses shouldn't grant a password reset.
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

    /// Any username holding this email (case-insensitive), even when several
    /// do. Used to block creating a second account with the same address.
    pub fn any_username_by_email(&self, email: &str) -> Result<Option<String>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT username FROM users WHERE LOWER(email) = LOWER(?1) LIMIT 1")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows: Vec<String> = stmt
            .query_map(params![email], |r| r.get::<_, String>(0))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows.into_iter().next())
    }

    /// Promote every account holding `email` to owner, returning the usernames
    /// changed. Matching is case-insensitive and covers duplicates, since
    /// `users.email` has no UNIQUE constraint.
    ///
    /// Idempotent: accounts already owners are not reported as changed, so a
    /// restart is silent rather than logging a promotion every boot.
    pub fn promote_owner_by_email(&self, email: &str) -> Result<Vec<String>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT username FROM users
                 WHERE LOWER(TRIM(email)) = LOWER(TRIM(?1)) AND role <> 'owner'",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let names: Vec<String> = stmt
            .query_map(params![email], |r| r.get::<_, String>(0))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        let now = Utc::now().to_rfc3339();
        for name in &names {
            self.conn
                .execute(
                    "UPDATE users SET role = 'owner', updated_at = ?1 WHERE username = ?2",
                    params![now, name],
                )
                .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        }
        Ok(names)
    }

    pub fn count_owners(&self) -> Result<i64, LicenseError> {
        self.conn
            .query_row("SELECT COUNT(*) FROM users WHERE role = 'owner'", [], |r| r.get(0))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    pub fn get_user_newsletter_opt_in(&self, username: &str) -> Result<bool, LicenseError> {
        let v: i32 = self
            .conn
            .query_row(
                "SELECT newsletter_opt_in FROM users WHERE username = ?1",
                params![username],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(v != 0)
    }

    pub fn set_user_newsletter_opt_in(
        &self,
        username: &str,
        opt_in: bool,
    ) -> Result<bool, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let n = self
            .conn
            .execute(
                "UPDATE users SET newsletter_opt_in = ?1, updated_at = ?2 WHERE username = ?3",
                params![opt_in as i32, now, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(n > 0)
    }

    /// Set the consent flag on many users at once. Returns the number of rows
    /// actually changed, which is how the caller detects unknown usernames.
    pub fn set_newsletter_opt_in_bulk(
        &self,
        usernames: &[String],
        opt_in: bool,
    ) -> Result<usize, LicenseError> {
        if usernames.is_empty() {
            return Ok(0);
        }
        let now = Utc::now().to_rfc3339();
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;
        let mut changed = 0;
        {
            let mut stmt = tx
                .prepare("UPDATE users SET newsletter_opt_in = ?1, updated_at = ?2 WHERE username = ?3")
                .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
            for u in usernames {
                changed += stmt
                    .execute(params![opt_in as i32, now, u])
                    .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
            }
        }
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB commit: {}", e)))?;
        Ok(changed)
    }

    pub fn set_user_name(
        &self,
        username: &str,
        first_name: &str,
        last_name: &str,
    ) -> Result<bool, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let n = self
            .conn
            .execute(
                "UPDATE users SET first_name = ?1, last_name = ?2, updated_at = ?3 WHERE username = ?4",
                params![first_name.trim(), last_name.trim(), now, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(n > 0)
    }

    pub fn get_user_name(&self, username: &str) -> Result<(String, String), LicenseError> {
        self.conn
            .query_row(
                "SELECT first_name, last_name FROM users WHERE username = ?1",
                params![username],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
            .map(|o| o.unwrap_or_default())
    }

    /// "First Last" for display, or None when the user has no name on file.
    /// Never falls back to the username - a byline showing an account name is
    /// worse than no byline at all.
    pub fn get_user_display_name(&self, username: &str) -> Result<Option<String>, LicenseError> {
        let name: Option<String> = self
            .conn
            .query_row(
                "SELECT TRIM(TRIM(first_name) || ' ' || TRIM(last_name)) FROM users WHERE username = ?1",
                params![username],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(name.filter(|n| !n.is_empty()))
    }

    /// TOTP replay protection: accept `step` only when it is strictly newer
    /// than the last accepted timestep. Returns false when the step was
    /// already used (replay) or the user doesn't exist.
    pub fn try_advance_totp_step(&self, username: &str, step: i64) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "UPDATE users SET totp_last_step = ?1
                 WHERE username = ?2 AND totp_last_step < ?1",
                params![step, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(n > 0)
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

}
