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
        // The token_version bump just revoked every outstanding JWT - drop
        // their now-dead session rows.
        let _ = self
            .conn
            .execute("DELETE FROM sessions WHERE username = ?1", params![username]);
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
            .prepare("SELECT username, role, totp_enabled, must_change_password, created_at, email, newsletter_opt_in FROM users ORDER BY created_at")
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
