use super::*;

impl LicenseDb {
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

}
