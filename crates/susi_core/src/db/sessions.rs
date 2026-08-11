use super::*;

impl LicenseDb {
    // -----------------------------------------------------------------------
    // Sessions (one row per issued session JWT, keyed by jti)
    // -----------------------------------------------------------------------

    pub fn create_session(
        &self,
        jti: &str,
        username: &str,
        device_label: &str,
        ip: &str,
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO sessions (jti, username, created_at, last_seen, device_label, ip)
                 VALUES (?1, ?2, ?3, ?3, ?4, ?5)",
                params![jti, username, now, device_label, ip],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert session: {}", e)))?;
        Ok(())
    }

    /// True when the session exists, belongs to `username`, isn't revoked,
    /// and has been active within `idle_timeout_days` (inactivity timeout on
    /// top of the JWT's absolute lifetime). Refreshes last_seen as a side
    /// effect, throttled to once a minute so the auth hot path isn't a write
    /// per request.
    pub fn session_valid(
        &self,
        jti: &str,
        username: &str,
        idle_timeout_days: i64,
    ) -> Result<bool, LicenseError> {
        let row: Option<(String, Option<String>, String)> = self
            .conn
            .query_row(
                "SELECT username, revoked_at, last_seen FROM sessions WHERE jti = ?1",
                params![jti],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query session: {}", e)))?;
        let Some((owner, revoked_at, last_seen)) = row else {
            return Ok(false);
        };
        if owner != username || revoked_at.is_some() {
            return Ok(false);
        }
        let now = Utc::now();
        let idle_cutoff = (now - Duration::days(idle_timeout_days)).to_rfc3339();
        if last_seen < idle_cutoff {
            return Ok(false);
        }
        let cutoff = (now - Duration::seconds(60)).to_rfc3339();
        let _ = self.conn.execute(
            "UPDATE sessions SET last_seen = ?1 WHERE jti = ?2 AND last_seen < ?3",
            params![now.to_rfc3339(), jti, cutoff],
        );
        Ok(true)
    }

    /// Server-side logout: revoke the caller's own session by its jti.
    pub fn revoke_session_by_jti(&self, username: &str, jti: &str) -> Result<bool, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let n = self
            .conn
            .execute(
                "UPDATE sessions SET revoked_at = ?1
                 WHERE jti = ?2 AND username = ?3 AND revoked_at IS NULL",
                params![now, jti, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update session: {}", e)))?;
        Ok(n > 0)
    }

    /// Active (non-revoked, non-expired) sessions for a user, newest first.
    /// `max_age_days` mirrors the JWT lifetime - older rows are dead tokens.
    pub fn list_sessions(
        &self,
        username: &str,
        max_age_days: i64,
    ) -> Result<Vec<SessionRow>, LicenseError> {
        let cutoff = (Utc::now() - Duration::days(max_age_days)).to_rfc3339();
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, jti, username, created_at, last_seen, device_label, ip
                 FROM sessions
                 WHERE username = ?1 AND revoked_at IS NULL AND created_at > ?2
                 ORDER BY last_seen DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows: Vec<SessionRow> = stmt
            .query_map(params![username, cutoff], |r| {
                Ok(SessionRow {
                    id: r.get(0)?,
                    jti: r.get(1)?,
                    username: r.get(2)?,
                    created_at: r.get(3)?,
                    last_seen: r.get(4)?,
                    device_label: r.get(5)?,
                    ip: r.get(6)?,
                })
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Revoke one of the user's sessions by row id. Scoped to the owner so a
    /// user can't revoke someone else's session by guessing ids.
    pub fn revoke_session(&self, username: &str, id: i64) -> Result<bool, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let n = self
            .conn
            .execute(
                "UPDATE sessions SET revoked_at = ?1
                 WHERE id = ?2 AND username = ?3 AND revoked_at IS NULL",
                params![now, id, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB update session: {}", e)))?;
        Ok(n > 0)
    }

    /// Revoke every session of the user except the one identified by
    /// `current_jti`. Returns how many were revoked.
    pub fn revoke_other_sessions(
        &self,
        username: &str,
        current_jti: &str,
    ) -> Result<usize, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let n = self
            .conn
            .execute(
                "UPDATE sessions SET revoked_at = ?1
                 WHERE username = ?2 AND jti != ?3 AND revoked_at IS NULL",
                params![now, username, current_jti],
            )
            .map_err(|e| LicenseError::Other(format!("DB update sessions: {}", e)))?;
        Ok(n)
    }

    /// Drop session rows whose JWT can no longer be valid: older than the
    /// token lifetime, or revoked more than a day ago.
    pub fn purge_stale_sessions(&self, max_age_days: i64) -> Result<usize, LicenseError> {
        let age_cutoff = (Utc::now() - Duration::days(max_age_days)).to_rfc3339();
        let revoked_cutoff = (Utc::now() - Duration::days(1)).to_rfc3339();
        let n = self
            .conn
            .execute(
                "DELETE FROM sessions WHERE created_at < ?1
                    OR (revoked_at IS NOT NULL AND revoked_at < ?2)",
                params![age_cutoff, revoked_cutoff],
            )
            .map_err(|e| LicenseError::Other(format!("DB purge sessions: {}", e)))?;
        Ok(n)
    }

}
