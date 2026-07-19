use super::*;

impl LicenseDb {
    // -----------------------------------------------------------------------
    // Dropbox backup — config/state KV + run history
    // -----------------------------------------------------------------------

    pub fn get_backup_state(&self, key: &str) -> Result<Option<String>, LicenseError> {
        self.conn
            .query_row(
                "SELECT value FROM backup_state WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB get backup state: {}", e)))
    }

    pub fn set_backup_state(&self, key: &str, value: &str) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT INTO backup_state (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(|e| LicenseError::Other(format!("DB set backup state: {}", e)))?;
        Ok(())
    }

    pub fn delete_backup_state(&self, key: &str) -> Result<(), LicenseError> {
        self.conn
            .execute("DELETE FROM backup_state WHERE key = ?1", params![key])
            .map_err(|e| LicenseError::Other(format!("DB delete backup state: {}", e)))?;
        Ok(())
    }

    /// Store the Dropbox OAuth refresh token sealed with the at-rest key.
    pub fn set_backup_refresh_token(&self, token: &str) -> Result<(), LicenseError> {
        let sealed = self.seal_secret(token)?;
        self.set_backup_state("dropbox_refresh_token", &sealed)
    }

    pub fn get_backup_refresh_token(&self) -> Result<Option<String>, LicenseError> {
        match self.get_backup_state("dropbox_refresh_token")? {
            Some(stored) => Ok(Some(self.open_secret(&stored)?)),
            None => Ok(None),
        }
    }

    /// Insert a new run in `running` state; returns its id.
    pub fn insert_backup_run(&self, source: &str) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO backup_runs (started_at, status, source) VALUES (?1, 'running', ?2)",
                params![now, source],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert backup run: {}", e)))?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn finish_backup_run(
        &self,
        id: i64,
        status: &str,
        archive_name: &str,
        size_bytes: i64,
        error: &str,
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE backup_runs SET finished_at = ?2, status = ?3, archive_name = ?4,
                        size_bytes = ?5, error = ?6 WHERE id = ?1",
                params![id, now, status, archive_name, size_bytes, error],
            )
            .map_err(|e| LicenseError::Other(format!("DB finish backup run: {}", e)))?;
        Ok(())
    }

    /// Flip any `running` rows to `error` — called once at startup so a run
    /// interrupted by a crash/redeploy doesn't show as running forever.
    pub fn mark_interrupted_backup_runs(&self) -> Result<usize, LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE backup_runs SET status = 'error', finished_at = ?1,
                        error = 'Interrupted by server restart' WHERE status = 'running'",
                params![now],
            )
            .map_err(|e| LicenseError::Other(format!("DB mark interrupted runs: {}", e)))
    }

    pub fn list_backup_runs(&self, limit: i64) -> Result<Vec<BackupRunRow>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, started_at, finished_at, status, source, archive_name,
                        size_bytes, error
                 FROM backup_runs ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(BackupRunRow {
                    id: r.get(0)?,
                    started_at: r.get(1)?,
                    finished_at: r.get(2)?,
                    status: r.get(3)?,
                    source: r.get(4)?,
                    archive_name: r.get(5)?,
                    size_bytes: r.get(6)?,
                    error: r.get(7)?,
                })
            })
            .map_err(|e| LicenseError::Other(format!("DB list backup runs: {}", e)))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| LicenseError::Other(format!("DB list backup runs: {}", e)))?;
        Ok(rows)
    }

    /// Drop history beyond the newest `keep` rows.
    pub fn prune_backup_runs(&self, keep: i64) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "DELETE FROM backup_runs WHERE id NOT IN
                 (SELECT id FROM backup_runs ORDER BY id DESC LIMIT ?1)",
                params![keep],
            )
            .map_err(|e| LicenseError::Other(format!("DB prune backup runs: {}", e)))?;
        Ok(())
    }

    /// Consistent point-in-time snapshot of the live database into `dest`
    /// (which must not exist yet). Safe to run while serving requests.
    pub fn vacuum_into(&self, dest: &str) -> Result<(), LicenseError> {
        self.conn
            .execute("VACUUM INTO ?1", params![dest])
            .map_err(|e| LicenseError::Other(format!("DB vacuum into: {}", e)))?;
        Ok(())
    }
}
