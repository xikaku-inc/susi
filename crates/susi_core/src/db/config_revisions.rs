use super::*;

impl LicenseDb {
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

}
