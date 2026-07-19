use super::*;

impl LicenseDb {
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

}
