use super::*;

impl LicenseDb {
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

}
