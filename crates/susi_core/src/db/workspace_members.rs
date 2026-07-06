use super::*;

impl LicenseDb {
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

}
