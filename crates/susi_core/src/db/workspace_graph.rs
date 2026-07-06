use super::*;

impl LicenseDb {
    // -----------------------------------------------------------------------
    // Workspace graph (one shared node-graph per workspace, version-tracked)
    // -----------------------------------------------------------------------

    /// Fetch the workspace's current graph. Returns `(graph_version, config_json,
    /// updated_by, updated_at)` or `None` when no graph has been pushed yet.
    pub fn get_workspace_graph(
        &self,
        workspace_id: &str,
    ) -> Result<Option<(u32, String, String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT graph_version, config, updated_by, updated_at
                 FROM workspace_graphs WHERE workspace_id = ?1",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let row = stmt
            .query_row(params![workspace_id], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u32,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .ok();
        Ok(row)
    }

    /// Cheap version-only fetch for the federation poll response — avoids
    /// shipping the (potentially large) config blob on every poll cycle.
    /// `None` when no graph row exists yet.
    pub fn get_workspace_graph_version(
        &self,
        workspace_id: &str,
    ) -> Result<Option<u32>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT graph_version FROM workspace_graphs WHERE workspace_id = ?1")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let row = stmt
            .query_row(params![workspace_id], |r| r.get::<_, i64>(0))
            .ok()
            .map(|v| v as u32);
        Ok(row)
    }

    /// Upsert the workspace's graph with optimistic-lock semantics. The caller
    /// passes the version it loaded; we bump to `loaded + 1` only when the row
    /// is still at that version (or absent ⇒ seed at version 1). Returns the
    /// new version. `Err(GraphConflict { current })` when another writer raced
    /// us — caller surfaces this as HTTP 409 with the current version so the
    /// editor can refresh.
    ///
    /// `expected_version` is `None` only for the very first save of a
    /// workspace (or when the caller is deliberately overwriting; today we
    /// route deliberate overwrites through the same `Some(current)` path).
    pub fn upsert_workspace_graph(
        &self,
        workspace_id: &str,
        expected_version: Option<u32>,
        config_json: &str,
        updated_by: &str,
    ) -> Result<u32, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let current = self.get_workspace_graph_version(workspace_id)?;

        match (current, expected_version) {
            // First save: no existing row, no expected version → seed at v1.
            (None, None) => {
                self.conn
                    .execute(
                        "INSERT INTO workspace_graphs
                            (workspace_id, graph_version, config, updated_by, updated_at)
                         VALUES (?1, 1, ?2, ?3, ?4)",
                        params![workspace_id, config_json, updated_by, now],
                    )
                    .map_err(|e| LicenseError::Other(format!("DB insert graph: {}", e)))?;
                Ok(1)
            }
            // Update: expected matches current → bump to current+1.
            (Some(cur), Some(exp)) if cur == exp => {
                let next = cur + 1;
                self.conn
                    .execute(
                        "UPDATE workspace_graphs
                            SET graph_version = ?2, config = ?3, updated_by = ?4, updated_at = ?5
                          WHERE workspace_id = ?1 AND graph_version = ?6",
                        params![
                            workspace_id,
                            next as i64,
                            config_json,
                            updated_by,
                            now,
                            cur as i64
                        ],
                    )
                    .map_err(|e| LicenseError::Other(format!("DB update graph: {}", e)))?;
                Ok(next)
            }
            // Anything else is a conflict — surface the current version so the
            // editor can re-fetch and re-apply local changes on top.
            _ => Err(LicenseError::GraphConflict {
                current: current.unwrap_or(0),
            }),
        }
    }

}
