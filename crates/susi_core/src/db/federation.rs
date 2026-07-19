use super::*;

impl LicenseDb {
    // -----------------------------------------------------------------------
    // Workspace federation: shared channel secret + peer registry
    // -----------------------------------------------------------------------

    /// Read the workspace's federation channel secret, creating one on first
    /// call. Members of the same workspace get the same secret on every call,
    /// so they all derive the same ChaCha20Poly1305 data-plane key.
    pub fn get_or_create_workspace_federation_secret(
        &self,
        workspace_id: &str,
    ) -> Result<String, LicenseError> {
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT channel_secret FROM workspace_federation WHERE workspace_id = ?1",
                params![workspace_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        if let Some(s) = existing {
            return self.open_secret(&s);
        }
        // Fresh 32 bytes of OS entropy, base64-encoded for transport.
        use base64::Engine as _;
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let secret = base64::engine::general_purpose::STANDARD.encode(&buf);
        let sealed = self.seal_secret(&secret)?;
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO workspace_federation (workspace_id, channel_secret, created_at, rotated_at)
                 VALUES (?1, ?2, ?3, ?3)",
                params![workspace_id, sealed, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert federation: {}", e)))?;
        Ok(secret)
    }

    /// Rotate the workspace's federation secret. Existing peers must re-fetch
    /// to keep encrypting on the wire; until they do their frames will fail to
    /// authenticate at the receiver and get dropped.
    pub fn rotate_workspace_federation_secret(
        &self,
        workspace_id: &str,
    ) -> Result<String, LicenseError> {
        use base64::Engine as _;
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let secret = base64::engine::general_purpose::STANDARD.encode(&buf);
        let sealed = self.seal_secret(&secret)?;
        let now = Utc::now().to_rfc3339();
        let updated = self
            .conn
            .execute(
                "UPDATE workspace_federation SET channel_secret = ?2, rotated_at = ?3
                 WHERE workspace_id = ?1",
                params![workspace_id, sealed, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB update federation: {}", e)))?;
        if updated == 0 {
            // No row yet - treat rotate as create.
            self.conn
                .execute(
                    "INSERT INTO workspace_federation (workspace_id, channel_secret, created_at, rotated_at)
                     VALUES (?1, ?2, ?3, ?3)",
                    params![workspace_id, sealed, now],
                )
                .map_err(|e| LicenseError::Other(format!("DB insert federation: {}", e)))?;
        }
        Ok(secret)
    }

    /// Insert or update a peer registration. Updates `url`, `label`,
    /// `network_id`, and `last_seen` on conflict so a peer that moved (new
    /// public URL, or changed its Network ID) refreshes in place rather than
    /// accumulating stale rows.
    pub fn upsert_workspace_peer(
        &self,
        workspace_id: &str,
        host_id: &str,
        url: &str,
        label: &str,
        network_id: &str,
        registered_by: &str,
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO workspace_peers
                    (workspace_id, host_id, url, label, network_id, registered_by, registered_at, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
                 ON CONFLICT(workspace_id, host_id) DO UPDATE SET
                    url = excluded.url,
                    label = excluded.label,
                    network_id = excluded.network_id,
                    last_seen = excluded.last_seen",
                params![workspace_id, host_id, url, label, network_id, registered_by, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert peer: {}", e)))?;
        Ok(())
    }

    /// List peers registered against a workspace. Returns
    /// `(host_id, url, label, network_id, registered_by, last_seen)`.
    pub fn list_workspace_peers(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<(String, String, String, String, String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT host_id, url, label, network_id, registered_by, last_seen
                 FROM workspace_peers
                 WHERE workspace_id = ?1
                 ORDER BY host_id",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows: Vec<_> = stmt
            .query_map(params![workspace_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Remove a peer registration. Returns true if a row was deleted.
    pub fn delete_workspace_peer(
        &self,
        workspace_id: &str,
        host_id: &str,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM workspace_peers WHERE workspace_id = ?1 AND host_id = ?2",
                params![workspace_id, host_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete peer: {}", e)))?;
        Ok(n > 0)
    }

}
