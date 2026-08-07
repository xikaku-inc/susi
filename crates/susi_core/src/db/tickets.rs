use super::*;

/// The only statuses a ticket may hold. Anything else is rejected at the
/// API edge so the admin filter and the UI badges stay exhaustive.
pub const TICKET_STATUSES: [&str; 3] = ["open", "in_progress", "closed"];

pub fn is_valid_ticket_status(s: &str) -> bool {
    TICKET_STATUSES.contains(&s)
}

/// Shared projection for both ticket list queries. `w` is the workspaces
/// join alias, `t` the tickets alias.
const TICKET_COLUMNS: &str = "t.id, t.workspace_id, COALESCE(w.name, ''), t.title, t.body,
     t.status, t.author, t.created_at, t.updated_at,
     (SELECT COUNT(*) FROM workspace_ticket_comments c WHERE c.ticket_id = t.id)";

fn row_to_ticket(r: &rusqlite::Row) -> rusqlite::Result<TicketRow> {
    Ok(TicketRow {
        id: r.get(0)?,
        workspace_id: r.get(1)?,
        workspace_name: r.get(2)?,
        title: r.get(3)?,
        body: r.get(4)?,
        status: r.get(5)?,
        author: r.get(6)?,
        created_at: r.get(7)?,
        updated_at: r.get(8)?,
        comment_count: r.get(9)?,
    })
}

impl LicenseDb {
    // -----------------------------------------------------------------------
    // Workspace tickets
    // -----------------------------------------------------------------------

    pub fn create_ticket(
        &self,
        workspace_id: &str,
        title: &str,
        body: &str,
        author: &str,
    ) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO workspace_tickets
                 (workspace_id, title, body, status, author, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 'open', ?4, ?5, ?5)",
                params![workspace_id, title, body, author, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert ticket: {}", e)))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Tickets of one workspace, open ones first, then newest first.
    pub fn list_tickets(&self, workspace_id: &str) -> Result<Vec<TicketRow>, LicenseError> {
        let sql = format!(
            "SELECT {cols} FROM workspace_tickets t
             LEFT JOIN workspaces w ON w.id = t.workspace_id
             WHERE t.workspace_id = ?1
             ORDER BY CASE t.status WHEN 'closed' THEN 1 ELSE 0 END, t.created_at DESC, t.id DESC",
            cols = TICKET_COLUMNS
        );
        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| LicenseError::Other(format!("DB prepare list_tickets: {}", e)))?;
        let rows = stmt
            .query_map(params![workspace_id], |r| row_to_ticket(r))
            .map_err(|e| LicenseError::Other(format!("DB query list_tickets: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Every ticket across every workspace (admin view), optionally filtered
    /// by status. Open first, then newest first.
    pub fn list_all_tickets(&self, status: Option<&str>) -> Result<Vec<TicketRow>, LicenseError> {
        let sql = format!(
            "SELECT {cols} FROM workspace_tickets t
             LEFT JOIN workspaces w ON w.id = t.workspace_id
             WHERE (?1 IS NULL OR t.status = ?1)
             ORDER BY CASE t.status WHEN 'closed' THEN 1 ELSE 0 END, t.created_at DESC, t.id DESC",
            cols = TICKET_COLUMNS
        );
        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| LicenseError::Other(format!("DB prepare list_all_tickets: {}", e)))?;
        let rows = stmt
            .query_map(params![status], |r| row_to_ticket(r))
            .map_err(|e| LicenseError::Other(format!("DB query list_all_tickets: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn get_ticket(
        &self,
        workspace_id: &str,
        id: i64,
    ) -> Result<Option<TicketRow>, LicenseError> {
        let sql = format!(
            "SELECT {cols} FROM workspace_tickets t
             LEFT JOIN workspaces w ON w.id = t.workspace_id
             WHERE t.workspace_id = ?1 AND t.id = ?2",
            cols = TICKET_COLUMNS
        );
        self.conn
            .query_row(&sql, params![workspace_id, id], |r| row_to_ticket(r))
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB lookup ticket: {}", e)))
    }

    /// Update title/body/status in one shot. Ok(false) when the ticket
    /// doesn't exist in that workspace.
    pub fn update_ticket(
        &self,
        workspace_id: &str,
        id: i64,
        title: &str,
        body: &str,
        status: &str,
    ) -> Result<bool, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let n = self
            .conn
            .execute(
                "UPDATE workspace_tickets
                 SET title = ?1, body = ?2, status = ?3, updated_at = ?4
                 WHERE workspace_id = ?5 AND id = ?6",
                params![title, body, status, now, workspace_id, id],
            )
            .map_err(|e| LicenseError::Other(format!("DB update ticket: {}", e)))?;
        Ok(n > 0)
    }

    pub fn delete_ticket(&self, workspace_id: &str, id: i64) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM workspace_tickets WHERE workspace_id = ?1 AND id = ?2",
                params![workspace_id, id],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete ticket: {}", e)))?;
        Ok(n > 0)
    }

    // -----------------------------------------------------------------------
    // Ticket comments (visible to every workspace member)
    // -----------------------------------------------------------------------

    pub fn list_ticket_comments(
        &self,
        ticket_id: i64,
    ) -> Result<Vec<TicketCommentRow>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, ticket_id, body, author, created_at
                 FROM workspace_ticket_comments WHERE ticket_id = ?1
                 ORDER BY created_at, id",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare list_ticket_comments: {}", e)))?;
        let rows = stmt
            .query_map(params![ticket_id], |r| {
                Ok(TicketCommentRow {
                    id: r.get(0)?,
                    ticket_id: r.get(1)?,
                    body: r.get(2)?,
                    author: r.get(3)?,
                    created_at: r.get(4)?,
                })
            })
            .map_err(|e| LicenseError::Other(format!("DB query list_ticket_comments: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Append a comment and bump the parent's `updated_at` so list ordering
    /// and "last activity" stay honest. Ok(None) when the ticket isn't in
    /// that workspace, so the caller can 404 without a separate lookup.
    pub fn add_ticket_comment(
        &self,
        workspace_id: &str,
        ticket_id: i64,
        body: &str,
        author: &str,
    ) -> Result<Option<i64>, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let bumped = self
            .conn
            .execute(
                "UPDATE workspace_tickets SET updated_at = ?1 WHERE workspace_id = ?2 AND id = ?3",
                params![now, workspace_id, ticket_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB touch ticket: {}", e)))?;
        if bumped == 0 {
            return Ok(None);
        }
        self.conn
            .execute(
                "INSERT INTO workspace_ticket_comments (ticket_id, body, author, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![ticket_id, body, author, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert ticket comment: {}", e)))?;
        Ok(Some(self.conn.last_insert_rowid()))
    }

    /// Delete one comment. Returns its author so the caller can enforce
    /// "author or admin" without a second query; Ok(None) when absent.
    pub fn delete_ticket_comment(
        &self,
        ticket_id: i64,
        comment_id: i64,
    ) -> Result<Option<String>, LicenseError> {
        let author: Option<String> = self
            .conn
            .query_row(
                "SELECT author FROM workspace_ticket_comments WHERE ticket_id = ?1 AND id = ?2",
                params![ticket_id, comment_id],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB lookup ticket comment: {}", e)))?;
        let Some(a) = author else {
            return Ok(None);
        };
        self.conn
            .execute(
                "DELETE FROM workspace_ticket_comments WHERE ticket_id = ?1 AND id = ?2",
                params![ticket_id, comment_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete ticket comment: {}", e)))?;
        Ok(Some(a))
    }
}
