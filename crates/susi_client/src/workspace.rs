use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::blocking_run;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WorkspaceInfo {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub product: String,
    #[serde(default)]
    pub description: String,
    pub created_by: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WorkspaceMember {
    pub username: String,
    pub role: String,
    #[serde(default)]
    pub added_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigRevisionInfo {
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub author: String,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigRevision {
    pub id: i64,
    pub config_json: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub author: String,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug)]
pub enum WorkspaceError {
    /// Authentication failed (wrong credentials or expired token).
    AuthFailed(String),
    /// Insufficient permissions for the requested operation.
    Forbidden(String),
    /// Resource not found.
    NotFound(String),
    /// Server or network error.
    RequestFailed(String),
    /// Unexpected server response.
    InvalidResponse(String),
}

impl std::fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthFailed(m) => write!(f, "Auth failed: {}", m),
            Self::Forbidden(m) => write!(f, "Forbidden: {}", m),
            Self::NotFound(m) => write!(f, "Not found: {}", m),
            Self::RequestFailed(m) => write!(f, "Request failed: {}", m),
            Self::InvalidResponse(m) => write!(f, "Invalid response: {}", m),
        }
    }
}

impl std::error::Error for WorkspaceError {}

/// Client for interacting with susi workspace API.
pub struct WorkspaceClient {
    server_url: String,
    token: String,
    http: Client,
}

impl WorkspaceClient {
    /// Authenticate with username/password and create a client.
    pub fn login(server_url: &str, username: &str, password: &str) -> Result<Self, WorkspaceError> {
        blocking_run(Self::login_async(server_url, username, password))
    }

    /// Async variant of [`login`].
    pub async fn login_async(server_url: &str, username: &str, password: &str) -> Result<Self, WorkspaceError> {
        let http = Client::new();
        let base = server_url.trim_end_matches('/');
        let url = format!("{}/api/v1/auth/login", base);

        let resp = http.post(&url)
            .json(&serde_json::json!({
                "username": username,
                "password": password,
            }))
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| WorkspaceError::RequestFailed(e.to_string()))?;

        if resp.status() == 401 {
            return Err(WorkspaceError::AuthFailed("Invalid credentials".into()));
        }
        if !resp.status().is_success() {
            return Err(WorkspaceError::RequestFailed(format!("Login failed: {}", resp.status())));
        }

        #[derive(Deserialize)]
        struct LoginResponse { token: String }

        let login: LoginResponse = resp.json()
            .await
            .map_err(|e| WorkspaceError::InvalidResponse(e.to_string()))?;

        Ok(Self {
            server_url: base.to_string(),
            token: login.token,
            http,
        })
    }

    /// Create a client with an existing JWT token.
    pub fn with_token(server_url: &str, token: &str) -> Self {
        Self {
            server_url: server_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http: Client::new(),
        }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    // -----------------------------------------------------------------------
    // Workspaces
    // -----------------------------------------------------------------------

    pub fn list_workspaces(&self) -> Result<Vec<WorkspaceInfo>, WorkspaceError> {
        blocking_run(self.list_workspaces_async())
    }

    pub async fn list_workspaces_async(&self) -> Result<Vec<WorkspaceInfo>, WorkspaceError> {
        #[derive(Deserialize)]
        struct Resp { workspaces: Vec<WorkspaceInfo> }

        let resp: Resp = self.get("/api/v1/workspaces").await?;
        Ok(resp.workspaces)
    }

    pub fn get_workspace(&self, id: &str) -> Result<WorkspaceInfo, WorkspaceError> {
        blocking_run(self.get_workspace_async(id))
    }

    pub async fn get_workspace_async(&self, id: &str) -> Result<WorkspaceInfo, WorkspaceError> {
        self.get(&format!("/api/v1/workspaces/{}", id)).await
    }

    pub fn create_workspace(
        &self,
        name: &str,
        product: &str,
        description: &str,
    ) -> Result<WorkspaceInfo, WorkspaceError> {
        blocking_run(self.create_workspace_async(name, product, description))
    }

    pub async fn create_workspace_async(
        &self,
        name: &str,
        product: &str,
        description: &str,
    ) -> Result<WorkspaceInfo, WorkspaceError> {
        self.post("/api/v1/workspaces", &serde_json::json!({
            "name": name,
            "product": product,
            "description": description,
        })).await
    }

    pub fn update_workspace(
        &self,
        id: &str,
        name: &str,
        product: &str,
        description: &str,
    ) -> Result<(), WorkspaceError> {
        blocking_run(self.update_workspace_async(id, name, product, description))
    }

    pub async fn update_workspace_async(
        &self,
        id: &str,
        name: &str,
        product: &str,
        description: &str,
    ) -> Result<(), WorkspaceError> {
        self.put::<serde_json::Value>(&format!("/api/v1/workspaces/{}", id), &serde_json::json!({
            "name": name,
            "product": product,
            "description": description,
        })).await?;
        Ok(())
    }

    pub fn delete_workspace(&self, id: &str) -> Result<(), WorkspaceError> {
        blocking_run(self.delete_workspace_async(id))
    }

    pub async fn delete_workspace_async(&self, id: &str) -> Result<(), WorkspaceError> {
        self.delete(&format!("/api/v1/workspaces/{}", id)).await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Members
    // -----------------------------------------------------------------------

    pub fn add_member(
        &self,
        workspace_id: &str,
        username: &str,
        role: &str,
    ) -> Result<(), WorkspaceError> {
        blocking_run(self.add_member_async(workspace_id, username, role))
    }

    pub async fn add_member_async(
        &self,
        workspace_id: &str,
        username: &str,
        role: &str,
    ) -> Result<(), WorkspaceError> {
        self.post_void(
            &format!("/api/v1/workspaces/{}/members", workspace_id),
            &serde_json::json!({ "username": username, "role": role }),
        ).await
    }

    pub fn remove_member(
        &self,
        workspace_id: &str,
        username: &str,
    ) -> Result<(), WorkspaceError> {
        blocking_run(self.remove_member_async(workspace_id, username))
    }

    pub async fn remove_member_async(
        &self,
        workspace_id: &str,
        username: &str,
    ) -> Result<(), WorkspaceError> {
        self.delete(&format!("/api/v1/workspaces/{}/members/{}", workspace_id, username)).await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Config revisions
    // -----------------------------------------------------------------------

    pub fn list_configs(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<ConfigRevisionInfo>, WorkspaceError> {
        blocking_run(self.list_configs_async(workspace_id))
    }

    pub async fn list_configs_async(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<ConfigRevisionInfo>, WorkspaceError> {
        #[derive(Deserialize)]
        struct Resp { configs: Vec<ConfigRevisionInfo> }

        let resp: Resp = self.get(&format!("/api/v1/workspaces/{}/configs", workspace_id)).await?;
        Ok(resp.configs)
    }

    pub fn push_config(
        &self,
        workspace_id: &str,
        config_json: &str,
        name: &str,
        description: &str,
    ) -> Result<i64, WorkspaceError> {
        blocking_run(self.push_config_async(workspace_id, config_json, name, description))
    }

    pub async fn push_config_async(
        &self,
        workspace_id: &str,
        config_json: &str,
        name: &str,
        description: &str,
    ) -> Result<i64, WorkspaceError> {
        #[derive(Deserialize)]
        struct Resp { id: i64 }

        let resp: Resp = self.post(
            &format!("/api/v1/workspaces/{}/configs", workspace_id),
            &serde_json::json!({
                "config_json": config_json,
                "name": name,
                "description": description,
            }),
        ).await?;
        Ok(resp.id)
    }

    pub fn update_config(
        &self,
        workspace_id: &str,
        id: i64,
        name: &str,
        description: &str,
    ) -> Result<(), WorkspaceError> {
        blocking_run(self.update_config_async(workspace_id, id, name, description))
    }

    pub async fn update_config_async(
        &self,
        workspace_id: &str,
        id: i64,
        name: &str,
        description: &str,
    ) -> Result<(), WorkspaceError> {
        self.put::<serde_json::Value>(
            &format!("/api/v1/workspaces/{}/configs/{}", workspace_id, id),
            &serde_json::json!({ "name": name, "description": description }),
        ).await?;
        Ok(())
    }

    pub fn delete_config(
        &self,
        workspace_id: &str,
        id: i64,
    ) -> Result<(), WorkspaceError> {
        blocking_run(self.delete_config_async(workspace_id, id))
    }

    pub async fn delete_config_async(
        &self,
        workspace_id: &str,
        id: i64,
    ) -> Result<(), WorkspaceError> {
        self.delete(&format!("/api/v1/workspaces/{}/configs/{}", workspace_id, id)).await?;
        Ok(())
    }

    pub fn get_config(
        &self,
        workspace_id: &str,
        id: i64,
    ) -> Result<ConfigRevision, WorkspaceError> {
        blocking_run(self.get_config_async(workspace_id, id))
    }

    pub async fn get_config_async(
        &self,
        workspace_id: &str,
        id: i64,
    ) -> Result<ConfigRevision, WorkspaceError> {
        self.get(&format!("/api/v1/workspaces/{}/configs/{}", workspace_id, id)).await
    }

    pub fn get_latest_config(
        &self,
        workspace_id: &str,
    ) -> Result<ConfigRevision, WorkspaceError> {
        blocking_run(self.get_latest_config_async(workspace_id))
    }

    pub async fn get_latest_config_async(
        &self,
        workspace_id: &str,
    ) -> Result<ConfigRevision, WorkspaceError> {
        self.get(&format!("/api/v1/workspaces/{}/configs/latest", workspace_id)).await
    }

    // -----------------------------------------------------------------------
    // HTTP helpers (async — sync paths go through `blocking_run`)
    // -----------------------------------------------------------------------

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, WorkspaceError> {
        let url = format!("{}{}", self.server_url, path);
        let resp = self.http.get(&url)
            .bearer_auth(&self.token)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| WorkspaceError::RequestFailed(e.to_string()))?;
        self.handle_response(resp).await
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T, WorkspaceError> {
        let url = format!("{}{}", self.server_url, path);
        let resp = self.http.post(&url)
            .bearer_auth(&self.token)
            .json(body)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| WorkspaceError::RequestFailed(e.to_string()))?;
        self.handle_response(resp).await
    }

    async fn post_void(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<(), WorkspaceError> {
        let url = format!("{}{}", self.server_url, path);
        let resp = self.http.post(&url)
            .bearer_auth(&self.token)
            .json(body)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| WorkspaceError::RequestFailed(e.to_string()))?;
        self.check_status(resp).await?;
        Ok(())
    }

    async fn put<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T, WorkspaceError> {
        let url = format!("{}{}", self.server_url, path);
        let resp = self.http.put(&url)
            .bearer_auth(&self.token)
            .json(body)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| WorkspaceError::RequestFailed(e.to_string()))?;
        self.handle_response(resp).await
    }

    async fn delete(&self, path: &str) -> Result<serde_json::Value, WorkspaceError> {
        let url = format!("{}{}", self.server_url, path);
        let resp = self.http.delete(&url)
            .bearer_auth(&self.token)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| WorkspaceError::RequestFailed(e.to_string()))?;
        self.handle_response(resp).await
    }

    async fn check_status(&self, resp: Response) -> Result<(), WorkspaceError> {
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }

        #[derive(Deserialize)]
        struct ErrBody { error: String }
        let msg = resp.json::<ErrBody>()
            .await
            .map(|b| b.error)
            .unwrap_or_else(|_| status.to_string());

        Err(match status.as_u16() {
            401 => WorkspaceError::AuthFailed(msg),
            403 => WorkspaceError::Forbidden(msg),
            404 => WorkspaceError::NotFound(msg),
            _ => WorkspaceError::RequestFailed(msg),
        })
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        resp: Response,
    ) -> Result<T, WorkspaceError> {
        let status = resp.status();
        if status.is_success() {
            return resp.json::<T>()
                .await
                .map_err(|e| WorkspaceError::InvalidResponse(e.to_string()));
        }

        #[derive(Deserialize)]
        struct ErrBody { error: String }
        let msg = resp.json::<ErrBody>()
            .await
            .map(|b| b.error)
            .unwrap_or_else(|_| status.to_string());

        Err(match status.as_u16() {
            401 => WorkspaceError::AuthFailed(msg),
            403 => WorkspaceError::Forbidden(msg),
            404 => WorkspaceError::NotFound(msg),
            _ => WorkspaceError::RequestFailed(msg),
        })
    }
}
