use anyhow::Context;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{Peer, RunningService};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{StreamableHttpClientTransport, TokioChildProcess};
use rmcp::{RoleClient, ServiceExt};
use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

/// Handle to a connected MCP server. Manages lifecycle and provides tool operations.
///
/// The `Peer` is used for all protocol operations (list tools, call tools).
/// The `RunningService` keeps the background task alive and is dropped on handle drop.
pub struct McpClientHandle {
    server_name: String,
    peer: Peer<RoleClient>,
    /// Kept alive to own the background service task + child process.
    _service: RunningService<RoleClient, ()>,
    call_timeout: Duration,
}

// Safety: Peer<RoleClient> is Clone + Send + Sync. RunningService is Send.
// We never share &mut RunningService across threads.
unsafe impl Sync for McpClientHandle {}

impl McpClientHandle {
    /// Connect to an MCP server via stdio transport (spawns child process).
    pub async fn connect_stdio(
        server_name: &str,
        command: &str,
        args: &[String],
        env: &HashMap<String, String>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Self> {
        let mut cmd = tokio::process::Command::new(command);
        cmd.args(args);
        for (k, v) in env {
            cmd.env(k, v);
        }

        let transport = TokioChildProcess::new(cmd)
            .with_context(|| format!("Failed to spawn MCP server '{server_name}'"))?;

        let service: RunningService<RoleClient, ()> =
            tokio::time::timeout(connect_timeout, ().serve(transport))
                .await
                .with_context(|| {
                    format!("MCP server '{server_name}' connection timed out ({connect_timeout:?})")
                })?
                .map_err(|e| anyhow::anyhow!("MCP server '{server_name}' handshake failed: {e}"))?;

        let peer = service.peer().clone();

        tracing::info!(server = server_name, "MCP server connected (stdio)");

        Ok(Self {
            server_name: server_name.to_string(),
            peer,
            _service: service,
            call_timeout: Duration::from_secs(120),
        })
    }

    /// Connect to an MCP server via streamable HTTP transport.
    pub async fn connect_http(
        server_name: &str,
        url: &str,
        headers: &HashMap<String, String>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Self> {
        let mut custom_headers = HashMap::new();
        let mut auth_header: Option<String> = None;

        for (k, v) in headers {
            let lower = k.to_ascii_lowercase();
            if lower == "authorization" {
                // Strip "Bearer " prefix if present — rmcp adds it via .bearer_auth().
                let token = v
                    .strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("bearer "))
                    .unwrap_or(v);
                auth_header = Some(token.to_string());
            } else {
                let name = reqwest::header::HeaderName::from_bytes(k.as_bytes()).with_context(|| {
                    format!("Invalid HTTP header name '{k}' for MCP server '{server_name}'")
                })?;
                let value = reqwest::header::HeaderValue::from_str(v).with_context(|| {
                    format!("Invalid HTTP header value for '{k}' on MCP server '{server_name}'")
                })?;
                custom_headers.insert(name, value);
            }
        }

        let mut config = StreamableHttpClientTransportConfig::with_uri(url);
        if let Some(token) = auth_header {
            config = config.auth_header(token);
        }
        if !custom_headers.is_empty() {
            config = config.custom_headers(custom_headers);
        }

        let transport =
            StreamableHttpClientTransport::<reqwest::Client>::from_config(config);

        let service: RunningService<RoleClient, ()> =
            tokio::time::timeout(connect_timeout, ().serve(transport))
                .await
                .with_context(|| {
                    format!(
                        "MCP server '{server_name}' HTTP connection timed out ({connect_timeout:?})"
                    )
                })?
                .map_err(|e| {
                    anyhow::anyhow!("MCP server '{server_name}' HTTP handshake failed: {e}")
                })?;

        let peer = service.peer().clone();

        tracing::info!(server = server_name, "MCP server connected (http)");

        Ok(Self {
            server_name: server_name.to_string(),
            peer,
            _service: service,
            call_timeout: Duration::from_secs(120),
        })
    }

    pub fn set_call_timeout(&mut self, timeout: Duration) {
        self.call_timeout = timeout;
    }

    /// Discover all tools exposed by this MCP server.
    pub async fn list_tools(&self) -> anyhow::Result<Vec<rmcp::model::Tool>> {
        self.peer
            .list_all_tools()
            .await
            .map_err(|e| anyhow::anyhow!("Tool discovery failed on '{}': {e}", self.server_name))
    }

    /// Call a tool by its original MCP name.
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> anyhow::Result<CallToolResult> {
        let params = CallToolRequestParams {
            name: Cow::Owned(name.to_string()),
            arguments: arguments.map(|m| m.into_iter().collect()),
            meta: None,
            task: None,
        };

        let result = tokio::time::timeout(self.call_timeout, self.peer.call_tool(params))
            .await
            .with_context(|| {
                format!(
                    "MCP tool call '{name}' timed out on '{}' ({:?})",
                    self.server_name, self.call_timeout
                )
            })?
            .map_err(|e| {
                anyhow::anyhow!(
                    "MCP tool call '{name}' failed on '{}': {e}",
                    self.server_name
                )
            })?;

        Ok(result)
    }
}
