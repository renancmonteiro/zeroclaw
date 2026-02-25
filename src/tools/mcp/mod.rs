pub mod bridge;
pub mod client;
pub mod env_expand;
pub mod oauth;

use crate::config::{McpConfig, McpTransportConfig};
use crate::tools::traits::Tool;
use bridge::McpBridgeTool;
use client::McpClientHandle;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

/// Connect to configured MCP servers and return bridge tools for each discovered tool.
///
/// Returns empty vecs if MCP is disabled or no servers are configured.
/// Logs warnings for servers that fail to connect but does not abort the entire process.
///
/// The second vec contains client handles that must be kept alive for the duration
/// of the agent session (they own the child processes and transport connections).
///
/// `zeroclaw_dir` is the ZeroClaw configuration directory (e.g. `~/.zeroclaw/`),
/// used for loading OAuth tokens for servers with `auth` configured.
pub async fn create_mcp_tools(
    config: &McpConfig,
    zeroclaw_dir: &Path,
) -> (Vec<Box<dyn Tool>>, Vec<Arc<McpClientHandle>>) {
    if !config.enabled || config.servers.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut tools: Vec<Box<dyn Tool>> = Vec::new();
    let mut clients: Vec<Arc<McpClientHandle>> = Vec::new();
    let mut registered_names: HashSet<String> = HashSet::new();

    for (server_key, server_config) in &config.servers {
        if !server_config.enabled {
            tracing::debug!(server = %server_key, "MCP server disabled, skipping");
            continue;
        }

        let prefix = server_config
            .tool_prefix
            .as_deref()
            .unwrap_or(server_key.as_str());

        let connect_timeout = std::time::Duration::from_secs(server_config.connect_timeout_secs);
        let call_timeout = std::time::Duration::from_secs(server_config.call_timeout_secs);

        let client_result = match &server_config.transport {
            McpTransportConfig::Stdio { command, args, env } => {
                let expanded_env = match env_expand::expand_env_map(env) {
                    Ok(e) => e,
                    Err(err) => {
                        tracing::warn!(
                            server = %server_key,
                            "MCP server env expansion failed: {err}, skipping"
                        );
                        continue;
                    }
                };
                McpClientHandle::connect_stdio(
                    server_key,
                    command,
                    args,
                    &expanded_env,
                    connect_timeout,
                )
                .await
            }
            McpTransportConfig::Http { url, headers, auth } => {
                let expanded_url = match env_expand::expand_env_vars(url) {
                    Ok(u) => u,
                    Err(err) => {
                        tracing::warn!(
                            server = %server_key,
                            "MCP server URL expansion failed: {err}, skipping"
                        );
                        continue;
                    }
                };
                let mut expanded_headers = match env_expand::expand_env_map(headers) {
                    Ok(h) => h,
                    Err(err) => {
                        tracing::warn!(
                            server = %server_key,
                            "MCP server header expansion failed: {err}, skipping"
                        );
                        continue;
                    }
                };

                // If OAuth is configured, resolve stored token and inject as Authorization header.
                if auth.is_some() {
                    match oauth::resolve_token(
                        zeroclaw_dir,
                        server_key,
                        &expanded_url,
                        auth.as_ref().unwrap(),
                    )
                    .await
                    {
                        Ok(token) => {
                            expanded_headers
                                .insert("Authorization".to_string(), format!("Bearer {token}"));
                        }
                        Err(err) => {
                            tracing::warn!(
                                server = %server_key,
                                "MCP OAuth token resolution failed: {err}, skipping"
                            );
                            continue;
                        }
                    }
                }

                McpClientHandle::connect_http(
                    server_key,
                    &expanded_url,
                    &expanded_headers,
                    connect_timeout,
                )
                .await
            }
        };

        let client = match client_result {
            Ok(mut c) => {
                c.set_call_timeout(call_timeout);
                Arc::new(c)
            }
            Err(err) => {
                tracing::warn!(
                    server = %server_key,
                    "MCP server connection failed: {err}, skipping"
                );
                continue;
            }
        };

        // Discover tools
        let mcp_tools = match client.list_tools().await {
            Ok(t) => t,
            Err(err) => {
                tracing::warn!(
                    server = %server_key,
                    "MCP tool discovery failed: {err}, skipping"
                );
                continue;
            }
        };

        tracing::info!(
            server = %server_key,
            tool_count = mcp_tools.len(),
            "MCP server tools discovered"
        );

        for mcp_tool in &mcp_tools {
            let input_schema =
                serde_json::to_value(mcp_tool.input_schema.as_ref()).unwrap_or_default();

            let bridge = McpBridgeTool::new(
                prefix,
                &mcp_tool.name,
                mcp_tool.description.as_deref().unwrap_or(""),
                input_schema,
                client.clone(),
            );

            let name = bridge.name().to_string();
            if registered_names.contains(&name) {
                tracing::warn!(
                    tool = %name,
                    server = %server_key,
                    "MCP tool name collision, skipping duplicate"
                );
                continue;
            }
            registered_names.insert(name);
            tools.push(Box::new(bridge));
        }

        clients.push(client);
    }

    (tools, clients)
}
