use super::client::McpClientHandle;
use crate::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use std::sync::Arc;

/// A ZeroClaw Tool that bridges to a single tool on a remote MCP server.
///
/// Each MCP server tool becomes one `McpBridgeTool` instance in the registry.
pub struct McpBridgeTool {
    /// Fully qualified tool name: `mcp_{prefix}__{original_name}`
    tool_name: String,
    /// Original MCP tool name (used in call_tool RPC)
    mcp_tool_name: String,
    /// Tool description from MCP server
    tool_description: String,
    /// JSON Schema for parameters from MCP server
    input_schema: serde_json::Value,
    /// Shared handle to the MCP client connection
    client: Arc<McpClientHandle>,
}

impl McpBridgeTool {
    pub fn new(
        prefix: &str,
        mcp_tool_name: &str,
        description: &str,
        input_schema: serde_json::Value,
        client: Arc<McpClientHandle>,
    ) -> Self {
        let safe_prefix = sanitize_tool_name_part(prefix);
        let safe_name = sanitize_tool_name_part(mcp_tool_name);
        Self {
            tool_name: format!("mcp_{safe_prefix}__{safe_name}"),
            mcp_tool_name: mcp_tool_name.to_string(),
            tool_description: description.to_string(),
            input_schema,
            client,
        }
    }
}

/// Replace characters that are not alphanumeric or underscore with underscore.
fn sanitize_tool_name_part(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[async_trait]
impl Tool for McpBridgeTool {
    fn name(&self) -> &str {
        &self.tool_name
    }

    fn description(&self) -> &str {
        &self.tool_description
    }

    fn parameters_schema(&self) -> serde_json::Value {
        self.input_schema.clone()
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let arguments = match args {
            serde_json::Value::Object(map) => Some(map),
            _ => None,
        };

        match self.client.call_tool(&self.mcp_tool_name, arguments).await {
            Ok(result) => {
                let is_error = result.is_error.unwrap_or(false);
                let output = convert_mcp_content(&result.content);

                Ok(ToolResult {
                    success: !is_error,
                    output: output.clone(),
                    error: if is_error { Some(output) } else { None },
                })
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("MCP call failed: {e}")),
            }),
        }
    }
}

/// Convert MCP Content items to a single string for ToolResult.output.
///
/// Text content is concatenated directly. Image/audio content is represented as
/// metadata markers since ToolResult only supports string output.
fn convert_mcp_content(content: &[rmcp::model::Content]) -> String {
    use rmcp::model::RawContent;
    use std::fmt::Write;

    let mut output = String::new();
    for item in content {
        match &**item {
            RawContent::Text(t) => {
                if !output.is_empty() {
                    output.push('\n');
                }
                output.push_str(&t.text);
            }
            RawContent::Image(img) => {
                let _ = write!(
                    output,
                    "\n[Image: {} ({} bytes base64)]",
                    img.mime_type,
                    img.data.len()
                );
            }
            RawContent::Audio(audio) => {
                let _ = write!(
                    output,
                    "\n[Audio: {} ({} bytes base64)]",
                    audio.mime_type,
                    audio.data.len()
                );
            }
            RawContent::Resource(res) => match &res.resource {
                rmcp::model::ResourceContents::TextResourceContents { text, .. } => {
                    if !output.is_empty() {
                        output.push('\n');
                    }
                    output.push_str(text);
                }
                rmcp::model::ResourceContents::BlobResourceContents { uri, blob, .. } => {
                    let _ = write!(
                        output,
                        "\n[Embedded blob resource: {} ({} bytes)]",
                        uri,
                        blob.len()
                    );
                }
            },
            RawContent::ResourceLink(link) => {
                let _ = write!(output, "\n[Resource: {}]", link.uri);
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_tool_name_replaces_special_chars() {
        assert_eq!(sanitize_tool_name_part("my-tool"), "my_tool");
        assert_eq!(sanitize_tool_name_part("tool.name"), "tool_name");
        assert_eq!(sanitize_tool_name_part("simple"), "simple");
        assert_eq!(sanitize_tool_name_part("a-b.c/d"), "a_b_c_d");
    }

    #[test]
    fn tool_name_format() {
        // Verify the naming convention without needing a real client
        let safe_prefix = sanitize_tool_name_part("github");
        let safe_name = sanitize_tool_name_part("get-issues");
        let expected = format!("mcp_{safe_prefix}__{safe_name}");
        assert_eq!(expected, "mcp_github__get_issues");
    }
}
