// MCP OAuth 2.1 — token acquisition, storage, and refresh for OAuth-protected MCP servers.
//
// Implements the MCP authorization spec (2025-03-26 draft):
//   1. Protected Resource Metadata discovery (RFC 9728)
//   2. Authorization Server Metadata discovery (RFC 8414)
//   3. Dynamic Client Registration (RFC 7591)
//   4. Authorization Code + PKCE (S256)
//   5. Token refresh
//
// Tokens are stored encrypted per-server in `~/.zeroclaw/mcp_tokens/`.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use crate::config::schema::McpAuthConfig;

// ── Discovery types ────────────────────────────────────────────

/// Authorization server metadata (subset of RFC 8414 fields we need).
#[derive(Debug, Clone, Deserialize)]
pub struct AuthServerMetadata {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

/// Protected resource metadata (RFC 9728).
#[derive(Debug, Deserialize)]
struct ProtectedResourceMetadata {
    #[serde(default)]
    authorization_servers: Vec<String>,
}

// ── Token storage types ────────────────────────────────────────

/// Persisted token set for a single MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTokens {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Unix timestamp (seconds) when the access token expires.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Token endpoint URL for refresh.
    #[serde(default)]
    pub token_endpoint: Option<String>,
    /// Client ID used to obtain these tokens.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Client secret (if confidential client).
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// OAuth token response from the authorization server.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    token_type: Option<String>,
}

/// Dynamic Client Registration response.
#[derive(Debug, Deserialize)]
pub struct RegistrationResponse {
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
}

// ── PKCE helpers ───────────────────────────────────────────────

/// Generate a random code_verifier (43–128 chars, URL-safe base64).
fn generate_code_verifier() -> String {
    let mut buf = [0u8; 32];
    rand::rng().fill(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Compute S256 code_challenge from a code_verifier.
fn compute_code_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

// ── Discovery ──────────────────────────────────────────────────

/// Discover the authorization server metadata for an MCP server URL.
///
/// Attempts (in order):
/// 1. Use explicit `authorization_server` from config if provided.
/// 2. Probe the MCP server (unauthenticated GET) for a 401 with
///    `WWW-Authenticate: Bearer resource_metadata="..."` header.
/// 3. Probe `.well-known/oauth-protected-resource` on the MCP server origin.
/// 4. Fetch authorization server metadata from `.well-known/oauth-authorization-server`.
pub async fn discover_auth_server(
    mcp_url: &str,
    auth_config: &McpAuthConfig,
) -> Result<AuthServerMetadata> {
    let client = reqwest::Client::new();

    let issuer_url: String = if let Some(ref explicit) = auth_config.authorization_server {
        explicit.clone()
    } else {
        discover_issuer(&client, mcp_url).await?
    };

    fetch_auth_server_metadata(&client, &issuer_url).await
}

/// Discover the authorization server issuer URL from the MCP server.
async fn discover_issuer(client: &reqwest::Client, mcp_url: &str) -> Result<String> {
    // Try probing the MCP endpoint for a 401 with resource_metadata hint.
    if let Ok(resp) = client.get(mcp_url).send().await {
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            if let Some(www_auth) = resp.headers().get("www-authenticate") {
                if let Ok(val) = www_auth.to_str() {
                    if let Some(rm_url) = extract_resource_metadata(val) {
                        if let Ok(prm) = client
                            .get(&rm_url)
                            .send()
                            .await
                            .and_then(|r| r.error_for_status())
                        {
                            if let Ok(meta) = prm.json::<ProtectedResourceMetadata>().await {
                                if let Some(issuer) = meta.authorization_servers.into_iter().next()
                                {
                                    return Ok(issuer);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: probe .well-known/oauth-protected-resource on the MCP origin.
    let parsed =
        reqwest::Url::parse(mcp_url).with_context(|| format!("Invalid MCP URL: {mcp_url}"))?;
    let origin = format!("{}://{}", parsed.scheme(), parsed.authority());
    let well_known = format!("{origin}/.well-known/oauth-protected-resource");

    let resp = client
        .get(&well_known)
        .send()
        .await
        .with_context(|| format!("Failed to fetch {well_known}"))?
        .error_for_status()
        .with_context(|| format!("Protected resource metadata not found at {well_known}"))?;

    let meta: ProtectedResourceMetadata = resp
        .json()
        .await
        .context("Invalid protected resource metadata JSON")?;

    meta.authorization_servers
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No authorization_servers in protected resource metadata"))
}

/// Extract `resource_metadata="URL"` from a WWW-Authenticate header value.
fn extract_resource_metadata(header: &str) -> Option<String> {
    let key = "resource_metadata=\"";
    let start = header.find(key)? + key.len();
    let end = header[start..].find('"')? + start;
    Some(header[start..end].to_string())
}

/// Fetch authorization server metadata from a well-known endpoint.
async fn fetch_auth_server_metadata(
    client: &reqwest::Client,
    issuer_url: &str,
) -> Result<AuthServerMetadata> {
    let parsed = reqwest::Url::parse(issuer_url)
        .with_context(|| format!("Invalid issuer URL: {issuer_url}"))?;

    // Try multiple well-known paths per RFC 8414.
    let candidates = if parsed.path() != "/" && !parsed.path().is_empty() {
        let origin = format!("{}://{}", parsed.scheme(), parsed.authority());
        let path = parsed.path().trim_end_matches('/');
        vec![
            format!("{origin}/.well-known/oauth-authorization-server{path}"),
            format!("{origin}/.well-known/openid-configuration{path}"),
            format!("{issuer_url}/.well-known/openid-configuration"),
        ]
    } else {
        let base = issuer_url.trim_end_matches('/');
        vec![
            format!("{base}/.well-known/oauth-authorization-server"),
            format!("{base}/.well-known/openid-configuration"),
        ]
    };

    for url in &candidates {
        if let Ok(resp) = client.get(url).send().await {
            if resp.status().is_success() {
                if let Ok(meta) = resp.json::<AuthServerMetadata>().await {
                    return Ok(meta);
                }
            }
        }
    }

    bail!(
        "Could not fetch authorization server metadata from issuer: {issuer_url}. \
         Tried well-known endpoints but none returned valid metadata."
    )
}

// ── Dynamic Client Registration ────────────────────────────────

/// Register this client via RFC 7591 Dynamic Client Registration.
pub async fn register_client(
    registration_endpoint: &str,
    redirect_uri: &str,
) -> Result<RegistrationResponse> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "client_name": "ZeroClaw Agent Runtime",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    });

    let resp = client
        .post(registration_endpoint)
        .json(&body)
        .send()
        .await
        .context("Dynamic client registration request failed")?
        .error_for_status()
        .context("Dynamic client registration rejected")?;

    resp.json::<RegistrationResponse>()
        .await
        .context("Invalid registration response")
}

// ── Authorization Code + PKCE flow ─────────────────────────────

/// Run the full interactive OAuth authorization flow.
///
/// 1. Starts a local callback server.
/// 2. Prints the authorization URL for the user to open.
/// 3. Waits for the callback with the authorization code.
/// 4. Exchanges the code for tokens.
/// 5. Returns the token set.
pub async fn authorize(
    server_name: &str,
    mcp_url: &str,
    auth_config: &McpAuthConfig,
    meta: &AuthServerMetadata,
) -> Result<StoredTokens> {
    let callback_port = auth_config.callback_port.unwrap_or(0);
    let listener = TcpListener::bind(format!("127.0.0.1:{callback_port}"))
        .await
        .context("Failed to bind local OAuth callback listener")?;
    let actual_port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{actual_port}/callback");

    // Resolve client_id — use config, or register dynamically.
    let (client_id, client_secret) = if let Some(ref cid) = auth_config.client_id {
        (cid.clone(), auth_config.client_secret.clone())
    } else if let Some(ref reg_endpoint) = meta.registration_endpoint {
        tracing::info!(server = server_name, "Registering client via DCR");
        let reg = register_client(reg_endpoint, &redirect_uri).await?;
        (reg.client_id, reg.client_secret)
    } else {
        bail!(
            "MCP server '{server_name}' requires OAuth but no client_id is configured \
             and the authorization server does not support Dynamic Client Registration. \
             Set `auth.client_id` in the MCP server config."
        );
    };

    // PKCE
    let code_verifier = generate_code_verifier();
    let code_challenge = compute_code_challenge(&code_verifier);

    // State parameter (CSRF protection)
    let mut state_buf = [0u8; 16];
    rand::rng().fill(&mut state_buf);
    let state = URL_SAFE_NO_PAD.encode(state_buf);

    // Build scopes
    let scopes = if auth_config.scopes.is_empty() {
        meta.scopes_supported.join(" ")
    } else {
        auth_config.scopes.join(" ")
    };

    // Build authorization URL
    let mut auth_url = reqwest::Url::parse(&meta.authorization_endpoint)
        .context("Invalid authorization_endpoint URL")?;
    {
        let mut q = auth_url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", &client_id);
        q.append_pair("redirect_uri", &redirect_uri);
        q.append_pair("code_challenge", &code_challenge);
        q.append_pair("code_challenge_method", "S256");
        q.append_pair("state", &state);
        q.append_pair("resource", mcp_url);
        if !scopes.is_empty() {
            q.append_pair("scope", &scopes);
        }
    }

    println!();
    println!("=== MCP OAuth Authorization for '{server_name}' ===");
    println!();
    println!("Open this URL in your browser to authorize:");
    println!();
    println!("  {auth_url}");
    println!();
    println!("Waiting for callback on http://127.0.0.1:{actual_port}/callback ...");

    // Wait for the OAuth callback (with 5 minute timeout).
    let code = wait_for_callback(&listener, &state).await?;

    println!("Authorization code received. Exchanging for tokens...");

    // Exchange code for tokens.
    let http = reqwest::Client::new();
    let mut form: HashMap<String, String> = HashMap::new();
    form.insert("grant_type".into(), "authorization_code".into());
    form.insert("code".into(), code);
    form.insert("redirect_uri".into(), redirect_uri);
    form.insert("client_id".into(), client_id.clone());
    form.insert("code_verifier".into(), code_verifier);
    form.insert("resource".into(), mcp_url.to_string());
    if let Some(ref secret) = client_secret {
        form.insert("client_secret".into(), secret.clone());
    }

    let resp = http
        .post(&meta.token_endpoint)
        .form(&form)
        .send()
        .await
        .context("Token exchange request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("Token exchange failed (HTTP {status}): {body}");
    }

    let token_resp: TokenResponse = resp.json().await.context("Invalid token response")?;

    let expires_at = token_resp.expires_in.map(|secs| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + secs
    });

    if let Some(ref tt) = token_resp.token_type {
        if !tt.eq_ignore_ascii_case("bearer") {
            tracing::warn!(
                server = server_name,
                token_type = %tt,
                "Unexpected token_type (expected Bearer)"
            );
        }
    }

    Ok(StoredTokens {
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token,
        expires_at,
        token_endpoint: Some(meta.token_endpoint.clone()),
        client_id: Some(client_id),
        client_secret,
    })
}

/// Wait for the OAuth redirect callback on the local listener.
///
/// Parses `?code=...&state=...` from the request, validates state, and returns the code.
async fn wait_for_callback(listener: &TcpListener, expected_state: &str) -> Result<String> {
    let timeout = std::time::Duration::from_secs(300);

    let (mut stream, _) = tokio::time::timeout(timeout, listener.accept())
        .await
        .context("OAuth callback timed out (5 minutes). Please try again.")?
        .context("Failed to accept callback connection")?;

    // Read the HTTP request line.
    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
        .await
        .context("Failed to read callback request")?;
    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse the request line: GET /callback?code=...&state=... HTTP/1.1
    let request_line = request.lines().next().unwrap_or("");
    let path = request_line.split_whitespace().nth(1).unwrap_or("");

    // Send a response before parsing (so the browser gets feedback).
    let response_body = "<html><body><h2>Authorization complete!</h2>\
                         <p>You can close this tab and return to ZeroClaw.</p></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    );
    let _ = stream.write_all(response.as_bytes()).await;

    // Parse query parameters.
    let dummy_base = format!("http://127.0.0.1{path}");
    let parsed = reqwest::Url::parse(&dummy_base)
        .with_context(|| format!("Failed to parse callback URL: {path}"))?;

    let params: HashMap<String, String> = parsed.query_pairs().into_owned().collect();

    // Check for error response.
    if let Some(error) = params.get("error") {
        let desc = params
            .get("error_description")
            .map(|d| format!(": {d}"))
            .unwrap_or_default();
        bail!("OAuth authorization denied: {error}{desc}");
    }

    let code = params
        .get("code")
        .ok_or_else(|| anyhow::anyhow!("No 'code' parameter in OAuth callback"))?;

    let state = params
        .get("state")
        .ok_or_else(|| anyhow::anyhow!("No 'state' parameter in OAuth callback"))?;

    if state != expected_state {
        bail!("OAuth state mismatch (possible CSRF). Expected: {expected_state}, got: {state}");
    }

    Ok(code.clone())
}

// ── Token refresh ──────────────────────────────────────────────

/// Refresh an access token using a stored refresh token.
pub async fn refresh_access_token(stored: &StoredTokens) -> Result<StoredTokens> {
    let refresh_token = stored
        .refresh_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No refresh token available"))?;
    let token_endpoint = stored
        .token_endpoint
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No token endpoint stored"))?;
    let client_id = stored
        .client_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No client_id stored"))?;

    let http = reqwest::Client::new();
    let mut form: HashMap<String, String> = HashMap::new();
    form.insert("grant_type".into(), "refresh_token".into());
    form.insert("refresh_token".into(), refresh_token.clone());
    form.insert("client_id".into(), client_id.clone());
    if let Some(ref secret) = stored.client_secret {
        form.insert("client_secret".into(), secret.clone());
    }

    let resp = http
        .post(token_endpoint)
        .form(&form)
        .send()
        .await
        .context("Token refresh request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("Token refresh failed (HTTP {status}): {body}");
    }

    let token_resp: TokenResponse = resp.json().await.context("Invalid refresh response")?;

    let expires_at = token_resp.expires_in.map(|secs| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + secs
    });

    Ok(StoredTokens {
        access_token: token_resp.access_token,
        // OAuth 2.1: refresh token rotation — use new one if provided, else keep old.
        refresh_token: token_resp
            .refresh_token
            .or_else(|| stored.refresh_token.clone()),
        expires_at,
        token_endpoint: stored.token_endpoint.clone(),
        client_id: stored.client_id.clone(),
        client_secret: stored.client_secret.clone(),
    })
}

// ── Token storage ──────────────────────────────────────────────

/// Directory for MCP OAuth token files.
fn token_dir(zeroclaw_dir: &Path) -> PathBuf {
    zeroclaw_dir.join("mcp_tokens")
}

/// Path for a specific server's token file.
fn token_path(zeroclaw_dir: &Path, server_key: &str) -> PathBuf {
    // Sanitize server key for filesystem safety.
    let safe_key: String = server_key
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    token_dir(zeroclaw_dir).join(format!("{safe_key}.json"))
}

/// Save tokens to disk (plaintext JSON with restrictive permissions).
pub async fn save_tokens(
    zeroclaw_dir: &Path,
    server_key: &str,
    tokens: &StoredTokens,
) -> Result<()> {
    let dir = token_dir(zeroclaw_dir);
    tokio::fs::create_dir_all(&dir)
        .await
        .context("Failed to create mcp_tokens directory")?;

    let path = token_path(zeroclaw_dir, server_key);
    let json = serde_json::to_string_pretty(tokens).context("Failed to serialize tokens")?;
    tokio::fs::write(&path, json.as_bytes())
        .await
        .context("Failed to write token file")?;

    // Restrict file permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .await
            .context("Failed to set token file permissions")?;
    }

    tracing::debug!(server = server_key, path = %path.display(), "MCP OAuth tokens saved");
    Ok(())
}

/// Load tokens from disk for a server.
pub async fn load_tokens(zeroclaw_dir: &Path, server_key: &str) -> Result<Option<StoredTokens>> {
    let path = token_path(zeroclaw_dir, server_key);
    if !path.exists() {
        return Ok(None);
    }
    let json = tokio::fs::read_to_string(&path)
        .await
        .context("Failed to read token file")?;
    let tokens: StoredTokens = serde_json::from_str(&json).context("Failed to parse token file")?;
    Ok(Some(tokens))
}

// ── Token resolution (called at MCP connect time) ──────────────

/// Resolve a valid access token for an MCP server.
///
/// Loads stored tokens, refreshes if expired, returns the access token string.
/// Returns an error if no tokens are stored or refresh fails (user must re-run `mcp auth`).
pub async fn resolve_token(
    zeroclaw_dir: &Path,
    server_key: &str,
    _mcp_url: &str,
    _auth_config: &McpAuthConfig,
) -> Result<String> {
    let stored = load_tokens(zeroclaw_dir, server_key)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No OAuth tokens for MCP server '{server_key}'. \
                 Run `zeroclaw mcp auth {server_key}` to authorize."
            )
        })?;

    // Check if token is expired (with 60s buffer).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let is_expired = stored
        .expires_at
        .map(|exp| now + 60 >= exp)
        .unwrap_or(false);

    if is_expired && stored.refresh_token.is_some() {
        tracing::info!(server = server_key, "MCP OAuth token expired, refreshing");
        match refresh_access_token(&stored).await {
            Ok(refreshed) => {
                save_tokens(zeroclaw_dir, server_key, &refreshed).await?;
                return Ok(refreshed.access_token);
            }
            Err(err) => {
                tracing::warn!(
                    server = server_key,
                    "Token refresh failed: {err}. Run `zeroclaw mcp auth {server_key}` to re-authorize."
                );
                bail!(
                    "OAuth token expired and refresh failed for '{server_key}': {err}. \
                     Run `zeroclaw mcp auth {server_key}` to re-authorize."
                );
            }
        }
    } else if is_expired {
        bail!(
            "OAuth token expired for '{server_key}' and no refresh token available. \
             Run `zeroclaw mcp auth {server_key}` to re-authorize."
        );
    }

    Ok(stored.access_token)
}

// ── Token status (for CLI) ─────────────────────────────────────

/// Token status summary for display.
pub struct TokenStatus {
    pub server_key: String,
    pub has_token: bool,
    pub expired: bool,
    pub has_refresh: bool,
    pub expires_at: Option<u64>,
}

/// Get token status for all OAuth-configured MCP servers.
#[allow(clippy::implicit_hasher)]
pub async fn get_all_token_status(
    zeroclaw_dir: &Path,
    servers: &HashMap<String, crate::config::McpServerConfig>,
) -> Vec<TokenStatus> {
    let mut statuses = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for (key, server_config) in servers {
        if let crate::config::McpTransportConfig::Http { auth: Some(_), .. } =
            &server_config.transport
        {
            let tokens = load_tokens(zeroclaw_dir, key).await.ok().flatten();
            let status = match tokens {
                Some(t) => TokenStatus {
                    server_key: key.clone(),
                    has_token: true,
                    expired: t.expires_at.map(|exp| now >= exp).unwrap_or(false),
                    has_refresh: t.refresh_token.is_some(),
                    expires_at: t.expires_at,
                },
                None => TokenStatus {
                    server_key: key.clone(),
                    has_token: false,
                    expired: false,
                    has_refresh: false,
                    expires_at: None,
                },
            };
            statuses.push(status);
        }
    }
    statuses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_verifier_length() {
        let v = generate_code_verifier();
        assert!(v.len() >= 43, "verifier too short: {}", v.len());
        assert!(v.len() <= 128, "verifier too long: {}", v.len());
    }

    #[test]
    fn pkce_challenge_is_s256() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = compute_code_challenge(verifier);
        // Known SHA-256 of this verifier (RFC 7636 appendix B).
        let expected_hash = Sha256::digest(verifier.as_bytes());
        let expected = URL_SAFE_NO_PAD.encode(expected_hash);
        assert_eq!(challenge, expected);
    }

    #[test]
    fn pkce_verifier_uniqueness() {
        let a = generate_code_verifier();
        let b = generate_code_verifier();
        assert_ne!(a, b, "Two verifiers should differ");
    }

    #[test]
    fn extract_resource_metadata_parses_header() {
        let header = r#"Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="files:read""#;
        let result = extract_resource_metadata(header);
        assert_eq!(
            result,
            Some("https://mcp.example.com/.well-known/oauth-protected-resource".to_string())
        );
    }

    #[test]
    fn extract_resource_metadata_returns_none_on_missing() {
        let header = "Bearer realm=\"example\"";
        assert!(extract_resource_metadata(header).is_none());
    }

    #[test]
    fn token_path_sanitizes_key() {
        let dir = Path::new("/tmp/zeroclaw");
        let path = token_path(dir, "my.server/with:chars");
        assert!(path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("my_server_with_chars"));
    }

    #[tokio::test]
    async fn save_and_load_tokens_roundtrip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let tokens = StoredTokens {
            access_token: "at_test".to_string(),
            refresh_token: Some("rt_test".to_string()),
            expires_at: Some(9_999_999_999),
            token_endpoint: Some("https://auth.example.com/token".to_string()),
            client_id: Some("cid".to_string()),
            client_secret: None,
        };

        save_tokens(tmp.path(), "test_server", &tokens)
            .await
            .unwrap();
        let loaded = load_tokens(tmp.path(), "test_server")
            .await
            .unwrap()
            .expect("should find tokens");

        assert_eq!(loaded.access_token, "at_test");
        assert_eq!(loaded.refresh_token.as_deref(), Some("rt_test"));
        assert_eq!(loaded.expires_at, Some(9_999_999_999));
    }

    #[tokio::test]
    async fn load_tokens_returns_none_when_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let result = load_tokens(tmp.path(), "nonexistent").await.unwrap();
        assert!(result.is_none());
    }
}
