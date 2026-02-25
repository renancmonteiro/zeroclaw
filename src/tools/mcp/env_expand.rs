use anyhow::Context;
use std::collections::HashMap;

/// Expand `${VAR_NAME}` references in a string using the process environment.
///
/// Returns an error if a referenced variable is not set.
pub fn expand_env_vars(input: &str) -> anyhow::Result<String> {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let var_name: String = chars.by_ref().take_while(|&ch| ch != '}').collect();
            if var_name.is_empty() {
                anyhow::bail!("Empty environment variable reference: ${{}}");
            }
            let value = std::env::var(&var_name).with_context(|| {
                format!("MCP config references undefined env var: ${{{var_name}}}")
            })?;
            result.push_str(&value);
        } else {
            result.push(c);
        }
    }

    Ok(result)
}

/// Expand `${VAR}` references in all values of a HashMap.
#[allow(clippy::implicit_hasher)]
pub fn expand_env_map(map: &HashMap<String, String>) -> anyhow::Result<HashMap<String, String>> {
    map.iter()
        .map(|(k, v)| Ok((k.clone(), expand_env_vars(v)?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_passes_through() {
        let result = expand_env_vars("hello world").unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn expands_set_var() {
        std::env::set_var("ZEROCLAW_TEST_MCP_VAR", "secret_value");
        let result = expand_env_vars("Bearer ${ZEROCLAW_TEST_MCP_VAR}").unwrap();
        assert_eq!(result, "Bearer secret_value");
        std::env::remove_var("ZEROCLAW_TEST_MCP_VAR");
    }

    #[test]
    fn errors_on_unset_var() {
        let result = expand_env_vars("${ZEROCLAW_DEFINITELY_NOT_SET_12345}");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("ZEROCLAW_DEFINITELY_NOT_SET_12345"));
    }

    #[test]
    fn errors_on_empty_ref() {
        let result = expand_env_vars("before ${}");
        assert!(result.is_err());
    }

    #[test]
    fn dollar_without_brace_passes_through() {
        let result = expand_env_vars("cost is $5").unwrap();
        assert_eq!(result, "cost is $5");
    }

    #[test]
    fn multiple_vars() {
        std::env::set_var("ZEROCLAW_TEST_A", "foo");
        std::env::set_var("ZEROCLAW_TEST_B", "bar");
        let result = expand_env_vars("${ZEROCLAW_TEST_A}:${ZEROCLAW_TEST_B}").unwrap();
        assert_eq!(result, "foo:bar");
        std::env::remove_var("ZEROCLAW_TEST_A");
        std::env::remove_var("ZEROCLAW_TEST_B");
    }

    #[test]
    fn expand_map_works() {
        std::env::set_var("ZEROCLAW_TEST_MAP", "val");
        let mut map = HashMap::new();
        map.insert("key".to_string(), "${ZEROCLAW_TEST_MAP}".to_string());
        map.insert("plain".to_string(), "no_expansion".to_string());
        let result = expand_env_map(&map).unwrap();
        assert_eq!(result["key"], "val");
        assert_eq!(result["plain"], "no_expansion");
        std::env::remove_var("ZEROCLAW_TEST_MAP");
    }
}
