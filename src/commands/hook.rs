use std::io::Read;

use crate::cli::HookFormat;
use crate::config::Config;
use crate::error::S2Error;

// --- Input (shared across formats) ---

#[derive(serde::Deserialize)]
struct HookInput {
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    tool_input: Option<ToolInput>,
}

#[derive(serde::Deserialize)]
struct ToolInput {
    command: Option<String>,
}

// --- Output: Claude / Copilot ---

#[derive(serde::Serialize)]
struct ClaudeOutput {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: ClaudeHookSpecific,
}

#[derive(serde::Serialize)]
struct ClaudeHookSpecific {
    #[serde(rename = "updatedInput")]
    updated_input: CommandUpdate,
}

// --- Output: Cursor ---

#[derive(serde::Serialize)]
struct CursorOutput {
    permission: String,
    updated_input: CommandUpdate,
}

// --- Shared ---

#[derive(serde::Serialize)]
struct CommandUpdate {
    command: String,
}

pub fn run(config: &Config, format: &HookFormat) -> Result<(), S2Error> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    let hook_input: HookInput = match serde_json::from_str(&input) {
        Ok(h) => h,
        Err(_) => return passthrough(format),
    };

    // Guard: only Bash tool (tool_name may be absent in some formats)
    if let Some(ref name) = hook_input.tool_name {
        if name != "Bash" {
            return passthrough(format);
        }
    }

    let command = match hook_input.tool_input.and_then(|t| t.command) {
        Some(c) if !c.is_empty() => c,
        _ => return passthrough(format),
    };

    if starts_with_s2(&command) || command.contains("s2 exec") {
        return passthrough(format);
    }

    let root_cmd = extract_root_command(&command);

    if !config.hook.should_wrap(&root_cmd) {
        return passthrough(format);
    }

    let exec_args = match config.hook.exec_args(&config.default_files) {
        Some(args) => args,
        None => return passthrough(format),
    };

    let wrapped = build_wrapped_command(&command, &exec_args);
    emit_rewrite(format, wrapped);
    Ok(())
}

/// Passthrough: no rewrite. Claude/Copilot = no output. Cursor = `{}`.
fn passthrough(format: &HookFormat) -> Result<(), S2Error> {
    match format {
        HookFormat::Cursor => println!("{{}}"),
        HookFormat::Claude | HookFormat::Copilot => {}
    }
    Ok(())
}

/// Emit a rewrite in the agent's expected JSON format.
fn emit_rewrite(format: &HookFormat, command: String) {
    let json = match format {
        HookFormat::Claude | HookFormat::Copilot => serde_json::to_string(&ClaudeOutput {
            hook_specific_output: ClaudeHookSpecific {
                updated_input: CommandUpdate { command },
            },
        })
        .unwrap(),
        HookFormat::Cursor => serde_json::to_string(&CursorOutput {
            permission: "allow".to_string(),
            updated_input: CommandUpdate { command },
        })
        .unwrap(),
    };
    println!("{}", json);
}

fn starts_with_s2(cmd: &str) -> bool {
    let trimmed = cmd.trim_start();
    trimmed == "s2" || trimmed.starts_with("s2 ") || trimmed.starts_with("s2\t")
}

fn extract_root_command(cmd: &str) -> String {
    let trimmed = cmd.trim_start();
    let mut rest = trimmed;
    loop {
        let token = match rest.split_whitespace().next() {
            Some(t) => t,
            None => return String::new(),
        };
        if token.contains('=') && !token.starts_with('=') {
            rest = rest[rest.find(token).unwrap() + token.len()..].trim_start();
            continue;
        }
        return token.to_string();
    }
}

fn is_complex_command(cmd: &str) -> bool {
    cmd.contains('|')
        || cmd.contains("&&")
        || cmd.contains("||")
        || cmd.contains(';')
        || cmd.contains('(')
        || cmd.contains(')')
        || cmd.contains('>')
        || cmd.contains('<')
        || cmd.contains('`')
        || cmd.contains("$(")
}

fn build_wrapped_command(original: &str, exec_args: &[String]) -> String {
    let mut parts = vec!["s2".to_string(), "exec".to_string()];
    parts.extend_from_slice(exec_args);
    parts.push("--".to_string());

    if is_complex_command(original) {
        let escaped = original.replace('\'', "'\\''");
        parts.push("bash".to_string());
        parts.push("-c".to_string());
        parts.push(format!("'{}'", escaped));
    } else {
        for token in original.split_whitespace() {
            parts.push(token.to_string());
        }
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HookConfig;

    #[test]
    fn test_extract_root_command_simple() {
        assert_eq!(extract_root_command("aws s3 ls"), "aws");
    }

    #[test]
    fn test_extract_root_command_with_env_prefix() {
        assert_eq!(
            extract_root_command("AWS_REGION=us-east-1 aws s3 ls"),
            "aws"
        );
    }

    #[test]
    fn test_extract_root_command_multiple_env() {
        assert_eq!(
            extract_root_command("FOO=1 BAR=2 kubectl get pods"),
            "kubectl"
        );
    }

    #[test]
    fn test_extract_root_command_empty() {
        assert_eq!(extract_root_command(""), "");
    }

    #[test]
    fn test_starts_with_s2() {
        assert!(starts_with_s2("s2 list"));
        assert!(starts_with_s2("s2 exec -f ~/.secrets -- aws s3 ls"));
        assert!(starts_with_s2("  s2 list"));
        assert!(!starts_with_s2("aws s3 ls"));
        assert!(!starts_with_s2("s2tool something"));
    }

    #[test]
    fn test_is_complex_command() {
        assert!(!is_complex_command("aws s3 ls"));
        assert!(is_complex_command("aws s3 ls | grep foo"));
        assert!(is_complex_command("aws configure && aws s3 ls"));
        assert!(is_complex_command("echo $(whoami)"));
    }

    #[test]
    fn test_build_wrapped_simple() {
        let result = build_wrapped_command("aws s3 ls", &["-p".into(), "aws".into()]);
        assert_eq!(result, "s2 exec -p aws -- aws s3 ls");
    }

    #[test]
    fn test_build_wrapped_with_files() {
        let result = build_wrapped_command("kubectl get pods", &["-f".into(), "~/.secrets".into()]);
        assert_eq!(result, "s2 exec -f ~/.secrets -- kubectl get pods");
    }

    #[test]
    fn test_build_wrapped_complex() {
        let result = build_wrapped_command("aws s3 ls | grep bucket", &["-p".into(), "aws".into()]);
        assert_eq!(
            result,
            "s2 exec -p aws -- bash -c 'aws s3 ls | grep bucket'"
        );
    }

    #[test]
    fn test_build_wrapped_complex_with_quotes() {
        let result = build_wrapped_command(
            "echo 'hello' | aws s3 cp - s3://b",
            &["-p".into(), "aws".into()],
        );
        assert_eq!(
            result,
            "s2 exec -p aws -- bash -c 'echo '\\''hello'\\'' | aws s3 cp - s3://b'"
        );
    }

    #[test]
    fn test_should_wrap() {
        let hook = HookConfig {
            commands: vec!["aws".into(), "kubectl".into()],
            skip: vec!["git".into()],
            ..Default::default()
        };
        assert!(hook.should_wrap("aws"));
        assert!(hook.should_wrap("kubectl"));
        assert!(!hook.should_wrap("terraform"));
        assert!(!hook.should_wrap("git"));
        assert!(!hook.should_wrap("s2"));
        assert!(!hook.should_wrap(""));
    }

    #[test]
    fn test_should_wrap_open_allowlist() {
        let hook = HookConfig {
            commands: vec![],
            skip: vec!["git".into()],
            ..Default::default()
        };
        assert!(hook.should_wrap("aws"));
        assert!(hook.should_wrap("terraform"));
        assert!(!hook.should_wrap("git"));
        assert!(!hook.should_wrap("s2"));
    }

    #[test]
    fn test_exec_args_profile() {
        let hook = HookConfig {
            profile: Some("aws".into()),
            ..Default::default()
        };
        assert_eq!(
            hook.exec_args(&[]),
            Some(vec!["-p".to_string(), "aws".to_string()])
        );
    }

    #[test]
    fn test_exec_args_files() {
        let hook = HookConfig {
            files: vec!["~/.secrets".into()],
            ..Default::default()
        };
        assert_eq!(
            hook.exec_args(&[]),
            Some(vec!["-f".to_string(), "~/.secrets".to_string()])
        );
    }

    #[test]
    fn test_exec_args_fallback_to_defaults() {
        let hook = HookConfig::default();
        assert_eq!(
            hook.exec_args(&["~/.secrets".into()]),
            Some(vec!["-f".to_string(), "~/.secrets".to_string()])
        );
    }

    #[test]
    fn test_exec_args_none() {
        let hook = HookConfig::default();
        assert_eq!(hook.exec_args(&[]), None);
    }
}
