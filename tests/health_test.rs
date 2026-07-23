use assert_cmd::Command;
use serde_json::Value;

fn s2() -> Command {
    Command::cargo_bin("s2").unwrap()
}

/// Run `s2 health --json -f <path>` and parse the single JSON report line from stdout.
/// `extra_env` lets a test force AWS credentials empty. Returns (report, exit_ok).
fn health_report(path: &str, extra_env: &[(&str, &str)]) -> (Value, bool) {
    let mut cmd = s2();
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.args(["health", "--json", "-f", path]).output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let line = stdout.lines().next().unwrap_or_default();
    let report: Value =
        serde_json::from_str(line).unwrap_or_else(|e| panic!("stdout not JSON: {stdout:?} ({e})"));
    (report, out.status.success())
}

/// Force the AWS SDK to resolve no credentials, so an SSM probe fails deterministically
/// regardless of the host's real AWS config.
const NO_AWS_CREDS: &[(&str, &str)] = &[
    ("AWS_ACCESS_KEY_ID", ""),
    ("AWS_SECRET_ACCESS_KEY", ""),
    ("AWS_SESSION_TOKEN", ""),
    ("AWS_PROFILE", ""),
    ("AWS_CONFIG_FILE", "/dev/null"),
    ("AWS_SHARED_CREDENTIALS_FILE", "/dev/null"),
    ("AWS_EC2_METADATA_DISABLED", "true"),
    ("AWS_REGION", "us-east-1"),
];

#[test]
fn test_health_encrypted_healthy_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.env");
    let p = path.to_str().unwrap();

    s2().args(["init", p]).assert().success();
    s2().args(["set", "API_KEY", "-f", p])
        .write_stdin("sk-test-123")
        .assert()
        .success();

    // Encrypted + decryptable + no provider refs → healthy; provider stage skipped.
    let (r, ok) = health_report(p, &[]);
    assert!(ok, "exit 0 when healthy");
    assert_eq!(r["status"], "ok");
    assert_eq!(r["reason"], "healthy");
    assert_eq!(r["stages"]["decryption"], "ok");
    assert_eq!(r["stages"]["provider"], "skipped");
}

#[test]
fn test_health_plaintext_is_healthy_decryption_ok() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain.env");
    let p = path.to_str().unwrap();

    // A `--no-encrypt` file is a legitimate state: its content is trivially accessible,
    // so the decryption stage PASSES (not skipped) and the file is healthy. This lets a
    // consumer branching on `stages.decryption == "ok"` treat plaintext as healthy.
    s2().args(["init", "--no-encrypt", p]).assert().success();

    let (r, ok) = health_report(p, &[]);
    assert!(ok);
    assert_eq!(r["status"], "ok");
    assert_eq!(r["reason"], "healthy");
    assert_eq!(r["stages"]["decryption"], "ok");
}

#[test]
fn test_health_not_found_json() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("nope.env");
    let p = p.to_str().unwrap();

    let (r, ok) = health_report(p, &[]);
    assert!(!ok, "exit non-zero when unhealthy");
    assert_eq!(r["status"], "fail");
    assert_eq!(r["reason"], "not_found");
    assert_eq!(r["stages"]["existence"], "fail");
}

#[test]
fn test_health_passphrase_missing_json() {
    let dir = tempfile::tempdir().unwrap();
    let orig = dir.path().join("secrets.env");
    let op = orig.to_str().unwrap();

    s2().args(["init", op]).assert().success();

    // Copy to a new path: the keychain passphrase is keyed by path, so the copy has no
    // resolvable passphrase — the churned/evicted-passphrase case atlas self-heals on.
    let moved = dir.path().join("moved.env");
    std::fs::copy(&orig, &moved).unwrap();
    let perms = std::os::unix::fs::PermissionsExt::from_mode(0o600);
    std::fs::set_permissions(&moved, perms).unwrap();
    let mp = moved.to_str().unwrap();

    let (r, ok) = health_report(mp, &[]);
    assert!(!ok);
    assert_eq!(r["status"], "fail");
    assert_eq!(r["reason"], "passphrase_missing");
    assert_eq!(r["stages"]["decryption"], "fail");
}

#[test]
fn test_health_human_mode_stderr_not_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.env");
    let p = path.to_str().unwrap();

    s2().args(["init", p]).assert().success();

    // Default (no --json), like `scan`: human summary on stderr, stdout stays empty.
    let out = s2().args(["health", "-f", p]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stdout.is_empty(), "human mode writes nothing to stdout");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains(p), "per-file line on stderr");
    assert!(stderr.contains("ok"), "status on stderr");
    assert!(stderr.contains("1 file(s) healthy"), "tally on stderr");
}

#[test]
fn test_health_human_mode_failure_exit_and_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("nope.env");
    let p = p.to_str().unwrap();

    // Human mode, unhealthy: exit 1, reason on stderr, stdout empty, no `s2:` error line.
    let out = s2().args(["health", "-f", p]).output().unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("not_found"));
    assert!(stderr.contains("of 1 file(s) unhealthy"));
    assert!(
        !stderr.contains("s2:"),
        "negative result exits directly, not via main's error path"
    );
}

#[test]
fn test_health_provider_stage_escalates_and_fires() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.env");
    let p = path.to_str().unwrap();

    s2().args(["init", p]).assert().success();
    // Wildcard mapping: key `*` → an SSM prefix URI (detected → provider stage runs).
    s2().args(["set", "*", "-f", p])
        .write_stdin("ssm:///bogus/prefix/that/does/not/exist")
        .assert()
        .success();

    // Escalation + proof of life: decryption passes, the chain walks up to the provider
    // stage, and it genuinely issues the SSM probe (a silent no-op would falsely pass).
    // With creds forced empty the probe fails → provider_unreachable — but decryption
    // stays `ok`, which is exactly what lets a consumer branch past a network hiccup.
    let (r, ok) = health_report(p, NO_AWS_CREDS);
    assert!(!ok, "process exits non-zero when a stage fails");
    assert_eq!(r["status"], "fail");
    assert_eq!(r["reason"], "provider_unreachable");
    assert_eq!(r["stages"]["decryption"], "ok");
    assert_eq!(r["stages"]["provider"], "fail");
}
