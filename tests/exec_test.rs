use std::os::unix::fs::PermissionsExt;

use assert_cmd::Command;
use predicates::prelude::*;

fn fixture_path(name: &str) -> String {
    format!(
        "{}/tests/fixtures/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

fn setup_fixture(name: &str) {
    let path = fixture_path(name);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn test_exec_injects_env() {
    setup_fixture("basic.env");
    let path = fixture_path("basic.env");

    Command::cargo_bin("s2")
        .unwrap()
        .args(["exec", "-f", &path, "--", "env"])
        .assert()
        .success()
        .stdout(predicate::str::contains("FOO=bar"))
        .stdout(predicate::str::contains("BAZ=qux"))
        .stdout(predicate::str::contains("QUOTED=hello world"));
}

#[test]
fn test_exec_key_filter() {
    setup_fixture("basic.env");
    let path = fixture_path("basic.env");

    Command::cargo_bin("s2")
        .unwrap()
        .args(["exec", "-f", &path, "-k", "FOO", "--", "env"])
        .assert()
        .success()
        .stdout(predicate::str::contains("FOO=bar"))
        .stdout(predicate::str::contains("BAZ=qux").not());
}

#[test]
fn test_exec_clean_env() {
    setup_fixture("basic.env");
    let path = fixture_path("basic.env");

    // With --clean-env, the output should be minimal
    let output = Command::cargo_bin("s2")
        .unwrap()
        .args(["exec", "-f", &path, "--clean-env", "--", "env"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    // Should have our secrets
    assert!(stdout.contains("FOO=bar"));
    // Should have minimal env vars (PATH, HOME, etc.)
    // but NOT random inherited vars
    let line_count = stdout.lines().count();
    assert!(
        line_count < 20,
        "clean-env should have few vars, got {}",
        line_count
    );
}

#[test]
fn test_exec_refuses_unsafe_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unsafe.env");
    std::fs::write(&path, "SECRET=value\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "exec",
            "-f",
            path.to_str().unwrap(),
            "--",
            "echo",
            "should-not-run",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsafe permissions"));
}
