use std::os::unix::fs::PermissionsExt;

use assert_cmd::Command;
use predicates::prelude::*;

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

fn setup_fixture(name: &str) {
    let path = fixture_path(name);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn test_check_all_present() {
    setup_fixture("basic.env");
    let path = fixture_path("basic.env");

    Command::cargo_bin("s2")
        .unwrap()
        .args(["check", "FOO", "BAZ", "-f", &path])
        .assert()
        .success();
}

#[test]
fn test_check_missing_key() {
    setup_fixture("basic.env");
    let path = fixture_path("basic.env");

    Command::cargo_bin("s2")
        .unwrap()
        .args(["check", "FOO", "NONEXISTENT", "-f", &path])
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing: NONEXISTENT"));
}
