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
fn test_redact_replaces_values() {
    setup_fixture("basic.env");
    let path = fixture_path("basic.env");

    Command::cargo_bin("s2")
        .unwrap()
        .args(["redact", "-f", &path])
        .write_stdin("the value is bar and also qux\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("[REDACTED]"))
        .stdout(predicate::str::contains("bar").not())
        .stdout(predicate::str::contains("qux").not());
}

#[test]
fn test_redact_passes_through_safe_text() {
    setup_fixture("basic.env");
    let path = fixture_path("basic.env");

    Command::cargo_bin("s2")
        .unwrap()
        .args(["redact", "-f", &path])
        .write_stdin("nothing secret here\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("nothing secret here"));
}
