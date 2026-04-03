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
fn test_list_shows_keys() {
    setup_fixture("basic.env");
    let path = fixture_path("basic.env");

    Command::cargo_bin("s2")
        .unwrap()
        .args(["list", "-f", &path])
        .assert()
        .success()
        .stdout(predicate::str::contains("FOO"))
        .stdout(predicate::str::contains("BAZ"))
        .stdout(predicate::str::contains("QUOTED"));
}

#[test]
fn test_list_never_shows_values() {
    setup_fixture("basic.env");
    let path = fixture_path("basic.env");

    Command::cargo_bin("s2")
        .unwrap()
        .args(["list", "-f", &path])
        .assert()
        .success()
        .stdout(predicate::str::contains("bar").not())
        .stdout(predicate::str::contains("qux").not())
        .stdout(predicate::str::contains("hello world").not());
}
