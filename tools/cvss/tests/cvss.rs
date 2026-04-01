// SPDX-License-Identifier: GPL-2.0-only
//
// Integration tests for the cvss binary.

use assert_cmd::Command;
use predicates::prelude::*;

fn cvss_cmd() -> Command {
    Command::cargo_bin("cvss").unwrap()
}

#[test]
fn help_flag() {
    cvss_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("CVSS v3.1"));
}

#[test]
fn no_args_shows_error() {
    cvss_cmd()
        .assert()
        .failure()
        .stderr(predicate::str::contains("provide"));
}

#[test]
fn vector_only_computes_score() {
    cvss_cmd()
        .args(["--vector-only", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"])
        .assert()
        .success()
        .stdout(predicate::str::contains("9.8"))
        .stdout(predicate::str::contains("CRITICAL"));
}

#[test]
fn vector_only_medium() {
    cvss_cmd()
        .args(["--vector-only", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"])
        .assert()
        .success()
        .stdout(predicate::str::contains("5.5"))
        .stdout(predicate::str::contains("MEDIUM"));
}

#[test]
fn vector_only_zero_impact() {
    cvss_cmd()
        .args(["--vector-only", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0.0"))
        .stdout(predicate::str::contains("NONE"));
}

#[test]
fn vector_only_json_output() {
    cvss_cmd()
        .args(["--vector-only", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"score\""))
        .stdout(predicate::str::contains("9.8"))
        .stdout(predicate::str::contains("\"severity\""))
        .stdout(predicate::str::contains("CRITICAL"));
}

#[test]
fn vector_only_verbose() {
    cvss_cmd()
        .args(["--vector-only", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Attack Vector"))
        .stdout(predicate::str::contains("ISS:"));
}

#[test]
fn invalid_vector_error() {
    cvss_cmd()
        .args(["--vector-only", "not-a-vector"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("CVSS:3.1/"));
}

#[test]
fn invalid_vector_wrong_version() {
    cvss_cmd()
        .args(["--vector-only", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"])
        .assert()
        .failure();
}

#[test]
fn cve_without_vector_error() {
    cvss_cmd()
        .arg("CVE-2026-22976")
        .assert()
        .failure()
        .stderr(predicate::str::contains("vector"));
}

#[test]
fn batch_file_not_found() {
    cvss_cmd()
        .args(["--batch", "/nonexistent/file.txt"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read"));
}

#[test]
fn batch_with_empty_and_comments() {
    let dir = tempfile::tempdir().unwrap();
    let batch_file = dir.path().join("batch.txt");
    std::fs::write(&batch_file, "# comment\n\n# another comment\n").unwrap();

    cvss_cmd()
        .args(["--batch", batch_file.to_str().unwrap()])
        .assert()
        .success();
}
