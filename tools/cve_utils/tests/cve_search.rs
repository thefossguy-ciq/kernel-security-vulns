// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//
// cve_search CLI tests

use assert_cmd::assert::OutputAssertExt;
use assert_cmd::cargo;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn no_args_shows_error() {
    let mut cmd = Command::new(cargo::cargo_bin!("cve_search"));

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required arguments"));
}

#[test]
fn help_flag_shows_usage() {
    let mut cmd = Command::new(cargo::cargo_bin!("cve_search"));

    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Search the published CVE records"));
}

#[test]
fn known_cve_id_returns_sha() {
    let mut cmd = Command::new(cargo::cargo_bin!("cve_search"));

    cmd.arg("CVE-2024-26581")
        .assert()
        .success()
        .stdout(predicate::str::contains("CVE-2024-26581"))
        .stdout(predicate::str::contains("60c0c230c6f046da536d3df8b39a20b9a9fd6af0"));
}

#[test]
fn known_sha_returns_cve_id() {
    let mut cmd = Command::new(cargo::cargo_bin!("cve_search"));

    cmd.arg("60c0c230c6f046da536d3df8b39a20b9a9fd6af0")
        .assert()
        .success()
        .stdout(predicate::str::contains("CVE-2024-26581"));
}

#[test]
fn nonexistent_cve_shows_not_found() {
    let mut cmd = Command::new(cargo::cargo_bin!("cve_search"));

    cmd.arg("CVE-9999-99999")
        .assert()
        .success()
        .stdout(predicate::str::contains("not found"));
}

#[test]
fn nonexistent_sha_shows_not_found() {
    let mut cmd = Command::new(cargo::cargo_bin!("cve_search"));

    cmd.arg("0000000000000000000000000000000000000000")
        .assert()
        .success()
        .stdout(predicate::str::contains("not found"));
}
