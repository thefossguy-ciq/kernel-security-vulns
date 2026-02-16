// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//
// strak CLI tests

use assert_cmd::assert::OutputAssertExt;
use assert_cmd::cargo;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn no_args_shows_error() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("You must provide either a Git SHA or --fixed option"));
}

#[test]
fn help_flag_shows_usage() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));

    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Dig in the CVE database"));
}

#[test]
fn fixed_with_known_version() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));

    cmd.arg("--fixed")
        .arg("6.12.3")
        .assert()
        .success()
        .stdout(predicate::str::contains("CVE"));
}

#[test]
fn fixed_with_version_no_fixes() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));

    // Use a very old version unlikely to have fixes in the database
    cmd.arg("--fixed")
        .arg("0.0.1")
        .assert()
        .success()
        .stdout(predicate::str::contains("did not fix any CVE"));
}

#[test]
fn positional_arg_known_tag() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));

    cmd.arg("v6.12.3")
        .assert()
        .success()
        .stdout(predicate::str::contains("vulnerable"));
}
