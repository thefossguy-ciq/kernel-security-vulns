// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//
// voting_results CLI tests

use assert_cmd::assert::OutputAssertExt;
use assert_cmd::cargo;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn no_args_shows_error() {
    let mut cmd = Command::new(cargo::cargo_bin!("voting_results"));

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Please supply a Git range"));
}

#[test]
fn help_flag_shows_usage() {
    let mut cmd = Command::new(cargo::cargo_bin!("voting_results"));

    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Git range"));
}

#[test]
fn invalid_range_format_shows_error() {
    let mut cmd = Command::new(cargo::cargo_bin!("voting_results"));

    cmd.arg("invalid_range")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unrecognized argument"));
}
