// SPDX-License-Identifier: GPL-2.0-only
//
// Integration tests for storing a score's rationale in the .cvss file.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const CNA: &str = "f4215fc3-5b6b-47ff-a258-f7189bd81038";
const VECTOR: &str = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H";
const CVE: &str = "CVE-2026-00001";

fn cvss_cmd() -> Command {
    Command::cargo_bin("cvss").unwrap()
}

fn rationale() -> String {
    [
        "AV:L - reachable only through local file I/O",
        "AC:L - fully deterministic, no race to win",
        "PR:L - an unprivileged local user suffices",
        "UI:N - no action from any other user is needed",
        "S:U - stays inside the kernel's own security authority",
        "C:N - the fault happens before any data is returned",
        "I:H - an attacker-chosen modification of protected state",
        "A:H - panics outright on panic_on_oops builds",
    ]
    .join("\n")
}

/// A throwaway tree shaped like the vulns repo, so the binary's own
/// directory discovery finds it.
struct FakeRepo {
    _dir: TempDir,
    root: PathBuf,
}

impl FakeRepo {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("vulns");
        let year_dir = root.join("cve/published/2026");

        fs::create_dir_all(&year_dir).unwrap();
        fs::create_dir_all(root.join("scripts")).unwrap();
        fs::write(root.join("scripts/linux.uuid"), format!("{CNA}\n")).unwrap();
        fs::write(year_dir.join(format!("{CVE}.sha1")), "0123456789abcdef\n").unwrap();

        Self { _dir: dir, root }
    }

    fn cvss_path(&self) -> PathBuf {
        self.root.join(format!("cve/published/2026/{CVE}.cvss"))
    }

    fn cmd(&self) -> Command {
        let mut cmd = cvss_cmd();
        cmd.current_dir(&self.root);
        cmd
    }

    fn write_rationale(&self, text: &str) -> PathBuf {
        let path = self.root.join("rationale.txt");
        fs::write(&path, text).unwrap();
        path
    }
}

fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

#[test]
fn writes_vector_and_rationale() {
    let repo = FakeRepo::new();
    let rationale_file = repo.write_rationale(&rationale());

    repo.cmd()
        .args([CVE, VECTOR])
        .arg("--rationale")
        .arg(&rationale_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("7.1"))
        .stdout(predicate::str::contains("HIGH"));

    let written = fs::read_to_string(repo.cvss_path()).unwrap();
    let mut lines = written.lines();
    assert_eq!(lines.next().unwrap(), format!("{CNA} {VECTOR}"));
    assert_eq!(lines.next().unwrap(), "");
    assert!(written.contains("AV:L - reachable only through local file I/O"));
    assert!(written.contains("A:H - panics outright on panic_on_oops builds"));
    assert!(written.ends_with('\n'));
}

#[test]
fn reads_rationale_from_stdin() {
    let repo = FakeRepo::new();

    repo.cmd()
        .args([CVE, VECTOR, "--rationale", "-"])
        .write_stdin(rationale())
        .assert()
        .success();

    let written = fs::read_to_string(repo.cvss_path()).unwrap();
    assert!(written.contains("AV:L - reachable only through local file I/O"));
}

#[test]
fn json_output_reports_the_written_path() {
    let repo = FakeRepo::new();

    let out = repo
        .cmd()
        .args([CVE, VECTOR, "--rationale", "-", "--json"])
        .write_stdin(rationale())
        .assert()
        .success();

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(json["cveId"], CVE);
    assert_eq!(json["score"], 7.1);
    assert_eq!(json["severity"], "HIGH");
    assert_eq!(json["vectorString"], VECTOR);
    assert_eq!(json["path"], repo.cvss_path().display().to_string());
    assert!(json["rationale"].as_str().unwrap().lines().count() == 8);
}

#[test]
fn rejects_a_rationale_that_disagrees_with_the_vector() {
    let repo = FakeRepo::new();
    let rationale_file = repo.write_rationale(&rationale());

    repo.cmd()
        .args([CVE, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H"])
        .arg("--rationale")
        .arg(&rationale_file)
        .assert()
        .failure()
        .stderr(predicate::str::contains("AV"));

    assert!(!repo.cvss_path().exists(), "nothing should have been written");
}

#[test]
fn rejects_an_incomplete_rationale() {
    let repo = FakeRepo::new();
    let rationale_file = repo.write_rationale("AV:L - reachable only through local file I/O");

    repo.cmd()
        .args([CVE, VECTOR])
        .arg("--rationale")
        .arg(&rationale_file)
        .assert()
        .failure();

    assert!(!repo.cvss_path().exists());
}

#[test]
fn rescoring_keeps_the_rationale_when_the_metrics_still_match() {
    let repo = FakeRepo::new();

    repo.cmd()
        .args([CVE, VECTOR, "--rationale", "-"])
        .write_stdin(rationale())
        .assert()
        .success();
    let first = fs::read_to_string(repo.cvss_path()).unwrap();

    // Same vector, no --rationale: the explanation must survive.
    repo.cmd().args([CVE, VECTOR]).assert().success();
    assert_eq!(fs::read_to_string(repo.cvss_path()).unwrap(), first);
}

#[test]
fn rescoring_refuses_to_leave_a_stale_rationale_behind() {
    let repo = FakeRepo::new();

    repo.cmd()
        .args([CVE, VECTOR, "--rationale", "-"])
        .write_stdin(rationale())
        .assert()
        .success();
    let before = fs::read_to_string(repo.cvss_path()).unwrap();

    repo.cmd()
        .args([CVE, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("update it along with the score"));

    assert_eq!(
        fs::read_to_string(repo.cvss_path()).unwrap(),
        before,
        "the file must be left untouched"
    );
}

#[test]
fn rescoring_accepts_a_replacement_rationale() {
    let repo = FakeRepo::new();

    repo.cmd()
        .args([CVE, VECTOR, "--rationale", "-"])
        .write_stdin(rationale())
        .assert()
        .success();

    let new_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H";
    let updated = rationale().replace(
        "AV:L - reachable only through local file I/O",
        "AV:N - a remote peer drives the vulnerable path",
    );

    repo.cmd()
        .args([CVE, new_vector, "--rationale", "-"])
        .write_stdin(updated)
        .assert()
        .success();

    let written = fs::read_to_string(repo.cvss_path()).unwrap();
    assert!(written.starts_with(&format!("{CNA} {new_vector}\n")));
    assert!(written.contains("AV:N - a remote peer drives the vulnerable path"));
}

#[test]
fn rejects_a_rationale_too_long_for_the_record() {
    let repo = FakeRepo::new();
    // Complete and correct, but past what scenarios[].value will hold.
    let padded = rationale().replace(
        "AV:L - reachable only through local file I/O",
        &format!("AV:L - reachable only through local file I/O {}", "word ".repeat(1000)),
    );
    let rationale_file = repo.write_rationale(&padded);

    repo.cmd()
        .args([CVE, VECTOR])
        .arg("--rationale")
        .arg(&rationale_file)
        .assert()
        .failure()
        .stderr(predicate::str::contains("4096"));

    assert!(!repo.cvss_path().exists());
}

#[test]
fn check_accepts_a_good_file() {
    let dir = TempDir::new().unwrap();
    write_file(
        dir.path(),
        "good.cvss",
        &format!("{CNA} {VECTOR}\n\n{}\n", rationale()),
    );

    cvss_cmd().arg("--check").arg(dir.path()).assert().success();
}

#[test]
fn check_accepts_a_file_with_no_rationale() {
    let dir = TempDir::new().unwrap();
    write_file(dir.path(), "bare.cvss", &format!("{CNA} {VECTOR}\n"));

    cvss_cmd().arg("--check").arg(dir.path()).assert().success();
}

#[test]
fn check_rejects_a_mismatched_file() {
    let dir = TempDir::new().unwrap();
    write_file(
        dir.path(),
        "bad.cvss",
        &format!(
            "{CNA} CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H\n\n{}\n",
            rationale()
        ),
    );

    cvss_cmd()
        .arg("--check")
        .arg(dir.path())
        .assert()
        .failure()
        .stdout(predicate::str::contains("bad.cvss"));
}

#[test]
fn check_rejects_a_malformed_file() {
    let dir = TempDir::new().unwrap();
    write_file(dir.path(), "junk.cvss", "not a cvss file at all\n");

    cvss_cmd().arg("--check").arg(dir.path()).assert().failure();
}

#[test]
fn check_takes_a_single_file() {
    let dir = TempDir::new().unwrap();
    let path = write_file(dir.path(), "one.cvss", &format!("{CNA} {VECTOR}\n"));

    cvss_cmd().arg("--check").arg(&path).assert().success();
}

#[test]
fn rendered_file_is_stable_across_rewrites() {
    let repo = FakeRepo::new();

    repo.cmd()
        .args([CVE, VECTOR, "--rationale", "-"])
        .write_stdin(rationale())
        .assert()
        .success();
    let first = fs::read_to_string(repo.cvss_path()).unwrap();

    // Feeding the rendered form back in must produce the same bytes.
    let body = first.split_once("\n\n").unwrap().1.to_string();
    repo.cmd()
        .args([CVE, VECTOR, "--rationale", "-"])
        .write_stdin(body)
        .assert()
        .success();

    assert_eq!(fs::read_to_string(repo.cvss_path()).unwrap(), first);
}

#[test]
fn rejects_a_whole_cvss_file_as_the_rationale() {
    let repo = FakeRepo::new();

    repo.cmd()
        .args([CVE, VECTOR, "--rationale", "-"])
        .write_stdin(rationale())
        .assert()
        .success();
    let before = fs::read_to_string(repo.cvss_path()).unwrap();

    // Easy mistake, and it would otherwise be stored verbatim as prose.
    repo.cmd()
        .args([CVE, VECTOR, "--rationale"])
        .arg(repo.cvss_path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a rationale"));

    assert_eq!(fs::read_to_string(repo.cvss_path()).unwrap(), before);
}
