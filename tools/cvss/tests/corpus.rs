// SPDX-License-Identifier: GPL-2.0-only
//
// Every .cvss file in the repository has to stay readable, has to agree with
// the vector it scores, and has to fit the CVE record field it is published
// in. Nothing else notices when one of those stops being true.

use cve_utils::cvss::file::CvssFile;
use cve_utils::cvss::rationale::MAX_SCENARIO_LEN;
use rayon::prelude::*;
use std::path::PathBuf;
use walkdir::WalkDir;

fn collect_cvss_files() -> Vec<PathBuf> {
    let Ok(cve_dir) = cve_utils::common::get_cve_root() else {
        return Vec::new();
    };

    let mut files: Vec<PathBuf> = WalkDir::new(&cve_dir)
        .into_iter()
        .filter_map(Result::ok)
        .map(|entry| entry.into_path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|e| e == "cvss"))
        .collect();
    files.sort();
    files
}

#[test]
fn all_cvss_files_are_valid() {
    let files = collect_cvss_files();
    if files.is_empty() {
        return; // not run from inside the vulns repo
    }

    let failures: Vec<String> = files
        .par_iter()
        .filter_map(|path| {
            CvssFile::read(path)
                .and_then(|file| file.validate())
                .err()
                .map(|e| format!("{}: {e:#}", path.display()))
        })
        .collect();

    assert!(
        failures.is_empty(),
        "{} of {} .cvss files are invalid:\n{}",
        failures.len(),
        files.len(),
        failures.join("\n")
    );
}

#[test]
fn all_rationales_fit_the_record_field() {
    let files = collect_cvss_files();
    if files.is_empty() {
        return;
    }

    let too_long: Vec<String> = files
        .par_iter()
        .filter_map(|path| {
            let file = CvssFile::read(path).ok()?;
            let rationale = file.rationale.as_ref()?;
            let length = rationale.to_scenario_value().chars().count();
            (length > MAX_SCENARIO_LEN)
                .then(|| format!("{}: {length} characters", path.display()))
        })
        .collect();

    assert!(
        too_long.is_empty(),
        "rationales over the {MAX_SCENARIO_LEN} character limit for \
         metrics[].scenarios[].value:\n{}",
        too_long.join("\n")
    );
}

#[test]
fn all_cvss_files_render_back_to_themselves() {
    let files = collect_cvss_files();
    if files.is_empty() {
        return;
    }

    let unstable: Vec<String> = files
        .par_iter()
        .filter_map(|path| {
            let content = std::fs::read_to_string(path).ok()?;
            let rendered = CvssFile::parse(&content).ok()?.render();
            (rendered != content).then(|| path.display().to_string())
        })
        .collect();

    assert!(
        unstable.is_empty(),
        "{} .cvss files are not in canonical form; run 'cvss <CVE> <vector>' \
         to rewrite them:\n{}",
        unstable.len(),
        unstable.join("\n")
    );
}
