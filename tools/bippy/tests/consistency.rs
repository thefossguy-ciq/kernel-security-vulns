// SPDX-License-Identifier: GPL-2.0-only
//
// Verify CVE JSON consistency against dyad ground truth and cross-product
// agreement between semver and CPE version types.

#![allow(clippy::collapsible_if)]

use cve_utils::dyad::DyadEntry;
use rayon::prelude::*;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

// ─── verify_cve_consistency logic ───────────────────────────────────────────

#[derive(Default)]
struct ConsistencyIssues {
    git: usize,
    cpe: usize,
    unfixed_branch: usize,
    stable_intro: usize,
}

fn check_consistency(json_path: &Path) -> ConsistencyIssues {
    let mut issues = ConsistencyIssues::default();

    let dyad_path = json_path.with_extension("dyad");
    let entries: Vec<DyadEntry> = fs::read_to_string(&dyad_path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| DyadEntry::new_no_validate(l).ok())
        .collect();
    if entries.is_empty() {
        return issues;
    }

    let content = match fs::read_to_string(json_path) {
        Ok(c) => c,
        Err(_) => return issues,
    };
    let data: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return issues,
    };

    let cna = &data["containers"]["cna"];
    let products = cna["affected"].as_array();

    // Extract git ranges from JSON
    let mut actual_git: HashSet<(String, String)> = HashSet::new();
    if let Some(prods) = products {
        for p in prods {
            for v in p["versions"].as_array().unwrap_or(&Vec::new()) {
                if v["versionType"].as_str() == Some("git")
                    && v["status"].as_str() == Some("affected")
                {
                    if let (Some(ver), Some(lt)) = (v["version"].as_str(), v["lessThan"].as_str()) {
                        actual_git.insert((ver.to_string(), lt.to_string()));
                    }
                }
            }
        }
    }

    // Extract CPE ranges from JSON
    let actual_cpe: HashSet<(String, String)> = iter_cpe_matches(cna)
        .filter(|(s, e)| !s.is_empty() && !e.is_empty())
        .map(|(s, e)| (s.to_string(), e.to_string()))
        .collect();

    // Collect all semver affected ranges across all products
    let mut all_affected_ranges: HashSet<(String, String)> = HashSet::new();
    if let Some(prods) = products {
        for p in prods {
            for v in p["versions"].as_array().unwrap_or(&Vec::new()) {
                if v["versionType"].as_str() == Some("semver")
                    && v["status"].as_str() == Some("affected")
                {
                    let start = v["version"].as_str().unwrap_or("");
                    let lt = v["lessThan"].as_str().unwrap_or("");
                    if !start.is_empty() && !lt.is_empty() {
                        all_affected_ranges.insert((start.to_string(), lt.to_string()));
                    }
                }
            }
        }
    }

    // Build expected git ranges from dyad
    const FIRST_LINUX_COMMIT: &str = "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2";
    let mut expected_git: HashSet<(String, String)> = HashSet::new();
    for e in &entries {
        if e.fixed.version() == "0" || e.fixed.git_id() == "0" {
            continue;
        }
        let start = if e.vulnerable.git_id() == "0" {
            FIRST_LINUX_COMMIT.to_string()
        } else {
            e.vulnerable.git_id()
        };
        expected_git.insert((start, e.fixed.git_id()));
    }

    // Build expected CPE ranges from dyad
    let mut expected_cpe: HashSet<(String, String)> = HashSet::new();
    for e in &entries {
        if e.is_same_version() {
            continue;
        }
        if e.vulnerable.version() != "0" && e.fixed.version() != "0" {
            expected_cpe.insert((e.vulnerable.version(), e.fixed.version()));
        }
    }

    // Check git
    let git_missing = expected_git.difference(&actual_git).count();
    let git_extra = actual_git.difference(&expected_git).count();
    issues.git = git_missing + git_extra;

    // Check CPE
    let cpe_missing = expected_cpe.difference(&actual_cpe).count();
    let cpe_extra = actual_cpe.difference(&expected_cpe).count();
    issues.cpe = cpe_missing + cpe_extra;

    // Check stable intro: for each stable fix, there should be an affected range
    let fixed_branches: HashSet<String> = entries
        .iter()
        .filter(|e| e.fixed.version() != "0" && !e.fixed.is_mainline())
        .map(|e| e.fixed.major())
        .collect();

    for e in &entries {
        if e.fixed.version() == "0" || e.fixed.is_mainline() || e.is_same_version() {
            continue;
        }
        if e.vulnerable.is_mainline() {
            continue;
        }
        if !all_affected_ranges.contains(&(e.vulnerable.version(), e.fixed.version())) {
            issues.stable_intro += 1;
        }
    }

    // Check unfixed branches
    for e in &entries {
        if e.fixed.version() != "0" || e.vulnerable.version() == "0" || e.vulnerable.is_mainline() {
            continue;
        }
        let branch = e.vulnerable.major();
        if fixed_branches.contains(&branch) {
            continue;
        }
        let has_range = all_affected_ranges.iter().any(|(s, _)| *s == e.vulnerable.version());
        if !has_range {
            issues.unfixed_branch += 1;
        }
    }

    issues
}

// ─── Shared utilities ───────────────────────────────────────────────────────

fn find_cve_dir() -> PathBuf {
    cve_utils::common::get_cve_root().expect("Failed to find CVE root directory")
}

fn collect_json_files(cve_dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let published = cve_dir.join("published");
    if let Ok(years) = fs::read_dir(&published) {
        for year in years.flatten() {
            if let Ok(cves) = fs::read_dir(year.path()) {
                for entry in cves.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|e| e == "json") {
                        files.push(path);
                    }
                }
            }
        }
    }
    files.sort();
    files
}

// ─── Tests ──────────────────────────────────────────────────────────────────

/// Verify CVE JSON output is consistent with dyad ground truth.
///
/// Checks: git ranges, CPE ranges, stable-intro ranges, unfixed-branch ranges.
/// Run with: RUN_INTEGRATION_TESTS=1 cargo test --test consistency -- --ignored
#[test]
#[ignore]
fn test_cve_consistency() {
    if std::env::var("RUN_INTEGRATION_TESTS").is_err() {
        println!("Skipping - set RUN_INTEGRATION_TESTS=1 to enable");
        return;
    }

    let cve_dir = find_cve_dir();
    let files = collect_json_files(&cve_dir);
    assert!(!files.is_empty(), "No CVE JSON files found");

    let total = files.len();
    let counters = ConsistencyCounters::default();

    files.par_iter().for_each(|f| {
        let issues = check_consistency(f);
        counters.git.fetch_add(issues.git, Ordering::Relaxed);
        counters.cpe.fetch_add(issues.cpe, Ordering::Relaxed);
        counters
            .unfixed_branch
            .fetch_add(issues.unfixed_branch, Ordering::Relaxed);
        counters
            .stable_intro
            .fetch_add(issues.stable_intro, Ordering::Relaxed);
        if issues.git > 0 || issues.cpe > 0 || issues.unfixed_branch > 0 || issues.stable_intro > 0
        {
            counters.cves_with_issues.fetch_add(1, Ordering::Relaxed);
        }
    });

    let git = counters.git.load(Ordering::Relaxed);
    let cpe = counters.cpe.load(Ordering::Relaxed);
    let unfixed = counters.unfixed_branch.load(Ordering::Relaxed);
    let intro = counters.stable_intro.load(Ordering::Relaxed);
    let with_issues = counters.cves_with_issues.load(Ordering::Relaxed);

    println!("\nverify_cve_consistency ({total} CVEs):");
    println!("  git:            {git}");
    println!("  cpe:            {cpe}");
    println!("  unfixed-branch: {unfixed}");
    println!("  stable-intro:   {intro}");
    println!("  CVEs w/ issues: {with_issues}");
}

#[derive(Default)]
struct ConsistencyCounters {
    git: AtomicUsize,
    cpe: AtomicUsize,
    unfixed_branch: AtomicUsize,
    stable_intro: AtomicUsize,
    cves_with_issues: AtomicUsize,
}

// ─── verify_cross_product logic ─────────────────────────────────────────────

/// Iterate over vulnerable CPE matches, yielding (versionStartIncluding, versionEndExcluding).
fn iter_cpe_matches(cna: &Value) -> impl Iterator<Item = (&str, &str)> {
    cna["cpeApplicability"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|node| node["nodes"].as_array().into_iter().flatten())
        .flat_map(|n| n["cpeMatch"].as_array().into_iter().flatten())
        .filter(|m| m["vulnerable"].as_bool() == Some(true))
        .map(|m| {
            (
                m["versionStartIncluding"].as_str().unwrap_or(""),
                m["versionEndExcluding"].as_str().unwrap_or(""),
            )
        })
}

/// Extract fix versions from semver/original_commit_for_fix entries.
fn get_fixes_from_semver(cna: &Value) -> HashSet<String> {
    let mut fixes = HashSet::new();
    for p in cna["affected"].as_array().unwrap_or(&vec![]) {
        let ds = p["defaultStatus"].as_str().unwrap_or("");
        for v in p["versions"].as_array().unwrap_or(&vec![]) {
            let vt = v["versionType"].as_str().unwrap_or("");
            let status = v["status"].as_str().unwrap_or("");
            let ver = v["version"].as_str().unwrap_or("0");
            if (vt == "semver" || vt == "original_commit_for_fix") && status == "unaffected" && ver != "0" {
                fixes.insert(ver.to_string());
            } else if vt == "semver" && status == "affected" && ds == "unaffected" {
                let lt = v["lessThan"].as_str().unwrap_or("");
                // Real fix has same component count as start; branch ceilings have fewer
                if !lt.is_empty() && !ver.is_empty() && lt.matches('.').count() >= ver.matches('.').count() {
                    fixes.insert(lt.to_string());
                }
            }
        }
    }
    fixes
}

/// Extract fix versions from CPE versionEndExcluding.
fn get_fixes_from_cpe(cna: &Value) -> HashSet<String> {
    iter_cpe_matches(cna)
        .filter(|(_, end)| !end.is_empty())
        .map(|(_, end)| end.to_string())
        .collect()
}

/// Extract intro versions from semver entries.
fn get_intros_from_semver(cna: &Value) -> HashSet<String> {
    let mut intros = HashSet::new();
    for p in cna["affected"].as_array().unwrap_or(&vec![]) {
        for v in p["versions"].as_array().unwrap_or(&vec![]) {
            let status = v["status"].as_str().unwrap_or("");
            let vt = v["versionType"].as_str().unwrap_or("");
            if status == "affected" {
                if vt.is_empty() {
                    let ver = v["version"].as_str().unwrap_or("");
                    if !ver.is_empty() {
                        intros.insert(ver.to_string());
                    }
                } else if vt == "semver" && v["lessThan"].as_str().is_some() {
                    let ver = v["version"].as_str().unwrap_or("");
                    if !ver.is_empty() && ver != "0" {
                        intros.insert(ver.to_string());
                    }
                }
            }
        }
    }
    intros
}

/// Extract intro versions from CPE versionStartIncluding.
fn get_intros_from_cpe(cna: &Value) -> HashSet<String> {
    iter_cpe_matches(cna)
        .filter(|(start, _)| !start.is_empty())
        .map(|(start, _)| start.to_string())
        .collect()
}

#[derive(Default)]
struct CrossProductIssues {
    fix_mismatch: usize,
    intro_mismatch: usize,
}

fn check_cross_product(json_path: &Path) -> CrossProductIssues {
    let mut issues = CrossProductIssues::default();

    let content = match fs::read_to_string(json_path) {
        Ok(c) => c,
        Err(_) => return issues,
    };
    let data: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return issues,
    };

    let cna = &data["containers"]["cna"];
    if cna["affected"].as_array().is_none() {
        return issues;
    }

    let semver_fixes = get_fixes_from_semver(cna);
    let cpe_fixes = get_fixes_from_cpe(cna);
    let semver_intros = get_intros_from_semver(cna);
    let cpe_intros = get_intros_from_cpe(cna);

    if !semver_fixes.is_empty() || !cpe_fixes.is_empty() {
        issues.fix_mismatch = semver_fixes.symmetric_difference(&cpe_fixes).count();
    }

    if !semver_intros.is_empty() && !cpe_intros.is_empty() {
        issues.intro_mismatch = semver_intros.symmetric_difference(&cpe_intros).count();
    }

    issues
}

/// Verify cross-product consistency: semver and CPE independently give the
/// same vulnerability picture (same fix versions, same intro versions).
///
/// Run with: RUN_INTEGRATION_TESTS=1 cargo test --test consistency -- --ignored
#[test]
#[ignore]
fn test_cross_product_consistency() {
    if std::env::var("RUN_INTEGRATION_TESTS").is_err() {
        return;
    }

    let cve_dir = find_cve_dir();
    let files = collect_json_files(&cve_dir);
    let total = files.len();

    let fix_mismatch = AtomicUsize::new(0);
    let intro_mismatch = AtomicUsize::new(0);
    let cves_with_issues = AtomicUsize::new(0);

    files.par_iter().for_each(|f| {
        let issues = check_cross_product(f);
        fix_mismatch.fetch_add(issues.fix_mismatch, Ordering::Relaxed);
        intro_mismatch.fetch_add(issues.intro_mismatch, Ordering::Relaxed);
        if issues.fix_mismatch > 0 || issues.intro_mismatch > 0 {
            cves_with_issues.fetch_add(1, Ordering::Relaxed);
        }
    });

    let fix = fix_mismatch.load(Ordering::Relaxed);
    let intro = intro_mismatch.load(Ordering::Relaxed);
    let with_issues = cves_with_issues.load(Ordering::Relaxed);

    println!("\nverify_cross_product ({total} CVEs):");
    println!("  fix-mismatch:   {fix}");
    println!("  intro-mismatch: {intro}");
    println!("  CVEs w/ issues: {with_issues}");
}
