// SPDX-License-Identifier: GPL-2.0-only
//
// cvss - assign CVSS v3.1 base scores to Linux kernel CVEs
//
// Copyright (c) 2026 - Sasha Levin <sashal@kernel.org>

mod output;
mod scoring;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use log::debug;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use cve_utils::cve_validation;
use scoring::file::{CvssEntry, CvssFile};
use scoring::formula::compute_base_score;
use scoring::rationale::Rationale;
use scoring::vector::{format_vector, parse_vector};

/// Assign CVSS v3.1 base scores to Linux kernel CVEs.
///
/// Examples:
///   cvss CVE-2026-22976 "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
///   cvss CVE-2026-22976 "CVSS:3.1/..." --rationale explanation.txt
///   cvss --vector-only "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
///   cvss --check
#[derive(Parser, Debug)]
#[clap(author, version, about, verbatim_doc_comment)]
struct Args {
    /// CVE ID (e.g., CVE-2026-22976)
    #[clap(index = 1)]
    cve_id: Option<String>,

    /// CVSS v3.1 vector string
    #[clap(index = 2)]
    vector: Option<String>,

    /// Compute score from vector only (no CVE lookup or file write)
    #[clap(long)]
    vector_only: Option<String>,

    /// File holding the rationale for the score ('-' to read stdin)
    #[clap(long)]
    rationale: Option<PathBuf>,

    /// Validate .cvss files instead of writing one (default: the whole cve/ tree)
    #[clap(long, num_args = 0.., value_name = "PATH")]
    check: Option<Vec<PathBuf>>,

    /// CNA org ID to use in the .cvss file (default: read from scripts/linux.uuid)
    #[clap(long)]
    cna_id: Option<String>,

    /// Output in JSON format
    #[clap(long)]
    json: bool,

    /// Enable verbose output
    #[clap(short, long)]
    verbose: bool,
}

fn initialize_logging(verbose: bool) {
    let logging_level = if verbose {
        log::LevelFilter::max()
    } else {
        log::LevelFilter::Error
    };

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(logging_level)
        .init();
}

/// Find the CVE path using cve_utils library functions, return the base path
/// (without extension) for writing .cvss file.
fn find_cve_base_path(cve_id: &str) -> Result<PathBuf> {
    let sha1_path = cve_validation::find_cve_id(cve_id)?
        .ok_or_else(|| anyhow!("CVE '{cve_id}' not found"))?;
    Ok(sha1_path.with_extension("cvss"))
}

fn read_rationale(path: &Path) -> Result<Rationale> {
    let text = if path == Path::new("-") {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read rationale from stdin")?;
        buf
    } else {
        fs::read_to_string(path)
            .context(format!("failed to read rationale from {}", path.display()))?
    };

    // Anything that parses as a .cvss file is the whole file, not the
    // rationale out of it, and would otherwise be stored as prose.
    if CvssFile::parse(&text).is_ok() {
        bail!("that is a .cvss file, not a rationale; pass only the explanation");
    }

    Rationale::parse(&text)
}

fn cna_id(args: &Args) -> Result<String> {
    if let Some(id) = &args.cna_id {
        return Ok(id.clone());
    }

    let vulns_dir = cve_utils::find_vulns_dir()?;
    let uuid = fs::read_to_string(vulns_dir.join("scripts/linux.uuid"))
        .context("failed to read scripts/linux.uuid")?;
    Ok(uuid.trim().to_string())
}

/// Process a single CVE + vector pair: validate, compute, and write .cvss file.
fn process_single(cve_id: &str, vector_str: &str, args: &Args) -> Result<()> {
    let metrics = parse_vector(vector_str)?;
    let result = compute_base_score(&metrics);
    let canonical_vector = format_vector(&metrics);
    let cvss_path = find_cve_base_path(cve_id)?;

    // A rationale on the command line wins; otherwise keep whatever the file
    // already had, so re-scoring does not silently discard the explanation.
    let existing = cvss_path.exists().then(|| CvssFile::read(&cvss_path)).transpose()?;
    let rationale = match &args.rationale {
        Some(path) => Some(read_rationale(path)?),
        None => existing.as_ref().and_then(|file| file.rationale.clone()),
    };

    if let Some(rationale) = &rationale {
        rationale.validate(&metrics).context(
            "the rationale does not describe this vector; update it along with the score",
        )?;
        rationale.checked_scenario_value()?;
    }

    let file = CvssFile::new(
        vec![CvssEntry {
            cna_id: cna_id(args)?,
            metrics: metrics.clone(),
        }],
        rationale.clone(),
    );
    file.write(&cvss_path)?;

    output::print_result(&output::Result_ {
        cve_id: Some(cve_id),
        vector: &canonical_vector,
        metrics: &metrics,
        result: &result,
        rationale: rationale.as_ref(),
        path: Some(&cvss_path),
        verbose: args.verbose,
        json: args.json,
    });

    debug!("Wrote {}", cvss_path.display());
    if !args.json {
        eprintln!("Wrote {}", cvss_path.display());
    }

    Ok(())
}

/// Collect the .cvss files to validate.
fn cvss_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let roots = if paths.is_empty() {
        vec![cve_utils::find_vulns_dir()?.join("cve")]
    } else {
        paths.to_vec()
    };

    let mut files = Vec::new();
    for root in roots {
        if root.is_file() {
            files.push(root);
            continue;
        }

        if !root.is_dir() {
            bail!("no such file or directory: {}", root.display());
        }

        for entry in WalkDir::new(&root) {
            // A directory we cannot read is not the same as one with nothing
            // in it; reporting "all clear" for it would be a lie.
            let entry = entry.context(format!("failed to walk {}", root.display()))?;
            let path = entry.path();
            if path.is_file() && path.extension().is_some_and(|ext| ext == "cvss") {
                files.push(path.to_path_buf());
            }
        }
    }

    files.sort();
    Ok(files)
}

/// Parse and validate .cvss files, reporting every problem found.
fn check(paths: &[PathBuf], verbose: bool) -> Result<()> {
    let files = cvss_files(paths)?;
    let mut failures = 0;
    let mut with_rationale = 0;

    for path in &files {
        match CvssFile::read(path).and_then(|file| {
            file.validate()?;
            Ok(file)
        }) {
            Ok(file) => {
                if file.rationale.is_some() {
                    with_rationale += 1;
                }
            }
            Err(e) => {
                failures += 1;
                println!("{}: {e:#}", path.display());
            }
        }
    }

    if verbose || failures > 0 {
        eprintln!(
            "checked {} files, {with_rationale} with a rationale, {failures} bad",
            files.len()
        );
    }

    if failures > 0 {
        bail!("{failures} of {} .cvss files failed validation", files.len());
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    initialize_logging(args.verbose);

    if let Some(paths) = &args.check {
        return check(paths, args.verbose);
    }

    // Vector-only mode: just compute and print
    if let Some(ref vector) = args.vector_only {
        let metrics = parse_vector(vector)?;
        let result = compute_base_score(&metrics);
        let canonical_vector = format_vector(&metrics);
        output::print_result(&output::Result_ {
            cve_id: None,
            vector: &canonical_vector,
            metrics: &metrics,
            result: &result,
            rationale: None,
            path: None,
            verbose: args.verbose,
            json: args.json,
        });
        return Ok(());
    }

    // Single CVE mode
    let cve_id = args.cve_id.as_deref().ok_or_else(|| {
        anyhow!("provide a CVE ID and vector, or use --vector-only\n\nUsage: cvss <CVE_ID> <VECTOR>\n       cvss --vector-only <VECTOR>\n       cvss --check [PATH...]")
    })?;
    let vector = args.vector.as_deref().ok_or_else(|| {
        anyhow!("provide a CVSS vector string as the second argument\n\nUsage: cvss {cve_id} \"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\"")
    })?;

    process_single(cve_id, vector, &args)
}
