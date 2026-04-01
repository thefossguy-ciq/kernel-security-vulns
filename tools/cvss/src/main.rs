// SPDX-License-Identifier: GPL-2.0-only
//
// cvss - assign CVSS v3.1 base scores to Linux kernel CVEs
//
// Copyright (c) 2026 - Sasha Levin <sashal@kernel.org>

mod json_writer;
mod output;
mod scoring;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::debug;
use std::fs;
use std::path::{Path, PathBuf};

use cve_utils::cve_validation;
use scoring::formula::compute_base_score;
use scoring::vector::{format_vector, parse_vector};

/// Assign CVSS v3.1 base scores to Linux kernel CVEs.
///
/// Examples:
///   cvss CVE-2026-22976 "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
///   cvss CVE-2026-22976 "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" --write
///   cvss --vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
///   cvss --batch scores.txt --write
#[derive(Parser, Debug)]
#[clap(author, version, about, verbatim_doc_comment)]
struct Args {
    /// CVE ID (e.g., CVE-2026-22976)
    #[clap(index = 1)]
    cve_id: Option<String>,

    /// CVSS v3.1 vector string
    #[clap(index = 2)]
    vector: Option<String>,

    /// Compute score from vector only (no CVE lookup)
    #[clap(long)]
    vector_only: Option<String>,

    /// Batch file: lines of "CVE-ID VECTOR" pairs
    #[clap(long)]
    batch: Option<PathBuf>,

    /// Write metrics into CVE JSON files
    #[clap(long)]
    write: bool,

    /// Preview writes without modifying files
    #[clap(long, conflicts_with = "write")]
    dry_run: bool,

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

/// Find the CVE JSON path using cve_utils library functions.
fn find_cve_json_path(cve_id: &str) -> Result<PathBuf> {
    let sha1_path = cve_validation::find_cve_id(cve_id)?
        .ok_or_else(|| anyhow!("CVE '{}' not found", cve_id))?;
    let json_path = sha1_path.with_extension("json");
    if !json_path.exists() {
        return Err(anyhow!(
            "JSON file not found: {}",
            json_path.display()
        ));
    }
    Ok(json_path)
}

/// Process a single CVE + vector pair.
fn process_single(
    cve_id: &str,
    vector_str: &str,
    args: &Args,
) -> Result<()> {
    let metrics = parse_vector(vector_str)?;
    let result = compute_base_score(&metrics);
    let canonical_vector = format_vector(&metrics);

    output::print_result(
        Some(cve_id),
        &canonical_vector,
        &metrics,
        &result,
        args.verbose,
        args.json,
    );

    if args.write || args.dry_run {
        let json_path = find_cve_json_path(cve_id)?;
        if args.dry_run {
            let preview =
                json_writer::build_metrics_value(&canonical_vector, result.score, &result.severity);
            eprintln!(
                "\nWould write to {}:\n{}",
                json_path.display(),
                serde_json::to_string_pretty(&preview).unwrap()
            );
        } else {
            json_writer::write_metrics(
                &json_path,
                &canonical_vector,
                result.score,
                &result.severity,
            )?;
            eprintln!("Wrote metrics to {}", json_path.display());
        }
    }

    Ok(())
}

/// Process a batch file of CVE-ID + vector pairs.
fn process_batch(batch_path: &Path, args: &Args) -> Result<()> {
    let content = fs::read_to_string(batch_path)
        .context(format!("failed to read batch file: {}", batch_path.display()))?;

    let mut errors = 0;
    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Split on first whitespace: "CVE-2026-22976 CVSS:3.1/..."
        let (cve_id, vector) = match line.split_once(char::is_whitespace) {
            Some((id, v)) => (id.trim(), v.trim()),
            None => {
                eprintln!("line {}: invalid format (expected 'CVE-ID VECTOR'): {line}", line_num + 1);
                errors += 1;
                continue;
            }
        };

        debug!("batch line {}: {} {}", line_num + 1, cve_id, vector);

        if let Err(e) = process_single(cve_id, vector, args) {
            eprintln!("line {}: {cve_id}: {e}", line_num + 1);
            errors += 1;
        }
    }

    if errors > 0 {
        Err(anyhow!("{errors} error(s) in batch processing"))
    } else {
        Ok(())
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    initialize_logging(args.verbose);

    // Vector-only mode: just compute and print
    if let Some(ref vector) = args.vector_only {
        let metrics = parse_vector(vector)?;
        let result = compute_base_score(&metrics);
        let canonical_vector = format_vector(&metrics);
        output::print_result(
            None,
            &canonical_vector,
            &metrics,
            &result,
            args.verbose,
            args.json,
        );
        return Ok(());
    }

    // Batch mode
    if let Some(ref batch_path) = args.batch {
        return process_batch(batch_path, &args);
    }

    // Single CVE mode
    let cve_id = args.cve_id.as_deref().ok_or_else(|| {
        anyhow!("provide a CVE ID and vector, or use --vector-only/--batch\n\nUsage: cvss <CVE_ID> <VECTOR>\n       cvss --vector-only <VECTOR>\n       cvss --batch <FILE>")
    })?;
    let vector = args.vector.as_deref().ok_or_else(|| {
        anyhow!("provide a CVSS vector string as the second argument\n\nUsage: cvss {cve_id} \"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\"")
    })?;

    process_single(cve_id, vector, &args)
}
