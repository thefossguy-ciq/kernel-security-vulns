// SPDX-License-Identifier: GPL-2.0-only
//
// cvss - assign CVSS v3.1 base scores to Linux kernel CVEs
//
// Copyright (c) 2026 - Sasha Levin <sashal@kernel.org>

mod output;
mod scoring;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::debug;
use std::fs;
use std::path::PathBuf;

use cve_utils::cve_validation;
use scoring::formula::compute_base_score;
use scoring::vector::{format_vector, parse_vector};

/// Assign CVSS v3.1 base scores to Linux kernel CVEs.
///
/// Examples:
///   cvss CVE-2026-22976 "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
///   cvss --vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
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

/// Process a single CVE + vector pair: validate, compute, and write .cvss file.
fn process_single(cve_id: &str, vector_str: &str, args: &Args) -> Result<()> {
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

    let cvss_path = find_cve_base_path(cve_id)?;

    // Use provided CNA ID or read from linux.uuid
    let cna_id = match &args.cna_id {
        Some(id) => id.clone(),
        None => {
            let vulns_dir = cve_utils::find_vulns_dir()?;
            let uuid = fs::read_to_string(vulns_dir.join("scripts/linux.uuid"))
                .context("failed to read scripts/linux.uuid")?;
            uuid.trim().to_string()
        }
    };

    // Write as "CNA_ID CVSS_VECTOR" format
    let content = format!("{cna_id} {canonical_vector}\n");
    fs::write(&cvss_path, &content)
        .context(format!("failed to write {}", cvss_path.display()))?;

    debug!("Wrote {}", cvss_path.display());
    eprintln!("Wrote {}", cvss_path.display());

    Ok(())
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

    // Single CVE mode
    let cve_id = args.cve_id.as_deref().ok_or_else(|| {
        anyhow!("provide a CVE ID and vector, or use --vector-only\n\nUsage: cvss <CVE_ID> <VECTOR>\n       cvss --vector-only <VECTOR>")
    })?;
    let vector = args.vector.as_deref().ok_or_else(|| {
        anyhow!("provide a CVSS vector string as the second argument\n\nUsage: cvss {cve_id} \"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\"")
    })?;

    process_single(cve_id, vector, &args)
}
