// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//
// dyad - create a listing of "pairs" of vulnerable:fixed kernels based on a
//        specific git SHA that purports to fix an issue.  Used in combination
//        with 'bippy' to create CVE entries for the Linux kernel.  Is VERY
//        specific to how the Linux kernel has its stable branches and how it
//        labels things.
//
// Usage: dyad --sha1 <git-sha> [--sha1 <git-sha> ...] [--vulnerable <git-sha> ...]

use colored::Colorize;
use log::{debug, error};
use std::env;
extern crate cve_utils;

mod cli;
mod kernel;
mod state;

/// Initialize and configure the logging system
fn initialize_logging(verbose: bool) -> log::LevelFilter {
    // Default to error level, but can turn it on based on the command line option
    let logging_level = if verbose {
        log::LevelFilter::max()
    } else {
        log::LevelFilter::Error
    };

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(logging_level)
        .init();

    logging_level
}

/// Process fixing SHA1s from command line arguments
fn process_fixing_shas(state: &mut state::DyadState, shas: &[String]) -> bool {
    state.git_sha_full.clear(); // Clear any existing values

    for git_sha in shas {
        if !kernel::process_fixing_sha(state, git_sha) {
            error!("Error: The provided git SHA1 '{git_sha}' could not be found in the repository");
            return false;
        }
    }

    // Print information about the fixing SHA1s
    for (idx, full_id) in state.git_sha_full.iter().enumerate() {
        debug!(" Full git id {idx}: '{full_id:?}'");
    }

    for git_sha in &state.git_sha_full {
        println!(
            "{} {}",
            "# \tgetting vulnerable:fixed pairs for git id".green(),
            git_sha.git_id().cyan()
        );
    }

    true
}

/// Process vulnerable SHA1s from command line arguments
fn process_vulnerable_shas(state: &mut state::DyadState, shas: &[String]) -> bool {
    for vuln_id in shas {
        if !kernel::process_vulnerable_sha(state, vuln_id) {
            error!(
                "Error: The provided vulnerable git SHA1 '{vuln_id}' could not be found in the repository"
            );
            return false;
        }
    }

    true
}

/// Process and generate kernel pairs
fn process_kernel_pairs(state: &mut state::DyadState) {
    // Find all of the places where each git commit was backported to
    kernel::find_fixed_kernels(state);

    // Process explicitly provided vulnerable commits
    let mut vulnerable_kernels = kernel::add_provided_vulnerabilities(state);

    // Derive vulnerabilities from fixing SHAs if needed
    kernel::derive_vulnerabilities(state, &mut vulnerable_kernels);

    // Find backported vulnerable kernels and winnow the vulnerable set
    kernel::process_vulnerable_kernels(state, &vulnerable_kernels);

    // Generate kernel pairs from vulnerable and fixed sets
    let fixed_pairs = kernel::generate_kernel_pairs(state);

    // Filter and sort pairs for consistency
    let filtered_pairs = kernel::filter_and_sort_pairs(&fixed_pairs);

    // Print the final kernel pairs
    kernel::print_kernel_pairs(&filtered_pairs);
}

fn main() {
    // Parse command line arguments
    let args = cli::parse_args();
    let program_name = env!("CARGO_BIN_NAME");
    let program_version = env!("CARGO_PKG_VERSION");

    // Handle version request
    if args.version {
        println!("{program_name} version: {program_version}");
        std::process::exit(0);
    }

    // Verify we have at least one SHA1
    if args.sha1.is_empty() {
        println!("Error: At least one --sha1 value is required\n");
        std::process::exit(1);
    }

    // Initialize logging system
    initialize_logging(args.verbose);

    // Debug message will only be seen after logger is initialized
    debug!("{args:#?}");

    // Initialize state
    let mut state = state::DyadState::new();
    state::validate_env_vars(&mut state);

    // output our version for the record to make things easier to track over time
    println!(
        "{} {} {} {}",
        "#".green(),
        program_name.purple(),
        "version:".green(),
        program_version.cyan()
    );

    // Process fixing SHA1s
    if !process_fixing_shas(&mut state, &args.sha1) {
        std::process::exit(1);
    }

    // Process vulnerable SHA1s
    if !process_vulnerable_shas(&mut state, &args.vulnerable) {
        std::process::exit(1);
    }

    // Process and generate kernel pairs
    process_kernel_pairs(&mut state);
}
