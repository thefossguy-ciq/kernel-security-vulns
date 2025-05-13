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
mod state;
mod kernel;

#[allow(clippy::too_many_lines)]
fn main() {
    // Default to no logging, can turn it on based on the command line.
    // Note, RUST_LOG_LEVEL does NOT work here anymore.  See
    // https://docs.rs/env_logger/latest/env_logger/#specifying-defaults-for-environment-variables
    // for a possible way to fix this up if anyone gets bored.
    let mut logging_level: log::LevelFilter = log::LevelFilter::Error;

    let program_name = env!("CARGO_BIN_NAME");
    let program_version = env!("CARGO_PKG_VERSION");

    // Parse our command line
    let args = cli::parse_args();

    // Will not work, move init of logger to above here if you want to see this
    debug!("{args:#?}");

    // If the version is asked for, just print that and exit
    if args.version {
        println!("{program_name} version: {program_version}");
        std::process::exit(0);
    }

    // Verify we at least got a git sha passed to us using the --sha1 flag
    // (not checking to see if it is valid just yet...)
    if args.sha1.is_empty() {
        println!("Error: At least one --sha1 value is required\n");
        std::process::exit(1);
    }

    // Set the logging level based on the command line option and turn on the logger
    if args.verbose {
        logging_level = log::LevelFilter::max();
    }
    env_logger::builder()
        .format_timestamp(None)
        .filter_level(logging_level)
        .init();

    // Copy the command line args to our local "state" so we can pass it around
    let mut state = state::DyadState::new();

    // Set up the locations of all of our external helper programs and databases are there before
    // we attempt to use any of them
    state::validate_env_vars(&mut state);

    // Calculate full git sha for each fixing SHA1 that was passed to us
    state.git_sha_full.clear(); // Clear any existing values
    for git_sha in &args.sha1 {
        if !kernel::process_fixing_sha(&mut state, git_sha) {
            error!(
                "Error: The provided git SHA1 '{git_sha}' could not be found in the repository"
            );
            std::process::exit(1);
        }
    }

    for (idx, full_id) in state.git_sha_full.iter().enumerate() {
        debug!(" Full git id {idx}: '{full_id:?}'");
    }

    // Parse the vulnerable command line and create a vector of vulnerable kernel ids.
    let vuln_ids = args.vulnerable.clone();
    for vuln_id in vuln_ids {
        if !kernel::process_vulnerable_sha(&mut state, &vuln_id) {
            error!(
                "Error: The provided vulnerable git SHA1 '{vuln_id}' could not be found in the repository"
            );
            std::process::exit(1);
        }
    }

    println!(
        "{} {} {} {}",
        "#".green(),
        program_name.purple(),
        "version:".green(),
        program_version.cyan()
    );

    // Print all fixing SHA1s
    for git_sha in &state.git_sha_full {
        println!(
            "{} {}",
            "# \tgetting vulnerable:fixed pairs for git id".green(),
            git_sha.git_id().cyan()
        );
    }

    // Find all of the places where each git commit was backported to
    kernel::find_fixed_kernels(&mut state);

    // Process explicitly provided vulnerable commits
    let mut vulnerable_kernels = kernel::add_provided_vulnerabilities(&mut state);

    // Derive vulnerabilities from fixing SHAs if needed
    kernel::derive_vulnerabilities(&mut state, &mut vulnerable_kernels);

    // Find backported vulnerable kernels and winnow the vulnerable set
    kernel::process_vulnerable_kernels(&mut state, &vulnerable_kernels);

    // Generate kernel pairs from vulnerable and fixed sets
    let fixed_pairs = kernel::generate_kernel_pairs(&state);

    // Filter and sort pairs for consistency
    let filtered_pairs = kernel::filter_and_sort_pairs(&fixed_pairs);

    // Print the final kernel pairs
    kernel::print_kernel_pairs(&filtered_pairs);
}