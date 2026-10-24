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
//        All of the real work happens in cve_utils::dyad_core, this is just
//        the command line front end for it.
//
// Usage: dyad --sha1 <git-sha> [--sha1 <git-sha> ...] [--vulnerable <git-sha> ...]

use cve_utils::dyad_core;
use log::{debug, error};
use owo_colors::{OwoColorize, Stream::Stdout};
use std::env;

mod cli;

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

/// Print the kernel pairs in the format required by bippy
fn print_kernel_pairs(pairs: &[cve_utils::KernelPair]) {
    for e in pairs {
        /* ***POLICY***
         * FIXME
         * Should we be testing for if we have a fix in an older kernel than was actually
         * vulnerable?  If so, uncomment this if {} out for it to print it in a comment only
         */
        /*
        if !e.fixed.is_empty() && (e.vulnerable > e.fixed) {
            print!("# fix before vulnerable ");
        }
        */
        println!(
            "{}:{}:{}:{}",
            e.vulnerable
                .version()
                .if_supports_color(Stdout, |x| x.green()),
            e.vulnerable
                .git_id()
                .if_supports_color(Stdout, |x| x.cyan()),
            e.fixed.version().if_supports_color(Stdout, |x| x.green()),
            e.fixed.git_id().if_supports_color(Stdout, |x| x.cyan())
        );
    }
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

    // Do all of the real work
    let result = match dyad_core::run(&args.sha1, &args.vulnerable) {
        Ok(result) => result,
        Err(e) => {
            error!("Error: {e}");
            std::process::exit(1);
        }
    };

    // output our version for the record to make things easier to track over time
    println!(
        "{} {} {} {}",
        "#".if_supports_color(Stdout, |x| x.green()),
        program_name.if_supports_color(Stdout, |x| x.purple()),
        "version:".if_supports_color(Stdout, |x| x.green()),
        program_version.if_supports_color(Stdout, |x| x.cyan())
    );

    for git_sha in &result.fixing_kernels {
        println!(
            "{} {}",
            "# \tgetting vulnerable:fixed pairs for git id"
                .if_supports_color(Stdout, |x| x.green()),
            git_sha.git_id().if_supports_color(Stdout, |x| x.cyan())
        );
    }

    for k in &result.vulnerable_kernels {
        println!(
            "{} {} {} {}",
            "# \tSetting original vulnerable kernel to be kernel"
                .if_supports_color(Stdout, |x| x.green()),
            k.version().if_supports_color(Stdout, |x| x.cyan()),
            "and git id".if_supports_color(Stdout, |x| x.green()),
            k.git_id().if_supports_color(Stdout, |x| x.cyan())
        );
    }

    // Print the final kernel pairs
    print_kernel_pairs(&result.pairs);
}
