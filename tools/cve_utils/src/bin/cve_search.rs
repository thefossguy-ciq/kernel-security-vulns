// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Result};
use clap::Parser;
use colored::Colorize;
use cve_utils::common;
use cve_utils::print_git_error_details;

/// Search the published CVE records for a git SHA or find a git SHA associated with a CVE ID
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Git SHA or CVE ID to search for
    #[clap(index = 1)]
    search_string: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.search_string.is_empty() {
        return Err(anyhow!("No search string provided"));
    }

    // Get the kernel tree and CVE root paths
    let kernel_tree = match common::get_kernel_tree() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error: {e}");
            print_git_error_details(&e);
            return Err(e);
        }
    };

    let cve_root = match common::get_cve_root() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error: {e}");
            print_git_error_details(&e);
            return Err(e);
        }
    };

    // Try to interpret the search string as a git SHA first
    if let Ok(_git_sha_full) = cve_utils::get_full_sha(&kernel_tree, &args.search_string) {
        // It's a valid SHA, search for it in the CVE records
        if let Some(cve) = common::find_cve_by_sha(&cve_root, &args.search_string) {
            println!("{} is assigned to git id {}",
                     cve.cyan(),
                     args.search_string.green());
            return Ok(());
        }
        println!("git sha1 {} not found in any CVE record.", args.search_string);
        return Ok(());
    }

    // If not a SHA or SHA not found, try interpreting as a CVE ID
    if let Some(sha) = common::find_sha_by_cve(&cve_root, &args.search_string) {
        println!("{} is assigned to git id {}",
                 args.search_string.cyan(),
                 sha.green());
    } else {
        println!("{} not found in any CVE record.", args.search_string);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use cve_utils::common;

    #[test]
    fn test_real_cve_lookup_by_id() {
        // Known CVEs from the database
        let test_cases = [
            ("CVE-2024-26581", "60c0c230c6f046da536d3df8b39a20b9a9fd6af0"),
            ("CVE-2024-26582", "32b55c5ff9103b8508c1e04bfa5a08c64e7a925f"),
            ("CVE-2023-52433", "2ee52ae94baabf7ee09cf2a8d854b990dac5d0e4"),
        ];

        let cve_root = common::get_cve_root().unwrap();

        for (cve_id, expected_sha) in test_cases {
            let result = common::find_sha_by_cve(&cve_root, cve_id);
            assert!(result.is_some(), "Should find SHA for {}", cve_id);
            assert_eq!(result.unwrap(), expected_sha, "SHA should match for {}", cve_id);
        }
    }

    #[test]
    fn test_real_cve_lookup_by_sha() {
        // Known SHAs from the database
        let test_cases = [
            ("60c0c230c6f046da536d3df8b39a20b9a9fd6af0", "CVE-2024-26581"),
            ("32b55c5ff9103b8508c1e04bfa5a08c64e7a925f", "CVE-2024-26582"),
            ("2ee52ae94baabf7ee09cf2a8d854b990dac5d0e4", "CVE-2023-52433"),
        ];

        let cve_root = common::get_cve_root().unwrap();

        for (sha, expected_cve) in test_cases {
            let result = common::find_cve_by_sha(&cve_root, sha);
            assert!(result.is_some(), "Should find CVE for {}", sha);
            assert_eq!(result.unwrap(), expected_cve, "CVE should match for {}", sha);
        }
    }

    #[test]
    fn test_partial_sha_lookup() {
        // Partial SHAs that should still resolve correctly
        let test_cases = [
            ("60c0c230", "CVE-2024-26581"),
            ("32b55c5f", "CVE-2024-26582"),
            ("2ee52ae9", "CVE-2023-52433"),
        ];

        let cve_root = common::get_cve_root().unwrap();

        for (partial_sha, expected_cve) in test_cases {
            let result = common::find_cve_by_sha(&cve_root, partial_sha);
            assert!(result.is_some(), "Should find CVE for partial SHA {}", partial_sha);
            assert_eq!(result.unwrap(), expected_cve, "CVE should match for partial SHA {}", partial_sha);
        }
    }

    #[test]
    fn test_nonexistent_cve_lookup() {
        let cve_root = common::get_cve_root().unwrap();

        let result = common::find_sha_by_cve(&cve_root, "NON-EXISTENT-CVE");
        assert!(result.is_none(), "Should not find SHA for non-existent CVE");
    }
}
