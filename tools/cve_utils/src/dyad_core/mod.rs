// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//
// dyad_core - create a listing of "pairs" of vulnerable:fixed kernels based
//             on specific git SHAs that purport to fix an issue.  This is the
//             engine behind the 'dyad' tool, usable as a library so that
//             tools which process many CVEs (e.g. update_dyad) do not have to
//             fork one dyad process per CVE.

use crate::{Kernel, KernelPair};
use anyhow::{anyhow, Result};
use std::fmt::Write;

mod kernel_pairs;
mod sha_processing;
mod state;
mod vulnerability;

pub use state::DyadState;

/// The result of a dyad run: everything needed to produce the dyad output
/// for a set of fixing (and optionally vulnerable) commits.
#[derive(Debug)]
pub struct DyadResult {
    /// The resolved fixing commits that were asked for
    pub fixing_kernels: Vec<Kernel>,
    /// The explicitly provided vulnerable commits, if any
    pub vulnerable_kernels: Vec<Kernel>,
    /// The computed vulnerable:fixed kernel pairs
    pub pairs: Vec<KernelPair>,
}

/// Compute the vulnerable:fixed kernel pairs for the given fixing commits.
///
/// `fixing_shas` is the list of git ids that fix the issue (i.e. the --sha1
/// options of the dyad tool), `vulnerable_shas` the optional list of git ids
/// where the issue became vulnerable (i.e. the --vulnerable options).
///
/// # Errors
///
/// Returns an error if:
/// - The kernel tree or the verhaal database cannot be found
/// - One of the provided git SHA1 values cannot be found in the repository
/// - No vulnerable:fixed pairs of kernels were found for the commit(s)
pub fn run(fixing_shas: &[String], vulnerable_shas: &[String]) -> Result<DyadResult> {
    // Initialize state
    let mut state = DyadState::new();
    state::validate_env_vars(&mut state)?;

    // Process fixing SHA1s
    for git_sha in fixing_shas {
        if !sha_processing::process_fixing_sha(&mut state, git_sha) {
            return Err(anyhow!(
                "The provided git SHA1 '{git_sha}' could not be found in the repository"
            ));
        }
    }

    // Process vulnerable SHA1s
    for vuln_id in vulnerable_shas {
        if !sha_processing::process_vulnerable_sha(&mut state, vuln_id) {
            return Err(anyhow!(
                "The provided vulnerable git SHA1 '{vuln_id}' could not be found in the repository"
            ));
        }
    }

    // Find all of the places where each git commit was backported to
    vulnerability::find_fixed_kernels(&mut state)?;

    // Process explicitly provided vulnerable commits
    let mut vulnerable_kernels = vulnerability::add_provided_vulnerabilities(&state);

    // Derive vulnerabilities from fixing SHAs if needed
    vulnerability::derive_vulnerabilities(&mut state, &mut vulnerable_kernels);

    // Find backported vulnerable kernels and winnow the vulnerable set
    vulnerability::process_vulnerable_kernels(&mut state, &vulnerable_kernels);

    // Generate kernel pairs from vulnerable and fixed sets
    let fixed_pairs = kernel_pairs::generate_kernel_pairs(&state);

    // Filter and sort pairs for consistency
    let pairs = kernel_pairs::filter_and_sort_pairs(fixed_pairs);

    Ok(DyadResult {
        fixing_kernels: state.git_sha_full,
        vulnerable_kernels: state.vulnerable_sha,
        pairs,
    })
}

/// Format a `DyadResult` as the canonical (uncolored) dyad output.
///
/// The output is the version and commit comment headers followed by one
/// vulnerable:fixed pair per line.  This is exactly what the dyad tool
/// writes when its output is redirected to a .dyad file.
#[must_use]
pub fn format_output(result: &DyadResult) -> String {
    let mut out = String::new();

    // output our version for the record to make things easier to track over time
    let _ = writeln!(out, "# dyad version: {}", env!("CARGO_PKG_VERSION"));

    for kernel in &result.fixing_kernels {
        let _ = writeln!(
            out,
            "# \tgetting vulnerable:fixed pairs for git id {}",
            kernel.git_id()
        );
    }

    for kernel in &result.vulnerable_kernels {
        let _ = writeln!(
            out,
            "# \tSetting original vulnerable kernel to be kernel {} and git id {}",
            kernel.version(),
            kernel.git_id()
        );
    }

    for pair in &result.pairs {
        let _ = writeln!(
            out,
            "{}:{}:{}:{}",
            pair.vulnerable.version(),
            pair.vulnerable.git_id(),
            pair.fixed.version(),
            pair.fixed.git_id()
        );
    }

    out
}
