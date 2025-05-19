// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{Context, Result};
use log::debug;
use std::fmt::Write;
use std::path::Path;

/// Run the dyad script to get version range information
pub fn run_dyad(
    script_dir: &Path,
    git_shas: &[String],
    vulnerable_shas: &[String],
) -> Result<String> {
    // Ensure dyad script exists
    let dyad_script = script_dir.join("dyad");
    if !dyad_script.exists() {
        return Err(anyhow::anyhow!(
            "Dyad script not found at {}",
            dyad_script.display()
        ));
    }

    // Change directory to the scripts directory
    let current_dir = std::env::current_dir()?;
    std::env::set_current_dir(script_dir)?;

    // Get kernel tree paths from environment variables
    let kernel_tree = std::env::var("CVEKERNELTREE")
        .with_context(|| "CVEKERNELTREE environment variable is not set")?;

    // Construct the command
    let mut command = std::process::Command::new(&dyad_script);

    // Set environment variables
    command.env("CVEKERNELTREE", &kernel_tree);

    // Add each vulnerable SHA as a separate -v argument
    for vuln_sha in vulnerable_shas {
        if !vuln_sha.trim().is_empty() {
            command.arg("-v").arg(vuln_sha);
            debug!("Using vulnerable SHA: {vuln_sha}");
        }
    }

    // Add each Git SHA as a separate --sha1 argument
    for git_sha in git_shas {
        if !git_sha.trim().is_empty() {
            command.arg("--sha1").arg(git_sha);
            debug!("Using fix SHA: {git_sha}");
        }
    }

    debug!("Running command: {command:?}");

    // Execute the command
    let output = command
        .output()
        .with_context(|| format!("Failed to execute dyad script at {}", dyad_script.display()))?;

    // Restore original directory
    std::env::set_current_dir(current_dir)?;

    // Check for success
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let status = output.status;
        let mut error_msg = format!("Dyad script failed with status: {status}");

        if !stderr.is_empty() {
            write!(error_msg, "\nStderr: {stderr}").unwrap();
        }

        if !stdout.is_empty() {
            write!(error_msg, "\nStdout: {stdout}").unwrap();
        }

        return Err(anyhow::anyhow!("{error_msg}"));
    }

    // Return the output
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(stdout)
}
