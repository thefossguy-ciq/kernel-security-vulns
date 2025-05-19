// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{Context, Result};
use git2::Object;
use git2::Repository;

/// Get the commit subject for a git reference
pub fn get_commit_subject(_repo: &Repository, obj: &Object) -> Result<String> {
    let commit = obj
        .as_commit()
        .ok_or_else(|| anyhow::anyhow!("Object is not a commit"))?;

    Ok(commit.summary().unwrap_or("").to_string())
}

/// Get the full commit message text
pub fn get_commit_text(_repo: &Repository, obj: &Object) -> Result<String> {
    let commit = obj
        .as_commit()
        .ok_or_else(|| anyhow::anyhow!("Object is not a commit"))?;

    // Get the raw commit message - don't truncate
    let message = commit.message().unwrap_or("").to_string();

    Ok(message)
}

/// Apply a diff to text and return the result
pub fn apply_diff_to_text(text: &str, diff_file: &std::path::Path) -> Result<String> {
    // Create a temporary file
    let mut temp_file = tempfile::NamedTempFile::new()
        .with_context(|| "Failed to create temporary file for applying diff")?;

    // Write the original text to the temporary file
    std::io::Write::write_all(&mut temp_file, text.as_bytes())
        .with_context(|| "Failed to write to temporary file")?;

    // Get the path of the temporary file
    let temp_path = temp_file.path();

    // Run the patch command
    let status = std::process::Command::new("patch")
        .arg("-p1")
        .arg(temp_path)
        .arg(diff_file)
        .status()
        .with_context(|| format!("Failed to execute patch command with diff file {}", diff_file.display()))?;

    if !status.success() {
        return Err(anyhow::anyhow!(
            "Patch command failed with status: {status}"
        ));
    }

    // Read the modified content
    let modified_text = std::fs::read_to_string(temp_path)
        .with_context(|| "Failed to read patched temporary file")?;

    // Ensure we handle newlines consistently - trim trailing newlines and add exactly one
    let trimmed = modified_text.trim_end();

    // Return the text with exactly one newline at the end, same as the original handling
    if text.ends_with('\n') {
        Ok(format!("{trimmed}\n"))
    } else {
        Ok(trimmed.to_string())
    }
}
