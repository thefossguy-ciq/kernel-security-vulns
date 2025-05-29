// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::Result;
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

