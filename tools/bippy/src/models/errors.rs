// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use thiserror::Error;

/// Error types for the bippy tool
#[derive(Error, Debug)]
pub enum BippyError {
    /// Error when parsing a dyad entry
    #[error("Invalid dyad entry: {0}")]
    InvalidDyadEntry(String),

    #[error("Invalid dyad git_id: {0}")]
    InvalidDyadGitId(String),

    #[error("Invalid dyad version: {0}")]
    InvalidDyadVersion(String),

    /// Error in git2 library
    #[error("Git error: {0}")]
    GitError(#[from] git2::Error),

    /// Error in io operations
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}