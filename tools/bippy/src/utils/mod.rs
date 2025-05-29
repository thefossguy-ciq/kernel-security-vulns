// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

pub mod dyad;
pub mod file;
pub mod git;
pub mod text;
pub mod version;

pub use dyad::run_dyad;
pub use file::{read_message_file, read_tags_file, read_uuid};
pub use git::{get_commit_subject, get_commit_text};
pub use text::strip_commit_text;
pub use version::{
    determine_default_status, generate_cpe_ranges, generate_git_ranges, generate_version_ranges,
};
