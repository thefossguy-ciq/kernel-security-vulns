// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use clap::Parser;
use std::path::PathBuf;

/// Arguments for the bippy tool
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None, disable_version_flag = true, trailing_var_arg = true)]
pub struct Args {
    /// CVE number (e.g., "CVE-2021-1234")
    #[clap(short, long)]
    pub cve: Option<String>,

    /// Git SHA(s) of the commit(s)
    #[clap(short, long, num_args = 1..)]
    pub sha: Vec<String>,

    /// Git SHA(s) of the vulnerable commit(s) (optional, can be specified multiple times)
    #[clap(short = 'V', long, num_args = 1..)]
    pub vulnerable: Vec<String>,

    /// Output JSON file path
    #[clap(short, long)]
    pub json: Option<PathBuf>,

    /// Output mbox file path
    #[clap(short, long)]
    pub mbox: Option<PathBuf>,

    /// Diff file to apply to the commit text (optional)
    #[clap(short, long)]
    pub diff: Option<PathBuf>,

    /// Reference file path
    #[clap(short, long)]
    pub reference: Option<PathBuf>,

    /// User email
    #[clap(short, long)]
    pub user: Option<String>,

    /// User name
    #[clap(short = 'n', long)]
    pub name: Option<String>,

    /// Verbose output
    #[clap(short, long)]
    pub verbose: bool,

    /// Catch any trailing arguments
    #[clap(hide = true)]
    pub remaining_parameters: Vec<String>,
}