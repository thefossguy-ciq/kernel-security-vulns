// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use cve_utils::git_utils::{get_affected_files, resolve_reference};
use cve_utils::version_utils::compare_kernel_versions;
use git2::Repository;
use log::error;
use std::fmt::Write;

use crate::models::DyadEntry;

/// Generate an mbox file for the CVE
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn generate_mbox(
    cve_number: &str,
    git_sha_full: &str,
    commit_subject: &str,
    user_name: &str,
    user_email: &str,
    dyad_entries: &Vec<DyadEntry>,
    script_name: &str,
    script_version: &str,
    additional_references: &[String],
    commit_text: &str,
) -> String {
    // For the From line we need the script name and version
    let from_line = format!(
        "From {script_name}-{script_version} Mon Sep 17 00:00:00 2001"
    );

    // Parse dyad output to generate vulnerability information
    let mut vuln_array_mbox = Vec::new();
    let Ok(kernel_tree) = std::env::var("CVEKERNELTREE") else {
        error!("CVEKERNELTREE environment variable is not set");
        return format!(
            "{from_line}\n\
            From: {user_name} <{user_email}>\n\
            To: <linux-cve-announce@vger.kernel.org>\n\
            Reply-to: <cve@kernel.org>, <linux-kernel@vger.kernel.org>\n\
            Subject: {cve_number}: {commit_subject}\n\
            \n\
            Error: CVEKERNELTREE environment variable is not set"
        );
    };

    let Ok(repo) = Repository::open(&kernel_tree) else {
        let e = format!("Failed to open kernel repo at {kernel_tree}");
        error!("{e}");
        return format!(
            "{from_line}\n\
            From: {user_name} <{user_email}>\n\
            To: <linux-cve-announce@vger.kernel.org>\n\
            Reply-to: <cve@kernel.org>, <linux-kernel@vger.kernel.org>\n\
            Subject: {cve_number}: {commit_subject}\n\
            \n\
            Error: Failed to open kernel repository"
        );
    };

    // Parse the dyad output
    for entry in dyad_entries {
        // Handle unfixed vulnerabilities
        if entry.fixed.is_empty() {
            // Issue is not fixed, so say that:
            vuln_array_mbox.push(format!(
                "Issue introduced in {} with commit {}",
                entry.vulnerable.version(),
                entry.vulnerable.git_id()
            ));
            continue;
        }

        // Skip entries where the vulnerability is in the same version it was fixed
        if entry.vulnerable.version() == entry.fixed.version() {
            continue;
        }

        // Handle different types of entries
        if entry.vulnerable.is_empty() {
            // We do not know when it showed up, so just say it is fixed
            vuln_array_mbox.push(format!(
                "Fixed in {} with commit {}",
                entry.fixed.version(),
                entry.fixed.git_id()
            ));
        } else {
            // Report when it was introduced and when it was fixed
            vuln_array_mbox.push(format!(
                "Issue introduced in {} with commit {} and fixed in {} with commit {}",
                entry.vulnerable.version(),
                entry.vulnerable.git_id(),
                entry.fixed.version(),
                entry.fixed.git_id()
            ));
        }
    }

    // If no vulnerabilities were found, do NOT create a CVE at all!
    if vuln_array_mbox.is_empty() {
        error!("Despite having some vulnerable:fixed kernels, none were in an actual release, so aborting and not assigning a CVE to {git_sha_full}");
        std::process::exit(1);
    }

    // Get affected files from the commit
    let affected_files = match resolve_reference(&repo, git_sha_full) {
        Ok(obj) => get_affected_files(&repo, &obj).unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    // First add all fix commit URLs from dyad entries (except the main fix)
    let mut version_url_pairs = Vec::new();
    for entry in dyad_entries {
        if !entry.fixed.is_empty() && entry.fixed.git_id() != git_sha_full {
            let fix_url = format!("https://git.kernel.org/stable/c/{}", entry.fixed.git_id());
            if !version_url_pairs.iter().any(|(_, url)| url == &fix_url) {
                version_url_pairs.push((entry.fixed.version().clone(), fix_url));
            }
        }
    }

    // Sort the URLs by kernel version
    version_url_pairs.sort_by(|(ver_a, _), (ver_b, _)| {
        // Use the shared compare_kernel_versions function
        compare_kernel_versions(ver_a, ver_b)
    });

    // Build the URL array from the sorted pairs
    let mut url_array = version_url_pairs
        .into_iter()
        .map(|(_, url)| url)
        .collect::<Vec<_>>();

    // Add the main fix commit URL at the end
    url_array.push(format!("https://git.kernel.org/stable/c/{git_sha_full}"));

    // Add any additional references from the reference file
    for url in additional_references {
        if !url_array.contains(url) {
            url_array.push(url.clone());
        }
    }

    // Format the vulnerability summary section
    let mut vuln_section = String::new();
    for line in vuln_array_mbox {
        writeln!(vuln_section, "\t{line}").unwrap();
    }

    // Format the affected files section
    let mut files_section = String::new();
    for file in affected_files {
        writeln!(files_section, "\t{file}").unwrap();
    }

    // Format the mitigation section with URLs
    let mut url_section = String::new();
    for url in url_array {
        writeln!(url_section, "\t{url}").unwrap();
    }

    // Use the provided commit_text, which might have been modified by the diff
    let commit_message = commit_text;

    // The full formatted mbox content
    let result = format!(
        "{}\n\
         From: {} <{}>\n\
         To: <linux-cve-announce@vger.kernel.org>\n\
         Reply-to: <cve@kernel.org>, <linux-kernel@vger.kernel.org>\n\
         Subject: {}: {}\n\
         \n\
         Description\n\
         ===========\n\
         \n\
         {}\n\
         \n\
         The Linux kernel CVE team has assigned {} to this issue.\n\
         \n\
         \n\
         Affected and fixed versions\n\
         ===========================\n\
         \n\
         {}\n\
         Please see https://www.kernel.org for a full list of currently supported\n\
         kernel versions by the kernel community.\n\
         \n\
         Unaffected versions might change over time as fixes are backported to\n\
         older supported kernel versions.  The official CVE entry at\n\
         \thttps://cve.org/CVERecord/?id={}\n\
         will be updated if fixes are backported, please check that for the most\n\
         up to date information about this issue.\n\
         \n\
         \n\
         Affected files\n\
         ==============\n\
         \n\
         The file(s) affected by this issue are:\n\
         {}\n\
         \n\
         Mitigation\n\
         ==========\n\
         \n\
         The Linux kernel CVE team recommends that you update to the latest\n\
         stable kernel version for this, and many other bugfixes.  Individual\n\
         changes are never tested alone, but rather are part of a larger kernel\n\
         release.  Cherry-picking individual commits is not recommended or\n\
         supported by the Linux kernel community at all.  If however, updating to\n\
         the latest release is impossible, the individual changes to resolve this\n\
         issue can be found at these commits:\n\
         {}",
        from_line,
        user_name,
        user_email,
        cve_number,
        commit_subject,
        commit_message.trim_end(), // Trim any trailing newlines
        cve_number,
        vuln_section,
        cve_number,
        files_section,
        url_section
    );

    // Ensure the result ends with a newline
    if result.ends_with('\n') {
        result
    } else {
        result + "\n"
    }
}