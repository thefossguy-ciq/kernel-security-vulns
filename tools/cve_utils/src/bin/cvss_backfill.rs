// SPDX-License-Identifier: GPL-2.0-only
//
// One-shot migration: move the explanation for each CVSS score out of the
// commit message that added the .cvss file and into the file itself.
//
// Copyright (c) 2026 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use cve_utils::common;
use cve_utils::cvss::file::CvssFile;
use cve_utils::cvss::rationale::Rationale;
use rayon::prelude::*;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

/// Backfill .cvss rationales from the git history.
#[derive(Parser, Debug)]
#[clap(author, version, about, verbatim_doc_comment)]
struct Args {
    /// Write the files (without this, only report what would change)
    #[clap(long)]
    write: bool,

    /// Overwrite a rationale the file already has
    #[clap(long)]
    force: bool,

    /// Limit the walk to these paths instead of the whole cve/ tree
    #[clap(value_name = "PATH")]
    paths: Vec<PathBuf>,
}

enum Outcome {
    /// Rationale recovered from the commit message. `note` records any
    /// repair that had to be made along the way.
    Backfilled {
        per_metric: bool,
        note: Option<String>,
    },
    /// The file already had one.
    AlreadyPresent,
    Failed(String),
}

fn collect_cvss_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let roots = if paths.is_empty() {
        vec![common::get_cve_root()?]
    } else {
        paths.to_vec()
    };

    let mut files = Vec::new();
    for root in roots {
        if root.is_file() {
            files.push(root);
            continue;
        }

        for entry in WalkDir::new(&root).into_iter().filter_map(Result::ok) {
            let path = entry.path();
            if path.is_file() && path.extension().is_some_and(|ext| ext == "cvss") {
                files.push(path.to_path_buf());
            }
        }
    }

    files.sort();
    Ok(files)
}

fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .context("failed to run git")?;

    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args[0],
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Map every .cvss path to the commit that first added it.
///
/// One history walk for the whole tree; doing this per file with --follow
/// takes hours. Renames are followed by hand for the same reason --follow
/// matters: a .cvss file moved from published/ to rejected/ has its
/// explanation in the commit that created the original.
fn adding_commits(repo: &Path) -> Result<HashMap<PathBuf, String>> {
    let log = git(
        repo,
        &[
            "log",
            "--reverse",
            "--diff-filter=AR",
            "--name-status",
            "--format=commit %H",
            "--",
            "*.cvss",
        ],
    )?;

    let mut origins: HashMap<PathBuf, String> = HashMap::new();
    let mut added: HashMap<String, usize> = HashMap::new();
    let mut sha = String::new();

    for line in log.lines() {
        if let Some(rest) = line.strip_prefix("commit ") {
            sha = rest.trim().to_string();
            continue;
        }

        let mut fields = line.split('\t');
        let Some(status) = fields.next() else { continue };

        match status.chars().next() {
            Some('A') => {
                if let Some(path) = fields.next() {
                    origins.insert(PathBuf::from(path), sha.clone());
                    *added.entry(sha.clone()).or_default() += 1;
                }
            }
            Some('R') => {
                if let (Some(from), Some(to)) = (fields.next(), fields.next()) {
                    let origin = origins
                        .remove(Path::new(from))
                        .unwrap_or_else(|| sha.clone());
                    origins.insert(PathBuf::from(to), origin);
                }
            }
            _ => {}
        }
    }

    // One message explains one score. A commit that adds several .cvss files
    // gives no way to tell which explanation belongs to which, and guessing
    // would attach one CVE's reasoning to another's score.
    origins.retain(|_, sha| added.get(sha).copied().unwrap_or(0) <= 1);

    Ok(origins)
}

/// Fetch the messages of every commit we care about in one go.
fn commit_messages(repo: &Path, shas: &BTreeSet<String>) -> Result<HashMap<String, String>> {
    if shas.is_empty() {
        return Ok(HashMap::new());
    }

    let mut args = vec!["log", "--no-walk", "--format=%H%x1f%B%x1e"];
    args.extend(shas.iter().map(String::as_str));

    let log = git(repo, &args)?;

    let mut messages = HashMap::new();
    for record in log.split('\x1e') {
        let Some((sha, message)) = record.trim_start().split_once('\x1f') else {
            continue;
        };
        messages.insert(sha.to_string(), message.to_string());
    }

    Ok(messages)
}

/// Pull the explanation out of a "CVE-...: Add CVSS 3.1 score" message.
///
/// The body is everything between the vector line, if there is one, and the
/// sign-off. Older entries have no vector line and no per-metric structure,
/// just prose after the subject.
fn rationale_from_message(message: &str) -> Result<(Rationale, Option<String>)> {
    let lines: Vec<&str> = message.lines().collect();

    let start = lines
        .iter()
        .position(|line| line.trim_start().starts_with("CVSS:3.1/"))
        .map_or(1, |i| i + 1);

    // Stop at the trailer block, not at Signed-off-by specifically: anything
    // above it - Co-developed-by, Reviewed-by - would otherwise be swept into
    // the last metric's justification and published as part of it. Search
    // from the body, since the subject "CVE-...: Add CVSS 3.1 score (...)"
    // has the shape of a trailer too.
    let end = lines
        .iter()
        .skip(start)
        .position(|line| is_trailer(line))
        .map_or(lines.len(), |i| start + i);

    if start >= end {
        bail!("no explanation between the subject and the sign-off");
    }

    let body = lines[start..end].join("\n");
    let (body, note) = match repair_misfiled_paragraph(&body) {
        Some((repaired, note)) => (repaired, Some(note)),
        None => (body, None),
    };

    let mut rationale = Rationale::parse(&body)?;

    match &mut rationale {
        Rationale::PerMetric(entries) => {
            for entry in entries {
                entry.text = dedupe_repeats(&entry.text);
            }
        }
        Rationale::Prose(paragraphs) => {
            for paragraph in paragraphs {
                *paragraph = dedupe_repeats(paragraph);
            }
        }
    }

    Ok((rationale, note))
}

/// Width the generator wrapped justifications to, via `fold -s -w 68`.
/// `fold -s` keeps the blank it broke on and counts it, so a line that could
/// still have taken the next word was ended by a newline in the source rather
/// than by wrapping. That is how a paragraph break survives in the message.
const FOLD_WIDTH: usize = 68;

/// One metric's justification as it appears in a commit message, split back
/// into the paragraphs the generator folded together.
struct MessageBlock {
    key: String,
    paragraphs: Vec<String>,
}

fn split_blocks(body: &str) -> Option<Vec<MessageBlock>> {
    let mut blocks: Vec<Vec<&str>> = Vec::new();

    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if metric_key(line).is_some() {
            blocks.push(vec![line]);
        } else {
            blocks.last_mut()?.push(line);
        }
    }

    if blocks.is_empty() {
        return None;
    }

    Some(
        blocks
            .iter()
            .map(|lines| {
                let key = metric_key(lines[0]).unwrap_or_default();
                let first = lines[0]
                    .split_once('-')
                    .map_or("", |(_, rest)| rest)
                    .trim()
                    .to_string();

                let mut paragraphs = Vec::new();
                let mut current = vec![first];

                for (i, line) in lines.iter().enumerate() {
                    let content = if i == 0 {
                        *line
                    } else {
                        let trimmed = line.trim_start();
                        current.push(trimmed.to_string());
                        trimmed
                    };

                    let Some(next) = lines.get(i + 1) else { continue };
                    let word = next.split_whitespace().next().unwrap_or_default();
                    if content.chars().count() + word.chars().count() + 2 <= FOLD_WIDTH {
                        paragraphs.push(current.join(" ").trim().to_string());
                        current.clear();
                    }
                }

                paragraphs.push(current.join(" ").trim().to_string());
                MessageBlock { key, paragraphs }
            })
            .collect(),
    )
}

/// The "AV:L" of an unindented "AV:L - ..." line.
fn metric_key(line: &str) -> Option<String> {
    if line.starts_with(char::is_whitespace) {
        return None;
    }

    let (head, _) = line.split_once('-')?;
    let (key, value) = head.trim_end().split_once(':')?;

    let known = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"].contains(&key);
    let valued = value.len() == 1 && value.chars().all(|c| c.is_ascii_uppercase());

    (known && valued).then(|| format!("{key}:{value}"))
}

/// Put back a justification that was filed under the previous metric.
///
/// When the model emitted one metric's label where the next metric's
/// belonged, the generator collected two lines for the first metric and none
/// for the second, so one block carries an extra paragraph and the block
/// right after it is empty. The extra paragraph is the missing one.
///
/// Only applied when that signature is exact - one block with one extra
/// paragraph, immediately followed by the one and only empty block - so
/// anything else is still reported rather than guessed at.
fn repair_misfiled_paragraph(body: &str) -> Option<(String, String)> {
    let mut blocks = split_blocks(body)?;

    let extra: Vec<usize> = (0..blocks.len())
        .filter(|&i| blocks[i].paragraphs.len() == 2)
        .collect();
    let empty: Vec<usize> = (0..blocks.len())
        .filter(|&i| blocks[i].paragraphs[0].is_empty())
        .collect();

    let ([from], [to]) = (extra.as_slice(), empty.as_slice()) else {
        return None;
    };
    if *to != from + 1 || blocks.iter().any(|b| b.paragraphs.len() > 2) {
        return None;
    }

    let orphan = blocks[*from].paragraphs.pop()?;
    blocks[*to].paragraphs[0] = orphan;

    let note = format!("moved a paragraph from {} to {}", blocks[*from].key, blocks[*to].key);
    let repaired = blocks
        .iter()
        .map(|block| format!("{} - {}", block.key, block.paragraphs.join(" ")))
        .collect::<Vec<_>>()
        .join("\n");

    Some((repaired, note))
}

/// Whether a line is a git trailer such as "Signed-off-by: ...".
fn is_trailer(line: &str) -> bool {
    let Some((key, rest)) = line.split_once(':') else {
        return false;
    };

    rest.starts_with(' ')
        && !key.is_empty()
        && key.starts_with(|c: char| c.is_ascii_uppercase())
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Collapse text that is one sentence repeated: "X X" and "X X X" become "X".
///
/// A few commit messages carry a justification two or three times over,
/// because the generator collected every line matching the metric's label
/// and the model emitted that label more than once. Publishing the
/// repetition would just look like a mistake, which is what it is.
fn dedupe_repeats(text: &str) -> String {
    let words: Vec<&str> = text.split(' ').collect();

    // Most copies first: testing two first would reduce "X X X X" to "X X".
    for copies in (2..=4).rev() {
        if !words.len().is_multiple_of(copies) {
            continue;
        }

        let unit = words.len() / copies;
        if (1..copies).all(|i| words[i * unit..(i + 1) * unit] == words[..unit]) {
            return words[..unit].join(" ");
        }
    }

    text.to_string()
}

struct History {
    origins: HashMap<PathBuf, String>,
    messages: HashMap<String, String>,
}

fn backfill_one(history: &History, repo: &Path, path: &Path, args: &Args) -> Outcome {
    match backfill_one_inner(history, repo, path, args) {
        Ok(outcome) => outcome,
        Err(e) => Outcome::Failed(format!("{e:#}")),
    }
}

fn backfill_one_inner(
    history: &History,
    repo: &Path,
    path: &Path,
    args: &Args,
) -> Result<Outcome> {
    let mut file = CvssFile::read(path)?;

    if file.rationale.is_some() && !args.force {
        return Ok(Outcome::AlreadyPresent);
    }

    let relative = path.strip_prefix(repo).unwrap_or(path);
    let sha = history
        .origins
        .get(relative)
        .ok_or_else(|| anyhow!("no commit adds this file"))?;
    let message = history
        .messages
        .get(sha)
        .ok_or_else(|| anyhow!("no message for {sha}"))?;
    let (rationale, note) = rationale_from_message(message)
        .context(format!("recovering the rationale from {sha}"))?;

    let per_metric = matches!(rationale, Rationale::PerMetric(_));

    file.rationale = Some(rationale);
    file.validate()
        .context(format!("the rationale in {sha} does not match the vector"))?;

    if args.write {
        file.write(path)?;
    }

    Ok(Outcome::Backfilled { per_metric, note })
}

fn main() -> Result<()> {
    let args = Args::parse();
    let repo = common::find_vulns_dir()?;
    let files = collect_cvss_files(&args.paths)?;

    if files.is_empty() {
        println!("No .cvss files found");
        return Ok(());
    }

    println!("Reading history for {} .cvss files...", files.len());
    let origins = adding_commits(&repo)?;
    let shas: BTreeSet<String> = origins.values().cloned().collect();
    let messages = commit_messages(&repo, &shas)?;
    let history = History { origins, messages };

    let results: Vec<(PathBuf, Outcome)> = files
        .par_iter()
        .map(|path| (path.clone(), backfill_one(&history, &repo, path, &args)))
        .collect();

    let mut per_metric = 0;
    let mut prose = 0;
    let mut already = 0;
    let mut repaired = Vec::new();
    let mut failures = Vec::new();

    for (path, outcome) in results {
        match outcome {
            Outcome::Backfilled { per_metric: kind, note } => {
                if kind {
                    per_metric += 1;
                } else {
                    prose += 1;
                    println!("prose: {}", path.display());
                }
                if let Some(note) = note {
                    repaired.push(format!("{}: {note}", path.display()));
                }
            }
            Outcome::AlreadyPresent => already += 1,
            Outcome::Failed(e) => {
                failures.push(format!("{}: {e}", path.display()));
            }
        }
    }

    for repair in &repaired {
        println!("REPAIRED: {repair}");
    }

    for failure in &failures {
        println!("FAIL: {failure}");
    }

    println!(
        "\n{} files: {per_metric} per-metric, {prose} prose, {} repaired, {already} already had one, {} failed",
        files.len(),
        repaired.len(),
        failures.len()
    );

    if !args.write {
        println!("(dry run, pass --write to update the files)");
    }

    if !failures.is_empty() {
        bail!("{} files could not be backfilled", failures.len());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_a_per_metric_body() {
        let message = "CVE-2025-21638: Add CVSS 3.1 score (7.1 HIGH)\n\
                       \n\
                       CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H\n\
                       \n\
                       AV:L -reachable only through local file I/O\n\
                       AC:L -fully deterministic, no race to win\n\
                       \n\
                       Signed-off-by: Sasha Levin <sashal@kernel.org>\n";

        let (rationale, _) = rationale_from_message(message).unwrap();
        let Rationale::PerMetric(entries) = rationale else {
            panic!("expected per-metric rationale");
        };
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].text, "reachable only through local file I/O");
    }

    #[test]
    fn extracts_a_prose_body_with_no_vector_line() {
        let message = "CVE-2025-21756: Add CVSS 3.1 score (7.8 HIGH)\n\
                       \n\
                       Deterministic UAF in vsock socket binding during transport\n\
                       reassignment.\n\
                       \n\
                       Signed-off-by: Sasha Levin <sashal@kernel.org>\n";

        let (rationale, _) = rationale_from_message(message).unwrap();
        let Rationale::Prose(paragraphs) = rationale else {
            panic!("expected prose rationale");
        };
        assert_eq!(paragraphs.len(), 1);
        assert!(paragraphs[0].starts_with("Deterministic UAF in vsock"));
        assert!(paragraphs[0].ends_with("reassignment."));
    }

    #[test]
    fn rejects_a_message_with_no_body() {
        let message = "CVE-2025-21756: Add CVSS 3.1 score (7.8 HIGH)\n\
                       \n\
                       Signed-off-by: Sasha Levin <sashal@kernel.org>\n";
        assert!(rationale_from_message(message).is_err());
    }

    #[test]
    fn collapses_a_repeated_justification() {
        assert_eq!(dedupe_repeats("one two three"), "one two three");
        assert_eq!(dedupe_repeats("same text. same text."), "same text.");
        assert_eq!(dedupe_repeats("a b. a b. a b."), "a b.");
        assert_eq!(dedupe_repeats("x. x. x. x."), "x.");
        // Not a repetition, just a shared prefix.
        assert_eq!(dedupe_repeats("a b. a c."), "a b. a c.");
        assert_eq!(dedupe_repeats("word"), "word");
    }

    #[test]
    fn stops_at_the_trailer_block() {
        let message = "CVE-2025-21638: Add CVSS 3.1 score (7.1 HIGH)\n\
                       \n\
                       CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H\n\
                       \n\
                       AV:L -reachable only through local file I/O\n\
                       \n\
                       Co-developed-by: Someone Else <nobody@example.com>\n\
                       Signed-off-by: Sasha Levin <sashal@kernel.org>\n\
                       Reviewed-by: A Third <third@example.com>\n";

        let value = rationale_from_message(message).unwrap().0.to_scenario_value();
        assert_eq!(value, "AV:L - reachable only through local file I/O");
    }

    #[test]
    fn moves_a_misfiled_paragraph_to_the_metric_it_belongs_to() {
        // AC's block carries a second paragraph - the generator collected two
        // AC_JUSTIFICATION lines because the model emitted that label where
        // PR_JUSTIFICATION belonged - and PR is left empty. Widths here match
        // what `fold -s -w 68` would have produced.
        let message = "CVE-2021-47135: Add CVSS 3.1 score (7.8 HIGH)\n\
                       \n\
                       CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\n\
                       \n\
                       AV:L - reachable only through local file I/O\n\
                       AC:L - the out-of-bounds read is deterministic with no race or other\n\
                       \x20   condition outside the attacker's influence.\n\
                       \x20   An unprivileged local user can reach it without needing root.\n\
                       PR:L -\n\
                       UI:N - no action from any other user is needed\n\
                       S:U - stays inside the kernel's own security authority\n\
                       C:N - the fault happens before any data is returned\n\
                       I:H - an attacker-chosen modification of protected state\n\
                       A:H - panics outright on panic_on_oops builds\n\
                       \n\
                       Signed-off-by: Sasha Levin <sashal@kernel.org>\n";

        let (rationale, note) = rationale_from_message(message).unwrap();
        assert_eq!(note.unwrap(), "moved a paragraph from AC:L to PR:L");

        let Rationale::PerMetric(entries) = rationale else {
            panic!("expected per-metric rationale");
        };
        assert_eq!(entries.len(), 8);
        assert_eq!(
            entries[1].text,
            "the out-of-bounds read is deterministic with no race or other \
             condition outside the attacker's influence."
        );
        assert_eq!(entries[1].key.abbreviation(), "AC");
        assert_eq!(entries[2].key.abbreviation(), "PR");
        assert_eq!(
            entries[2].text,
            "An unprivileged local user can reach it without needing root."
        );
    }

    #[test]
    fn leaves_a_well_formed_message_alone() {
        let message = "CVE-2025-21638: Add CVSS 3.1 score (7.1 HIGH)\n\
                       \n\
                       CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H\n\
                       \n\
                       AV:L - reachable only through local file I/O\n\
                       AC:L - fully deterministic, no race to win\n\
                       \n\
                       Signed-off-by: Sasha Levin <sashal@kernel.org>\n";

        let (_, note) = rationale_from_message(message).unwrap();
        assert!(note.is_none());
    }

    #[test]
    fn does_not_guess_when_the_signature_is_not_exact() {
        // An empty metric with no orphan paragraph anywhere has nothing to
        // recover, and must not borrow text from a neighbour.
        let message = "CVE-2026-63944: Add CVSS 3.1 score (8.8 HIGH)\n\
                       \n\
                       CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H\n\
                       \n\
                       AV:L - reachable only through local file I/O\n\
                       AC:L - fully deterministic, no race to win\n\
                       PR:L -\n\
                       \n\
                       Signed-off-by: Sasha Levin <sashal@kernel.org>\n";

        assert!(rationale_from_message(message).is_err());
    }

    #[test]
    fn a_justification_is_not_mistaken_for_a_trailer() {
        // Colons turn up in justification text all the time.
        assert!(!is_trailer("AV:L - reachable only through local file I/O"));
        assert!(!is_trailer("    security/commoncap.c:92 grants the owner"));
        assert!(!is_trailer("The bug: a double free."));
        assert!(is_trailer("Signed-off-by: Sasha Levin <sashal@kernel.org>"));
        assert!(is_trailer("Co-developed-by: Someone <a@b.c>"));
    }
}
