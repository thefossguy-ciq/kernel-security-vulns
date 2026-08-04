// SPDX-License-Identifier: GPL-2.0-only
//
// The human explanation that goes with a CVSS v3.1 vector: why each of the
// eight base metrics was given the value it has.
//
// Copyright (c) 2026 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Result};
use std::fmt;

use super::metrics::CvssMetrics;

/// Maximum length of `metrics[].scenarios[].value` in a CVE record, from
/// `definitions.metrics` in cve/CVE_JSON_5.1.1_schema.json.
pub const MAX_SCENARIO_LEN: usize = 4096;

/// Column a rendered rationale line is wrapped to, indent included.
const WRAP_WIDTH: usize = 72;

/// Indent applied to the continuation lines of a wrapped paragraph.
const CONTINUATION_INDENT: &str = "    ";

/// One of the eight CVSS v3.1 base metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKey {
    Av,
    Ac,
    Pr,
    Ui,
    S,
    C,
    I,
    A,
}

impl MetricKey {
    /// The eight base metrics in the order they appear in a vector string.
    pub const ORDER: [Self; 8] = [
        Self::Av,
        Self::Ac,
        Self::Pr,
        Self::Ui,
        Self::S,
        Self::C,
        Self::I,
        Self::A,
    ];

    pub fn abbreviation(self) -> &'static str {
        match self {
            Self::Av => "AV",
            Self::Ac => "AC",
            Self::Pr => "PR",
            Self::Ui => "UI",
            Self::S => "S",
            Self::C => "C",
            Self::I => "I",
            Self::A => "A",
        }
    }

    pub fn from_abbreviation(s: &str) -> Result<Self> {
        match s {
            "AV" => Ok(Self::Av),
            "AC" => Ok(Self::Ac),
            "PR" => Ok(Self::Pr),
            "UI" => Ok(Self::Ui),
            "S" => Ok(Self::S),
            "C" => Ok(Self::C),
            "I" => Ok(Self::I),
            "A" => Ok(Self::A),
            _ => Err(anyhow!("invalid metric key: '{s}'")),
        }
    }

    /// The value this metric has in `metrics`, as a vector abbreviation.
    pub fn value_of(self, metrics: &CvssMetrics) -> &'static str {
        match self {
            Self::Av => metrics.av.abbreviation(),
            Self::Ac => metrics.ac.abbreviation(),
            Self::Pr => metrics.pr.abbreviation(),
            Self::Ui => metrics.ui.abbreviation(),
            Self::S => metrics.scope.abbreviation(),
            Self::C => metrics.confidentiality.abbreviation(),
            Self::I => metrics.integrity.abbreviation(),
            Self::A => metrics.availability.abbreviation(),
        }
    }
}

impl fmt::Display for MetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.abbreviation())
    }
}

/// The justification for a single metric. `text` is always stored as one
/// line with runs of whitespace collapsed; wrapping happens on render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricRationale {
    pub key: MetricKey,
    pub value: String,
    pub text: String,
}

impl MetricRationale {
    /// "AV:L - Despite living in net/sctp/, ..." — one line, unwrapped.
    pub fn to_line(&self) -> String {
        format!("{}:{} - {}", self.key, self.value, self.text)
    }
}

/// The explanation attached to a CVSS vector.
///
/// The structured `PerMetric` shape is what tooling generates today. `Prose`
/// exists for the handful of early entries that predate that convention, and
/// for anything else that does not decompose per metric.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rationale {
    PerMetric(Vec<MetricRationale>),
    /// Free text, one entry per paragraph, each stored as a single line.
    Prose(Vec<String>),
}

impl Rationale {
    /// Parse a rationale block.
    ///
    /// A line with no leading whitespace of the form `KEY:V - text` starts a
    /// new per-metric paragraph; everything else continues the paragraph it
    /// follows. If the first non-blank line is not such a header the whole
    /// block is treated as prose, split into paragraphs on blank lines.
    pub fn parse(text: &str) -> Result<Self> {
        if text.trim().is_empty() {
            return Err(anyhow!("empty rationale"));
        }

        // Only the indent *relative* to the block carries meaning - it is
        // what tells a wrapped continuation line from the start of the next
        // metric. A block that is indented as a whole, as it would be if
        // pasted out of a commit message, means the same thing.
        let text = &dedent(text);

        // Any line that is a metric justification makes this a per-metric
        // block. Deciding on the first line alone would quietly demote a
        // block with a stray line in front of it to unchecked prose.
        if text.lines().any(|line| split_metric_header(line).is_some()) {
            return Self::parse_per_metric(text);
        }

        // Nothing here is a metric justification, so this is prose - unless
        // it looks like one that went wrong, which is the more likely
        // reading and must not be published unvalidated. Either the key is
        // mistyped, or the block is indented too unevenly to dedent.
        if let Some(line) = text.lines().find(|line| looks_like_metric_header(line)) {
            return Err(anyhow!(
                "'{}' looks like a metric justification but was not read as one; \
                 check the metric key and that the block is indented evenly",
                line.trim()
            ));
        }

        Ok(Self::parse_prose(text))
    }

    fn parse_per_metric(text: &str) -> Result<Self> {
        let mut entries: Vec<MetricRationale> = Vec::new();
        let mut current: Option<(MetricKey, String, String)> = None;

        for line in text.lines() {
            if let Some((key, value, rest)) = split_metric_header(line) {
                if let Some(entry) = current.take() {
                    entries.push(finish_entry(entry)?);
                }
                current = Some((key, value, rest.to_string()));
            } else if let Some((_, _, text)) = current.as_mut() {
                text.push(' ');
                text.push_str(line);
            } else if !line.trim().is_empty() {
                return Err(anyhow!(
                    "text before the first metric key: '{}'",
                    line.trim()
                ));
            }
        }

        if let Some(entry) = current.take() {
            entries.push(finish_entry(entry)?);
        }

        Ok(Self::PerMetric(entries))
    }

    fn parse_prose(text: &str) -> Self {
        let paragraphs = text
            .split("\n\n")
            .map(collapse_whitespace)
            .filter(|p| !p.is_empty())
            .collect();
        Self::Prose(paragraphs)
    }

    /// Render back to the wrapped form stored in a .cvss file. Always ends
    /// with a newline.
    pub fn render(&self) -> String {
        let mut out = match self {
            // A metric's text hangs off its key; prose has nothing to hang
            // off, so it is wrapped flush.
            Self::PerMetric(entries) => entries
                .iter()
                .map(|entry| wrap(&entry.to_line(), CONTINUATION_INDENT))
                .collect::<Vec<_>>()
                .join("\n"),
            Self::Prose(paragraphs) => paragraphs
                .iter()
                .map(|paragraph| wrap(paragraph, ""))
                .collect::<Vec<_>>()
                .join("\n\n"),
        };
        out.push('\n');
        out
    }

    /// The unwrapped form published as `metrics[].scenarios[].value`: one
    /// line per metric (or per paragraph), joined by newlines.
    pub fn to_scenario_value(&self) -> String {
        match self {
            Self::PerMetric(entries) => entries
                .iter()
                .map(MetricRationale::to_line)
                .collect::<Vec<_>>()
                .join("\n"),
            Self::Prose(paragraphs) => paragraphs.join("\n"),
        }
    }

    /// Same as [`Self::to_scenario_value`], but refuses to hand back a value
    /// the CVE schema would reject.
    pub fn checked_scenario_value(&self) -> Result<String> {
        let value = self.to_scenario_value();
        // JSON Schema maxLength counts code points, not bytes.
        let length = value.chars().count();
        if length > MAX_SCENARIO_LEN {
            return Err(anyhow!(
                "rationale is {length} characters, over the {MAX_SCENARIO_LEN} \
                 limit for metrics[].scenarios[].value"
            ));
        }
        Ok(value)
    }

    /// Check that a per-metric rationale actually describes `metrics`: all
    /// eight keys, in vector order, each with the value the vector gives it.
    ///
    /// Prose rationales carry no per-metric claims, so nothing to check.
    pub fn validate(&self, metrics: &CvssMetrics) -> Result<()> {
        let Self::PerMetric(entries) = self else {
            return Ok(());
        };

        if entries.len() != MetricKey::ORDER.len() {
            return Err(anyhow!(
                "expected {} metric justifications, got {}",
                MetricKey::ORDER.len(),
                entries.len()
            ));
        }

        for (entry, expected_key) in entries.iter().zip(MetricKey::ORDER) {
            if entry.key != expected_key {
                return Err(anyhow!(
                    "expected justification for {expected_key}, got {}",
                    entry.key
                ));
            }

            let expected_value = expected_key.value_of(metrics);
            if entry.value != expected_value {
                return Err(anyhow!(
                    "{expected_key} justification is for {expected_key}:{}, \
                     but the vector says {expected_key}:{expected_value}",
                    entry.value
                ));
            }
        }

        Ok(())
    }
}

/// Split a per-metric header line into (key, value, remaining text).
///
/// Only unindented lines qualify, which is what keeps a wrapped continuation
/// line from being mistaken for the start of the next paragraph.
fn split_metric_header(line: &str) -> Option<(MetricKey, String, &str)> {
    if line.starts_with(char::is_whitespace) {
        return None;
    }

    let (head, rest) = line.split_once('-')?;
    let (key, value) = head.trim_end().split_once(':')?;

    let key = MetricKey::from_abbreviation(key).ok()?;
    if value.len() != 1 || !value.chars().all(|c| c.is_ascii_uppercase()) {
        return None;
    }

    Some((key, value.to_string(), rest))
}

/// Strip the whitespace prefix shared by every non-blank line.
///
/// Matches the prefix itself rather than counting characters, so a block
/// mixing tabs and spaces does not come out still misaligned.
fn dedent(text: &str) -> String {
    let mut common: Option<&str> = None;

    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let indent = &line[..line.len() - line.trim_start().len()];
        common = Some(match common {
            None => indent,
            Some(prefix) => &prefix[..shared_prefix_len(prefix, indent)],
        });
    }

    let common = common.unwrap_or_default();
    if common.is_empty() {
        return text.to_string();
    }

    text.lines()
        .map(|line| line.strip_prefix(common).unwrap_or_else(|| line.trim_start()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Length in bytes of the longest common prefix of two strings, always on a
/// character boundary.
fn shared_prefix_len(a: &str, b: &str) -> usize {
    a.char_indices()
        .zip(b.chars())
        .take_while(|((_, x), y)| x == y)
        .map(|((i, x), _)| i + x.len_utf8())
        .last()
        .unwrap_or(0)
}

/// Whether a line has the shape of a metric justification. Only consulted
/// once no line has been accepted as one, so a match here means something is
/// wrong with the block rather than that it is prose.
fn looks_like_metric_header(line: &str) -> bool {
    let line = line.trim_start();

    let Some((head, _)) = line.split_once('-') else {
        return false;
    };
    let Some((key, value)) = head.trim_end().split_once(':') else {
        return false;
    };

    (1..=2).contains(&key.len())
        && key.chars().all(|c| c.is_ascii_alphabetic())
        && value.len() == 1
        && value.chars().all(|c| c.is_ascii_alphabetic())
}

fn finish_entry(entry: (MetricKey, String, String)) -> Result<MetricRationale> {
    let (key, value, text) = entry;
    let text = collapse_whitespace(&text);
    if text.is_empty() {
        return Err(anyhow!("{key}:{value} has no justification text"));
    }
    Ok(MetricRationale { key, value, text })
}

fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Greedy word wrap to WRAP_WIDTH columns, indenting continuation lines by
/// `indent`, so every rendered line ends at the same margin. A word longer
/// than the available width gets a line to itself rather than being split.
fn wrap(text: &str, indent: &str) -> String {
    let indent_width = indent.chars().count();
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        let available = if lines.is_empty() {
            WRAP_WIDTH
        } else {
            WRAP_WIDTH - indent_width
        };

        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= available {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }

    lines
        .iter()
        .enumerate()
        .map(|(i, line)| {
            if i == 0 {
                line.clone()
            } else {
                format!("{indent}{line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cvss::vector::parse_vector;

    const VECTOR: &str = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H";

    fn full_rationale() -> String {
        [
            "AV:L - reachable only through local file I/O",
            "AC:L - fully deterministic, no race to win",
            "PR:L - an unprivileged local user suffices",
            "UI:N - no action from any other user is needed",
            "S:U - stays inside the kernel's own security authority",
            "C:N - the fault happens before any data is returned",
            "I:H - an attacker-chosen modification of protected state",
            "A:H - panics outright on panic_on_oops builds",
        ]
        .join("\n")
    }

    #[test]
    fn parses_per_metric() {
        let r = Rationale::parse(&full_rationale()).unwrap();
        let Rationale::PerMetric(entries) = &r else {
            panic!("expected per-metric rationale");
        };
        assert_eq!(entries.len(), 8);
        assert_eq!(entries[0].key, MetricKey::Av);
        assert_eq!(entries[0].value, "L");
        assert_eq!(entries[0].text, "reachable only through local file I/O");
        assert_eq!(entries[7].key, MetricKey::A);
        assert_eq!(entries[7].text, "panics outright on panic_on_oops builds");
    }

    #[test]
    fn joins_wrapped_continuation_lines() {
        let text = "AV:L - reachable only through\n    local file I/O\nAC:L - deterministic";
        let Rationale::PerMetric(entries) = Rationale::parse(text).unwrap() else {
            panic!("expected per-metric rationale");
        };
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].text, "reachable only through local file I/O");
    }

    #[test]
    fn normalises_missing_space_after_dash() {
        let text = "AV:L -reachable only through local file I/O";
        let Rationale::PerMetric(entries) = Rationale::parse(text).unwrap() else {
            panic!("expected per-metric rationale");
        };
        assert_eq!(entries[0].text, "reachable only through local file I/O");
        assert_eq!(
            entries[0].to_line(),
            "AV:L - reachable only through local file I/O"
        );
    }

    #[test]
    fn continuation_containing_a_dash_is_not_a_header() {
        let text = "AV:L - a procfs sysctl\n    ->proc_handler that nothing else invokes";
        let Rationale::PerMetric(entries) = Rationale::parse(text).unwrap() else {
            panic!("expected per-metric rationale");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].text,
            "a procfs sysctl ->proc_handler that nothing else invokes"
        );
    }

    #[test]
    fn parses_prose() {
        let text = "Bluetooth L2CAP accepts incoming connections with weak keys.\n\
                    Missing check allows a nearby device to eavesdrop.";
        let r = Rationale::parse(text).unwrap();
        assert_eq!(
            r,
            Rationale::Prose(vec![
                "Bluetooth L2CAP accepts incoming connections with weak keys. \
                 Missing check allows a nearby device to eavesdrop."
                    .to_string()
            ])
        );
    }

    #[test]
    fn parses_multi_paragraph_prose() {
        let text = "First paragraph here.\n\nSecond paragraph here.";
        let Rationale::Prose(paragraphs) = Rationale::parse(text).unwrap() else {
            panic!("expected prose rationale");
        };
        assert_eq!(paragraphs.len(), 2);
        assert_eq!(paragraphs[1], "Second paragraph here.");
    }

    #[test]
    fn an_indented_block_is_still_per_metric() {
        // As pasted out of a commit message. Rendering strips the indent, so
        // treating this as prose would mean parse(render(x)) != x and a file
        // that fails its own validation on the next read.
        let indented: String = full_rationale()
            .lines()
            .map(|line| format!("    {line}\n"))
            .collect();

        let r = Rationale::parse(&indented).unwrap();
        assert!(matches!(r, Rationale::PerMetric(_)));
        assert_eq!(Rationale::parse(&r.render()).unwrap(), r);
        r.validate(&parse_vector(VECTOR).unwrap()).unwrap();
    }

    #[test]
    fn dedent_matches_the_prefix_not_a_character_count() {
        // Counting characters would call a tab and four spaces the same
        // indent and strip one from each, silently turning the second line
        // into a continuation of the first. There is no common prefix here,
        // so the block is rejected instead of being quietly misread.
        let mixed = "\tAV:L - tab indented\n    AC:L - space indented";
        let err = Rationale::parse(mixed).unwrap_err().to_string();
        assert!(err.contains("indented evenly"), "unexpected error: {err}");
    }

    #[test]
    fn dedent_handles_a_multi_character_common_indent() {
        let indented: String = full_rationale()
            .lines()
            .map(|line| format!("\t\t{line}\n"))
            .collect();
        let r = Rationale::parse(&indented).unwrap();
        assert!(matches!(r, Rationale::PerMetric(_)));
        r.validate(&parse_vector(VECTOR).unwrap()).unwrap();
    }

    #[test]
    fn dedent_ignores_blank_lines() {
        let text = "    First paragraph.\n\n    Second paragraph.";
        let Rationale::Prose(paragraphs) = Rationale::parse(text).unwrap() else {
            panic!("expected prose rationale");
        };
        assert_eq!(paragraphs, ["First paragraph.", "Second paragraph."]);
    }

    #[test]
    fn rejects_stray_text_before_the_first_metric() {
        let text = format!("some preamble\n{}", full_rationale());
        let err = Rationale::parse(&text).unwrap_err().to_string();
        assert!(err.contains("preamble"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_a_mistyped_metric_key() {
        // "VA:L" is not a metric, and silently taking the block as prose
        // would skip every check we have.
        let typo = full_rationale().replace("AV:L -", "VA:L -");
        let err = Rationale::parse(&typo).unwrap_err().to_string();
        assert!(err.contains("VA"), "unexpected error: {err}");

        // Real prose must still be accepted.
        assert!(matches!(
            Rationale::parse("A double free lets the same object be handed out twice.").unwrap(),
            Rationale::Prose(_)
        ));
    }

    #[test]
    fn rejects_empty() {
        assert!(Rationale::parse("").is_err());
        assert!(Rationale::parse("   \n\n  ").is_err());
    }

    #[test]
    fn rejects_metric_with_no_text() {
        assert!(Rationale::parse("AV:L -   \nAC:L - fine").is_err());
    }

    #[test]
    fn render_wraps_and_indents() {
        let long = format!("AV:L - {}", "word ".repeat(40).trim());
        let rendered = Rationale::parse(&long).unwrap().render();
        let lines: Vec<&str> = rendered.trim_end().lines().collect();
        assert!(lines.len() > 1);
        assert!(!lines[0].starts_with(' '));
        for line in &lines[1..] {
            assert!(line.starts_with(CONTINUATION_INDENT));
        }
        for line in &lines {
            assert!(
                line.chars().count() <= WRAP_WIDTH,
                "line too long: {line:?}"
            );
        }
    }

    #[test]
    fn render_round_trips() {
        let original = Rationale::parse(&full_rationale()).unwrap();
        let reparsed = Rationale::parse(&original.render()).unwrap();
        assert_eq!(original, reparsed);
        assert_eq!(original.render(), reparsed.render());
    }

    #[test]
    fn prose_render_round_trips() {
        let original = Rationale::parse("First paragraph.\n\nSecond one, a bit longer.").unwrap();
        let reparsed = Rationale::parse(&original.render()).unwrap();
        assert_eq!(original, reparsed);
    }

    #[test]
    fn prose_is_wrapped_flush() {
        let rendered = Rationale::parse(&"sentence ".repeat(30)).unwrap().render();
        let lines: Vec<&str> = rendered.trim_end().lines().collect();
        assert!(lines.len() > 1);
        for line in &lines {
            assert!(!line.starts_with(' '), "prose must not be indented: {line:?}");
            assert!(line.chars().count() <= WRAP_WIDTH);
        }
    }

    #[test]
    fn scenario_value_is_one_line_per_metric() {
        let value = Rationale::parse(&full_rationale())
            .unwrap()
            .to_scenario_value();
        assert_eq!(value.lines().count(), 8);
        assert!(value.starts_with("AV:L - reachable"));
        assert!(value.ends_with("A:H - panics outright on panic_on_oops builds"));
    }

    #[test]
    fn scenario_value_rejects_over_length() {
        let long = format!("AV:L - {}", "x ".repeat(MAX_SCENARIO_LEN));
        let r = Rationale::parse(&long).unwrap();
        assert!(r.to_scenario_value().chars().count() > MAX_SCENARIO_LEN);
        assert!(r.checked_scenario_value().is_err());
        assert!(Rationale::parse(&full_rationale())
            .unwrap()
            .checked_scenario_value()
            .is_ok());
    }

    #[test]
    fn validate_accepts_matching_vector() {
        let metrics = parse_vector(VECTOR).unwrap();
        Rationale::parse(&full_rationale())
            .unwrap()
            .validate(&metrics)
            .unwrap();
    }

    #[test]
    fn validate_rejects_mismatched_value() {
        let metrics = parse_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H").unwrap();
        let err = Rationale::parse(&full_rationale())
            .unwrap()
            .validate(&metrics)
            .unwrap_err()
            .to_string();
        assert!(err.contains("AV:L"), "unexpected error: {err}");
        assert!(err.contains("AV:N"), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_missing_metric() {
        let metrics = parse_vector(VECTOR).unwrap();
        let text = full_rationale().replace("A:H - panics outright on panic_on_oops builds", "");
        assert!(Rationale::parse(&text)
            .unwrap()
            .validate(&metrics)
            .is_err());
    }

    #[test]
    fn validate_rejects_duplicate_metric() {
        let metrics = parse_vector(VECTOR).unwrap();
        let text = full_rationale().replace(
            "AC:L - fully deterministic, no race to win",
            "AV:L - said twice",
        );
        assert!(Rationale::parse(&text)
            .unwrap()
            .validate(&metrics)
            .is_err());
    }

    #[test]
    fn validate_rejects_wrong_order() {
        let metrics = parse_vector(VECTOR).unwrap();
        let mut lines: Vec<String> = full_rationale().lines().map(str::to_string).collect();
        lines.swap(0, 1);
        assert!(Rationale::parse(&lines.join("\n"))
            .unwrap()
            .validate(&metrics)
            .is_err());
    }

    #[test]
    fn scenario_length_is_counted_in_code_points() {
        // An em dash is one code point but three bytes; the limit is on
        // code points, so a value made of them must not be rejected early.
        let text = format!("AV:L - {}", "\u{2014} ".repeat(MAX_SCENARIO_LEN / 4));
        let r = Rationale::parse(&text).unwrap();
        let value = r.to_scenario_value();
        assert!(value.len() > MAX_SCENARIO_LEN);
        assert!(value.chars().count() <= MAX_SCENARIO_LEN);
        assert!(r.checked_scenario_value().is_ok());
    }

    #[test]
    fn validate_ignores_prose() {
        let metrics = parse_vector(VECTOR).unwrap();
        Rationale::parse("Just some prose about the bug.")
            .unwrap()
            .validate(&metrics)
            .unwrap();
    }
}
