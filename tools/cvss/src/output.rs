// SPDX-License-Identifier: GPL-2.0-only
//
// Output formatting for CVSS scoring results.
//
// Copyright (c) 2026 - Sasha Levin <sashal@kernel.org>

use std::path::Path;

use crate::scoring::formula::ScoreResult;
use crate::scoring::metrics::CvssMetrics;
use crate::scoring::rationale::Rationale;

/// Everything there is to say about one scored vector.
pub struct Result_<'a> {
    pub cve_id: Option<&'a str>,
    pub vector: &'a str,
    pub metrics: &'a CvssMetrics,
    pub result: &'a ScoreResult,
    pub rationale: Option<&'a Rationale>,
    pub path: Option<&'a Path>,
    pub verbose: bool,
    pub json: bool,
}

pub fn print_result(args: &Result_) {
    if args.json {
        print_json(args);
        return;
    }

    if let Some(id) = args.cve_id {
        println!(
            "{}  {:.1}  {}  {}",
            id, args.result.score, args.result.severity, args.vector
        );
    } else {
        println!(
            "{:.1}  {}  {}",
            args.result.score, args.result.severity, args.vector
        );
    }

    if args.verbose {
        print_verbose(args.metrics, args.result);

        if let Some(rationale) = args.rationale {
            println!("  ---");
            for line in rationale.render().lines() {
                println!("  {line}");
            }
        }
    }
}

fn print_verbose(metrics: &CvssMetrics, result: &ScoreResult) {
    println!(
        "  Attack Vector:       {} ({:.2})",
        metrics.av,
        metrics.av.weight()
    );
    println!(
        "  Attack Complexity:   {} ({:.2})",
        metrics.ac,
        metrics.ac.weight()
    );
    println!(
        "  Privileges Required: {} ({:.2})",
        metrics.pr,
        metrics.pr.weight(metrics.scope)
    );
    println!(
        "  User Interaction:    {} ({:.2})",
        metrics.ui,
        metrics.ui.weight()
    );
    println!("  Scope:               {}", metrics.scope);
    println!(
        "  Confidentiality:     {} ({:.2})",
        metrics.confidentiality,
        metrics.confidentiality.weight()
    );
    println!(
        "  Integrity:           {} ({:.2})",
        metrics.integrity,
        metrics.integrity.weight()
    );
    println!(
        "  Availability:        {} ({:.2})",
        metrics.availability,
        metrics.availability.weight()
    );
    println!("  ---");
    println!(
        "  ISS: {:.4}  Impact: {:.4}  Exploitability: {:.4}",
        result.iss, result.impact, result.exploitability
    );
}

fn print_json(args: &Result_) {
    let mut json = serde_json::Map::new();

    if let Some(id) = args.cve_id {
        json.insert("cveId".to_string(), id.into());
    }
    json.insert("score".to_string(), args.result.score.into());
    json.insert("severity".to_string(), args.result.severity.clone().into());
    json.insert("vectorString".to_string(), args.vector.into());
    if let Some(path) = args.path {
        json.insert("path".to_string(), path.display().to_string().into());
    }
    if let Some(rationale) = args.rationale {
        json.insert(
            "rationale".to_string(),
            rationale.to_scenario_value().into(),
        );
    }

    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"   ");
    let mut buf = Vec::new();
    let mut ser = serde_json::ser::Serializer::with_formatter(&mut buf, formatter);
    serde::Serialize::serialize(&serde_json::Value::Object(json), &mut ser).unwrap();
    println!("{}", String::from_utf8(buf).unwrap());
}
