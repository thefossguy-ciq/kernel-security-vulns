// SPDX-License-Identifier: GPL-2.0
// (c) 2025, Sasha Levin <sashal@kernel.org>

use clap::{Arg, ArgAction, Command};
use log::{info, debug, error, warn};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use indicatif::{ProgressBar, ProgressStyle};

// Internal modules
mod collector;
mod classifier;
mod utils;

// Import from commit-classifier library
use commit_classifier::ProviderResult;
use collector::CVEDataCollector;
use classifier::CVEClassifier;
use utils::{setup_logging, get_cve_root};

fn main() {
    let matches = Command::new("Linux Kernel CVE Classifier")
        .version("0.1.0")
        .author("Sasha Levin <sashal@kernel.org>")
        .about("Classifies if Linux kernel commits should be assigned CVE identifiers")
        .arg(Arg::new("cve-commits")
            .long("cve-commits")
            .value_name("PATH")
            .help("Path to CVE commits directory"))
        .arg(Arg::new("kernel-repo")
            .long("kernel-repo")
            .value_name("PATH")
            .help("Path to the Linux kernel repository")
            .default_value("~/linux"))
        .arg(Arg::new("model-dir")
            .long("model-dir")
            .value_name("PATH")
            .help("Path to store the model")
            .default_value("./model"))
        .arg(Arg::new("models")
            .long("models")
            .value_name("MODELS")
            .help("Comma-separated list of models to use (claude, openai, nvidia, ollama)"))
        .arg(Arg::new("train")
            .long("train")
            .action(ArgAction::SetTrue)
            .help("Train the model"))
        .arg(Arg::new("test")
            .long("test")
            .action(ArgAction::SetTrue)
            .help("Test mode with limited dataset"))
        .arg(Arg::new("debug")
            .long("debug")
            .action(ArgAction::SetTrue)
            .help("Enable debug logging"))
        .arg(Arg::new("commit")
            .long("commit")
            .value_name("SHA")
            .help("Commit SHA to analyze"))
        .arg(Arg::new("commits")
            .long("commits")
            .value_name("SHAs")
            .num_args(1..)
            .help("List of commit SHAs to analyze"))
        .arg(Arg::new("output")
            .long("output")
            .value_name("FILE")
            .help("Output file for results (JSON format)"))
        .arg(Arg::new("verbose")
            .long("verbose")
            .action(ArgAction::SetTrue)
            .help("Enable verbose output"))
        .arg(Arg::new("batch")
            .long("batch")
            .value_name("EXPLANATION_DIR")
            .help("Output only commit ID and yes/no for each commit. If a directory path is provided, save LLM responses in that directory."))
        .arg(Arg::new("make-prompt")
            .long("make-prompt")
            .value_name("PROMPT_DIR")
            .help("Only generate LLM prompts for given commits and save them in the provided directory as $sha1.txt"))
        .arg(Arg::new("send-prompt")
            .long("send-prompt")
            .value_name("FILE")
            .help("Skip embeddings initialization and send the prompt in the provided file to the selected LLMs"))
        .arg(Arg::new("ollama-server")
            .long("ollama-server")
            .value_name("URL")
            .help("URL of the Ollama API server (default: http://localhost:11434)"))
        .arg(Arg::new("ollama-model")
            .long("ollama-model")
            .value_name("MODEL")
            .help("Ollama model to use (default: llama3, options: llama3, mistral, gemma, or a custom model name)"))
        .arg(Arg::new("exec")
            .long("exec")
            .value_name("PATH")
            .help("Path to an executable for inference when using 'exec' as a model"))
        .arg(Arg::new("exec-params")
            .long("exec-params")
            .value_name("PARAMS")
            .help("Comma-separated list of parameters to pass to the executable"))
        .get_matches();

    let batch_mode = matches.contains_id("batch");

    setup_logging(matches.get_flag("debug"), batch_mode);

    let kernel_repo = matches.get_one::<String>("kernel-repo").unwrap();
    let model_dir = matches.get_one::<String>("model-dir").unwrap();
    let test_mode = matches.get_flag("test");
    let verbose = matches.get_flag("verbose");
    let explanation_dir = matches.get_one::<String>("batch").map(|s| s.as_str());
    let prompt_dir = matches.get_one::<String>("make-prompt").map(|s| s.as_str());
    let prompt_file = matches.get_one::<String>("send-prompt").map(|s| s.as_str());

    let model_dir_path = Path::new(model_dir);
    if !model_dir_path.exists() {
        if let Err(e) = fs::create_dir_all(model_dir_path) {
            error!("Failed to create model directory: {e}");
            std::process::exit(1);
        }
    }

    let vectorstore_dir = model_dir_path.join("vectorstore");
    if !vectorstore_dir.exists() {
        if let Err(e) = fs::create_dir_all(&vectorstore_dir) {
            error!("Failed to create vectorstore directory: {e}");
            std::process::exit(1);
        }
    }

    let llm_providers = if let Some(models) = matches.get_one::<String>("models") {
        models.split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>()
    } else {
        vec!["claude".to_string()]
    };

    if matches.contains_id("commit") || matches.contains_id("commits") {
        info!("Using LLM providers: {llm_providers:?}");
    }

    let expanded_kernel_repo = shellexpand::tilde(kernel_repo);
    let kernel_repo_path = Path::new(expanded_kernel_repo.as_ref());

    let runtime = tokio::runtime::Runtime::new()
        .expect("Failed to create tokio runtime");

    if matches.get_flag("train") {
        info!("Starting training process...");

        // Use the provided path or fall back to the default published directory
        let cve_path = match matches.get_one::<String>("cve-commits").map(|s| s.as_str()) {
            Some(path) => PathBuf::from(path),
            None => {
                match get_cve_root() {
                    Ok(cve_root) => cve_root.join("published"),
                    Err(e) => {
                        error!("Failed to find CVE root directory: {e}");
                        std::process::exit(1);
                    }
                }
            }
        };

        debug!("Initializing data collector with kernel repo: {}", kernel_repo_path.display());
        debug!("CVE commits path: {}", cve_path.display());
        let collector = match CVEDataCollector::new(kernel_repo_path, Some(&cve_path)) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to initialize data collector: {e}");
                std::process::exit(1);
            }
        };

        info!("Building dataset...");

        let max_workers = 48;

        let (max_cve, max_non_cve) = if test_mode {
            info!("Test mode: limiting dataset to 500 CVE and 500 non-CVE commits");
            (Some(500), Some(500))
        } else {
            (None, None)
        };

        let mut collector = collector;
        let dataset = collector.build_dataset(
            max_workers,
            max_cve,
            max_non_cve
        );

        // Count commits that were assigned CVEs
        let cve_count = dataset.iter().filter(|c| c.was_selected == Some(true)).count();
        info!("Dataset built with {} total commits:", dataset.len());
        info!("  - {cve_count} commits with CVEs");
        info!("  - {} commits without CVEs", dataset.len() - cve_count);

        info!("Training classifier...");

        let mut classifier = CVEClassifier::new(
            Vec::new(),
            None,
            Some(&vectorstore_dir),
            Some(kernel_repo_path)
        );

        if let Err(e) = classifier.train(&dataset) {
                error!("Failed to train classifier: {e}");
            std::process::exit(1);
        }

        let model_path = model_dir_path.join("cve_classifier.bin");
        info!("Saving model to {}", model_path.display());

        if let Err(e) = classifier.save_model(&model_path) {
            error!("Failed to save model: {e}");
            std::process::exit(1);
        }

        info!("Training completed successfully");
    }

    if matches.contains_id("commit") || matches.contains_id("commits") {
        let model_path = model_dir_path.join("cve_classifier.bin");

        if !model_path.exists() {
            error!("Model file not found at {}. Please train the model first.", model_path.display());
            std::process::exit(1);
        }

        info!("Loading model from {}", model_path.display());

        let mut classifier = match CVEClassifier::load_model(&model_path) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to load model: {e}");
                std::process::exit(1);
            }
        };

        classifier.repo_path = Some(kernel_repo_path.to_path_buf());

        if matches.contains_id("models") {
            classifier.llm_providers = llm_providers.clone();
            classifier.llms = None;

            // Set debug logging for verbose mode
            if verbose {
                for provider in &llm_providers {
                    if let Some(config) = classifier.llm_configs.get_mut(provider) {
                        if let Some(obj) = config.as_object_mut() {
                            obj.insert("debug_logging".to_string(), serde_json::json!(true));
                        }
                    }
                }
            }

            // Configure Ollama parameters if provided
            if classifier.llm_providers.contains(&"ollama".to_string()) {
                if let Some(config) = classifier.llm_configs.get_mut("ollama") {
                    if let Some(obj) = config.as_object_mut() {
                        // Set Ollama server URL if provided
                        if let Some(ollama_server) = matches.get_one::<String>("ollama-server").map(|s| s.as_str()) {
                            obj.insert("api_host".to_string(), serde_json::json!(ollama_server));
                        }

                        // Set Ollama model if provided
                        if let Some(ollama_model) = matches.get_one::<String>("ollama-model").map(|s| s.as_str()) {
                            // Check if it's a built-in model or custom
                            let is_builtin = ["llama3", "mistral", "gemma"].contains(&ollama_model);

                            if is_builtin {
                                obj.insert("model_type".to_string(), serde_json::json!(ollama_model));
                            } else {
                                // For custom models, we'll set it as a custom model name
                                obj.insert("custom_model".to_string(), serde_json::json!(ollama_model));
                            }
                        }
                    }
                }
            }

            // Configure Exec parameters if provided
            if classifier.llm_providers.contains(&"exec".to_string()) {
                if let Some(exec_path) = matches.get_one::<String>("exec").map(|s| s.as_str()) {
                    // Create or get existing config for exec
                    let exec_config = classifier.llm_configs.entry("exec".to_string())
                        .or_insert_with(|| serde_json::json!({}));

                    if let Some(obj) = exec_config.as_object_mut() {
                        // Set executable path
                        obj.insert("executable_path".to_string(), serde_json::json!(exec_path));

                        // Set debug logging
                        obj.insert("debug_logging".to_string(), serde_json::json!(verbose));

                        // Parse and set exec parameters if provided
                        if let Some(exec_params) = matches.get_one::<String>("exec-params").map(|s| s.as_str()) {
                            let params: Vec<String> = exec_params.split(',')
                                .map(|s| s.trim().to_string())
                                .collect();

                            obj.insert("arguments".to_string(), serde_json::json!(params));
                        } else {
                            // Set empty arguments if not provided
                            obj.insert("arguments".to_string(), serde_json::json!(Vec::<String>::new()));
                        }
                    }
                } else {
                    error!("The 'exec' model provider requires --exec parameter to be set");
                    std::process::exit(1);
                }
            }
        }

        let mut commits_to_analyze = Vec::new();
        if let Some(commit) = matches.get_one::<String>("commit").map(|s| s.as_str()) {
            commits_to_analyze.push(commit.to_string());
        }
        if let Some(commits) = matches.get_many::<String>("commits") {
            commits_to_analyze.extend(commits.map(|s| s.to_string()));
        }

        // Use the provided path or fall back to the default published directory
        let cve_path = match matches.get_one::<String>("cve-commits").map(|s| s.as_str()) {
            Some(path) => PathBuf::from(path),
            None => {
                match get_cve_root() {
                    Ok(cve_root) => cve_root.join("published"),
                    Err(e) => {
                        error!("Failed to find CVE root directory: {e}");
                        std::process::exit(1);
                    }
                }
            }
        };

        debug!("CVE commits path: {}", cve_path.display());
        let collector = match CVEDataCollector::new(kernel_repo_path, Some(&cve_path)) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to initialize data collector: {e}");
                std::process::exit(1);
            }
        };

        let mut results = HashMap::new();

        if commits_to_analyze.is_empty() {
            error!("No valid commits to analyze. Please provide valid commit SHAs with --commit SHA or --commits SHA1 SHA2 SHA3");
            std::process::exit(1);
        }

        let pb = ProgressBar::new(commits_to_analyze.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap());

        for sha in &commits_to_analyze {
            if sha.len() < 6 {
                warn!("Invalid commit SHA: {sha} (too short)");
                continue;
            }

            match collector.get_commit_features(sha) {
                Some(features) => {
                    if let Some(dir) = prompt_dir {
                        if !classifier.embeddings.is_initialized() {
                            info!("Initializing embeddings model for prompt generation");
                            if let Err(e) = classifier.embeddings.initialize() {
                                error!("Failed to initialize embeddings model: {e}");
                                continue;
                            }
                        }

                        let commit_text = classifier.format_commit_info(&features);

                        let similar_commits = classifier.find_similar_commits(&commit_text, 5);

                        let prompt = classifier.construct_prompt(&commit_text, similar_commits);

                        let prompt_dir_path = Path::new(dir);
                        if !prompt_dir_path.exists() {
                            if let Err(e) = fs::create_dir_all(prompt_dir_path) {
                                error!("Failed to create prompt directory: {e}");
                                continue;
                            }
                        }

                        let filename = format!("{sha}.txt");
                        let filepath = prompt_dir_path.join(&filename);

                        if let Err(e) = fs::write(&filepath, prompt) {
                            error!("Failed to write prompt file {}: {}", filepath.display(), e);
                        } else {
                            debug!("Saved prompt for {} to {}", sha, filepath.display());
                        }

                        pb.inc(1);
                        continue;
                    }

                    match runtime.block_on(classifier.predict(&features, verbose)) {
                        Ok(result) => {
                            if batch_mode {
                                // Use should_select field to represent CVE decision
                                let decision = if result.should_select { "yes" } else { "no" };
                                println!("{sha} {decision}");

                                if let Some(dir) = explanation_dir {
                                    let explanation_dir_path = Path::new(dir);

                                    if !explanation_dir_path.exists() {
                                        if let Err(e) = fs::create_dir_all(explanation_dir_path) {
                                            error!("Failed to create explanation directory: {e}");
                                        }
                                    }

                                    let filename = format!("{sha}.txt");
                                    let filepath = explanation_dir_path.join(&filename);

                                    let mut full_explanation = String::new();
                                    for (provider, provider_result) in &result.provider_results {
                                        full_explanation.push_str(&format!("Provider: {provider}\n"));
                                        if let Some(raw_response) = &provider_result.raw_response {
                                            full_explanation.push_str(raw_response);
                                        } else {
                                            full_explanation.push_str(&provider_result.explanation);
                                        }
                                        full_explanation.push_str("\n\n");
                                    }

                                    if let Err(e) = fs::write(&filepath, full_explanation) {
                                        error!("Failed to write explanation file {}: {}", filepath.display(), e);
                                    } else {
                                        debug!("Saved explanation for {} to {}", sha, filepath.display());
                                    }
                                }
                            }
                            results.insert(sha.clone(), result);
                        },
                        Err(e) => {
                            error!("Failed to get prediction for commit {sha}: {e}");
                        }
                    }
                },
                None => {
                    warn!("Failed to get features for commit {sha}");
                }
            }

            pb.inc(1);
        }

        pb.finish_with_message("Processed commits");

        if !results.is_empty() {
            if batch_mode {
                // Results already printed as they were processed
            } else {
                for (sha, result) in &results {
                    let subject = &result.subject;
                    let should_assign_cve = result.should_select;
                    let vote_ratio = &result.vote_ratio;

                    let status = if should_assign_cve { "ASSIGN CVE" } else { "NO CVE NEEDED" };
                    info!("Commit {}: {} (Votes: {}) - {}", &sha[0..10], status, vote_ratio, subject);

                    if verbose {
                        for (provider, provider_result) in &result.provider_results {
                            let should_assign_cve = provider_result.should_select;
                            let provider_decision = if should_assign_cve { "ASSIGN CVE" } else { "NO CVE NEEDED" };
                            info!("  - {provider}: {provider_decision}");

                            if let Some(error) = &provider_result.error {
                                info!("      Error: {error}");
                            } else {
                                let explanation_lines: Vec<&str> = provider_result.explanation.lines().take(3).collect();
                                for line in &explanation_lines {
                                    info!("      {line}");
                                }
                                if explanation_lines.len() < provider_result.explanation.lines().count() {
                                    info!("      ...");
                                }
                            }
                        }
                    }
                }
            }

            if let Some(output_file) = matches.get_one::<String>("output").map(|s| s.as_str()) {
                let output_path = Path::new(output_file);
                info!("Saving results to {}", output_path.display());

                match serde_json::to_string_pretty(&results) {
                    Ok(json) => {
                        match fs::write(output_path, json) {
                            Ok(_) => info!("Results saved successfully"),
                            Err(e) => error!("Error writing results file: {e}"),
                        }
                    },
                    Err(e) => error!("Error serializing results: {e}"),
                }
            }
        } else {
            warn!("No results to display");
        }
    }

    if let Some(prompt_file_path) = prompt_file {
        info!("Creating classifier for prompt processing");

        let config = if matches.contains_id("models") {
            let mut configs = HashMap::new();

            // Set debug logging for verbose mode
            if verbose {
                for provider in &llm_providers {
                    configs.insert(provider.clone(), serde_json::json!({
                        "debug_logging": true
                    }));
                }
            }

            // Configure Ollama parameters if provided
            if llm_providers.contains(&"ollama".to_string()) {
                let mut ollama_config = serde_json::json!({
                    "debug_logging": verbose
                });

                if let Some(obj) = ollama_config.as_object_mut() {
                    // Set Ollama server URL if provided
                    if let Some(ollama_server) = matches.get_one::<String>("ollama-server").map(|s| s.as_str()) {
                        obj.insert("api_host".to_string(), serde_json::json!(ollama_server));
                    }

                    // Set Ollama model if provided
                    if let Some(ollama_model) = matches.get_one::<String>("ollama-model").map(|s| s.as_str()) {
                        // Check if it's a built-in model or custom
                        let is_builtin = ["llama3", "mistral", "gemma"].contains(&ollama_model);

                        if is_builtin {
                            obj.insert("model_type".to_string(), serde_json::json!(ollama_model));
                        } else {
                            // For custom models, we'll set it as a custom model name
                            obj.insert("custom_model".to_string(), serde_json::json!(ollama_model));
                        }
                    }
                }

                configs.insert("ollama".to_string(), ollama_config);
            }

            // Configure Exec parameters if provided
            if llm_providers.contains(&"exec".to_string()) {
                if let Some(exec_path) = matches.get_one::<String>("exec").map(|s| s.as_str()) {
                    let mut exec_config = serde_json::json!({
                        "debug_logging": verbose
                    });

                    if let Some(obj) = exec_config.as_object_mut() {
                        // Set executable path
                        obj.insert("executable_path".to_string(), serde_json::json!(exec_path));

                        // Parse and set exec parameters if provided
                        if let Some(exec_params) = matches.get_one::<String>("exec-params").map(|s| s.as_str()) {
                            let params: Vec<String> = exec_params.split(',')
                                .map(|s| s.trim().to_string())
                                .collect();

                            obj.insert("arguments".to_string(), serde_json::json!(params));
                        } else {
                            // Set empty arguments if not provided
                            obj.insert("arguments".to_string(), serde_json::json!(Vec::<String>::new()));
                        }
                    }

                    configs.insert("exec".to_string(), exec_config);
                } else {
                    error!("The 'exec' model provider requires --exec parameter to be set");
                    std::process::exit(1);
                }
            }

            Some(configs)
        } else {
            None
        };

        let mut classifier = CVEClassifier::new_for_prompt(
            llm_providers.clone(),
            config,
            Some(kernel_repo_path)
        );

        let file_stem = Path::new(prompt_file_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("custom_prompt");

        let prompt = match fs::read_to_string(prompt_file_path) {
            Ok(content) => content,
            Err(e) => {
                error!("Failed to read prompt file {prompt_file_path}: {e}");
                std::process::exit(1);
            }
        };

        info!("Processing prompt from {prompt_file_path}");
        match runtime.block_on(classifier.process_custom_prompt(&prompt, verbose)) {
            Ok(result) => {
                if batch_mode {
                    let should_assign_cve = result.should_select;
                    let decision = if should_assign_cve { "yes" } else { "no" };
                    println!("{file_stem} {decision}");

                    if let Some(dir) = explanation_dir {
                        save_explanation(dir, file_stem, &result.provider_results);
                    }
                } else {
                    let should_assign_cve = result.should_select;
                    let status = if should_assign_cve { "ASSIGN CVE" } else { "NO CVE NEEDED" };
                    info!("Result: {} (Votes: {})", status, &result.vote_ratio);

                    if verbose {
                        print_provider_details(&result.provider_results);
                    }
                }

                if let Some(output_file) = matches.get_one::<String>("output").map(|s| s.as_str()) {
                    let output_path = Path::new(output_file);
                    info!("Saving results to {}", output_path.display());

                    let mut results = HashMap::new();
                    results.insert(file_stem.to_string(), result);

                    if let Err(e) = fs::write(output_path,
                        serde_json::to_string_pretty(&results).unwrap_or_default()) {
                        error!("Error writing results file: {e}");
                    } else {
                        info!("Results saved successfully");
                    }
                }
            },
            Err(e) => {
                error!("Failed to process prompt: {e}");
            }
        }
    }

    if matches.contains_id("make-prompt") {
        if let Some(dir) = prompt_dir {
            info!("All prompts saved to directory: {dir}");
        }
    }

    if !matches.get_flag("train") && !matches.contains_id("commit") && !matches.contains_id("commits") &&
       !matches.contains_id("make-prompt") && !matches.contains_id("send-prompt") {
        let mut cmd = Command::new("Linux Kernel CVE Classifier");
        println!("{}", cmd.render_help());
    }
}

fn save_explanation(dir: &str, file_stem: &str, provider_results: &HashMap<String, ProviderResult>) {
    let explanation_dir_path = Path::new(dir);

    if !explanation_dir_path.exists() {
        if let Err(e) = fs::create_dir_all(explanation_dir_path) {
            error!("Failed to create explanation directory: {e}");
            return;
        }
    }

    let filename = format!("{file_stem}.txt");
    let filepath = explanation_dir_path.join(&filename);

    let mut full_explanation = String::new();
    for (provider, provider_result) in provider_results {
        full_explanation.push_str(&format!("Provider: {provider}\n"));
        if let Some(raw_response) = &provider_result.raw_response {
            full_explanation.push_str(raw_response);
        } else {
            full_explanation.push_str(&provider_result.explanation);
        }
        full_explanation.push_str("\n\n");
    }

    if let Err(e) = fs::write(&filepath, full_explanation) {
        error!("Failed to write explanation file {}: {}", filepath.display(), e);
    } else {
        debug!("Saved explanation for {} to {}", file_stem, filepath.display());
    }
}

fn print_provider_details(provider_results: &HashMap<String, ProviderResult>) {
    for (provider, provider_result) in provider_results {
        let should_assign_cve = provider_result.should_select;
        let provider_decision = if should_assign_cve { "ASSIGN CVE" } else { "NO CVE NEEDED" };
        info!("  - {provider}: {provider_decision}");

        if let Some(error) = &provider_result.error {
            info!("      Error: {error}");
        } else {
            let explanation_lines: Vec<&str> = provider_result.explanation.lines().take(3).collect();
            for line in &explanation_lines {
                info!("      {line}");
            }
            if explanation_lines.len() < provider_result.explanation.lines().count() {
                info!("      ...");
            }
        }
    }
}