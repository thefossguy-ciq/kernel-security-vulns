// SPDX-License-Identifier: GPL-2.0
// (c) 2025, Sasha Levin <sashal@kernel.org>

use std::collections::HashMap;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use log::{info, debug, warn, error};
use regex::Regex;
use indicatif::{ProgressBar, ProgressStyle};

// Import from the commit-classifier library
use commit_classifier::{
    HuggingFaceEmbeddings,
    ChromaStore,
    Metadata,
    Llm,
    CommitFeatures,
    ProviderResult,
    PredictionResult,
};

// ModelState from commit-classifier
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ModelState {
    pub persist_directory: Option<PathBuf>,
}

// Full CVE classifier with embeddings functionality
pub struct CVEClassifier {
    pub embeddings: HuggingFaceEmbeddings,
    pub vectorstore: Option<ChromaStore>,
    pub persist_directory: Option<PathBuf>,
    pub repo_path: Option<PathBuf>,
    pub llm_providers: Vec<String>,
    pub llm_configs: HashMap<String, serde_json::Value>,
    pub llms: Option<HashMap<String, Box<dyn Llm>>>,
}

impl CVEClassifier {
    pub fn new(
        llm_providers: Vec<String>,
        llm_configs: Option<HashMap<String, serde_json::Value>>,
        persist_directory: Option<&Path>,
        repo_path: Option<&Path>
    ) -> Self {
        let default_configs = Self::create_default_llm_configs();

        let final_configs = if let Some(user_configs) = llm_configs {
            let mut merged = default_configs.clone();
            for (k, v) in user_configs {
                merged.insert(k, v);
            }
            merged
        } else {
            default_configs
        };

        CVEClassifier {
            embeddings: HuggingFaceEmbeddings::new(),
            vectorstore: None,
            persist_directory: persist_directory.map(Path::to_path_buf),
            repo_path: repo_path.map(Path::to_path_buf),
            llm_providers,
            llm_configs: final_configs,
            llms: None,
        }
    }

    /// Extract Fixes tag references from a commit message
    /// Returns a vector of SHA1 hashes referenced in Fixes tags
    pub fn extract_fixes_references(message: &str) -> Vec<String> {
        let mut fixes = Vec::new();
        let re = regex::Regex::new(r"(?i)Fixes:\s*([a-f0-9]{12,40})").unwrap();

        for line in message.lines() {
            if let Some(caps) = re.captures(line) {
                if let Some(sha) = caps.get(1) {
                    fixes.push(sha.as_str().to_string());
                }
            }
        }

        fixes
    }

    /// Retrieve the content of a commit referenced by a Fixes tag
    /// Returns a tuple with (subject, full message, diff) for the fixed commit
    /// Skips commits with diffs longer than 1000 lines to avoid overwhelming context
    pub fn get_fix_commit_content(&self, commit_sha: &str) -> Option<(String, String, String)> {
        let repo_path = self.repo_path.as_ref()?;

        // Create the git command to get commit message
        let mut cmd = std::process::Command::new("git");
        cmd.current_dir(repo_path)
            .args(["log", "-1", "--pretty=format:%s", commit_sha]);

        // Get the commit subject
        let subject = match cmd.output() {
            Ok(output) if output.status.success() => {
                match String::from_utf8(output.stdout) {
                    Ok(s) => s,
                    Err(_) => return None,
                }
            },
            _ => return None,
        };

        // Get the full commit message
        let mut cmd = std::process::Command::new("git");
        cmd.current_dir(repo_path)
            .args(["log", "-1", "--pretty=format:%B", commit_sha]);

        let message = match cmd.output() {
            Ok(output) if output.status.success() => {
                match String::from_utf8(output.stdout) {
                    Ok(s) => s,
                    Err(_) => return None,
                }
            },
            _ => return None,
        };

        // Get the diff with 20 lines of context
        let mut cmd = std::process::Command::new("git");
        cmd.current_dir(repo_path)
            .args(["show", "-U20", "--format=", commit_sha]);

        let diff = match cmd.output() {
            Ok(output) if output.status.success() => {
                match String::from_utf8(output.stdout) {
                    Ok(s) => {
                        // Check if diff is too large (more than 1000 lines)
                        let line_count = s.lines().count();
                        if line_count > 1000 {
                            debug!("Skipping large diff for commit {} ({} lines)", commit_sha, line_count);
                            return None;
                        }
                        s
                    },
                    Err(_) => return None,
                }
            },
            _ => return None,
        };

        Some((subject, message, diff))
    }

    // Helper function to create default LLM configurations
    fn create_default_llm_configs() -> HashMap<String, serde_json::Value> {
        let mut configs = HashMap::new();

        // Claude default config
        configs.insert("claude".to_string(), serde_json::json!({
            "model": "claude-3-7-sonnet-20250219",
            "temperature": 0,
            "max_tokens": 4000,
            "debug_logging": false
        }));

        // NVIDIA default config
        configs.insert("nvidia".to_string(), serde_json::json!({
            "model_type": "deepseek",
            "temperature": 0.6,
            "max_tokens": 4096
        }));

        // OpenAI default config
        configs.insert("openai".to_string(), serde_json::json!({
            "model_type": "gpt4o",
            "temperature": 0.2,
            "max_tokens": 4096,
            "debug_logging": false
        }));

        // Ollama default config
        configs.insert("ollama".to_string(), serde_json::json!({
            "model_type": "llama3",
            "temperature": 0.1,
            "max_tokens": 4096,
            "api_host": "http://localhost:11434",
            "debug_logging": false
        }));

        configs
    }

    /// Creates a new `CVEClassifier` instance optimized for processing prompts
    /// This is a lighter version that doesn't require a vectorstore
    pub fn new_for_prompt(
        llm_providers: Vec<String>,
        llm_configs: Option<HashMap<String, serde_json::Value>>,
        repo_path: Option<&Path>
    ) -> Self {
        // Initialize with the standard constructor but no persist_directory
        Self::new(llm_providers, llm_configs, None, repo_path)
    }

        // Helper to process a single commit feature into training data
    fn process_commit_to_training_data(
        commit: &CommitFeatures,
        max_chunk_length: usize
    ) -> (String, HashMap<String, String>) {
        // Extract subject and message body
        let message_lines: Vec<&str> = commit.message.trim().lines().collect();
        let subject = (*message_lines.first().unwrap_or(&"")).to_string();
        let message_body = if message_lines.len() > 1 {
            message_lines[1..].join("\n")
        } else {
            String::new()
        };

        // Build rich context for each commit
        let mut commit_context = Vec::new();

        commit_context.push(format!("Subject: {subject}"));
        commit_context.push(format!("Commit Message:\n{message_body}"));

        // Add code changes
        let diff_text = if commit.diff.len() > max_chunk_length {
            let truncated = commit.diff.chars().take(max_chunk_length).collect::<String>();
            warn!("Truncating large diff for commit {} (size: {})", commit.sha, commit.diff.len());
            format!("{truncated}\n[... truncated due to size ...]")
        } else {
            commit.diff.clone()
        };

        commit_context.push(format!("Changes:\n{diff_text}"));

        // Add files changed
        let files_text = if commit.files_changed.is_empty() {
            "Files: [none]".to_string()
        } else {
            let displayed_files = if commit.files_changed.len() > 5 {
                let joined = commit.files_changed[0..5].join(", ");
                format!("{} and {} more", joined, commit.files_changed.len() - 5)
            } else {
                commit.files_changed.join(", ")
            };
            format!("Files: {displayed_files}")
        };

        commit_context.push(files_text);

        // Mark CVE status prominently
        let cve_status = if commit.was_selected == Some(true) { "YES" } else { "NO" };
        let text = format!("[CVE Status: {}]\n\n{}", cve_status, commit_context.join("\n\n"));

        // Create metadata
        let mut metadata = HashMap::new();
        metadata.insert("has_cve".to_string(), cve_status.to_string());
        metadata.insert("sha".to_string(), commit.sha.clone());
        metadata.insert("date".to_string(), commit.date.to_rfc3339());

        // Add file paths joined with commas (limited to 10)
        if !commit.files_changed.is_empty() {
            let file_list = commit.files_changed.iter()
                .take(10)
                .cloned()
                .collect::<Vec<String>>()
                .join(",");
            metadata.insert("files".to_string(), file_list);
        }

        (text, metadata)
    }

    // Helper to process a batch of commit data with progress tracking
    fn process_commit_dataset(
        commit_dataset: &[CommitFeatures],
        max_chunk_length: usize
    ) -> (Vec<String>, Vec<Metadata>) {
        let mut texts = Vec::new();
        let mut metadatas = Vec::new();

        let pb = ProgressBar::new(commit_dataset.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap());

        for commit in commit_dataset {
            let (text, metadata) = Self::process_commit_to_training_data(commit, max_chunk_length);

            // Add text to the texts vector
            texts.push(text);

            // Convert HashMap to Metadata
            let mut metadata_obj = Metadata::default();
            for (k, v) in metadata {
                metadata_obj.extra.insert(k, serde_json::Value::String(v));
            }
            metadatas.push(metadata_obj);

            pb.inc(1);
        }

        pb.finish_with_message("Processed commit dataset");

        (texts, metadatas)
    }

    // Helper to create initial vectorstore from the first batch
    fn create_initial_vectorstore(
        &mut self,
        texts: &[String],
        metadatas: &[Metadata],
        batch_size: usize
    ) -> Result<usize, String> {
        let actual_batch_size = std::cmp::min(batch_size, texts.len());
        let batch_texts = texts[..actual_batch_size].to_vec();
        let batch_metadatas = metadatas[..actual_batch_size].to_vec();

        info!("Creating vectorstore with initial {actual_batch_size} items");

        self.vectorstore = match ChromaStore::from_texts(
            &batch_texts,
            &mut self.embeddings,
            Some(&batch_metadatas.iter().map(|m| {
                let mut map = HashMap::new();
                for (k, v) in &m.extra {
                    if let serde_json::Value::String(s) = v {
                        map.insert(k.clone(), s.clone());
                    }
                }
                map
            }).collect::<Vec<_>>()),
            self.persist_directory.as_deref()
        ) {
            Ok(vs) => Some(vs),
            Err(e) => return Err(format!("Failed to create vectorstore: {e}")),
        };

        Ok(actual_batch_size)
    }

    // Helper to add remaining batches to vectorstore
    fn add_remaining_batches(
        &mut self,
        texts: &[String],
        metadatas: &[Metadata],
        start_idx: usize,
        batch_size: usize
    ) {
        if start_idx >= texts.len() {
            return;
        }

        let pb = ProgressBar::new((texts.len() - start_idx) as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap());

        for batch_start in (start_idx..texts.len()).step_by(batch_size) {
            let batch_end = std::cmp::min(batch_start + batch_size, texts.len());
            let current_batch_size = batch_end - batch_start;

            let batch_texts = texts[batch_start..batch_end].to_vec();
            let batch_metadatas = metadatas[batch_start..batch_end].to_vec();

            if let Some(vs) = &mut self.vectorstore {
                if let Err(e) = vs.add_texts(batch_texts, Some(batch_metadatas)) {
                    warn!("Failed to add batch to vectorstore: {e}");
                }
            }

            pb.inc(current_batch_size as u64);
        }

        pb.finish_with_message("Added all batches to vectorstore");
    }

    // Training statistics helper
    fn log_training_statistics(commit_dataset: &[CommitFeatures]) {
        let cve_count = commit_dataset.iter()
            .filter(|c| c.was_selected == Some(true))
            .count();

        info!("Training complete - indexed {} commits ({} with CVE, {} without CVE)",
              commit_dataset.len(), cve_count, commit_dataset.len() - cve_count);
    }

    pub fn train(&mut self, commit_dataset: &[CommitFeatures]) -> Result<(), String> {
        // Define constants at the beginning of the function
        const BATCH_SIZE: usize = 1000;
        const MAX_CHUNK_LENGTH: usize = 100_000; // Characters

        info!("Training classifier with {} commits", commit_dataset.len());

        // Process dataset into texts and metadata for vectorstore
        let (texts, metadatas) = Self::process_commit_dataset(commit_dataset, MAX_CHUNK_LENGTH);

        // Initialize embeddings
        if let Err(e) = self.embeddings.initialize() {
            return Err(format!("Failed to initialize embeddings: {e}"));
        }

        // Process in reasonable batches
        let mut start_idx = 0;

        if self.vectorstore.is_none() {
            // Create initial vectorstore with first batch
            start_idx = self.create_initial_vectorstore(&texts, &metadatas, BATCH_SIZE)?;
        }

        // Add remaining batches
        self.add_remaining_batches(&texts, &metadatas, start_idx, BATCH_SIZE);

        // Log training statistics
        Self::log_training_statistics(commit_dataset);

        Ok(())
    }

    pub fn save_model(&self, model_path: &Path) -> Result<(), String> {
        // Save the vectorstore first if it exists
        if let Some(vectorstore) = &self.vectorstore {
            if let Some(persist_dir) = &self.persist_directory {
                debug!("Saving vectorstore to {}", persist_dir.display());
                if let Err(e) = vectorstore.persist(persist_dir) {
                    return Err(format!("Failed to save vectorstore: {e}"));
                }
            }
        }

        // Create a simplified model state for serialization
        let model_state = ModelState {
            persist_directory: self.persist_directory.clone(),
        };

        // Serialize and save
        match serde_json::to_string_pretty(&model_state) {
            Ok(json) => match std::fs::write(model_path, json) {
                Ok(()) => Ok(()),
                Err(e) => Err(format!("Failed to write model file: {e}")),
            },
            Err(e) => Err(format!("Failed to serialize model state: {e}")),
        }
    }

    pub fn load_model(model_path: &Path) -> Result<Self, String> {
        // Load the model state from file
        let model_state: ModelState = match std::fs::read_to_string(model_path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(state) => state,
                Err(e) => return Err(format!("Failed to parse model state: {e}")),
            },
            Err(e) => return Err(format!("Failed to read model file: {e}")),
        };

        // Set persist directory from model state
        let persist_dir = match &model_state.persist_directory {
            Some(dir) => {
                if !dir.exists() {
                    return Err(format!("Persist directory does not exist: {}", dir.display()));
                }
                Some(dir.as_path())
            },
            None => None,
        };

        // Create classifier
        let mut classifier = CVEClassifier::new(
            vec!["claude".to_string()],
            None,
            persist_dir,
            None,
        );

        // Try to load the vectorstore if persist directory is set
        if let Some(persist_dir) = persist_dir {
            // No need to initialize embeddings here - the vectorstore load will initialize it if needed

            // Load the vectorstore
            info!("Loading vectorstore from {}", persist_dir.display());
            match ChromaStore::load(persist_dir, classifier.embeddings.clone()) {
                Ok(vs) => classifier.vectorstore = Some(vs),
                Err(e) => return Err(format!("Failed to load vectorstore: {e}")),
            }
        }

        Ok(classifier)
    }

    pub fn format_commit_info(commit_info: &CommitFeatures) -> String {
        let mut commit_parts = Vec::new();

        // Extract subject (first line of commit message)
        let message_lines: Vec<&str> = commit_info.message.trim().lines().collect();
        let subject = (*message_lines.first().unwrap_or(&"No subject")).to_string();

        commit_parts.push(format!("Subject: {subject}"));
        commit_parts.push(format!("Commit Message:\n{}", commit_info.message));

        // Add code changes
        if !commit_info.diff.is_empty() {
            commit_parts.push(format!("Changes:\n{}", commit_info.diff));
        }

        // Add files changed
        if !commit_info.files_changed.is_empty() {
            let mut files_text = commit_info.files_changed.iter()
                .take(10)
                .map(ToString::to_string)
                .collect::<Vec<String>>()
                .join(", ");

            if commit_info.files_changed.len() > 10 {
                write!(files_text, " and {} more", commit_info.files_changed.len() - 10).unwrap();
            }

            commit_parts.push(format!("Files Changed: {files_text}"));
        }

        commit_parts.join("\n\n")
    }

    pub fn construct_prompt(commit_text: &str, similar_commits: &[(String, bool)], fixes_context: Option<&str>) -> String {
        // Template for the prompt
        let prompt_template = r#"You are a security expert analyzing Linux kernel commits to determine if they should be assigned a CVE identifier.

Your task requires THOROUGH and DETAILED research. This is a critical security assessment that demands comprehensive analysis.

## Available Tools and Sub-Agents

**IMPORTANT: Use the semcode MCP when available** - The semcode MCP provides semantic code search capabilities for the Linux kernel codebase. It can help you:
- Find function definitions and understand their purpose: `find_function <name>`
- Analyze call chains to understand impact: `find_callchain <function_name>`
- Find callers of a function: `find_callers <function_name>`
- Find functions called by a function: `find_calls <function_name>`
- Search for specific patterns in code: `grep_functions <pattern>`
- Extract functions from diffs: `diff_functions <diff_content>`
- Search for commits: `find_commit <git_ref>` or `find_commit --git-range <range>`
- Understand type definitions: `find_type <type_name>`

**Use sub-agents as necessary**: You have access to specialized sub-agents for different tasks:
- Use the "Explore" agent for complex codebase exploration
- Use the "kernel-code-researcher" agent to investigate design decisions and rationale
- Use other specialized agents as you deem appropriate

## Research Requirements

Perform a THOROUGH and DETAILED analysis:
1. **Understand the vulnerability context**:
   - What is the root cause of the issue?
   - Use semcode to examine the affected functions and their call chains
   - Investigate the history and purpose of the code being fixed

2. **Assess security impact**:
   - What attack vectors does this enable?
   - What are the consequences of exploitation?
   - Who can trigger this vulnerability (local user, remote attacker, etc.)?
   - What privileges are needed to exploit this?

3. **Analyze code changes in depth**:
   - Review the actual code diff line by line
   - Use semcode to understand the context of modified functions
   - Examine how the fix addresses the vulnerability
   - Look for similar patterns in the codebase

4. **Consider security-relevant indicators**:
   - Buffer overflow/underflow vulnerabilities
   - Use-after-free or double-free bugs
   - Race conditions and TOCTOU issues
   - Privilege escalation vectors
   - Information disclosure vulnerabilities
   - Denial of service conditions (including resource exhaustion)
   - Memory corruption issues
   - Access control bypasses
   - Input validation failures
   - Integer overflows/underflows
   - Memory leaks and resource leaks

5. **Memory leaks and resource exhaustion**:
   Memory leaks ARE security vulnerabilities when they can be exploited for denial of service.
   A memory leak warrants a CVE if:
   - An attacker can trigger the leak repeatedly (even if slowly)
   - The leaked memory accumulates over time without bounds
   - The leak can eventually exhaust system memory causing DoS

   Key considerations:
   - The size of each leak matters less than whether it can be triggered repeatedly
   - Privileged access (CAP_NET_ADMIN, root) does NOT disqualify a leak from being a security issue -
     many real-world attacks involve compromised privileged processes or containers
   - Kernel memory exhaustion affects system stability and availability
   - Consider whether the leak path is reachable via syscalls, network, filesystems, or device interfaces

   Memory leaks should generally receive CVEs unless:
   - The leak is bounded (cannot grow indefinitely)
   - The trigger requires already having kernel code execution
   - The affected code path is not reachable in practice

6. **Evaluate scope and impact**:
   - What subsystems are affected (memory management, networking, filesystem, etc.)?
   - Is this a widespread issue or limited to specific configurations?
   - Does this affect user data, system integrity, or availability?

Historical similar commits and their CVE status for reference:
{context}

{fixes_context}

IMPORTANT: Pay close attention to the CVE Status (YES/NO) of similar commits as they provide valuable reference points.
Commits with similar characteristics to those marked with "CVE Status: YES" are more likely to need a CVE.

New Commit to analyze:
{commit_info}

## Your Task

Based on your THOROUGH and DETAILED analysis (using semcode MCP and sub-agents as needed):
1. Research the vulnerability deeply using all available tools
2. Understand the security implications comprehensively
3. Make an informed decision on CVE assignment

Provide your answer as **YES** or **NO**, followed by a detailed explanation that:
- References specific parts of the code changes
- Explains the security impact (or lack thereof)
- Justifies your decision with technical reasoning
- Cites any relevant research you performed using semcode or other tools"#;

        // Format the context from similar commits
        let mut context_parts = Vec::new();

        for (i, (content, has_cve)) in similar_commits.iter().enumerate() {
            if content.is_empty() {
                continue;  // Skip empty content
            }

            // Extract CVE status
            let cve_status = if *has_cve { "YES" } else { "NO" };

            // Add a clear separator with the similarity ranking and status
            context_parts.push(format!("Similar Commit {} [CVE Status: {}]:\n{}", i+1, cve_status, content));
        }

        let context_text = context_parts.join("\n\n");

        // Determine fixes context string
        let fixes_context_text = fixes_context.unwrap_or("");

        // Replace placeholders in the template
        prompt_template
            .replace("{context}", &context_text)
            .replace("{fixes_context}", fixes_context_text)
            .replace("{commit_info}", commit_text)
    }

    pub fn find_similar_commits(&self, commit_text: &str, k: usize) -> Vec<(String, bool)> {
        // If no vectorstore is available, return empty results
        if self.vectorstore.is_none() {
            warn!("No vectorstore available for similarity search");
            return Vec::new();
        }

        // Check if embeddings are initialized
        if !self.embeddings.is_initialized() {
            error!("Embeddings model not initialized");
            return Vec::new();
        }

        // Get the vectorstore
        let vectorstore = self.vectorstore.as_ref().unwrap();

        // Perform similarity search
        match vectorstore.similarity_search(commit_text, k) {
            Ok(scored_docs) => {
                scored_docs.into_iter()
                    .map(|scored_doc| {
                        let doc_text = scored_doc.document.text;
                        let has_cve = scored_doc.document.metadata.extra.get("has_cve")
                            .and_then(|v| {
                                if let serde_json::Value::String(s) = v {
                                    Some(s == "YES")
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(false);
                        (doc_text, has_cve)
                    })
                    .collect()
            },
            Err(e) => {
                error!("Error performing similarity search: {e}");
                Vec::new()
            }
        }
    }

    fn initialize_llms(&mut self) -> Result<(), String> {
        if self.llms.is_none() {
            let mut llms = HashMap::new();

            for provider in &self.llm_providers {
                let config = self.llm_configs.get(provider).cloned();
                match commit_classifier::create_llm(provider, config) {
                    Ok(llm) => {
                        llms.insert(provider.clone(), llm);
                    },
                    Err(e) => {
                        return Err(format!("Failed to initialize {provider} LLM: {e}"));
                    }
                }
            }

            if llms.is_empty() {
                return Err("No valid LLM providers specified".to_string());
            }

            self.llms = Some(llms);
        }

        Ok(())
    }

    // Helper method to invoke an LLM with retry logic for common error cases
    async fn invoke_llm_with_retry(&self, llm: &dyn Llm, prompt: &str, provider: &str, verbose: bool)
        -> Result<(bool, String, String), String> {
        // Maximum number of retries for errors
        let max_retries = 3;
        let mut retry_count = 0;

        loop {
            match llm.invoke(prompt).await {
                Ok(response) => {
                    // Check if the response is just "yes" (case insensitive)
                    let trimmed_response = response.trim().to_lowercase();
                    if trimmed_response == "yes" && retry_count < max_retries {
                        retry_count += 1;
                        warn!("Received bare 'yes' response from {provider} LLM, retrying ({retry_count}/{max_retries})");

                        // Wait a bit before retrying
                        tokio::time::sleep(std::time::Duration::from_millis(1000 * retry_count)).await;
                        continue; // Try again
                    }

                    // Show full response when verbose is enabled
                    if verbose {
                        info!("===== FULL RESPONSE FROM {} =====", provider.to_uppercase());
                        info!("{response}");
                        info!("==========================================");
                    }

                    let (should_assign_cve, explanation) = Self::parse_llm_response(&response);
                    return Ok((should_assign_cve, explanation, response));
                },
                Err(e) => {
                    let err_str = e.to_string();

                    // Check if we still have retries available
                    if retry_count < max_retries {
                        retry_count += 1;

                        // Log specific error types differently
                        if err_str.contains("Failed to parse response: EOF while parsing a value at line 1 column 0") {
                            warn!("Encountered EOF parsing error with {provider} LLM, retrying ({retry_count}/{max_retries})");
                        } else {
                            warn!("Error invoking {provider} LLM: {err_str}, retrying ({retry_count}/{max_retries})");
                        }

                        // Wait a bit before retrying with exponential backoff
                        let backoff_ms = 1000 * retry_count;
                        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                        continue; // Try again
                    }

                    // We've exhausted all retries
                    error!("Error invoking {provider} LLM after {max_retries} retries: {err_str}");
                    return Err(format!("Error: {err_str}"));
                }
            }
        }
    }

    pub async fn predict(&mut self, commit_info: &CommitFeatures, verbose: bool) -> Result<PredictionResult, String> {
        // Initialize LLMs if not already done
        self.initialize_llms()?;

        // Generate the vector database search for context
        let commit_text = Self::format_commit_info(commit_info);

        // Get similar commits for context if vectorstore is available
        let similar_commits = if self.vectorstore.is_some() {
            // Ensure embeddings are initialized only if they aren't already
            if !self.embeddings.is_initialized() {
                info!("Initializing embeddings model for prediction");
                if let Err(e) = self.embeddings.initialize() {
                    warn!("Failed to initialize embeddings model: {e}. Continuing without RAG.");
                    Vec::new()
                } else {
                    self.find_similar_commits(&commit_text, 5)
                }
            } else {
                self.find_similar_commits(&commit_text, 5)
            }
        } else {
            info!("No vectorstore available, proceeding without RAG");
            Vec::new()
        };

        // Generate fixes context if available
        let fixes_context = if self.repo_path.is_some() {
            // Extract fixed commits
            let fixes_refs = Self::extract_fixes_references(&commit_info.message);
            if fixes_refs.is_empty() {
                None
            } else {
                let mut fixes_parts = Vec::new();
                fixes_parts.push("Referenced Fixes commit(s):".to_string());

                for fix_ref in &fixes_refs {
                    if let Some((subject, message, diff)) = self.get_fix_commit_content(fix_ref) {
                        fixes_parts.push(format!(
                            "Fixes commit {fix_ref}: {subject}\n\nFull message:\n{message}\n\nDiff:\n{diff}"
                        ));
                    }
                }

                if fixes_parts.len() > 1 {
                    Some(fixes_parts.join("\n\n"))
                } else {
                    None
                }
            }
        } else {
            None
        };

        // Construct prompt with context and commit info
        let prompt = Self::construct_prompt(&commit_text, &similar_commits, fixes_context.as_deref());

        // Show full prompt when verbose is enabled
        if verbose {
            info!("===== FULL PROMPT =====");
            // Print each line without extra indentation
            for line in prompt.lines() {
                info!("{line}");
            }
            info!("=======================");
        }

        // Process the prompt and get the prediction result
        let result = self.process_with_llms(&prompt, verbose).await?;

        // Return the consolidated results with commit-specific information
        // Return the CVE assignment decision
        Ok(PredictionResult {
            sha: commit_info.sha.clone(),
            subject: commit_info.message.lines().next().unwrap_or("Unknown").to_string(),
            should_select: result.should_select,
            vote_ratio: result.vote_ratio,
            provider_results: result.provider_results,
        })
    }

    // Parse LLM response to extract decision and explanation
    pub fn parse_llm_response(response: &str) -> (bool, String) {
        // First, filter out any content inside <think> blocks
        let filtered_response = if response.contains("<think>") && response.contains("</think>") {
            // Extract content outside of think blocks
            let mut result = String::new();
            let mut in_think_block = false;

            for line in response.lines() {
                if line.contains("<think>") {
                    in_think_block = true;
                    continue;
                }
                if line.contains("</think>") {
                    in_think_block = false;
                    continue;
                }

                if !in_think_block {
                    result.push_str(line);
                    result.push('\n');
                }
            }

            result
        } else {
            response.to_string()
        };

        // If we got an error message back
        if filtered_response.starts_with("Error:") {
            debug!("Found error message in response");
            return (false, format!("LLM Error: {filtered_response}"));
        }

        // First check for bold indicators in the original response (case-insensitive)
        // Match **YES**, **NO**, or even partial bold like **YES or YES**
        let bold_patterns = [
            Regex::new(r"(?i)\*\*(YES|NO)\*\*").unwrap(),  // Standard **YES** or **NO**
            Regex::new(r"(?i)\*\*(YES|NO)\b").unwrap(),    // **YES or **NO followed by word boundary
            Regex::new(r"(?i)\b(YES|NO)\*\*").unwrap(),    // YES** or NO**
        ];

        for bold_pattern in &bold_patterns {
            if let Some(captures) = bold_pattern.captures(&filtered_response) {
                let decision = captures.get(1).unwrap().as_str().to_uppercase();
                debug!("Found bold {decision} indicator");
                return (decision == "YES", filtered_response.to_string());
            }
        }

        // Convert to uppercase for case-insensitive pattern matching
        let upper_response = filtered_response.to_uppercase();

        // Look for patterns in this order (most to least reliable)
        let patterns = [
            // ANSWER: YES/NO
            (Regex::new(r"ANSWER:\s*(YES|NO)").unwrap(), "ANSWER: format"),

            // YES/NO at the beginning
            (Regex::new(r"^\s*(YES|NO)\b").unwrap(), "Start of response"),

            // ANSWER IS/: YES/NO
            (Regex::new(r"ANSWER\s+(?:IS|:)\s*(YES|NO)").unwrap(), "ANSWER IS/: format"),

            // GPT-4 style: YES/NO at beginning followed by newline, end, or "Explanation"
            (Regex::new(r"(YES|NO)\s*(?:\n|$|EXPLANATION|:)").unwrap(), "GPT-4 style"),

            // DECISION: YES/NO
            (Regex::new(r"DECISION:\s*(YES|NO)").unwrap(), "DECISION: format"),
        ];

        for (pattern, pattern_name) in &patterns {
            if let Some(captures) = pattern.captures(&upper_response) {
                let decision = captures.get(1).unwrap().as_str();
                debug!("Found {pattern_name} pattern: {decision}");
                return (decision == "YES", filtered_response.to_string());
            }
        }

        // If specific patterns don't match, try these common cases
        if upper_response.trim().starts_with("NO:") {
            debug!("Found 'NO:' at start of response");
            return (false, filtered_response.to_string());
        }

        // Look for YES/NO anywhere in the text (first occurrence)
        let yes_pos = upper_response.find("YES");
        let no_pos = upper_response.find("NO");

        if yes_pos.is_some() && no_pos.is_some() {
            // Return based on which comes first
            let yes_idx = yes_pos.unwrap();
            let no_idx = no_pos.unwrap();
            debug!("Found both YES and NO at positions {yes_idx} and {no_idx}");
            return (yes_idx < no_idx, filtered_response.to_string());
        } else if yes_pos.is_some() {
            debug!("Found only YES in response");
            return (true, filtered_response.to_string());
        } else if no_pos.is_some() {
            debug!("Found only NO in response");
            return (false, filtered_response.to_string());
        }

        // If still no match, check for phrases
        let cve_phrases = [
            // Positive phrases
            (true, "should be assigned a cve"),
            (true, "needs a cve"),
            (true, "deserves a cve"),
            (true, "qualifies for a cve"),
            (true, "warrants a cve"),

            // Negative phrases
            (false, "should not be assigned a cve"),
            (false, "does not need a cve"),
            (false, "doesn't deserve a cve"),
            (false, "doesn't qualify for a cve"),
            (false, "doesn't warrant a cve"),
        ];

        let lower_response = filtered_response.to_lowercase();
        for (decision, phrase) in &cve_phrases {
            if lower_response.contains(phrase) {
                debug!("Found phrase: '{phrase}'");
                return (*decision, filtered_response.to_string());
            }
        }

        // Default fallback - consider it not needing a CVE unless clearly indicated
        // This is safer from a security perspective
        debug!("No clear YES/NO found in response, defaulting to NO");
        (false, filtered_response.to_string())
    }

    // Shared method to process a prompt with all available LLMs
    async fn process_with_llms(&mut self, prompt: &str, verbose: bool) -> Result<PredictionResult, String> {
        // Initialize LLMs if not already done
        self.initialize_llms()?;

        // Clone the LLM providers for later use
        let llm_providers: Vec<String> = if let Some(llms) = &self.llms {
            llms.keys().cloned().collect()
        } else {
            return Err("LLMs not initialized".to_string());
        };

        // Extract the LLMs into a local variable to avoid borrowing issues
        let llms = if let Some(llms) = &self.llms {
            // Create a new HashMap with cloned keys and the original Box<dyn Llm> pointers
            let mut llm_map = HashMap::new();
            for (k, v) in llms {
                llm_map.insert(k.clone(), v);
            }
            llm_map
        } else {
            return Err("LLMs not initialized".to_string());
        };

        // Get LLM predictions
        let mut results = HashMap::new();
        let mut should_assign_cve_votes = 0;
        let mut provider_count = 0;

        for provider in &llm_providers {
            if let Some(llm) = llms.get(provider) {
                // Deref Box<dyn Llm> to get a dyn Llm, then take a reference
                let llm_ref: &dyn Llm = llm.as_ref();
                match self.invoke_llm_with_retry(llm_ref, prompt, provider, verbose).await {
                    Ok((should_assign_cve, explanation, response)) => {
                        // Store our CVE assignment decision
                        results.insert(provider.clone(), ProviderResult {
                            should_select: should_assign_cve, // Store the CVE assignment decision
                            explanation,
                            error: None,
                            raw_response: Some(response),
                        });

                        should_assign_cve_votes += i32::from(should_assign_cve);
                        provider_count += 1;
                    },
                    Err(e) => {
                        // Store our CVE assignment decision (default: no CVE)
                        results.insert(provider.clone(), ProviderResult {
                            should_select: false, // Default to false (no CVE) in error case
                            explanation: String::new(),
                            error: Some(e),
                            raw_response: None,
                        });
                    }
                }
            }
        }

        // Calculate the consensus result
        let consensus_threshold = (provider_count + 1) / 2; // This rounds up for odd numbers
        let consensus_should_assign_cve = should_assign_cve_votes >= consensus_threshold;

        // Return a generic prediction result (will be enhanced by specific methods)
        // Return the CVE assignment decision
        Ok(PredictionResult {
            sha: String::new(), // Will be overridden by the calling method
            subject: String::new(), // Will be overridden by the calling method
            should_select: consensus_should_assign_cve,
            vote_ratio: format!("{should_assign_cve_votes}/{provider_count}"),
            provider_results: results,
        })
    }

    // Process a custom prompt directly without using embeddings or similar commit search
    pub async fn process_custom_prompt(&mut self, prompt: &str, verbose: bool) -> Result<PredictionResult, String> {
        // Initialize LLMs if needed
        self.initialize_llms()?;

        if verbose {
            info!("===== CUSTOM PROMPT =====");
            // Print each line without extra indentation
            for line in prompt.lines() {
                info!("{line}");
            }
            info!("=======================");
        }

        // Process the prompt and get the prediction result
        let result = self.process_with_llms(prompt, verbose).await?;

        // Return the consolidated results with custom values for sha and subject
        // Return the CVE assignment decision
        Ok(PredictionResult {
            sha: "custom_prompt".to_string(),
            subject: "Custom prompt".to_string(),
            should_select: result.should_select,
            vote_ratio: result.vote_ratio,
            provider_results: result.provider_results,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::CVEClassifier;

    #[test]
    fn test_parse_bold_yes_indicator() {
        let response = "**YES** This commit should be backported to stable kernel trees because it fixes a real bug that can lead to crashes or undefined behavior.";
        let (decision, _) = CVEClassifier::parse_llm_response(response);
        assert_eq!(decision, true);
    }

    #[test]
    fn test_parse_bold_no_indicator() {
        let response = "Based on my analysis of this commit and understanding of stable kernel rules, here is my determination: **NO** This commit should NOT be backported to stable kernel trees.";
        let (decision, _) = CVEClassifier::parse_llm_response(response);
        assert_eq!(decision, false);
    }

    #[test]
    fn test_parse_bold_yes_with_context() {
        let response = "Let me analyze this commit based on the information provided: **YES** This commit should definitely be backported to stable kernel trees.";
        let (decision, _) = CVEClassifier::parse_llm_response(response);
        assert_eq!(decision, true);
    }

    #[test]
    fn test_parse_bold_no_with_emphasis() {
        let response = "**NO** This commit should **NOT** be backported to stable kernel trees.";
        let (decision, _) = CVEClassifier::parse_llm_response(response);
        assert_eq!(decision, false);
    }

    #[test]
    fn test_parse_plain_no_without_bold() {
        let response = "NO This commit should not be backported to stable kernel trees.";
        let (decision, _) = CVEClassifier::parse_llm_response(response);
        assert_eq!(decision, false);
    }

    #[test]
    fn test_parse_partial_bold_yes() {
        let response = "The answer is **YES, this commit needs a CVE assignment.";
        let (decision, _) = CVEClassifier::parse_llm_response(response);
        assert_eq!(decision, true);
    }

    #[test]
    fn test_parse_answer_format() {
        let response = "ANSWER: YES\n\nThis is a security fix.";
        let (decision, _) = CVEClassifier::parse_llm_response(response);
        assert_eq!(decision, true);
    }

    #[test]
    fn test_parse_with_think_blocks() {
        let response = "<think>\nSome internal reasoning\n</think>\n**YES** This is a security vulnerability.";
        let (decision, _) = CVEClassifier::parse_llm_response(response);
        assert_eq!(decision, true);
    }

    #[test]
    fn test_parse_mixed_case_bold() {
        let response = "**yes** this should be backported";
        let (decision, _) = CVEClassifier::parse_llm_response(response);
        assert_eq!(decision, true);
    }

    #[test]
    fn test_parse_no_clear_indicator() {
        let response = "This commit appears to be a feature addition and not a bug fix.";
        let (decision, explanation) = CVEClassifier::parse_llm_response(response);
        assert_eq!(decision, false); // Should default to false
        assert!(explanation.contains("feature addition"));
    }
}
