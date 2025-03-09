# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
#
import os
import git
import logging
import argparse
from pathlib import Path
import pickle
from datetime import datetime, timedelta, timezone
import pandas as pd
from langchain_community.vectorstores import FAISS
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_huggingface import HuggingFaceEmbeddings
from langchain.prompts import PromptTemplate
from langchain_anthropic import ChatAnthropic
from abc import ABC, abstractmethod
from huggingface_hub import InferenceClient
from typing import Union, List
import concurrent.futures
from tqdm import tqdm  # For progress bars
import sys
from openai import OpenAI
import hashlib
import re

class BaseLLM(ABC):
    @abstractmethod
    def invoke(self, prompt: str) -> str:
        pass

class ClaudeLLM(BaseLLM):
    def __init__(self, model: str = "claude-3-sonnet-20240229", temperature: float = 0):
        self.llm = ChatAnthropic(
            model=model,
            temperature=temperature,
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY")
        )

    def invoke(self, prompt: str) -> str:
        response = self.llm.invoke(prompt)
        return response.content

class HuggingFaceLLM(BaseLLM):
    MODELS = {
        "llama": "meta-llama/llama-3.1-70b-instruct",
        "qwen": "Qwen/Qwen2.5-72B-Instruct"
    }

    def __init__(self, model_type: str = "llama", temperature: float = 0.1):
        self.client = InferenceClient(
            token=os.getenv("HUGGINGFACE_API_KEY")
        )
        self.model = self.MODELS.get(model_type, model_type)
        self.temperature = temperature
        self.model_type = model_type

    def invoke(self, prompt: str) -> str:
        if self.model_type == "llama":
            formatted_prompt = f"[INST] {prompt} [/INST]"
        elif self.model_type == "qwen":
            formatted_prompt = f"<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n"
        else:
            formatted_prompt = prompt

        response = self.client.text_generation(
            formatted_prompt,
            model=self.model,
            temperature=self.temperature,
            max_new_tokens=512,
            return_full_text=False,
            stop=["<|im_end|>"] if self.model_type == "qwen" else None
        )
        return response

class OpenAILLM(BaseLLM):
    MODELS = {
        "gpt4": "gpt-4-0125-preview",  # GPT-4 Turbo
    }

    def __init__(self, model_type: str = "gpt4", temperature: float = 0):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = self.MODELS.get(model_type, model_type)
        self.temperature = temperature

    def invoke(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=self.temperature
        )
        return response.choices[0].message.content

class CommitDataCollector:
    def __init__(self, kernel_repo_path: str, cve_commits_path: str):
        self.kernel_repo_path = kernel_repo_path
        self.cve_commits_path = cve_commits_path
        self.repo = git.Repo(kernel_repo_path)
        self.cve_commits = self.get_cve_commits()
        self.seen_commit_messages = set()  # Track unique commit messages
        self.seen_subject_lines = set()  # Track unique subject lines

    def get_cve_commits(self) -> dict:
        """Read CVE-assigned commit SHAs from the published directory
        Returns a dictionary with:
            - 'cve_fixes': set of commits that fix CVEs
            - 'cve_vulns': set of commits that introduce vulnerabilities
        """
        cve_fixes = set()
        cve_vulns = set()
        logging.debug(f"Searching for .dyad files in {self.cve_commits_path}")

        for file_path in self.cve_commits_path.rglob('*.dyad'):
            try:
                with open(file_path) as f:
                    for line in f:
                        line = line.strip()
                        # Skip comments and empty lines
                        if not line or line.startswith('#'):
                            continue
                        # Parse the dyad line format: vuln_ver:vuln_commit:fix_ver:fix_commit
                        parts = line.split(':')
                        if len(parts) == 4:
                            vuln_commit = parts[1]
                            fix_commit = parts[3]
                            # Add non-zero commits
                            if vuln_commit != '0':
                                cve_vulns.add(vuln_commit)
                            if fix_commit != '0':
                                cve_fixes.add(fix_commit)
            except Exception as e:
                logging.warning(f"Error reading {file_path}: {e}")
                continue

        logging.info(f"Total CVE fix commits found: {len(cve_fixes)}")
        logging.info(f"Total CVE vulnerable commits found: {len(cve_vulns)}")
        return {'cve_fixes': cve_fixes, 'cve_vulns': cve_vulns}

    def get_commit_features(self, commit_sha: str) -> dict:
        """Extract relevant features from a commit"""
        commit = self.repo.commit(commit_sha)
        return {
            'sha': commit.hexsha,
            'message': commit.message,
            'diff': commit.parents[0].diff(commit, create_patch=True) if commit.parents else "",
            'author': commit.author.name,
            'date': commit.authored_datetime,
            'files_changed': list(commit.stats.files.keys())
        }

    def process_cve_commit(self, sha: str) -> dict:
        """Process a single CVE commit with extended context"""
        try:
            features = self.get_commit_features(sha)
            features['has_cve'] = True
            commit = self.repo.commit(sha)

            # Get parent commit context
            if commit.parents:
                parent = commit.parents[0]
                features['parent_message'] = parent.message
                features['parent_diff'] = parent.diff(commit, create_patch=True)

                # Get grandparent for more history
                if parent.parents:
                    grandparent = parent.parents[0]
                    features['grandparent_message'] = grandparent.message
                    features['grandparent_diff'] = grandparent.diff(parent, create_patch=True)

            # Look for related commits (both before and after)
            related_commits = []

            # Look back for related changes
            for related in self.repo.iter_commits(f'{sha}^..HEAD', max_count=10):
                if any(word in related.message.lower() for word in ['cve', 'fix', 'security', 'vuln']):
                    related_commits.append({
                        'message': related.message,
                        'diff': related.parents[0].diff(related, create_patch=True) if related.parents else "",
                        'relation': 'after'
                    })

            # Look forward for follow-up fixes
            for related in self.repo.iter_commits(f'HEAD..{sha}', max_count=10):
                if any(word in related.message.lower() for word in ['cve', 'fix', 'security', 'vuln']):
                    related_commits.append({
                        'message': related.message,
                        'diff': related.parents[0].diff(related, create_patch=True) if related.parents else "",
                        'relation': 'before'
                    })

            features['related_commits'] = related_commits

            # Add file-level analysis
            file_analysis = {}
            for file_path in features['files_changed']:
                try:
                    # Get file history only if the file exists in the parent commit
                    if commit.parents:
                        parent = commit.parents[0]
                        try:
                            # Check if file exists in parent
                            parent.tree[file_path]

                            # Get file history with better error handling
                            try:
                                file_history = list(self.repo.iter_commits(
                                    f'{parent.hexsha}',
                                    paths=file_path,
                                    max_count=5
                                ))
                            except git.exc.GitCommandError:
                                file_history = []

                            # Get blame info for changed lines
                            blame_info = []
                            for old_path, new_path, flag in commit.diff(parent):
                                if new_path and new_path.path == file_path:
                                    try:
                                        for blame_entry in self.repo.blame(parent, file_path):
                                            blame_commit, lines = blame_entry
                                            blame_info.append({
                                                'author': blame_commit.author.name,
                                                'date': blame_commit.authored_datetime,
                                                'message': blame_commit.message
                                            })
                                    except git.exc.GitCommandError:
                                        continue

                            file_analysis[file_path] = {
                                'history': [{
                                    'sha': c.hexsha,
                                    'message': c.message,
                                    'date': c.authored_datetime
                                } for c in file_history],
                                'blame': blame_info
                            }
                        except KeyError:
                            # File doesn't exist in parent commit
                            continue
                except Exception as e:
                    logging.debug(f"Error analyzing file {file_path}: {e}")
                    continue

            features['file_analysis'] = file_analysis
            return features

        except (git.exc.GitCommandError, KeyError) as e:
            logging.debug(f"Failed to get features for CVE commit {sha}: {e}")
            return None

    def process_non_cve_commit(self, sha: str) -> dict:
        """Process a single non-CVE commit with context"""
        try:
            features = self.get_commit_features(sha)
            features['has_cve'] = False

            # Add parent commit context
            commit = self.repo.commit(sha)
            if commit.parents:
                parent = commit.parents[0]
                features['parent_message'] = parent.message
                features['parent_diff'] = parent.diff(commit, create_patch=True)

            return features

        except (git.exc.GitCommandError, KeyError) as e:
            logging.debug(f"Failed to get features for non-CVE commit {sha}: {e}")
            return None

    def _get_commit_message_hash(self, commit_sha: str) -> dict:
        """Generate a hash of a commit's message (subject + body) for deduplication.
        Only uses the commit subject and body, ignoring any metadata like dates, signoffs, etc."""
        try:
            commit = self.repo.commit(commit_sha)
            # Get the raw message
            message = commit.message

            # Split into lines and process
            lines = message.strip().split('\n')

            # Get subject (first line)
            subject = lines[0].strip()

            # Get body (skip any metadata lines)
            body_lines = []
            for line in lines[1:]:
                line = line.strip()
                # Skip empty lines and metadata lines
                if not line:
                    continue
                if any(line.startswith(x) for x in [
                    'Signed-off-by:', 'Acked-by:', 'Reviewed-by:', 'Tested-by:',
                    'Reported-by:', 'Suggested-by:', 'Co-developed-by:', 'Link:',
                    'Fixes:', 'Cc:', 'Reference:', 'commit', 'Author:', 'Date:',
                    'BugLink:', 'CVE:', 'Reported-and-tested-by:'
                ]):
                    continue
                body_lines.append(line)

            # Combine subject and body, normalizing whitespace
            clean_message = subject
            if body_lines:
                clean_message += '\n' + '\n'.join(body_lines)

            # Return hash of the cleaned message and the subject
            return {
                'hash': hashlib.sha256(clean_message.encode()).hexdigest(),
                'subject': subject
            }
        except Exception as e:
            logging.error(f"Failed to get message hash for commit {commit_sha}: {e}")
            return None

    def _is_duplicate_commit(self, commit_sha: str) -> bool:
        """Check if we've seen this commit message or subject line before"""
        msg_data = self._get_commit_message_hash(commit_sha)
        if msg_data is None:
            return False  # On error, assume it's not a duplicate

        msg_hash = msg_data['hash']
        subject = msg_data['subject']

        # Check for duplicate hash or subject
        if msg_hash in self.seen_commit_messages or subject in self.seen_subject_lines:
            return True

        # Store hash and subject
        self.seen_commit_messages.add(msg_hash)
        self.seen_subject_lines.add(subject)
        return False

    def build_dataset(self, min_months: int = 1, max_months: int = 12, chunk_size: int = 1000, max_workers: int = 24,
                     max_cve: int = None, max_non_cve: int = None) -> pd.DataFrame:
        """Build a dataset of CVE and non-CVE commits using parallel processing"""
        logging.info("Getting CVE commits...")
        cve_commits = self.get_cve_commits()

        # Create a set of all commits that were ever assigned a CVE (either as fix or vulnerability)
        all_cve_shas = cve_commits['cve_fixes'] | cve_commits['cve_vulns']

        # Reset seen commit messages
        self.seen_commit_messages = set()

        # If in test mode, limit CVE commits
        if max_cve is not None:
            cve_commits = {k: set(list(v)[:max_cve]) for k, v in cve_commits.items()}
            logging.info(f"Limited to {sum(len(v) for v in cve_commits.values())} CVE commits for testing")

        # Process CVE commits in parallel, filtering duplicates
        all_commits = []
        duplicates_found = 0
        with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            # Process in smaller chunks to show progress
            chunk_size = 100
            for k, shas in cve_commits.items():
                for sha in shas:
                    if not self._is_duplicate_commit(sha):
                        futures.append(executor.submit(self.process_cve_commit, sha))
                    else:
                        duplicates_found += 1

            with tqdm(total=len(futures), desc="Processing unique CVE commits") as pbar:
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result is not None:
                            all_commits.append(result)
                    except Exception as e:
                        logging.error(f"Error processing commit: {e}")
                    pbar.update(1)

        logging.info(f"Processed {len(all_commits)} unique CVE commits (skipped {duplicates_found} duplicates)")

        # Get non-CVE commits from linux- branches
        logging.info(f"Getting non-CVE commits between {min_months} and {max_months} months old from linux- branches...")

        # Calculate date boundaries
        now = datetime.now(timezone.utc)
        oldest_date = now - timedelta(days=max_months * 30)  # Approximate months
        newest_date = now - timedelta(days=min_months * 30)

        # Get list of linux- branches
        branches = [ref.name for ref in self.repo.refs if ref.name.startswith('origin/linux-')]
        logging.info(f"Found {len(branches)} linux- branches: {', '.join(branches)}")

        non_cve_commits = []
        processed_count = 0
        branch_duplicates = 0

        for branch in branches:
            try:
                # Get the branch tip commit and its date
                try:
                    branch_tip = self.repo.git.rev_parse(branch).strip()
                    tip_commit = self.repo.commit(branch_tip)
                    tip_date = tip_commit.committed_datetime

                    # Skip branch if tip is older than our oldest acceptable date
                    if tip_date < oldest_date:
                        logging.debug(f"Skipping {branch} - tip ({tip_date}) is older than oldest acceptable date ({oldest_date})")
                        continue

                    logging.debug(f"Branch tip for {branch}: {branch_tip} (date: {tip_date})")
                except git.GitCommandError as e:
                    logging.error(f"Failed to get tip of {branch}: {e}")
                    continue

                # Get merge-base with origin/master
                try:
                    merge_base = self.repo.git.merge_base('origin/master', branch).strip()
                    logging.debug(f"Found merge-base {merge_base} between origin/master and {branch}")
                except git.GitCommandError as e:
                    logging.error(f"Failed to find merge-base for {branch}: {e}")
                    continue

                # Get all commits in this branch between merge-base and tip, respecting date constraints
                cmd = [
                    'git', 'rev-list', '--no-merges',
                    f'--since="{max_months} months ago"',
                    f'--until="{min_months} months ago"',
                    f'{merge_base}..{branch_tip}'  # Range from merge-base to tip
                ]
                output = self.repo.git.execute(cmd)
                all_branch_shas = set(output.strip().split('\n')) if output.strip() else set()
                total_commits = len(all_branch_shas)

                # Count CVE vs non-CVE commits
                cve_assigned = all_branch_shas & all_cve_shas
                non_cve = all_branch_shas - all_cve_shas

                # Filter out duplicates from non_cve set
                unique_non_cve = {sha for sha in non_cve if not self._is_duplicate_commit(sha)}
                branch_duplicates += len(non_cve) - len(unique_non_cve)

                logging.info(f"Found {total_commits} total commits in {branch} between merge-base and tip "
                           f"({len(cve_assigned)} with CVEs, {len(unique_non_cve)} unique non-CVE, "
                           f"skipped {len(non_cve) - len(unique_non_cve)} duplicates)")

                # Skip if no commits in date range
                if total_commits == 0:
                    logging.debug(f"Skipping {branch} - no commits in date range")
                    continue

                # Process commits in chunks
                branch_processed_commits = 0
                for skip in range(0, len(unique_non_cve), chunk_size):
                    if max_non_cve is not None and len(non_cve_commits) >= max_non_cve:
                        break

                    # Take a chunk of non-CVE commits
                    current_chunk = list(unique_non_cve)[skip:skip + chunk_size]

                    # Process chunk in parallel
                    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
                        futures = []
                        for sha in current_chunk:
                            if max_non_cve is not None and len(non_cve_commits) >= max_non_cve:
                                break
                            futures.append(executor.submit(self.process_non_cve_commit, sha))

                        if futures:
                            processed_results = []
                            for future in concurrent.futures.as_completed(futures):
                                try:
                                    result = future.result()
                                    if result is not None:
                                        non_cve_commits.append(result)
                                        processed_results.append(result)
                                except Exception as e:
                                    logging.error(f"Error processing commit: {e}")

                    processed_count += len(current_chunk)
                    branch_processed_commits += len(processed_results) if 'processed_results' in locals() else 0

                    if max_non_cve is not None and len(non_cve_commits) >= max_non_cve:
                        logging.info(f"Reached maximum non-CVE commits ({max_non_cve})")
                        break

                # Log one summary line per branch
                if branch_processed_commits > 0:
                    logging.info(f"Processed {branch_processed_commits} non-CVE commits from {branch} (total: {len(non_cve_commits)})")

            except git.GitCommandError as e:
                logging.error(f"Git command failed for branch {branch}: {e}")
                continue

        # Combine and convert to DataFrame
        all_commits += non_cve_commits
        df = pd.DataFrame(all_commits)

        logging.info(f"Final dataset: {len(df)} total unique commits")
        logging.info(f"  - CVE commits: {sum(df.has_cve)} (skipped {duplicates_found} duplicates)")
        logging.info(f"  - Non-CVE commits: {sum(~df.has_cve)} (skipped {branch_duplicates} duplicates)")

        return df

class CVEClassifier:
    def __init__(self,
                 embedding_model: str = "all-MiniLM-L6-v2",
                 llm_providers: Union[str, List[str]] = ["claude", "llama", "qwen", "gpt4"],
                 llm_configs: dict = None):
        self.embeddings = HuggingFaceEmbeddings(model_name=embedding_model)
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            separators=["\n\n", "\n", " ", ""]
        )
        self.vectorstore = None

        # Store configurations for later LLM initialization
        if isinstance(llm_providers, str):
            llm_providers = [llm_providers]

        self.llm_providers = llm_providers

        # Default configurations
        self.default_configs = {
            "claude": {
                "model": "claude-3-sonnet-20240229",
                "temperature": 0
            },
            "llama": {
                "model_type": "llama",
                "temperature": 0.1
            },
            "qwen": {
                "model_type": "qwen",
                "temperature": 0.1
            },
            "gpt4": {
                "model_type": "gpt4",
                "temperature": 0
            }
        }

        # Override defaults with any provided configs
        self.llm_configs = self.default_configs.copy()
        if llm_configs:
            for provider, provider_config in llm_configs.items():
                if provider in self.llm_configs:
                    self.llm_configs[provider].update(provider_config)

        self.llms = None  # Will be initialized when needed

        self.prompt_template = PromptTemplate(
            input_variables=["context", "commit_info"],
            template="""You are a security expert analyzing kernel commits to determine if they should be assigned a CVE.
            Analyze both the commit message and the code changes carefully to identify security implications.

            Consider:
            1. Does the commit fix a security vulnerability?
            2. What is the potential impact of the issue being fixed?
            3. Are there any sensitive components affected (memory management, access control, etc.)?
            4. Does the commit message mention security concerns?
            5. Do the code changes show:
               - Buffer overflow fixes
               - Memory leak fixes
               - Access control changes
               - Input validation improvements
               - Race condition fixes
               - Privilege escalation fixes
               - Other security-relevant patterns

            Historical similar commits and their CVE status for reference:
            {context}

            IMPORTANT: Pay close attention to the CVE Status (YES/NO) of similar commits as they provide valuable reference points.
            Commits with similar characteristics to those marked with "CVE Status: YES" are more likely to need a CVE.

            New Commit to analyze:
            {commit_info}

            Based on your analysis of both the commit message AND code changes, should this commit be assigned a CVE?
            Provide your answer as YES or NO, followed by a brief explanation that references specific parts of the code changes."""
        )

    def _initialize_llms(self):
        """Initialize LLM clients when needed"""
        if self.llms is None:
            self.llms = {}
            for provider in self.llm_providers:
                if provider == "claude":
                    self.llms["claude"] = ClaudeLLM(**self.llm_configs["claude"])
                elif provider in ["llama", "qwen"]:
                    self.llms[provider] = HuggingFaceLLM(**self.llm_configs[provider])
                elif provider == "gpt4":
                    self.llms["gpt4"] = OpenAILLM(**self.llm_configs["gpt4"])

            if not self.llms:
                raise ValueError("No valid LLM providers specified")

    def train(self, commit_dataset):
        """Process the dataset and create the vector store with rich context"""
        texts = []
        metadatas = []

        for _, row in tqdm(commit_dataset.iterrows(), desc="Processing commits", total=len(commit_dataset)):
            # Extract the subject line (first line of the commit message)
            message_lines = row['message'].strip().split('\n')
            subject = message_lines[0].strip()
            message_body = '\n'.join(message_lines[1:]).strip() if len(message_lines) > 1 else ""

            # Build rich context for each commit
            commit_context = [
                f"Subject: {subject}",
                f"Commit Message:\n{message_body}",
                f"Changes:\n{str(row['diff'])}",
            ]

            # Add historical context
            if 'parent_message' in row and isinstance(row['parent_message'], str):
                # Extract subject from parent commit message
                parent_message_lines = row['parent_message'].strip().split('\n')
                parent_subject = parent_message_lines[0].strip()
                parent_message_body = '\n'.join(parent_message_lines[1:]).strip() if len(parent_message_lines) > 1 else ""

                commit_context.append(f"Parent Commit:\nSubject: {parent_subject}")
                if parent_message_body:
                    commit_context.append(f"Parent Commit Body:\n{parent_message_body}")

                if 'parent_diff' in row:
                    commit_context.append(f"Parent Changes:\n{str(row['parent_diff'])}")

            if 'grandparent_message' in row and isinstance(row['grandparent_message'], str):
                # Extract subject from grandparent commit message
                grandparent_message_lines = row['grandparent_message'].strip().split('\n')
                grandparent_subject = grandparent_message_lines[0].strip()
                grandparent_message_body = '\n'.join(grandparent_message_lines[1:]).strip() if len(grandparent_message_lines) > 1 else ""

                commit_context.append(f"Grandparent Commit:\nSubject: {grandparent_subject}")
                if grandparent_message_body:
                    commit_context.append(f"Grandparent Commit Body:\n{grandparent_message_body}")

                if 'grandparent_diff' in row:
                    commit_context.append(f"Grandparent Changes:\n{str(row['grandparent_diff'])}")

            # Add related commits
            if 'related_commits' in row and isinstance(row['related_commits'], list):
                for related in row['related_commits']:
                    relation_type = related.get('relation', 'unknown')

                    # Extract subject from related commit messages
                    related_message_lines = related['message'].strip().split('\n')
                    related_subject = related_message_lines[0].strip()
                    related_message_body = '\n'.join(related_message_lines[1:]).strip() if len(related_message_lines) > 1 else ""

                    commit_context.append(f"Related Commit ({relation_type}):\nSubject: {related_subject}")
                    if related_message_body:
                        commit_context.append(f"Related Commit Body:\n{related_message_body}")

                    commit_context.append(f"Related Changes:\n{str(related['diff'])}")

            # Add file-level analysis
            if 'file_analysis' in row and isinstance(row['file_analysis'], dict):
                for file_path, analysis in row['file_analysis'].items():
                    file_context = [f"\nFile: {file_path}"]

                    # Add file history
                    if analysis.get('history'):
                        history_context = ["Recent changes:"]
                        for change in analysis['history']:
                            history_context.append(f"- {change['date']}: {change['message']}")
                        file_context.extend(history_context)

                    # Add blame information
                    if analysis.get('blame'):
                        blame_context = ["Code ownership:"]
                        for blame in analysis['blame'][:5]:  # Limit to 5 most recent
                            blame_context.append(f"- {blame['author']} ({blame['date']}): {blame['message']}")
                        file_context.extend(blame_context)

                    commit_context.extend(file_context)

            # Make CVE status more prominent by adding it at the beginning and end
            cve_status_text = f"CVE Status: {'YES' if row['has_cve'] else 'NO'}"
            text = f"[{cve_status_text}]\n\n" + "\n\n".join(commit_context) + f"\n\n[{cve_status_text}]"

            # Create chunks with the text splitter
            chunks = self.text_splitter.split_text(text)

            # Add each chunk with its metadata
            for chunk in chunks:
                texts.append(chunk)
                metadatas.append({
                    "has_cve": row["has_cve"],
                    "sha": row["sha"],
                    "date": str(row["date"]),
                    "files": ",".join(row["files_changed"])
                })

        self.vectorstore = FAISS.from_texts(
            texts,
            self.embeddings,
            metadatas=metadatas
        )

    def predict(self, commit_info: dict, verbose: bool = False, batch_mode: bool = False, commit_sha: str = None) -> dict:
        """Predict if a commit should be assigned a CVE using all configured LLMs"""
        if not self.vectorstore:
            raise ValueError("Model not trained. Call train() first.")

        # Initialize LLMs if needed
        self._initialize_llms()

        # Extract subject from commit message
        message_lines = commit_info['message'].strip().split('\n')
        subject = message_lines[0].strip()
        message_body = '\n'.join(message_lines[1:]).strip() if len(message_lines) > 1 else ""

        # Format commit info for better readability
        commit_text = f"""
        Subject: {subject}

        Commit Message:
        {message_body}

        Files Changed:
        {', '.join(commit_info['files_changed'])}

        Code Changes:
        {commit_info['diff']}
        """

        # Get similar commits for context
        query = f"Commit: {commit_info['message']}\nDiff: {commit_info['diff']}"
        docs = self.vectorstore.similarity_search(query, k=10)  # Get 10 most similar commits

        # Extract and highlight the CVE status from each similar commit
        formatted_contexts = []
        for i, doc in enumerate(docs):
            content = doc.page_content

            # Extract CVE status if present
            cve_status = "UNKNOWN"
            if "CVE Status: YES" in content:
                cve_status = "YES"
            elif "CVE Status: NO" in content:
                cve_status = "NO"

            # Get metadata for additional information
            has_cve_metadata = doc.metadata.get('has_cve', None) if hasattr(doc, 'metadata') else None
            if has_cve_metadata is not None:
                cve_status = "YES" if has_cve_metadata else "NO"

            # Format with explicit CVE status highlight
            formatted_content = f"Similar Commit {i+1} [CVE Status: {cve_status}]:\n{content}"
            formatted_contexts.append(formatted_content)

        context = "\n\n".join(formatted_contexts)

        # Format the full prompt
        full_prompt = self.prompt_template.format(
            context=context,
            commit_info=commit_text
        )

        # Log the full prompt only in verbose mode
        if verbose:
            logging.info("\n" + "="*80)
            logging.info("Sending prompt to LLMs:")
            logging.info("-"*80)
            logging.info(full_prompt)
            logging.info("="*80 + "\n")

        results = {}
        if batch_mode and commit_sha:
            # Print the commit SHA first
            print(f"{commit_sha}", end='', flush=True)

        for name, llm in sorted(self.llms.items()):  # Sort to ensure consistent order
            try:
                response = llm.invoke(full_prompt)
                prediction = "YES" in response.upper()

                if verbose and not batch_mode:
                    logging.info(f"\n{'='*80}")
                    logging.info(f"{name.upper()} response:")
                    logging.info("-"*80)
                    logging.info(response)
                    logging.info("="*80 + "\n")

                if batch_mode and commit_sha:
                    # Print result immediately
                    print(f" {'yes' if prediction else 'no'}", end='', flush=True)

                results[name] = {
                    "prediction": prediction,
                    "explanation": response
                }
            except Exception as e:
                logging.error(f"Error with {name} LLM: {e}")
                if batch_mode and commit_sha:
                    print(" error", end='', flush=True)
                results[name] = {
                    "error": str(e)
                }

        if batch_mode and commit_sha:
            print()  # New line after all results

        return results

    def __getstate__(self):
        """Custom serialization that excludes unpicklable LLM clients"""
        state = self.__dict__.copy()
        state['llms'] = None  # Don't pickle LLM clients
        return state

    def __setstate__(self, state):
        """Custom deserialization"""
        self.__dict__.update(state)

def setup_logging(debug: bool):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def check_environment():
    """Check if required environment variables are set"""
    missing = []
    if not os.getenv("ANTHROPIC_API_KEY"):
        missing.append("ANTHROPIC_API_KEY")
    if not os.getenv("HUGGINGFACE_API_KEY"):
        missing.append("HUGGINGFACE_API_KEY")
    if not os.getenv("OPENAI_API_KEY"):
        missing.append("OPENAI_API_KEY")

    if missing:
        raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

def main():
    check_environment()
    parser = argparse.ArgumentParser(description='CVE Classification using RAG')
    parser.add_argument('--kernel-repo', type=str, default='~/linux',
                        help='Path to Linux kernel repository')
    parser.add_argument('--cve-commits', type=str, default='cve/published',
                        help='Path to CVE commits directory')
    parser.add_argument('--model-dir', type=str, default='./model',
                        help='Directory to save/load the trained model')
    parser.add_argument('--train', action='store_true',
                        help='Train the model')
    parser.add_argument('--test', action='store_true',
                        help='Run training with limited dataset (500 CVE + 500 non-CVE commits)')
    parser.add_argument('--commit', type=str,
                        help='Single commit SHA to analyze')
    parser.add_argument('--commits', nargs='+',
                        help='List of commit SHAs to analyze')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug output')
    parser.add_argument('--verbose', action='store_true',
                        help='Show detailed LLM prompts and responses')
    parser.add_argument('--batch', action='store_true',
                        help='Output only SHA and yes/no responses for batch processing')

    args = parser.parse_args()

    # Only setup logging if not in batch mode
    if not args.batch:
        setup_logging(args.debug)

    model_path = Path(args.model_dir) / "cve_classifier.pkl"

    if args.train:
        if not args.batch:
            logging.info("Starting training process...")
        # Create model directory if it doesn't exist
        Path(args.model_dir).mkdir(parents=True, exist_ok=True)

        # Initialize data collector
        logging.debug(f"Initializing data collector with kernel repo: {args.kernel_repo}")
        logging.debug(f"CVE commits path: {args.cve_commits}")
        collector = CommitDataCollector(
            kernel_repo_path=Path(args.kernel_repo).expanduser(),
            cve_commits_path=Path(args.cve_commits).expanduser()
        )

        # Build training dataset
        logging.info("Building dataset...")
        logging.debug("Reading CVE commits...")
        cve_commits = collector.get_cve_commits()
        logging.debug(f"Found {sum(len(v) for v in cve_commits.values())} CVE commits")

        # If in test mode, limit the dataset size
        if args.test:
            logging.info("Test mode: limiting dataset to 500 commits of each type")
            dataset = collector.build_dataset(max_cve=500, max_non_cve=5000)
        else:
            dataset = collector.build_dataset()

        cve_count = sum(dataset.has_cve)
        logging.info(f"Dataset built with {len(dataset)} total commits:")
        logging.info(f"  - {cve_count} CVE commits")
        logging.info(f"  - {len(dataset) - cve_count} non-CVE commits")

        # Initialize and train classifier
        logging.info("Training classifier...")
        classifier = CVEClassifier()
        classifier.train(dataset)

        # Save the trained model
        logging.info(f"Saving model to {model_path}")
        with open(model_path, 'wb') as f:
            pickle.dump(classifier, f)
        logging.info("Training complete!")

    elif args.commit or args.commits:
        if not model_path.exists():
            if not args.batch:
                logging.error(f"No trained model found at {model_path}. Please train first using --train")
            sys.exit(1)

        # Load the trained model
        if not args.batch:
            logging.info(f"Loading model from {model_path}")
        with open(model_path, 'rb') as f:
            classifier = pickle.load(f)

        # Initialize data collector for feature extraction
        if not args.batch:
            logging.debug("Initializing data collector for commit analysis")
        collector = CommitDataCollector(
            kernel_repo_path=Path(args.kernel_repo).expanduser(),
            cve_commits_path=Path(args.cve_commits).expanduser()
        )

        # Get list of commits to analyze
        commits_to_analyze = []
        if args.commit:
            commits_to_analyze.append(args.commit)
        if args.commits:
            commits_to_analyze.extend(args.commits)

        # Analyze each commit
        for commit_sha in commits_to_analyze:
            if not args.batch:
                logging.info(f"Analyzing commit: {commit_sha}")

            try:
                commit_info = collector.get_commit_features(commit_sha)
                results = classifier.predict(
                    commit_info,
                    verbose=args.verbose and not args.batch,
                    batch_mode=args.batch,
                    commit_sha=commit_sha if args.batch else None
                )

                if not args.batch:
                    print("\n" + "="*60)
                    print(f"Commit: {commit_sha}")
                    print(f"Author: {commit_info['author']}")
                    print(f"Date: {commit_info['date']}")
                    print("-"*60)
                    for name, result in results.items():
                        if "error" in result:
                            print(f"{name.upper()}: Error - {result['error']}")
                        else:
                            print(f"{name.upper()}: {'YES' if result['prediction'] else 'NO'}")
                            print(f"Explanation: {result['explanation']}")
                        print("-"*60)
            except Exception as e:
                if args.batch:
                    print(f"{commit_sha} error error error")
                else:
                    print(f"Error analyzing commit {commit_sha}: {e}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
