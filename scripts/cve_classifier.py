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
from typing import Union, List, Dict, Any, Optional
import concurrent.futures
from tqdm import tqdm  # For progress bars
import sys
from openai import OpenAI
import hashlib
import re
import time
import json
import random
import string
import tempfile
import math
import shlex
import shutil
import subprocess
import asyncio  # Add asyncio for async/await support

# Try to import Anthropic SDK - will be used if available
try:
    import anthropic
except ImportError:
    anthropic = None
    logging.warning("Anthropic SDK not found. Will use LangChain wrapper for Claude API.")

class BaseLLM(ABC):
    @abstractmethod
    def invoke(self, prompt: str) -> str:
        pass

class ClaudeLLM(BaseLLM):
    def __init__(self, model: str = "claude-3-7-sonnet-20250219", temperature: float = 0, thinking_enabled: bool = False, thinking_budget: int = 0, max_tokens: int = 4000, debug_logging: bool = False):
        """Initialize Claude LLM

        Args:
            model: The Claude model to use
            temperature: Controls randomness in responses
            thinking_enabled: Not currently supported for Claude 3.7
            thinking_budget: Not currently supported for Claude 3.7
            max_tokens: Maximum tokens for the response
            debug_logging: Enable detailed debug logging
        """
        # Store the user's desired temperature
        self.user_temperature = temperature
        self.debug_logging = debug_logging

        # Note: Claude 3.7 does not support the thinking feature in the way we previously handled it
        # We keep these parameters for backward compatibility with existing code
        self.thinking_enabled = False  # Force to False as it's not supported
        self.thinking_budget = 0  # Not used

        self.llm = ChatAnthropic(
            model=model,
            temperature=temperature,
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY")
        )
        self.model = model
        # Set max_tokens
        self.max_tokens = max_tokens

        # Create direct client for more controlled access
        try:
            from anthropic import Anthropic
            self.direct_client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        except ImportError:
            self.direct_client = None
            if self.debug_logging:
                logging.warning("Could not import Anthropic SDK. Will use langchain wrapper only.")

    def invoke(self, prompt: str) -> str:
        """Invoke Claude with extended thinking if enabled"""
        try:
            # If thinking is enabled and direct client is available, use it
            if self.thinking_enabled and self.direct_client:
                try:
                    # Use direct Anthropic client for more control
                    message = self.direct_client.messages.create(
                        model=self.model,
                        max_tokens=self.max_tokens,
                        messages=[{"role": "user", "content": prompt}],
                        temperature=1.0,  # Must be 1.0 with thinking
                        system="You are a security expert analyzing kernel commits to detect security vulnerabilities.",
                    )

                    # Extract the response content text
                    response_text = ""

                    # Process the content blocks
                    for block in message.content:
                        if block.type == "text":
                            response_text += block.text

                    return response_text

                except Exception as e:
                    if self.debug_logging:
                        logging.warning(f"Direct client failed, falling back to langchain: {e}")
                    # Fall back to langchain wrapper

            # If direct client failed or not available, use langchain wrapper
            if self.thinking_enabled:
                # Use a try-except block to handle potential serialization issues
                try:
                    response = self.llm.invoke(
                        prompt,
                        max_tokens=self.max_tokens,
                        # Claude 3.7 doesn't support thinking in the extra_body format,
                        # but we keep the temperature at 1 as required when thinking would be enabled
                    )

                    # Handle the structured content format from Claude 3.7
                    if hasattr(response, 'content') and isinstance(response.content, list):
                        # Extract text from content blocks
                        text_content = ""
                        for block in response.content:
                            # Handle both dictionary and object formats
                            if isinstance(block, dict):
                                block_type = block.get('type')
                                if block_type == 'text':
                                    text_content += block.get('text', '')
                            elif hasattr(block, 'type') and hasattr(block, 'text'):
                                if block.type == 'text':
                                    text_content += block.text
                        return text_content
                    else:
                        # Fallback to string representation if not structured
                        return str(response.content)
                except Exception as e:
                    if self.debug_logging:
                        logging.warning(f"Error in structured content handling: {e}")
                    # If we hit an error in structured content handling, return raw content as string
                    if hasattr(response, 'content'):
                        if isinstance(response.content, str):
                            return response.content
                        else:
                            return str(response.content)
                    else:
                        raise  # Re-raise if we can't extract content
            else:
                # Standard invocation without extended thinking, use the user's desired temperature
                response = self.llm.invoke(prompt, temperature=self.user_temperature)

                # Similar handling for non-thinking mode
                if hasattr(response, 'content'):
                    if isinstance(response.content, list):
                        text_content = ""
                        for block in response.content:
                            if isinstance(block, dict):
                                block_type = block.get('type')
                                if block_type == 'text':
                                    text_content += block.get('text', '')
                            elif hasattr(block, 'type') and hasattr(block, 'text') and block.type == 'text':
                                text_content += block.text
                        return text_content
                    elif isinstance(response.content, str):
                        return response.content
                    else:
                        return str(response.content)
                else:
                    return str(response)
        except Exception as e:
            # Don't log the error here - let the calling code handle it
            # The error will be handled by the retry logic in the predict method
            raise

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

        try:
            response = self.client.text_generation(
                formatted_prompt,
                model=self.model,
                temperature=self.temperature,
                max_new_tokens=1024,  # Increased token limit to ensure complete responses
                return_full_text=False,
                stop=["<|im_end|>"] if self.model_type == "qwen" else None
            )

            # Process the response - this applies to all model types
            if response:
                # Check if the response has YES/NO but no explanation
                if ("YES" in response.upper() or "NO" in response.upper()) and "EXPLANATION:" not in response.upper():
                    # Extract the yes/no part and any explanation if it exists
                    if ":" in response:
                        # If there's a colon, split at the first one
                        answer_part = response.split(":", 1)[0].strip()
                        explanation_part = response.split(":", 1)[1].strip()
                        if explanation_part:
                            return f"{answer_part}\nExplanation: {explanation_part}"
                        else:
                            # Add a default explanation if none provided
                            return f"{answer_part}\nExplanation: No further details provided by the model."
                    else:
                        # Just has YES/NO with no explanation
                        answer = "YES" if "YES" in response.upper() else "NO"
                        return f"{answer}\nExplanation: No further details provided by the model."
            elif response == "" or response is None:
                # Handle completely empty responses
                logging.warning(f"Empty response received from model")
                return "NO\nExplanation: The model returned an empty response. Defaulting to NO for security reasons."

            return response
        except Exception as e:
            logging.error(f"Error invoking model: {e}")
            # Return a formatted error response that can still be parsed
            return f"NO\nExplanation: Error occurred while generating response: {str(e)}"

class OpenAILLM(BaseLLM):
    MODELS = {
        "gpt4": "gpt-4-turbo-2024-04-09",  # GPT-4 Turbo (April 2024)
        "gpt4o": "gpt-4o-2024-05-13"       # GPT-4o (May 2024)
    }

    def __init__(self, model_type: str = "gpt4o", temperature: float = 0):
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

        # Convert diff objects to string representation
        diff_text = ""
        if commit.parents:
            parent = commit.parents[0]
            diffs = parent.diff(commit, create_patch=True)
            for diff in diffs:
                try:
                    # Get the actual diff text
                    if diff.a_path and diff.b_path:
                        diff_text += f"--- a/{diff.a_path}\n+++ b/{diff.b_path}\n"
                    elif diff.a_path:
                        diff_text += f"--- a/{diff.a_path}\n+++ /dev/null\n"
                    elif diff.b_path:
                        diff_text += f"--- /dev/null\n+++ b/{diff.b_path}\n"

                    # Add the diff content
                    if hasattr(diff, 'diff'):
                        try:
                            diff_content = diff.diff.decode('utf-8', errors='replace')
                            diff_text += diff_content + "\n\n"
                        except (UnicodeDecodeError, AttributeError):
                            diff_text += "[Binary diff not shown]\n\n"
                except Exception as e:
                    logging.warning(f"Error processing diff: {e}")
                    diff_text += f"[Error processing diff: {e}]\n\n"

        return {
            'sha': commit.hexsha,
            'message': commit.message,
            'diff': diff_text,  # Use the converted text instead of diff objects
            'author': commit.author.name,
            'date': commit.authored_datetime,
            'files_changed': list(commit.stats.files.keys())
        }

    def _safe_git_command(self, cmd, timeout=30):
        """Run a git command with a timeout to prevent hanging"""
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.kernel_repo_path
            )
            stdout, stderr = process.communicate(timeout=timeout)
            if process.returncode != 0:
                logging.warning(f"Git command failed: {' '.join(cmd)}")
                return None
            return stdout.decode('utf-8', errors='replace')
        except subprocess.TimeoutExpired:
            process.kill()
            logging.warning(f"Git command timed out after {timeout}s: {' '.join(cmd)}")
            return None
        except Exception as e:
            logging.error(f"Error executing git command {' '.join(cmd)}: {e}")
            return None

    def process_cve_commit(self, sha: str) -> dict:
        """Process a single CVE commit

        Extracts basic commit information and file-level analysis.
        Does not track related commits (commits that come after this one)
        as they could bias the security assessment.
        """
        try:
            features = self.get_commit_features(sha)
            features['has_cve'] = True

            # Skip collecting related commits as requested

            # Add file-level analysis
            file_analysis = {}
            for file_path in features['files_changed']:
                try:
                    # Use safe git command with timeout instead of iter_commits
                    cmd = ['git', 'rev-list', '--max-count=5', sha, '--', file_path]
                    output = self._safe_git_command(cmd, timeout=30)

                    if output:
                        commit_shas = output.strip().split('\n')
                        file_history = []

                        for commit_sha in commit_shas:
                            if not commit_sha:
                                continue

                            # Get commit info safely
                            commit_info_cmd = ['git', 'show', '--no-patch', '--format=%H%n%s%n%at', commit_sha]
                            commit_info = self._safe_git_command(commit_info_cmd, timeout=10)

                            if commit_info:
                                lines = commit_info.strip().split('\n')
                                if len(lines) >= 3:
                                    c_sha = lines[0]
                                    c_message = lines[1]
                                    try:
                                        c_date = datetime.fromtimestamp(int(lines[2]), tz=timezone.utc)
                                        file_history.append({
                                            'sha': c_sha,
                                            'message': c_message,
                                            'date': c_date
                                        })
                                    except (ValueError, IndexError):
                                        continue

                        if file_history:
                            file_analysis[file_path] = {'history': file_history}
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

    def process_commit_with_timeout(self, process_func, sha, timeout=120):
        """Process a commit with a timeout limit"""
        try:
            # Use the function_timeout decorator for the processing function
            start_time = time.time()
            result = process_func(sha)
            elapsed = time.time() - start_time
            if elapsed > timeout:
                logging.warning(f"Commit processing took {elapsed:.1f}s (exceeded timeout) for SHA: {sha}")
            return result
        except Exception as e:
            logging.error(f"Error processing commit {sha}: {e}")
            return None

    def build_dataset(self, min_months: int = 1, max_months: int = 12, chunk_size: int = 1000, max_workers: int = 24,
                     max_cve: int = None, max_non_cve: int = None, commit_timeout: int = 120) -> pd.DataFrame:
        """Build a dataset of CVE and non-CVE commits using parallel processing"""
        logging.info("Getting CVE commits...")
        cve_commits = self.get_cve_commits()

        # Create a set of all commits that were ever assigned a CVE (either as fix or vulnerability)
        all_cve_shas = cve_commits['cve_fixes'] | cve_commits['cve_vulns']

        # Reset seen commit messages
        self.seen_commit_messages = set()

        # If in test mode, limit CVE commits
        if max_cve is not None:
            # Since max_cve is applied per dictionary entry (for both cve_fixes and cve_vulns),
            # we need to calculate how many to take from each to get max_cve total
            total_cve_count = sum(len(v) for v in cve_commits.values())
            if total_cve_count > 0:
                # Calculate proportion for each key to maintain original ratio but limit total to max_cve
                cve_per_key = {k: int(max_cve * len(v) / total_cve_count) for k, v in cve_commits.items()}
                # Ensure we get exactly max_cve by adding any remainder to the largest set
                remainder = max_cve - sum(cve_per_key.values())
                if remainder > 0:
                    max_key = max(cve_per_key.keys(), key=lambda k: cve_per_key[k])
                    cve_per_key[max_key] += remainder
                # Apply the calculated limits
                cve_commits = {k: set(list(v)[:cve_per_key[k]]) for k, v in cve_commits.items()}
                logging.info(f"Limited to {sum(len(v) for v in cve_commits.values())} CVE commits for testing")

        # Process CVE commits in parallel, filtering duplicates
        all_commits = []
        duplicates_found = 0
        timeouts_count = 0

        with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            # Process in smaller chunks to show progress
            shas_to_process = []
            for k, shas in cve_commits.items():
                for sha in shas:
                    if not self._is_duplicate_commit(sha):
                        shas_to_process.append(sha)
                    else:
                        duplicates_found += 1

            # Submit all tasks to the executor
            sha_to_future = {sha: executor.submit(self.process_cve_commit, sha) for sha in shas_to_process}

            with tqdm(total=len(sha_to_future), desc="Processing unique CVE commits") as pbar:
                for sha, future in sha_to_future.items():
                    try:
                        # Wait for the result with a timeout
                        result = future.result(timeout=commit_timeout)
                        if result is not None:
                            all_commits.append(result)
                    except concurrent.futures.TimeoutError:
                        logging.warning(f"Commit processing timed out after {commit_timeout} seconds for SHA: {sha}")
                        timeouts_count += 1
                    except Exception as e:
                        logging.error(f"Error processing commit {sha}: {e}")
                    pbar.update(1)

        logging.info(f"Processed {len(all_commits)} unique CVE commits (skipped {duplicates_found} duplicates, {timeouts_count} timeouts)")

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
        non_cve_timeouts = 0

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
                        # Submit all tasks to the executor
                        sha_to_future = {}
                        for sha in current_chunk:
                            if max_non_cve is not None and len(non_cve_commits) + len(sha_to_future) >= max_non_cve:
                                break
                            sha_to_future[sha] = executor.submit(self.process_non_cve_commit, sha)

                        if sha_to_future:
                            processed_results = []
                            for sha, future in sha_to_future.items():
                                try:
                                    # Wait for the result with a timeout
                                    result = future.result(timeout=commit_timeout)
                                    if result is not None:
                                        non_cve_commits.append(result)
                                        processed_results.append(result)
                                except concurrent.futures.TimeoutError:
                                    logging.warning(f"Non-CVE commit processing timed out after {commit_timeout} seconds for SHA: {sha}")
                                    non_cve_timeouts += 1
                                except Exception as e:
                                    logging.error(f"Error processing commit {sha}: {e}")

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
        logging.info(f"  - CVE commits: {sum(df.has_cve)} (skipped {duplicates_found} duplicates, {timeouts_count} timeouts)")
        logging.info(f"  - Non-CVE commits: {sum(~df.has_cve)} (skipped {branch_duplicates} duplicates, {non_cve_timeouts} timeouts)")

        return df

class CVEClassifier:
    def __init__(self,
                 embedding_model: str = "all-MiniLM-L6-v2",
                 llm_providers: Union[str, List[str]] = ["claude", "llama", "qwen", "gpt4"],
                 llm_configs: dict = None,
                 repo: git.Repo = None):
        self.embeddings = HuggingFaceEmbeddings(model_name=embedding_model)
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            separators=["\n\n", "\n", " ", ""]
        )
        self.vectorstore = None
        self.repo = repo  # Store repo for retrieving missing commit info

        # Store configurations for later LLM initialization
        if isinstance(llm_providers, str):
            llm_providers = [llm_providers]

        self.llm_providers = llm_providers

        # Default configurations
        self.default_configs = {
            "claude": {
                "model": "claude-3-7-sonnet-20250219",
                "temperature": 0,
                "thinking_enabled": False,  # Not supported for Claude 3.7
                "thinking_budget": 0,       # Not used
                "max_tokens": 4000,
                "debug_logging": False      # Disable detailed debug logging by default
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
            },
            "gpt4o": {
                "model_type": "gpt4o",
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
                elif provider in ["gpt4", "gpt4o"]:
                    self.llms[provider] = OpenAILLM(**self.llm_configs.get(provider, {"model_type": provider}))

            if not self.llms:
                raise ValueError("No valid LLM providers specified")

    def train(self, commit_dataset):
        """Process the dataset and create the vector store with rich context"""
        texts = []
        metadatas = []

        # Set a maximum size limit for text chunks to prevent memory issues
        MAX_CHUNK_LENGTH = 5000  # Characters
        MAX_CHUNKS_PER_BATCH = 1000  # Maximum number of chunks to process at once

        for _, row in tqdm(commit_dataset.iterrows(), desc="Processing commits", total=len(commit_dataset)):
            try:
                # Extract the subject line (first line of the commit message)
                message_lines = row['message'].strip().split('\n')
                subject = message_lines[0].strip()
                message_body = '\n'.join(message_lines[1:]).strip() if len(message_lines) > 1 else ""

                # Build rich context for each commit
                commit_context = [
                    f"Subject: {subject}",
                    f"Commit Message:\n{message_body}",
                ]

                # Add code changes with encoding safety and size limitation
                try:
                    # Ensure diff is a string and handle encoding issues
                    if isinstance(row['diff'], str):
                        diff_text = row['diff']
                    else:
                        diff_text = str(row['diff'])

                    # If diff is too large, truncate it
                    if len(diff_text) > MAX_CHUNK_LENGTH:
                        logging.warning(f"Truncating large diff for commit {row['sha']} (size: {len(diff_text)})")
                        diff_text = diff_text[:MAX_CHUNK_LENGTH] + "\n[... truncated due to size ...]"

                    # Clean the diff text to avoid encoding problems
                    diff_text = diff_text.encode('ascii', 'replace').decode('ascii')
                    commit_context.append(f"Changes:\n{diff_text}")
                except Exception as e:
                    logging.warning(f"Error processing diff for embedding: {e}")
                    commit_context.append("Changes: [Error processing diff]")

                # Remove related commits processing as requested
                # No processing of related commits

                # Simplify file analysis to reduce memory usage
                if 'file_analysis' in row and isinstance(row['file_analysis'], dict):
                    num_files = len(row['file_analysis'])
                    commit_context.append(f"File Analysis: [Summary of {num_files} files]")
                    # Only list file names without details
                    file_names = list(row['file_analysis'].keys())
                    if file_names:
                        commit_context.append(f"Files: {', '.join(file_names[:5])}" +
                                            (f" and {len(file_names) - 5} more" if len(file_names) > 5 else ""))

                # Make CVE status more prominent by adding it at the beginning only
                cve_status_text = f"CVE Status: {'YES' if row['has_cve'] else 'NO'}"
                text = f"[{cve_status_text}]\n\n" + "\n\n".join(commit_context)

                # Ensure the text is ASCII-encodable and not too long
                text = text.encode('ascii', 'replace').decode('ascii')
                if len(text) > MAX_CHUNK_LENGTH * 3:  # Allow a reasonable multiplier
                    text = text[:MAX_CHUNK_LENGTH * 3] + "\n[... remainder truncated ...]"

                # Create a single chunk per commit to keep metadata and diff together
                # Skip chunking for now since it's causing diff information to be separated from metadata
                clean_text = text.encode('ascii', 'replace').decode('ascii')
                if len(clean_text) > MAX_CHUNK_LENGTH * 3:  # If text is too large, truncate
                    clean_text = clean_text[:MAX_CHUNK_LENGTH * 3] + "\n[... remainder truncated ...]"

                # Add single chunk with metadata
                texts.append(clean_text)
                metadatas.append({
                    "has_cve": row["has_cve"],
                    "sha": row["sha"],
                    "date": str(row["date"]),
                    "files": ",".join(row["files_changed"][:10])  # Limit number of files
                })

                # Process in batches to prevent memory buildup
                if len(texts) >= MAX_CHUNKS_PER_BATCH:
                    self._create_partial_vectorstore(texts, metadatas)
                    texts = []
                    metadatas = []
                    # Force garbage collection to free memory
                    import gc
                    gc.collect()

            except Exception as e:
                logging.error(f"Error processing commit for embeddings: {e}")
                continue

        # Process any remaining texts
        if texts:
            self._create_partial_vectorstore(texts, metadatas)

        logging.info("Vector store creation complete")

    def _create_partial_vectorstore(self, texts, metadatas):
        """Helper method to create/update vector store with a batch of texts"""
        logging.info(f"Creating/updating vectorstore with {len(texts)} text chunks")

        try:
            # If vectorstore doesn't exist yet, create it
            if self.vectorstore is None:
                self.vectorstore = FAISS.from_texts(
                    texts,
                    self.embeddings,
                    metadatas=metadatas
                )
                logging.info("Initial vectorstore created successfully")
            else:
                # Add to existing vectorstore
                self.vectorstore.add_texts(texts, metadatas=metadatas)
                logging.info("Added batch to existing vectorstore")

        except Exception as e:
            logging.error(f"Error updating vectorstore: {e}")
            # Try with a simpler approach for this batch
            try:
                logging.info("Trying with a simpler approach for this batch...")
                # Create a simpler set of texts
                simple_texts = []
                simple_metadatas = []
                for i, (text, metadata) in enumerate(zip(texts, metadatas)):
                    try:
                        # More aggressive text cleaning
                        simple_text = ''.join(c if c.isascii() and c.isprintable() else ' ' for c in text)
                        simple_text = ' '.join(simple_text.split())  # Normalize whitespace
                        # Further limit length
                        if len(simple_text) > 2000:
                            simple_text = simple_text[:2000]
                        simple_texts.append(simple_text)
                        simple_metadatas.append(metadata)
                    except:
                        logging.warning(f"Skipping text chunk {i} due to encoding issues")

                if self.vectorstore is None:
                    logging.info(f"Creating simplified initial vectorstore with {len(simple_texts)} cleaned text chunks")
                    self.vectorstore = FAISS.from_texts(
                        simple_texts,
                        self.embeddings,
                        metadatas=simple_metadatas
                    )
                else:
                    logging.info(f"Adding {len(simple_texts)} simplified chunks to vectorstore")
                    self.vectorstore.add_texts(simple_texts, metadatas=simple_metadatas)

                logging.info("Simplified vectorstore update successful")
            except Exception as e2:
                logging.error(f"Error with simplified vectorstore update: {e2}")
                # Continue anyway - we'll just miss this batch

    def _parse_llm_response(self, response: str) -> tuple[bool, str]:
        """Parse LLM response to extract the prediction and explanation.

        Args:
            response: Raw response from the LLM

        Returns:
            tuple: (prediction boolean, full response text)
        """
        # Convert to uppercase for case-insensitive matching
        response_upper = response.upper()

        # Try different patterns to extract the YES/NO response
        patterns = [
            # Look for "ANSWER: YES/NO"
            r"ANSWER:\s*(YES|NO)",
            # Look for YES/NO at the beginning of the text
            r"^\s*(YES|NO)\b",
            # Look for patterns like "Answer is YES/NO" or "Answer: YES/NO"
            r"ANSWER\s+(?:IS|:)\s*(YES|NO)",
            # Check for GPT-4 style response with YES/NO at the beginning
            r"(YES|NO)\s*(?:\n|$|Explanation|:)",
        ]

        for pattern in patterns:
            match = re.search(pattern, response_upper)
            if match:
                return match.group(1) == "YES", response

        # If no pattern matches, look for the first YES/NO in the text
        yes_pos = response_upper.find("YES")
        no_pos = response_upper.find("NO")

        # If we found both YES and NO
        if yes_pos != -1 and no_pos != -1:
            # Return based on which comes first
            return yes_pos < no_pos, response
        # If we only found YES
        elif yes_pos != -1:
            return True, response
        # If we only found NO
        elif no_pos != -1:
            return False, response

        # If we can't find a clear YES/NO, default to NO
        # This is safer from a security perspective
        logging.warning("Could not find clear YES/NO in LLM response. Defaulting to NO.")
        return False, response

    async def _async_batch_process_claude(self, commit_infos: Dict[str, dict]) -> Dict[str, Dict[str, Any]]:
        """
        Process multiple commits using Claude's batch API with async/await pattern.

        Args:
            commit_infos: Dictionary mapping commit SHAs to commit info dictionaries

        Returns:
            Dictionary mapping commit SHAs to prediction results
        """
        if not self.vectorstore:
            raise ValueError("Model not trained. Call train() first.")

        try:
            # Import Anthropic direct client
            import anthropic
            client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        except ImportError:
            raise ImportError("Anthropic SDK not found. Please install with 'pip install anthropic'")

        # Prepare batch requests
        batch_requests = []
        prompts = {}

        logging.info(f"Preparing batch requests for {len(commit_infos)} commits")

        for commit_sha, commit_info in commit_infos.items():
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
            # Use fetch_k=20 to search through more documents, and k=10 to return the most similar
            docs = self.vectorstore.similarity_search(
                query,
                k=10,
                fetch_k=20  # Search through more documents first
            )

            # Extract and highlight the CVE status from each similar commit
            formatted_contexts = []
            for i, doc in enumerate(docs):
                if not doc.page_content:
                    continue  # Skip empty content
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

                # Remove CVE status from beginning of content if present
                content = re.sub(r'^\[CVE Status: (YES|NO)\]\s*\n+', '', content, flags=re.MULTILINE)

                # Make sure commit displays have a consistent structure
                if "Subject:" not in content:
                    # Extract subject if possible from metadata
                    sha = doc.metadata.get('sha', 'unknown') if hasattr(doc, 'metadata') else 'unknown'
                    try:
                        # Try to get commit info from the repository to ensure we have complete data
                        if sha != 'unknown' and hasattr(self, 'repo'):
                            content_parts = []
                            commit = self.repo.commit(sha)
                            message_lines = commit.message.strip().split('\n')
                            subject = message_lines[0].strip()
                            content_parts.append(f"Subject: {subject}")
                            content_parts.append(f"Commit Message:\n{commit.message}")
                            content = "\n\n".join(content_parts)
                    except:
                        # If we can't get the commit info, just note that
                        content = f"Subject: [Missing subject for commit {sha}]\n\nCommit Message: [Missing message]"

                # Check if code changes are present
                if "Code Changes:" not in content and "Changes:" not in content:
                    content += "\n\nCode Changes:\n[No code changes found or extracted for this commit]"

                # Format with CVE status in the title only
                formatted_content = f"Similar Commit {i+1} [CVE Status: {cve_status}]:\n{content}"
                formatted_contexts.append(formatted_content)

            context = "\n\n".join(formatted_contexts)

            # Format the full prompt
            full_prompt = self.prompt_template.format(
                context=context,
                commit_info=commit_text
            )

            # Store prompt for logging/debugging purposes
            prompts[commit_sha] = full_prompt

            # Add to batch requests
            batch_requests.append({
                "custom_id": commit_sha,
                "params": {
                    "model": self.llm_configs["claude"]["model"],
                    "max_tokens": self.llm_configs["claude"]["max_tokens"],
                    "temperature": self.llm_configs["claude"]["temperature"],
                    "messages": [{"role": "user", "content": full_prompt}],
                    "system": "You are a security expert analyzing kernel commits to detect security vulnerabilities."
                }
            })

        # Create batch request
        logging.info("Submitting batch request to Claude API...")
        batch = client.beta.messages.batches.create(requests=batch_requests)
        batch_id = batch.id
        logging.info(f"Batch submitted with ID: {batch_id}")

        # Poll for batch completion
        results = {}
        poll_interval = 5 * 60  # 5 minutes in seconds
        total_requests = len(batch_requests)
        processed_ids = set()

        # Wait until the batch is completed
        while True:
            try:
                # Get batch status
                status = client.beta.messages.batches.retrieve(batch_id)
                processing_status = status.processing_status
                logging.info(f"Batch status: {processing_status}")

                # If the batch is still being processed, wait and check again
                if processing_status == "in_progress":
                    logging.info(f"Batch still in progress. Waiting {poll_interval//60} minutes before checking again...")
                    time.sleep(poll_interval)
                    continue

                # If the batch is ended, process results
                if processing_status == "ended":
                    logging.info("Batch processing completed, retrieving results...")
                    break

                # If the batch failed or has some other status, handle accordingly
                if processing_status not in ["in_progress", "ended"]:
                    logging.error(f"Unexpected batch status: {processing_status}")
                    raise Exception(f"Batch processing failed with status: {processing_status}")

                # Wait before polling again
                time.sleep(poll_interval)

            except Exception as e:
                logging.error(f"Error checking batch status: {e}")
                time.sleep(60)  # Wait a minute before trying again

        # Now retrieve and process all results
        try:
            # Process each request one by one to get results
            for commit_sha in commit_infos.keys():
                try:
                    # Get the result for this specific request
                    result = client.beta.messages.batches.results.retrieve(
                        batch_id=batch_id,
                        request_id=commit_sha
                    )

                    if result.result.type == "succeeded":
                        # Extract text content from result
                        response_text = ""
                        for block in result.result.message.content:
                            if block.type == "text":
                                response_text += block.text

                        # Parse the response
                        prediction, explanation = self._parse_llm_response(response_text)

                        # Store result
                        results[commit_sha] = {
                            "prediction": prediction,
                            "explanation": explanation
                        }

                        # Print result in batch mode format
                        print(f"{commit_sha} {'yes' if prediction else 'no'}")
                    elif result.result.type == "failed":
                        error_msg = "Unknown error"
                        if hasattr(result.result, 'error') and hasattr(result.result.error, 'message'):
                            error_msg = result.result.error.message
                        results[commit_sha] = {"error": error_msg}
                        print(f"{commit_sha} error")
                        logging.error(f"Batch API error for {commit_sha}: {error_msg}")
                except Exception as e:
                    logging.error(f"Error retrieving result for {commit_sha}: {e}")
                    results[commit_sha] = {"error": str(e)}
                    print(f"{commit_sha} error")

        except Exception as e:
            logging.error(f"Error processing batch results: {e}")
            # If batch processing fails, fall back to processing commits one by one
            logging.warning("Falling back to processing commits one by one")
            for sha, commit_info in commit_infos.items():
                if sha not in results:  # Only process commits that don't have results yet
                    try:
                        # Use the regular non-batch predict method as fallback
                        result = self.predict(commit_info, batch_mode=True, commit_sha=sha)
                        results[sha] = result["claude"] if "claude" in result else {"error": "No result from Claude"}
                    except Exception as e:
                        results[sha] = {"error": str(e)}
                        print(f"{sha} error")

        return results

    def batch_process_claude(self, commit_infos: Dict[str, dict]) -> Dict[str, Dict[str, Any]]:
        """
        Process multiple commits using Claude's batch API.

        Args:
            commit_infos: Dictionary mapping commit SHAs to commit info dictionaries

        Returns:
            Dictionary mapping commit SHAs to prediction results
        """
        if not self.vectorstore:
            raise ValueError("Model not trained. Call train() first.")

        try:
            # Import Anthropic direct client
            import anthropic
            client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        except ImportError:
            raise ImportError("Anthropic SDK not found. Please install with 'pip install anthropic'")

        # Prepare batch requests
        batch_requests = []
        prompts = {}

        logging.info(f"Preparing batch requests for {len(commit_infos)} commits")

        for commit_sha, commit_info in commit_infos.items():
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
            # Use fetch_k=20 to search through more documents, and k=10 to return the most similar
            docs = self.vectorstore.similarity_search(
                query,
                k=10,
                fetch_k=20  # Search through more documents first
            )

            # Extract and highlight the CVE status from each similar commit
            formatted_contexts = []
            for i, doc in enumerate(docs):
                if not doc.page_content:
                    continue  # Skip empty content
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

                # Remove CVE status from beginning of content if present
                content = re.sub(r'^\[CVE Status: (YES|NO)\]\s*\n+', '', content, flags=re.MULTILINE)

                # Make sure commit displays have a consistent structure
                if "Subject:" not in content:
                    # Extract subject if possible from metadata
                    sha = doc.metadata.get('sha', 'unknown') if hasattr(doc, 'metadata') else 'unknown'
                    try:
                        # Try to get commit info from the repository to ensure we have complete data
                        if sha != 'unknown' and hasattr(self, 'repo'):
                            content_parts = []
                            commit = self.repo.commit(sha)
                            message_lines = commit.message.strip().split('\n')
                            subject = message_lines[0].strip()
                            content_parts.append(f"Subject: {subject}")
                            content_parts.append(f"Commit Message:\n{commit.message}")
                            content = "\n\n".join(content_parts)
                    except:
                        # If we can't get the commit info, just note that
                        content = f"Subject: [Missing subject for commit {sha}]\n\nCommit Message: [Missing message]"

                # Check if code changes are present
                if "Code Changes:" not in content and "Changes:" not in content:
                    content += "\n\nCode Changes:\n[No code changes found or extracted for this commit]"

                # Format with CVE status in the title only
                formatted_content = f"Similar Commit {i+1} [CVE Status: {cve_status}]:\n{content}"
                formatted_contexts.append(formatted_content)

            context = "\n\n".join(formatted_contexts)

            # Format the full prompt
            full_prompt = self.prompt_template.format(
                context=context,
                commit_info=commit_text
            )

            # Store prompt for logging/debugging purposes
            prompts[commit_sha] = full_prompt

            # Add to batch requests
            batch_requests.append({
                "custom_id": commit_sha,
                "params": {
                    "model": self.llm_configs["claude"]["model"],
                    "max_tokens": self.llm_configs["claude"]["max_tokens"],
                    "temperature": self.llm_configs["claude"]["temperature"],
                    "messages": [{"role": "user", "content": full_prompt}],
                    "system": "You are a security expert analyzing kernel commits to detect security vulnerabilities."
                }
            })

        # Create batch request
        logging.info("Submitting batch request to Claude API...")
        batch = client.beta.messages.batches.create(requests=batch_requests)
        batch_id = batch.id
        logging.info(f"Batch submitted with ID: {batch_id}")

        # Poll for batch completion
        results = {}
        poll_interval = 5 * 60  # 5 minutes in seconds
        max_retries = 288  # Maximum number of retries (24 hours with 5-minute intervals)
        retry_count = 0

        # Wait for batch to complete
        while retry_count < max_retries:
            try:
                # Get batch status
                status = client.beta.messages.batches.retrieve(batch_id)
                processing_status = status.processing_status
                logging.info(f"Batch status: {processing_status}, attempt {retry_count+1}/{max_retries}")

                # If batch is complete, break the loop
                if processing_status == "ended":
                    logging.info("Batch processing completed, retrieving results...")
                    break

                # Wait before polling again
                retry_count += 1
                logging.info(f"Waiting {poll_interval//60} minutes before checking batch status again...")
                time.sleep(poll_interval)

            except Exception as e:
                logging.error(f"Error in batch polling loop: {e}")
                retry_count += 1
                time.sleep(60)  # Wait a minute before trying again

        # Process batch results
        if retry_count < max_retries:
            try:
                # Stream results file in memory-efficient chunks
                processed_count = 0
                for result in client.beta.messages.batches.results(batch_id):
                    try:
                        # Get the custom_id (commit SHA)
                        commit_sha = result.custom_id if hasattr(result, 'custom_id') else None
                        if not commit_sha:
                            logging.warning(f"Result missing custom_id: {result}")
                            continue

                        # Check if the result was successful
                        if hasattr(result, 'result'):
                            result_obj = result.result
                            result_type = result_obj.type if hasattr(result_obj, 'type') else None

                            if result_type == "succeeded":
                                # Extract message content
                                message = result_obj.message if hasattr(result_obj, 'message') else None
                                if message and hasattr(message, 'content'):
                                    content_blocks = message.content

                                    # Extract text content from result
                                    response_text = ""
                                    for block in content_blocks:
                                        if hasattr(block, 'type') and block.type == "text":
                                            response_text += block.text if hasattr(block, 'text') else ""

                                    # Parse the response
                                    prediction, explanation = self._parse_llm_response(response_text)

                                    # Store result
                                    results[commit_sha] = {
                                        "prediction": prediction,
                                        "explanation": explanation
                                    }

                                    # Print result in batch mode format
                                    print(f"{commit_sha} {'yes' if prediction else 'no'}")
                                    processed_count += 1
                            elif result_type == "failed":
                                error_msg = "Unknown error"
                                if hasattr(result_obj, 'error') and hasattr(result_obj.error, 'message'):
                                    error_msg = result_obj.error.message
                                results[commit_sha] = {"error": error_msg}
                                print(f"{commit_sha} error")
                                logging.error(f"Batch API error for {commit_sha}: {error_msg}")
                                processed_count += 1
                    except Exception as e:
                        logging.error(f"Error processing result: {e}")

                logging.info(f"Processed {processed_count} results from batch {batch_id}")
            except Exception as e:
                logging.error(f"Error retrieving batch results: {e}")

        # If we couldn't get results or not all commits were processed, process remaining commits individually
        missing_commits = set(commit_infos.keys()) - set(results.keys())
        if missing_commits:
            logging.warning(f"Failed to get all results via batch API. Processing {len(missing_commits)} remaining commits individually.")

            # Process remaining commits one by one
            for commit_sha in missing_commits:
                try:
                    # Use the regular non-batch predict method as fallback
                    result = self.predict(commit_infos[commit_sha], batch_mode=True, commit_sha=commit_sha)
                    results[commit_sha] = result.get("claude", {"error": "No result from Claude"})
                except Exception as e:
                    results[commit_sha] = {"error": str(e)}
                    print(f"{commit_sha} error")

        return results

    def batch_process_openai(self, commit_infos: Dict[str, dict]) -> Dict[str, Dict[str, Any]]:
        """
        Process multiple commits using OpenAI's official Batch API.

        Args:
            commit_infos: Dictionary mapping commit SHAs to commit info dictionaries

        Returns:
            Dictionary mapping commit SHAs to prediction results
        """
        if not self.vectorstore:
            raise ValueError("Model not trained. Call train() first.")

        # Get the OpenAI client and model configuration
        openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

        # Determine which OpenAI model to use (gpt4 or gpt4o)
        model_key = next((k for k in ["gpt4o", "gpt4"] if k in self.llm_providers), "gpt4o")

        # Handle case where model_key isn't in llm_configs by using default values
        if model_key in self.llm_configs:
            model_config = self.llm_configs[model_key]
            model_name = model_config.get("model_type", model_key)
            temperature = model_config.get("temperature", 0)
        else:
            # Use defaults if config not found
            model_name = model_key
            temperature = 0
            logging.info(f"Config for {model_key} not found in llm_configs, using defaults")

        # Get the actual model name from OpenAILLM.MODELS dict or use model_name directly
        model = OpenAILLM.MODELS.get(model_name, model_name)

        logging.info(f"Preparing OpenAI Batch API requests using model: {model}")

        # Prepare prompts for each commit
        prompts = {}
        batch_jsonl_content = []

        for commit_sha, commit_info in commit_infos.items():
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
            # Use fetch_k=20 to search through more documents, and k=10 to return the most similar
            docs = self.vectorstore.similarity_search(
                query,
                k=10,
                fetch_k=20  # Search through more documents first
            )

            # Extract and highlight the CVE status from each similar commit
            formatted_contexts = []
            for i, doc in enumerate(docs):
                if not doc.page_content:
                    continue  # Skip empty content
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

                # Remove CVE status from beginning of content if present
                content = re.sub(r'^\[CVE Status: (YES|NO)\]\s*\n+', '', content, flags=re.MULTILINE)

                # Make sure commit displays have a consistent structure
                if "Subject:" not in content:
                    # Extract subject if possible from metadata
                    sha = doc.metadata.get('sha', 'unknown') if hasattr(doc, 'metadata') else 'unknown'
                    try:
                        # Try to get commit info from the repository to ensure we have complete data
                        if sha != 'unknown' and hasattr(self, 'repo'):
                            content_parts = []
                            commit = self.repo.commit(sha)
                            message_lines = commit.message.strip().split('\n')
                            subject = message_lines[0].strip()
                            content_parts.append(f"Subject: {subject}")
                            content_parts.append(f"Commit Message:\n{commit.message}")
                            content = "\n\n".join(content_parts)
                    except:
                        # If we can't get the commit info, just note that
                        content = f"Subject: [Missing subject for commit {sha}]\n\nCommit Message: [Missing message]"

                # Check if code changes are present
                if "Code Changes:" not in content and "Changes:" not in content:
                    content += "\n\nCode Changes:\n[No code changes found or extracted for this commit]"

                # Format with CVE status in the title only
                formatted_content = f"Similar Commit {i+1} [CVE Status: {cve_status}]:\n{content}"
                formatted_contexts.append(formatted_content)

            context = "\n\n".join(formatted_contexts)

            # Format the full prompt
            full_prompt = self.prompt_template.format(
                context=context,
                commit_info=commit_text
            )

            # Store prompt for this commit
            prompts[commit_sha] = full_prompt

            # Add this request to the batch JSONL content
            batch_request = {
                "custom_id": commit_sha,
                "method": "POST",
                "url": "/v1/chat/completions",
                "body": {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": "You are a security expert analyzing kernel commits to detect security vulnerabilities."},
                        {"role": "user", "content": full_prompt}
                    ],
                    "temperature": temperature
                }
            }
            batch_jsonl_content.append(json.dumps(batch_request))

        # Create a JSONL file with all requests
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".jsonl", delete=False) as batch_file:
            batch_file_path = batch_file.name
            # Write each request as a JSON line
            batch_file.write("\n".join(batch_jsonl_content))

        try:
            logging.info(f"Created batch requests file with {len(batch_jsonl_content)} requests")

            # Step 1: Upload the JSONL file
            logging.info("Uploading batch requests file to OpenAI")
            with open(batch_file_path, "rb") as file:
                uploaded_file = openai_client.files.create(
                    file=file,
                    purpose="batch"
                )
            file_id = uploaded_file.id
            logging.info(f"Batch file uploaded successfully, file ID: {file_id}")

            # Step 2: Create a batch job
            logging.info("Creating batch job")
            batch = openai_client.batches.create(
                input_file_id=file_id,
                endpoint="/v1/chat/completions",
                completion_window="24h"
            )
            batch_id = batch.id
            logging.info(f"Batch job created successfully, batch ID: {batch_id}")

            # Step 3: Poll for batch completion
            results = {}
            poll_interval = 5 * 60  # 5 minutes in seconds
            max_retries = 288  # Maximum number of retries (24 hours with 5-minute intervals)
            retry_count = 0

            # Wait for batch to complete
            while retry_count < max_retries:
                try:
                    # Get batch status
                    batch_status = openai_client.batches.retrieve(batch_id)
                    status = batch_status.status
                    logging.info(f"Batch status: {status}, attempt {retry_count+1}/{max_retries}")

                    # If batch is complete, break the loop
                    if status == "completed":
                        logging.info("Batch processing completed, retrieving results...")
                        break

                    # If batch failed, raise an exception
                    if status in ["failed", "expired", "cancelled"]:
                        raise Exception(f"Batch processing {status}")

                    # Wait before polling again
                    retry_count += 1
                    logging.info(f"Waiting {poll_interval//60} minutes before checking batch status again...")
                    time.sleep(poll_interval)

                except Exception as e:
                    logging.error(f"Error in batch polling loop: {e}")
                    retry_count += 1
                    time.sleep(60)  # Wait a minute before trying again

            # Step 4: Download and process results
            if retry_count < max_retries and batch_status.status == "completed":
                try:
                    # Get the output file ID
                    output_file_id = batch_status.output_file_id
                    if not output_file_id:
                        raise Exception("No output file ID found in batch status")

                    # Download the output file
                    logging.info(f"Downloading batch results from file ID: {output_file_id}")
                    output_content = openai_client.files.content(output_file_id)
                    output_text = output_content.text

                    # Process the output file line by line
                    for line in output_text.strip().split('\n'):
                        try:
                            result_data = json.loads(line)
                            commit_sha = result_data.get("custom_id")

                            if not commit_sha:
                                logging.warning(f"Result missing custom_id: {result_data}")
                                continue

                            # Check if there was an error
                            if result_data.get("error"):
                                error_msg = result_data["error"].get("message", "Unknown error")
                                results[commit_sha] = {"error": error_msg}
                                print(f"{commit_sha} error")
                                logging.error(f"Batch API error for {commit_sha}: {error_msg}")
                                continue

                            # Get the response
                            response = result_data.get("response", {})
                            if response.get("status_code") != 200:
                                results[commit_sha] = {"error": f"API returned status code {response.get('status_code')}"}
                                print(f"{commit_sha} error")
                                continue

                            # Extract the message content
                            body = response.get("body", {})
                            choices = body.get("choices", [])
                            if not choices:
                                results[commit_sha] = {"error": "No choices in response"}
                                print(f"{commit_sha} error")
                                continue

                            message = choices[0].get("message", {})
                            response_text = message.get("content", "")

                            # Parse the response
                            prediction, explanation = self._parse_llm_response(response_text)

                            # Store result
                            results[commit_sha] = {
                                "prediction": prediction,
                                "explanation": explanation
                            }

                            # Print result in batch mode format
                            print(f"{commit_sha} {'yes' if prediction else 'no'}")

                        except Exception as e:
                            logging.error(f"Error processing result line: {e}")

                    # Check if there are any error results
                    error_file_id = batch_status.error_file_id
                    if error_file_id:
                        logging.warning(f"Some requests failed. Downloading error file: {error_file_id}")
                        error_content = openai_client.files.content(error_file_id)
                        error_text = error_content.text

                        # Process the error file line by line
                        for line in error_text.strip().split('\n'):
                            try:
                                error_data = json.loads(line)
                                commit_sha = error_data.get("custom_id")

                                if not commit_sha:
                                    continue

                                # Extract error details
                                error_obj = error_data.get("error", {})
                                error_msg = error_obj.get("message", "Unknown error")

                                # Store error in results
                                results[commit_sha] = {"error": error_msg}
                                print(f"{commit_sha} error")
                                logging.error(f"Batch API error for {commit_sha}: {error_msg}")

                            except Exception as e:
                                logging.error(f"Error processing error line: {e}")

                except Exception as e:
                    logging.error(f"Error retrieving batch results: {e}")
            else:
                logging.error(f"Batch did not complete successfully. Status: {batch_status.status}")

        finally:
            # Clean up the temporary file
            try:
                os.unlink(batch_file_path)
            except Exception as e:
                logging.warning(f"Failed to delete temporary file {batch_file_path}: {e}")

        # Process any missing commits individually as a fallback
        missing_commits = set(commit_infos.keys()) - set(results.keys())
        if missing_commits:
            logging.warning(f"Failed to get results for {len(missing_commits)} commits. Processing individually as fallback.")

            # Process remaining commits one by one
            for commit_sha in missing_commits:
                try:
                    # Make a direct API call as fallback
                    response = openai_client.chat.completions.create(
                        model=model,
                        messages=[
                            {"role": "system", "content": "You are a security expert analyzing kernel commits to detect security vulnerabilities."},
                            {"role": "user", "content": prompts[commit_sha]}
                        ],
                        temperature=temperature
                    )

                    # Extract response text
                    response_text = response.choices[0].message.content

                    # Parse the response
                    prediction, explanation = self._parse_llm_response(response_text)

                    # Store result
                    results[commit_sha] = {
                        "prediction": prediction,
                        "explanation": explanation
                    }

                    # Print result in batch mode format
                    print(f"{commit_sha} {'yes' if prediction else 'no'}")

                except Exception as e:
                    results[commit_sha] = {"error": str(e)}
                    print(f"{commit_sha} error")
                    logging.error(f"Error processing fallback request for {commit_sha}: {e}")

        return results

    def predict_multiple(self, commit_infos: Dict[str, dict], batch_mode: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        Predict for multiple commits at once, with option to use batch API for Claude or OpenAI

        Args:
            commit_infos: Dictionary mapping commit SHAs to commit info dictionaries
            batch_mode: Whether to use batch mode output

        Returns:
            Dictionary mapping commit SHAs to prediction results
        """
        # If only Claude is enabled and batch mode is true, use Claude's batch API
        if self.llm_providers == ["claude"] and batch_mode:
            return self.batch_process_claude(commit_infos)

        # If only OpenAI (gpt4/gpt4o) is enabled and batch mode is true, use OpenAI batch processing
        if batch_mode and len(self.llm_providers) == 1 and self.llm_providers[0] in ["gpt4", "gpt4o"]:
            return self.batch_process_openai(commit_infos)

        # Otherwise, process commits one by one
        results = {}
        for sha, commit_info in commit_infos.items():
            try:
                result = self.predict(commit_info, batch_mode=batch_mode, commit_sha=sha)
                results[sha] = result
            except Exception as e:
                results[sha] = {"error": str(e)}
                if batch_mode:
                    print(f"{sha} error")

        return results

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
        # Use fetch_k=20 to search through more documents, and k=10 to return the most similar
        # This increases the chance of getting complete commit information including diffs
        docs = self.vectorstore.similarity_search(
            query,
            k=10,
            fetch_k=20  # Search through more documents first
        )

        # Extract and highlight the CVE status from each similar commit
        formatted_contexts = []
        for i, doc in enumerate(docs):
            if not doc.page_content:
                continue  # Skip empty content
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

            # Remove CVE status from beginning of content if present
            content = re.sub(r'^\[CVE Status: (YES|NO)\]\s*\n+', '', content, flags=re.MULTILINE)

            # Add debug logging for the content of similar commits when verbose is enabled
            if verbose:
                sha = doc.metadata.get('sha', 'unknown') if hasattr(doc, 'metadata') else 'unknown'
                logging.debug(f"Similar commit #{i+1} (SHA: {sha}) content size: {len(content)} bytes")
                # Count how many occurrences of "Code Changes:" or "Changes:" appear in the content
                code_change_count = content.count("Code Changes:") + content.count("Changes:")
                logging.debug(f"Similar commit #{i+1} has {code_change_count} code change sections")

            # Make sure commit displays have a consistent structure
            if "Subject:" not in content:
                # Extract subject if possible from metadata
                sha = doc.metadata.get('sha', 'unknown') if hasattr(doc, 'metadata') else 'unknown'
                try:
                    # Try to get commit info from the repository to ensure we have complete data
                    if sha != 'unknown' and hasattr(self, 'repo'):
                        content_parts = []
                        commit = self.repo.commit(sha)
                        message_lines = commit.message.strip().split('\n')
                        subject = message_lines[0].strip()
                        content_parts.append(f"Subject: {subject}")
                        content_parts.append(f"Commit Message:\n{commit.message}")
                        content = "\n\n".join(content_parts)
                except:
                    # If we can't get the commit info, just note that
                    content = f"Subject: [Missing subject for commit {sha}]\n\nCommit Message: [Missing message]"

            # Check if code changes are present
            if "Code Changes:" not in content and "Changes:" not in content:
                content += "\n\nCode Changes:\n[No code changes found or extracted for this commit]"

            # Format with CVE status in the title only
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
            # Add retry logic
            max_retries = 5  # Maximum number of retries
            retry_count = 0
            retry_delay = 5  # Seconds between retries

            while retry_count <= max_retries:  # Try until successful or max retries reached
                try:
                    # For Claude, get the raw response first to check for thinking
                    if name == "claude" and verbose and not batch_mode and isinstance(llm, ClaudeLLM) and llm.thinking_enabled:
                        # For Claude with thinking enabled, we need to access the raw response
                        try:
                            # Use direct client if available
                            if hasattr(llm, 'direct_client') and llm.direct_client:
                                message = llm.direct_client.messages.create(
                                    model=llm.model,
                                    max_tokens=llm.max_tokens,
                                    messages=[{"role": "user", "content": full_prompt}],
                                    temperature=1.0,  # Must be 1.0 with thinking
                                    system="You are a security expert analyzing kernel commits to detect security vulnerabilities.",
                                )

                                # Extract the response content text
                                response_content = ""

                                # Process the content blocks
                                for block in message.content:
                                    if block.type == "text":
                                        response_content += block.text
                            else:
                                # Fall back to langchain wrapper
                                raw_response = llm.llm.invoke(
                                    full_prompt,
                                    max_tokens=llm.max_tokens,
                                    temperature=1,  # Must be 1 when thinking is enabled
                                )

                                # Extract thinking if available
                                thinking = None
                                response_content = ""

                                # Process the structured response content from Claude 3.7
                                if hasattr(raw_response, 'content') and isinstance(raw_response.content, list):
                                    for block in raw_response.content:
                                        # Handle each content block based on its type
                                        if isinstance(block, dict):
                                            block_type = block.get('type')
                                            # Only process text blocks
                                            if block_type == 'text':
                                                response_content += block.get('text', '')
                                        # If it's an object, access properties differently
                                        elif hasattr(block, 'type'):
                                            # Only process text blocks
                                            if block.type == 'text':
                                                response_content += getattr(block, 'text', '')
                                else:
                                    # Fallback for older response format
                                    response_content = str(raw_response.content)

                            # Parse the response using the new helper function
                            prediction, response_content = self._parse_llm_response(response_content)

                            # Normal verbose logging for the response
                            logging.info(f"\n{'='*80}")
                            logging.info(f"{name.upper()} response:")
                            logging.info("-"*80)
                            logging.info(response_content)
                            logging.info("="*80 + "\n")

                            results[name] = {
                                "prediction": prediction,
                                "explanation": response_content
                            }
                            # If we got here without error, break the retry loop
                            break
                        except Exception as e:
                            # Increment retry count
                            retry_count += 1

                            if retry_count > max_retries:
                                # Only log the full error when we've exhausted all retries
                                logging.error(f"Error with {name} LLM after {max_retries} attempts: {e}")
                                if batch_mode and commit_sha:
                                    print(" error", end='', flush=True)
                                results[name] = {
                                    "error": f"Failed after {max_retries} retries: {str(e)}"
                                }
                            else:
                                # Just log that we're retrying without detailed error info
                                logging.info(f"Retrying {name} LLM (attempt {retry_count}/{max_retries}) in {retry_delay} seconds...")
                                # Don't print anything during retries in batch mode
                                time.sleep(retry_delay)
                    else:
                        # For other LLMs or when not in verbose mode
                        response = llm.invoke(full_prompt)
                        # Parse the response using the new helper function
                        prediction, response = self._parse_llm_response(response)

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
                        # If we got here without error, break the retry loop
                        break

                except Exception as e:
                    # Increment retry count
                    retry_count += 1

                    if retry_count > max_retries:
                        # Only log the full error when we've exhausted all retries
                        logging.error(f"Error with {name} LLM after {max_retries} attempts: {e}")
                        if batch_mode and commit_sha:
                            print(" error", end='', flush=True)
                        results[name] = {
                            "error": f"Failed after {max_retries} retries: {str(e)}"
                        }
                    else:
                        # Just log that we're retrying without detailed error info
                        logging.info(f"Retrying {name} LLM (attempt {retry_count}/{max_retries}) in {retry_delay} seconds...")
                        # Don't print anything during retries in batch mode
                        time.sleep(retry_delay)

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

def setup_logging(debug: bool, batch_mode: bool = False):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Suppress HTTP request logs from Anthropic SDK in batch mode
    if batch_mode:
        logging.getLogger("anthropic").setLevel(logging.WARNING)
        # Also suppress httpx which is used by the SDK
        logging.getLogger("httpx").setLevel(logging.WARNING)

def check_environment(models=None):
    """Check if required environment variables are set for the specified models

    Args:
        models: List of model providers to check keys for. If None, checks all keys.
    """
    if models is None:
        models = ["claude", "llama", "qwen", "gpt4", "gpt4o"]
    elif isinstance(models, str):
        models = [m.strip() for m in models.split(',')]

    missing = []
    if any(model in ["claude"] for model in models) and not os.getenv("ANTHROPIC_API_KEY"):
        missing.append("ANTHROPIC_API_KEY")
    if any(model in ["llama", "qwen"] for model in models) and not os.getenv("HUGGINGFACE_API_KEY"):
        missing.append("HUGGINGFACE_API_KEY")
    if any(model in ["gpt4", "gpt4o"] for model in models) and not os.getenv("OPENAI_API_KEY"):
        missing.append("OPENAI_API_KEY")

    if missing:
        raise ValueError(f"Missing required environment variables for selected models: {', '.join(missing)}")

def main():
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
                        help='Run training with limited dataset (100 CVE + 200 non-CVE commits)')
    parser.add_argument('--commit', type=str,
                        help='Single commit SHA to analyze')
    parser.add_argument('--commits', nargs='+',
                        help='List of commit SHAs to analyze')
    parser.add_argument('--models', type=str,
                        help='Comma-separated list of models to use (e.g., claude,llama,qwen,gpt4)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug output')
    parser.add_argument('--verbose', action='store_true',
                        help='Show detailed LLM prompts and responses')
    parser.add_argument('--batch', action='store_true',
                        help='Output only SHA and yes/no responses for batch processing')

    args = parser.parse_args()

    # Always set up logging, but adjust level based on debug flag
    # This ensures debug output works even with --batch
    setup_logging(args.debug, args.batch)

    # Check environment variables based on specified models
    if args.models:
        check_environment(args.models)
    else:
        check_environment()

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
            logging.info("Test mode: limiting dataset to 100 CVE and 200 non-CVE commits")
            dataset = collector.build_dataset(max_cve=100, max_non_cve=200, commit_timeout=120)
        else:
            dataset = collector.build_dataset(commit_timeout=120)

        cve_count = sum(dataset.has_cve)
        logging.info(f"Dataset built with {len(dataset)} total commits:")
        logging.info(f"  - {cve_count} CVE commits")
        logging.info(f"  - {len(dataset) - cve_count} non-CVE commits")

        # Parse models list if provided
        llm_providers = None
        if args.models:
            llm_providers = [m.strip() for m in args.models.split(',')]
            logging.info(f"Using specified models: {', '.join(llm_providers)}")

        # Initialize and train classifier
        logging.info("Training classifier...")

        # Create repo object to use for retrieving commit details
        repo_path = Path(args.kernel_repo).expanduser()
        repo = git.Repo(repo_path)

        # Pass repo to classifier for better commit detail retrieval
        classifier = CVEClassifier(llm_providers=llm_providers, repo=repo) if llm_providers else CVEClassifier(repo=repo)
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

        # Update the model's LLM providers if specified
        if args.models:
            llm_providers = [m.strip() for m in args.models.split(',')]
            if not args.batch:
                logging.info(f"Using specified models: {', '.join(llm_providers)}")
            classifier.llm_providers = llm_providers
            classifier.llms = None  # Reset LLMs to force reinitialization with new providers

        # Set the repository for enhanced commit lookups if not already set
        if not hasattr(classifier, 'repo') or classifier.repo is None:
            repo_path = Path(args.kernel_repo).expanduser()
            classifier.repo = git.Repo(repo_path)
            if not args.batch:
                logging.info("Added repository to classifier for enhanced commit lookups")

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

        # Check if we should use batch processing (for Claude or OpenAI)
        use_batch_processing = False
        if args.batch and args.models:
            models_list = args.models.lower().strip().split(",")
            # Check if we're using Claude or OpenAI models exclusively (batch-capable models)
            if "claude" in models_list or any(model in models_list for model in ["gpt4", "gpt4o"]):
                # If we only have one kind of model or if we only have batch-capable models
                if len(models_list) == 1 or all(model in ["claude", "gpt4", "gpt4o"] for model in models_list):
                    use_batch_processing = True

        if use_batch_processing:
            # Collect commit info for all commits first
            commit_infos = {}
            for commit_sha in commits_to_analyze:
                try:
                    commit_infos[commit_sha] = collector.get_commit_features(commit_sha)
                except Exception as e:
                    print(f"{commit_sha} error")
                    logging.error(f"Error getting commit features for {commit_sha}: {e}")

            # Process all commits in batch mode
            if commit_infos:
                classifier.predict_multiple(commit_infos, batch_mode=True)
        else:
            # Process each commit individually
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
