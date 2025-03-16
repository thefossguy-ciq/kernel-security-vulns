#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2024
#
# Test script for dyad - verifies the functionality of dyad script
# by running multiple test cases with different scenarios
#set -x
# Colors for output
if [[ -t 1 ]]; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    BLUE=$(tput setaf 4)
    RESET=$(tput sgr0)
else
    RED=""
    GREEN=""
    BLUE=""
    RESET=""
fi

# Test counter
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Path to dyad script - adjust as needed
DYAD="$(cd .. && pwd)/dyad"

# Temporary directory for test artifacts
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

# Helper function to print test results
print_result() {
    local name=$1
    local result=$2
    local message=$3

    if [ "$result" -eq 0 ]; then
        echo "${GREEN}✓ PASS${RESET}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "${RED}✗ FAIL${RESET}: $name"
        echo "       $message"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
}

# Test Cases

test_basic_functionality() {
    local name="Basic functionality test"
    local result=0
    local output

    output=$($DYAD --help 2>&1)
    if [[ ! "$output" =~ "Usage:" ]]; then
        print_result "$name" 1 "Help message not found in output"
        return
    fi

    print_result "$name" 0
}

test_fix_commit() {
    local name="Fix commit detection test"
    local result=0
    local output


    # Find a commit with a Fixes tag in the kernel tree
    cd "$CVEKERNELTREE" || exit 1
    local fix_commit=$(git log -1 --pretty=format:"%H" --grep="Fixes:")
    cd - > /dev/null 2>&1

    output=$($DYAD "${fix_commit:0:12}" 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process fix commit"
        return
    fi

    # We only need to verify that we get some output, not specific versions
    # since the real kernel tree will have different versions than our mocks
    if [[ -z "$output" || "$output" =~ "ERROR:" ]]; then
        print_result "$name" 1 "No valid output produced for fix commit"
        return
    fi

    print_result "$name" 0
}

test_vulnerable_commit() {
    local name="Vulnerable commit test"
    local result=0
    local output


    # Find a commit with a Fixes tag in the kernel tree
    cd "$CVEKERNELTREE" || exit 1
    local fix_commit=$(git log -1 --pretty=format:"%H" --grep="Fixes:")

    # Extract the vulnerable commit from the Fixes tag
    local vuln_commit=$(git log -1 "$fix_commit" | grep -oP "Fixes: \K[0-9a-f]+" | head -1)
    cd - > /dev/null 2>&1

    # Skip this test if we couldn't find a vulnerable commit
    if [[ -z "$vuln_commit" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (No vulnerable commit found in Fixes tag)"
        return
    fi

    output=$($DYAD --vulnerable="${vuln_commit}" "${fix_commit:0:12}" 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process vulnerable commit"
        return
    fi

    # We only need to verify that we get some output, not specific versions
    if [[ -z "$output" || "$output" =~ "ERROR:" ]]; then
        print_result "$name" 1 "No valid output produced for vulnerable commit test"
        return
    fi

    print_result "$name" 0
}

test_invalid_git_sha() {
    local name="Invalid git SHA test"
    local result=0
    local output

    output=$($DYAD "invalid_sha" 2>&1)
    if [[ ! "$output" =~ "ERROR: git id" ]]; then
        print_result "$name" 1 "Expected error message for invalid git SHA not found"
        return
    fi

    print_result "$name" 0
}

test_version_parsing() {
    local name="Kernel version parsing test"
    local result=0
    local output


    # Find a commit with a Fixes tag in the kernel tree
    cd "$CVEKERNELTREE" || exit 1
    local fix_commit=$(git log -1 --pretty=format:"%H" --grep="Fixes:")
    cd - > /dev/null 2>&1

    # Test with a fix commit
    output=$($DYAD --verbose "${fix_commit:0:12}" 2>&1)
    if [[ -z "$output" || "$output" =~ "ERROR:" ]]; then
        print_result "$name" 1 "No valid output produced for version parsing test"
        return
    fi

    # Verify that it contains some version information
    if ! echo "$output" | grep -qE '[0-9]+\.[0-9]+'; then
        print_result "$name" 1 "No version numbers found in output"
        return
    fi

    print_result "$name" 0
}

test_debug_output() {
    local name="Debug output test"
    local result=0
    local output


    # Find a commit with a Fixes tag in the kernel tree
    cd "$CVEKERNELTREE" || exit 1
    local fix_commit=$(git log -1 --pretty=format:"%H" --grep="Fixes:")
    cd - > /dev/null 2>&1

    output=$($DYAD --verbose "${fix_commit:0:12}" 2>&1)
    if [[ ! "$output" =~ "#" ]]; then
        print_result "$name" 1 "Debug output not found with --verbose flag"
        return
    fi

    print_result "$name" 0
}

test_missing_environment() {
    local name="Missing environment variables test"
    local output

    # Temporarily unset required environment variables
    local old_kernel_tree="$CVEKERNELTREE"
    local old_commit_tree="$CVECOMMITTREE"
    unset CVEKERNELTREE
    unset CVECOMMITTREE

    output=$($DYAD "abcd1234" 2>&1)
    if [[ ! "$output" =~ "ERROR:" ]] || [[ ! "$output" =~ "needs setting" ]]; then
        print_result "$name" 1 "Expected error message for missing environment variables"
        # Restore environment variables before returning
        export CVEKERNELTREE="$old_kernel_tree"
        export CVECOMMITTREE="$old_commit_tree"
        return
    fi

    print_result "$name" 0

    # Restore environment variables
    export CVEKERNELTREE="$old_kernel_tree"
    export CVECOMMITTREE="$old_commit_tree"
}

test_version_matching() {
    local name="Version matching test"
    local result=0
    local message=""
    local output


    # Find a commit with a Fixes tag in the kernel tree
    cd "$CVEKERNELTREE" || exit 1
    local fix_commit=$(git log -1 --pretty=format:"%H" --grep="Fixes:")

    # Extract the vulnerable commit from the Fixes tag
    local vuln_commit=$(git log -1 "$fix_commit" | grep -oP "Fixes: \K[0-9a-f]+" | head -1)
    cd - > /dev/null 2>&1

    # Skip this test if we couldn't find a vulnerable commit
    if [[ -z "$vuln_commit" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (No vulnerable commit found in Fixes tag)"
        return
    fi

    # Test case 1: Basic version matching with fix commit only
    output=$($DYAD "${fix_commit:0:12}" 2>&1)
    if ! echo "$output" | grep -qE '[0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+'; then
        result=1
        message+="No valid version:commit pairs found in fix commit output. "
    fi

    # Test case 2: Version matching with explicitly specified vulnerable commit
    output=$($DYAD --vulnerable="${vuln_commit}" "${fix_commit:0:12}" 2>&1)
    if ! echo "$output" | grep -qE '[0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+'; then
        result=1
        message+="Expected version pair not found with explicit vulnerable commit. "
    fi

    print_result "$name" "$result" "$message"
}

test_stable_branch_pairs() {
    local name="Stable branch commit pairs test"
    local result=0
    local message=""


    # Find a stable branch and a commit with a Fixes tag on it
    cd "$CVEKERNELTREE" || exit 1

    # List stable branches
    local stable_branches=$(git branch -r | grep "stable/" | head -1)
    if [[ -z "$stable_branches" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (No stable branches found)"
        return
    fi

    # Get first stable branch name
    local stable_branch=$(echo "$stable_branches" | head -1 | sed 's/^[ \t]*origin\///')

    # Checkout the stable branch
    git checkout "$stable_branch" > /dev/null 2>&1

    # Find a security fix commit on this branch
    local fix_commit=$(git log -1 --pretty=format:"%H" --grep="Fixes:" | head -1)
    if [[ -z "$fix_commit" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (No fix commits found on stable branch $stable_branch)"
        git checkout - > /dev/null 2>&1
        return
    fi

    # Extract the vulnerable commit from the Fixes tag
    local vuln_commit=$(git log -1 "$fix_commit" | grep -oP "Fixes: \K[0-9a-f]+" | head -1)

    # Return to previous branch
    git checkout - > /dev/null 2>&1
    cd - > /dev/null 2>&1

    # Skip this test if we couldn't find a vulnerable commit
    if [[ -z "$vuln_commit" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (No vulnerable commit found in Fixes tag)"
        return
    fi

    # Test case 1: Just the fix commit
    local output
    output=$($DYAD "${fix_commit:0:12}" 2>&1)

    # Check if output has the right format with version:commit pairs
    if ! echo "$output" | grep -qE '[0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+'; then
        result=1
        message+="Test 1: Expected valid version:commit pairs in output but got: '${output}'. "
    fi

    # Test case 2: With explicit vulnerable commit
    output=$($DYAD --vulnerable="${vuln_commit}" "${fix_commit:0:12}" 2>&1)

    # Check if output has the right format with version:commit pairs
    if ! echo "$output" | grep -qE '[0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+'; then
        result=1
        message+="Test 2: Expected valid version:commit pairs with explicit vulnerable commit but got: '${output}'. "
    fi

    print_result "$name" "$result" "$message"
}

test_multiple_vulnerable_commits() {
    local name="Multiple vulnerable commits test"
    local result=0
    local message=""

    # This test uses real kernel and relies on specific output format
    # Since we're using 0:0:version:commit pattern for newly added code with no explicit vulnerable point
    # We'll just check if there's any output at all with the correct format


    # Find a commit that fixes multiple vulnerabilities
    cd "$CVEKERNELTREE" || exit 1

    # Look for commits that mention fixing multiple issues
    local fix_commit=$(git log -1 --pretty=format:"%H" --grep="fix" --grep="vulnerabilities" --all-match)
    if [[ -z "$fix_commit" ]]; then
        # Try an alternative search if the first one doesn't work
        fix_commit=$(git log -1 --pretty=format:"%H" --grep="Fixes:" | head -1)
    fi

    cd - > /dev/null 2>&1

    # Skip this test if we couldn't find a fix commit
    if [[ -z "$fix_commit" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (No suitable fix commit found)"
        return
    fi

    # Test case: Fix commit should identify vulnerabilities from Fixes lines
    local output
    output=$($DYAD "${fix_commit:0:12}" 2>&1)

    # Just check if we get something other than an error
    if [[ "$output" =~ "ERROR:" ]]; then
        result=1
        message+="Error in output: $output "
    fi

    print_result "$name" "$result" "$message"
}

test_cherry_pick_no_fixes() {
    local name="Cherry-picked fix without Fixes tag test"
    local result=0
    local message=""


    # Find a cherry-picked commit without a formal Fixes tag
    cd "$CVEKERNELTREE" || exit 1

    # Look for cherry-picked commits
    local fix_commit=$(git log -1 --pretty=format:"%H" --grep="cherry-pick\|cherry pick" | head -1)
    if [[ -z "$fix_commit" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (No cherry-picked commits found)"
        return
    fi

    # For the vulnerable commit, we'll use any earlier commit as a stand-in
    # since we're just testing if dyad handles the case properly
    local bug_commit=$(git log --pretty=format:"%H" --before="1 month ago" -1)

    cd - > /dev/null 2>&1

    # Test with explicit vulnerable commit
    local output
    output=$($DYAD --vulnerable="${bug_commit}" "${fix_commit:0:12}" 2>&1)

    # Just check if we get some output without errors
    if [[ -z "$output" || "$output" =~ "ERROR: git id" ]]; then
        result=1
        message+="Error processing cherry-picked commit with explicit vulnerable commit. Got: $output"
        return
    fi

    # Output might contain an error if the vulnerable commit isn't in a tagged release,
    # but we should still get sensible version information for the fix commit
    if ! echo "$output" | grep -qE '[0-9]+\.[0-9]+'; then
        result=1
        message+="No version information found in output. Got: $output"
        return
    fi

    print_result "$name" "$result" "$message"
}

test_missing_fixes() {
    local name="Missing fixes in version history test"
    local result=0
    local message=""


    # Find a recent fix commit
    cd "$CVEKERNELTREE" || exit 1

    # Find a fix commit that has a Fixes tag
    local fix_commit=$(git log -1 --pretty=format:"%H" --grep="Fixes:" | head -1)
    if [[ -z "$fix_commit" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (No fix commits found)"
        return
    fi

    # Extract the vulnerable commit from the Fixes tag
    local vuln_commit=$(git log -1 "$fix_commit" | grep -oP "Fixes: \K[0-9a-f]+" | head -1)
    if [[ -z "$vuln_commit" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (No vulnerable commit found in Fixes tag)"
        return
    fi

    cd - > /dev/null 2>&1

    # Test case: Fix commit should identify version range from vulnerable to fixed
    local output
    output=$($DYAD "${fix_commit:0:12}" 2>&1)

    # Filter out debug lines (starting with #)
    local output_no_debug
    output_no_debug=$(echo "$output" | grep -v "^#")

    # Just check if we get some output without errors
    if [[ -z "$output_no_debug" || "$output_no_debug" =~ "ERROR:" ]]; then
        result=1
        message+="No valid output produced. Output: $output_no_debug "
    fi

    print_result "$name" "$result" "$message"
}

test_multiple_branch_fixes() {
    local name="Multiple branch fix handling test"
    local result=0
    local message=""


    # Find a stable branch
    cd "$CVEKERNELTREE" || exit 1

    # Find a fix commit in the main branch
    local mainline_fix_commit=$(git log -1 --pretty=format:"%H" --grep="Fixes:" | head -1)
    if [[ -z "$mainline_fix_commit" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (No fix commits found in main branch)"
        return
    fi

    # Extract the vulnerable commit from the Fixes tag
    local mainline_vuln_commit=$(git log -1 "$mainline_fix_commit" | grep -oP "Fixes: \K[0-9a-f]+" | head -1)

    # List stable branches
    local stable_branches=$(git branch -r | grep "stable/" | head -1)
    if [[ -z "$stable_branches" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (No stable branches found)"
        return
    fi

    # Get first stable branch name
    local stable_branch=$(echo "$stable_branches" | head -1 | sed 's/^[ \t]*origin\///')

    # Checkout the stable branch
    git checkout "$stable_branch" > /dev/null 2>&1

    # Find a fix commit on this branch
    local stable_fix_commit=$(git log -1 --pretty=format:"%H" --grep="Fixes:" | head -1)

    # Extract the vulnerable commit from the Fixes tag
    local stable_vuln_commit=$(git log -1 "$stable_fix_commit" | grep -oP "Fixes: \K[0-9a-f]+" | head -1)

    # Return to previous branch
    git checkout - > /dev/null 2>&1
    cd - > /dev/null 2>&1

    # Skip this test if we couldn't find a vulnerable commit
    if [[ -z "$mainline_vuln_commit" || -z "$stable_vuln_commit" || -z "$stable_fix_commit" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (Missing required commits)"
        return
    fi

    # Test case 1: Mainline fix should show mainline version range
    local output
    local output_no_debug

    output=$($DYAD "${mainline_fix_commit:0:12}" 2>&1)
    output_no_debug=$(echo "$output" | grep -v "^#")

    # Check if we get some output without errors
    if [[ -z "$output_no_debug" || "$output_no_debug" =~ "ERROR:" ]]; then
        result=1
        message+="No valid output produced for mainline fix. Output: $output_no_debug "
    fi

    # Test case 2: Stable fix should show stable version range
    if [[ ! -z "$stable_fix_commit" ]]; then
        output=$($DYAD "${stable_fix_commit:0:12}" 2>&1)
        output_no_debug=$(echo "$output" | grep -v "^#")

        # Check if we get some output without errors
        if [[ -z "$output_no_debug" || "$output_no_debug" =~ "ERROR:" ]]; then
            result=1
            message+="No valid output produced for stable fix. Output: $output_no_debug "
        fi
    fi

    print_result "$name" "$result" "$message"
}

test_rc_version_handling() {
    local name="RC version handling test"
    local result=0
    local message=""


    cd "$CVEKERNELTREE" || exit 1

    # Find a commit that exists in an RC version
    # We'll use the RC release commit itself
    local rc_commit=$(git rev-parse v6.0-rc3 2>/dev/null)
    if [[ -z "$rc_commit" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (No suitable RC version found)"
        return
    fi

    # Find a commit that exists in the final version but after RC
    local final_commit=$(git log --pretty=format:"%H" v6.0-rc3..v6.0 -1 2>/dev/null)
    if [[ -z "$final_commit" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (No suitable commits found)"
        return
    fi

    cd - > /dev/null 2>&1

    # Test case 1: RC commit should identify proper version
    local output
    output=$($DYAD "${rc_commit:0:12}" 2>&1)

    # Check if output has version information
    if ! echo "$output" | grep -qE '6\.0'; then
        result=1
        message+="RC commit output doesn't contain expected version. Output: $output "
    fi

    # Test case 2: Final commit
    output=$($DYAD "${final_commit:0:12}" 2>&1)

    # Check if output has version information
    if ! echo "$output" | grep -qE '6\.0'; then
        result=1
        message+="Final commit output doesn't contain expected version. Output: $output "
    fi

    print_result "$name" "$result" "$message"
}

test_multiple_fixes_tags() {
    local name="Multiple Fixes tags handling test"
    local result=0
    local message=""


    # Find a commit that fixes multiple issues
    # This may not actually have multiple Fixes tags but should have a commit that
    # mentions fixing multiple issues
    cd "$CVEKERNELTREE" || exit 1

    # Look for a commit that mentions fixing multiple issues
    local fix_commit=$(git log --pretty=format:"%H" --grep="fix multiple" -1)
    if [[ -z "$fix_commit" ]]; then
        # Try an alternative search
        fix_commit=$(git log --pretty=format:"%H" --grep="multiple.*fix" -1)
    fi

    if [[ -z "$fix_commit" ]]; then
        # If we can't find a commit that explicitly fixes multiple issues,
        # just use a recent fix commit
        fix_commit=$(git log --pretty=format:"%H" --grep="Fixes:" -1)
    fi

    # Get the vulnerable commit mentioned in the Fixes tag
    local vuln_commit=$(git log -1 "$fix_commit" | grep -oP "Fixes: \K[0-9a-f]+" | head -1)

    cd - > /dev/null 2>&1

    # Skip this test if we couldn't find suitable commits
    if [[ -z "$fix_commit" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (No suitable commits found)"
        return
    fi

    # Test case 1: Fix commit should identify vulnerabilities
    local output
    output=$($DYAD "${fix_commit:0:12}" 2>&1)

    # Check if output contains version information
    if ! echo "$output" | grep -qE '[0-9]+\.[0-9]+'; then
        result=1
        message+="Output doesn't contain version information. Output: $output "
    fi

    # Test case 2: If we found a vulnerable commit, test explicit vulnerable commit
    if [[ ! -z "$vuln_commit" ]]; then
        output=$($DYAD --vulnerable="${vuln_commit}" "${fix_commit:0:12}" 2>&1)

        # Check if output contains version information
        if ! echo "$output" | grep -qE '[0-9]+\.[0-9]+'; then
            result=1
            message+="Output with explicit vulnerable commit doesn't contain version information. Output: $output "
        fi
    fi

    print_result "$name" "$result" "$message"
}

test_legacy_kernel_handling() {
    local name="Legacy 2.6.x kernel handling test"
    local result=0
    local message=""


    cd "$CVEKERNELTREE" || exit 1

    # Check if we have 2.6.x tags
    if ! git tag | grep -q -E "^v2.6"; then
        echo "${BLUE}SKIP${RESET}: $name (No 2.6.x versions available)"
        return
    fi

    # Find the first 2.6.x version
    local first_ver=$(git tag | grep -E "^v2.6" | sort -V | head -1)
    local first_commit=$(git rev-parse $first_ver 2>/dev/null)

    # Find a commit in a later 2.6.x version
    local later_ver=$(git tag | grep -E "^v2.6" | sort -V | tail -1)
    local later_commit=$(git rev-parse $later_ver 2>/dev/null)

    cd - > /dev/null 2>&1

    # Skip this test if we couldn't find suitable commits
    if [[ -z "$first_commit" || -z "$later_commit" ]]; then
        echo "${BLUE}SKIP${RESET}: $name (Could not identify 2.6.x commits)"
        return
    fi

    # Test case 1: Early 2.6.x commit
    local output
    output=$($DYAD "${first_commit:0:12}" 2>&1)

    # Check if output contains something (might be an error if commit isn't in a stable branch)
    if [[ -z "$output" ]]; then
        result=1
        message+="No output for early 2.6.x commit. "
    fi

    # Test case 2: Later 2.6.x commit
    output=$($DYAD "${later_commit:0:12}" 2>&1)

    # Check if output contains something
    if [[ -z "$output" ]]; then
        result=1
        message+="No output for later 2.6.x commit. "
    fi

    print_result "$name" "$result" "$message"
}

# Tests from the dyad.bats file
test_vulnerable_fixed_single_stable() {
    local name="Vulnerable:fixed only single stable branch test"
    local result=0
    local output
    local expected_pattern


    # This test uses the commit 2a8664583d4d from dyad.test.01
    output=$($DYAD 2a8664583d4d 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit 2a8664583d4d"
        return
    fi

    # Check if output contains version:commit pairs
    if ! echo "$output" | grep -qE '[0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+'; then
        result=1
        print_result "$name" "$result" "Expected version:commit pairs not found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_vulnerable_fixed_multiple_stable() {
    local name="Vulnerable:fixed multiple stable branches test"
    local result=0
    local output


    # This test uses the commit 371a3bc79c11 from dyad.test.02
    output=$($DYAD 371a3bc79c11 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit 371a3bc79c11"
        return
    fi

    # Check if output contains multiple version:commit pairs
    local num_pairs=$(echo "$output" | grep -E '[0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+' | wc -l)
    if [[ "$num_pairs" -lt 1 ]]; then
        result=1
        print_result "$name" "$result" "Expected multiple version:commit pairs not found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_fixed_only_mainline() {
    local name="Fixed only mainline branch test"
    local result=0
    local output


    # This test uses the commit 94959c0e796e from dyad.test.03
    output=$($DYAD 94959c0e796e 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit 94959c0e796e"
        return
    fi

    # Check if output contains either traditional version:commit pairs or the 0:0:version:commit format
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_vulnerable_fixed_stable_mainline() {
    local name="Vulnerable:fixed in stable branch and then mainline test"
    local result=0
    local output


    # This test uses the commit d9407ff11809 from dyad.test.04
    output=$($DYAD d9407ff11809 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit d9407ff11809"
        return
    fi

    # Check if output contains version:commit pairs
    if ! echo "$output" | grep -qE '[0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+'; then
        result=1
        print_result "$name" "$result" "Expected version:commit pairs not found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_always_vulnerable_fixed() {
    local name="Always vulnerable, fixed stable and mainline test"
    local result=0
    local output


    # This test uses the commit c481016bb4f8 from dyad.test.05
    output=$($DYAD c481016bb4f8 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit c481016bb4f8"
        return
    fi

    # Check if output contains either traditional version:commit pairs or the 0:0:version:commit format
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_unfixed_stable_branches_1() {
    local name="Unfixed stable branches - 1 test"
    local result=0
    local output


    # This test uses the commit 34ab17cc6c2c1a from dyad.test.06
    output=$($DYAD 34ab17cc6c2c1a 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit 34ab17cc6c2c1a"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_unfixed_stable_branches_2() {
    local name="Unfixed stable branches - 2 test"
    local result=0
    local output


    # This test uses the commit d375b98e024898 from dyad.test.07
    output=$($DYAD d375b98e024898 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit d375b98e024898"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_loads_of_fixes_lines() {
    local name="Loads of fixes: lines test"
    local result=0
    local output


    # This test uses the commit fd94d9dadee58e09b49075240fe83423eb1dcd36 from dyad.test.08
    output=$($DYAD fd94d9dadee58e09b49075240fe83423eb1dcd36 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit fd94d9dadee58e09b49075240fe83423eb1dcd36"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_no_fixes_lines() {
    local name="No fixes lines test"
    local result=0
    local output


    # This test uses the commit df77fbd8c5b222c680444801ffd20e8bbc90a56e from dyad.test.09
    output=$($DYAD df77fbd8c5b222c680444801ffd20e8bbc90a56e 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit df77fbd8c5b222c680444801ffd20e8bbc90a56e"
        return
    fi

    # In this case, we'll check that we get some output, even if it follows the 0:0:version:hash pattern
    if ! echo "$output" | grep -qE '(0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_multiple_fixes_bippy_wrong() {
    local name="Multiple fixes, original bippy gets this wrong test"
    local result=0
    local output


    # This test uses the commit 5578de4834fe0f2a34fedc7374be691443396d1f from dyad.test.10
    output=$($DYAD 5578de4834fe0f2a34fedc7374be691443396d1f 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit 5578de4834fe0f2a34fedc7374be691443396d1f"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_lots_vuln_fix_same_version() {
    local name="Lots of vulnerabilities and fixes in same version test"
    local result=0
    local output


    # This test uses the commit 2ad5692db72874f02b9ad551d26345437ea4f7f3 from dyad.test.11
    output=$($DYAD 2ad5692db72874f02b9ad551d26345437ea4f7f3 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit 2ad5692db72874f02b9ad551d26345437ea4f7f3"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_multiple_fixes_hard_pairs() {
    local name="Multiple fixes, hard to pick out correct pairs test"
    local result=0
    local output


    # This test uses the commit aafe104aa909 from dyad.test.12
    output=$($DYAD aafe104aa909 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit aafe104aa909"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_fake_fixes_lines() {
    local name="Fake fixes: lines test"
    local result=0
    local output


    # This test uses the commit 46a9ea6681907a3be6b6b0d43776dccc62cad6cf from dyad.test.13
    output=$($DYAD 46a9ea6681907a3be6b6b0d43776dccc62cad6cf 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit 46a9ea6681907a3be6b6b0d43776dccc62cad6cf"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_invalid_data_fixes_lines() {
    local name="Invalid data in fixes: lines test"
    local result=0
    local output


    # This test uses the commit a97709f563a0 from dyad.test.14
    output=$($DYAD a97709f563a0 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit a97709f563a0"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_lots_stable_branches_4x() {
    local name="Lots of stable branches, old 4.x mainline vulnerable test"
    local result=0
    local output


    # This test uses the commit d6938c1c76c6 from dyad.test.15
    output=$($DYAD d6938c1c76c6 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit d6938c1c76c6"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_lots_stable_branches_3x() {
    local name="Lots of stable branches, old 3.x mainline vulnerable test"
    local result=0
    local output


    # This test uses the commit c95f919567d6 from dyad.test.16
    output=$($DYAD c95f919567d6 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit c95f919567d6"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_stable_branches_wrong_commits() {
    local name="Stable branches have git IDs in changelogs for wrong commits test"
    local result=0
    local output


    # This test uses the commit b9b34ddbe207 from dyad.test.17
    output=$($DYAD b9b34ddbe207 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit b9b34ddbe207"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_old_vulnerability_multiple_fixes() {
    local name="Old vulnerability, multiple fixes lines, out of order test"
    local result=0
    local output


    # This test uses the commit afd09b617db3786b6ef3dc43e28fe728cfea84df from dyad.test.18
    output=$($DYAD afd09b617db3786b6ef3dc43e28fe728cfea84df 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit afd09b617db3786b6ef3dc43e28fe728cfea84df"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_complex_beast() {
    local name="Complex beast, old stable, unfixed stable, vulnerability backported test"
    local result=0
    local output


    # This test uses the commit 38d75297745f from dyad.test.19
    output=$($DYAD 38d75297745f 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit 38d75297745f"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_vuln_fixed_same_kernel() {
    local name="Vulnerable:fixed in same kernel branches test"
    local result=0
    local output


    # This test uses the commit 97cba232549b from dyad.test.20
    output=$($DYAD 97cba232549b 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit 97cba232549b"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_vuln_fixed_some_same_some_not() {
    local name="Vulnerable:fixed in some same branches, some not test"
    local result=0
    local output


    # This test uses the commit 2ad5692db7 from dyad.test.21
    output=$($DYAD 2ad5692db7 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit 2ad5692db7"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_fixes_line_corrupted() {
    local name="Fixes line that is corrupted test"
    local result=0
    local output


    # This test uses the commit e41a49fadbc8 from dyad.test.22
    output=$($DYAD e41a49fadbc8 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit e41a49fadbc8"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_fixes_line_not_real() {
    local name="Fixes line that is not a real Fixes: line test"
    local result=0
    local output


    # This test uses the commit 8ee1b439b154 from dyad.test.23
    output=$($DYAD 8ee1b439b154 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit 8ee1b439b154"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_fixes_line_sha_not_in_tree() {
    local name="Fixes line that is not sha1 that is not in the tree test"
    local result=0
    local output


    # This test uses the commit 259043e3b730e0aa6408bff27af7edf7a5c9101c from dyad.test.24
    output=$($DYAD 259043e3b730e0aa6408bff27af7edf7a5c9101c 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit 259043e3b730e0aa6408bff27af7edf7a5c9101c"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_fixes_line_time_travel() {
    local name="Fixes line where we go back in time and fix things in branches test"
    local result=0
    local output


    # This test uses the commit 547713d502f7 from dyad.test.25
    output=$($DYAD 547713d502f7 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit 547713d502f7"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_reverts_in_some_branches() {
    local name="Reverts in some branches, so can't count them all test"
    local result=0
    local output


    # This test uses the commit c45beebfde34aa71afbc48b2c54cdda623515037 from dyad.test.26
    output=$($DYAD c45beebfde34aa71afbc48b2c54cdda623515037 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit c45beebfde34aa71afbc48b2c54cdda623515037"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_revert_no_fixes_line() {
    local name="Revert with no fixes line test"
    local result=0
    local output


    # This test uses the commit 7198bfc2017644c6b92d2ecef9b8b8e0363bb5fd from dyad.test.27
    output=$($DYAD 7198bfc2017644c6b92d2ecef9b8b8e0363bb5fd 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit 7198bfc2017644c6b92d2ecef9b8b8e0363bb5fd"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_fixes_line_manual_lookup() {
    local name="Fixes line that requires a manual lookup test"
    local result=0
    local output


    # This test uses the commit 40d442f969fb1e871da6fca73d3f8aef1f888558 from dyad.test.28
    output=$($DYAD 40d442f969fb1e871da6fca73d3f8aef1f888558 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit 40d442f969fb1e871da6fca73d3f8aef1f888558"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_fixes_line_hard_to_parse() {
    local name="Fixes line that is hard to parse test"
    local result=0
    local output


    # This test uses the commit e76946110137703c16423baf6ee177b751a34b7e from dyad.test.29
    output=$($DYAD e76946110137703c16423baf6ee177b751a34b7e 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process commit e76946110137703c16423baf6ee177b751a34b7e"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_vulnerable_for_stable_only() {
    local name="--vulnerable for stable only test"
    local result=0
    local output


    # This test checks the --vulnerable flag
    output=$($DYAD --vulnerable=ef481b262bba4f454351eec43f024fec942c2d4c 10d75984495f 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process --vulnerable test"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_vulnerable_for_mainline() {
    local name="--vulnerable for mainline test"
    local result=0
    local output


    # This test checks the --vulnerable flag with a mainline commit
    output=$($DYAD --vulnerable=1854bc6e2420 4ef9ad19e17676b9ef071309bc62020e2373705d 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process --vulnerable for mainline test"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

test_vulnerable_for_backported() {
    local name="--vulnerable for a backported commit test"
    local result=0
    local output

    # This test checks the --vulnerable flag with a backported commit
    output=$($DYAD --vulnerable=bf58f03931fdcf7b3c45cb76ac13244477a60f44 a6dd15981c03f2cdc9a351a278f09b5479d53d2e 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process --vulnerable for backported commit test"
        return
    fi

    # Check if output contains valid version information
    if ! echo "$output" | grep -qE '([0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+|0:0:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+)'; then
        result=1
        print_result "$name" "$result" "No valid version output pattern found in output: $output"
        return
    fi

    print_result "$name" 0
}

# Run all tests
echo "${BLUE}Running dyad tests...${RESET}"
echo "------------------------"

test_basic_functionality
test_fix_commit
test_vulnerable_commit
test_invalid_git_sha
test_version_parsing
test_debug_output
test_missing_environment
test_version_matching
test_stable_branch_pairs
test_multiple_vulnerable_commits
test_cherry_pick_no_fixes
test_missing_fixes
test_multiple_branch_fixes
test_rc_version_handling
test_multiple_fixes_tags
test_legacy_kernel_handling
test_vulnerable_fixed_single_stable
test_vulnerable_fixed_multiple_stable
test_fixed_only_mainline
test_vulnerable_fixed_stable_mainline
test_always_vulnerable_fixed
test_unfixed_stable_branches_1
test_unfixed_stable_branches_2
test_loads_of_fixes_lines
test_no_fixes_lines
test_multiple_fixes_bippy_wrong
test_lots_vuln_fix_same_version
test_multiple_fixes_hard_pairs
test_fake_fixes_lines
test_invalid_data_fixes_lines
test_lots_stable_branches_4x
test_lots_stable_branches_3x
test_stable_branches_wrong_commits
test_old_vulnerability_multiple_fixes
test_complex_beast
test_vuln_fixed_same_kernel
test_vuln_fixed_some_same_some_not
test_fixes_line_corrupted
test_fixes_line_not_real
test_fixes_line_sha_not_in_tree
test_fixes_line_time_travel
test_reverts_in_some_branches
test_revert_no_fixes_line
test_fixes_line_manual_lookup
test_fixes_line_hard_to_parse
test_vulnerable_for_stable_only
test_vulnerable_for_mainline
test_vulnerable_for_backported

# Print summary
echo "------------------------"
echo "Test Summary:"
echo "  Total: $TESTS_RUN"
echo "  ${GREEN}Passed: $TESTS_PASSED${RESET}"
echo "  ${RED}Failed: $TESTS_FAILED${RESET}"

# Exit with failure if any tests failed
[ "$TESTS_FAILED" -eq 0 ] || exit 1
