#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2024 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
#
# update_dyad - Update all .dyad files in the tree.
#
# This is good to do after older stable kernels have been released as often
# CVEs are included in older stable kernels AFTER they show up in newer ones,
# and this keeps the database at CVE more up to date and friendly for others to
# rely on.  The mbox files generally shouldn't be resent, as that's just noise
# that no one wants to see.
#
# Usage:
#	update_dyad [--cve-user=email@example.com] [CVE-ID or year]
#
# Requires:
#  dyad

# set to 1 to get some debugging logging messages (or use -v/--verbose option)
DEBUG=0

# Initialize our color variables if we are a normal terminal
if [[ -t 1 ]]; then
	txtred=$(tput setaf 1)          # Red
	txtgrn=$(tput setaf 2)          # Green
	txtblu=$(tput setaf 4)          # Blue
	txtcyn=$(tput setaf 6)          # Cyan
	txtrst=$(tput sgr0)             # Text reset
else
	txtred=""
	txtgrn=""
	txtblu=""
	txtcyn=""
	txtrst=""
fi

# set where the tool was run from,
# the name of our script,
# and the git version of it
DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
SCRIPT=${0##*/}

help() {
	echo "Usage: ${SCRIPT} [OPTIONS] [CVE-ID or year]"
	echo "Options:"
	echo "  --cve-user=EMAIL    Set the CVE user email address"
	echo "  -h, --help          Show this help message"
	echo "  -v, --verbose       Enable verbose output"
	echo ""
	echo "Either set CVE_USER environment variable or use --cve-user option"
	exit 1
}

# Parse command line arguments
parse_args() {
	local TEMP
	TEMP=$(getopt -o hv --long help,verbose,cve-user: -n "${SCRIPT}" -- "$@")
	if [ $? -ne 0 ]; then
		help
	fi

	eval set -- "$TEMP"

	while true; do
		case "$1" in
			--cve-user)
				export CVE_USER="$2"
				shift 2
				;;
			-h|--help)
				help
				;;
			-v|--verbose)
				DEBUG=1
				shift
				;;
			--)
				shift
				break
				;;
			*)
				echo "${txtred}Error:${txtrst} Invalid option: $1" >&2
				help
				;;
		esac
	done

	# Store remaining argument (CVE-ID or year) if any
	CVE="$1"

	# Validate that CVE_USER is set either via environment or command line
	if [ -z "${CVE_USER}" ]; then
		echo "${txtred}Error:${txtrst} CVE_USER must be set via environment variable or --cve-user option" >&2
		help
	fi
}

dyad="${DIR}/dyad"

# Progress tracking
PROGRESS_FILE=$(mktemp -t "${SCRIPT}_progress.XXXX")
trap 'rm -f "${PROGRESS_FILE}"' EXIT

#############################
# dbg()
#	if DEBUG is enabled, print out a message.
#	Can also be set with -v or --verbose command line option
#	Does so with an initial "#" so it can be easily filtered out
# arguments:
# 	"message to print"
# assumes:
#	DEBUG is defined to something
#############################
dbg()
{
	if [[ ${DEBUG} -ge 1 ]] ; then
		echo "${txtcyn}# ${1}${txtrst}"
	fi
}

# Draw progress bar
draw_progress() {
	local current=$1
	local total=$2
	local width=50  # Width of progress bar
	local progress=$((current * width / total))
	local percentage=$((current * 100 / total))

	# Create the progress bar string
	local bar="["
	for ((i=0; i<width; i++)); do
		if ((i < progress)); then
			bar+="="
		else
			bar+=" "
		fi
	done
	bar+="]"

	# Print the progress bar with percentage
	printf "\r%s %3d%%" "${bar}" "${percentage}"
}

# Worker script for parallel processing
process_single_file() {
	local id=$1
	local total=$2
	local sha cve root vuln_file tmp_dyad result

	tmp_dyad=$(mktemp -t "${SCRIPT}XXXX.dyad" || exit 1)
	sha=$(cat "${id}")
	cve=$(echo "${id}" | cut -f 1 -d '.' | cut -f 4 -d '/')
	root=$(echo "${id}" | cut -f 1 -d '.')

	dbg "processing ${id}"

	# Check for vulnerable file
	vuln_file="${root}.vulnerable"
	vulnerable_option=""
	if [[ -f "${vuln_file}" ]]; then
		vulnerable_option="--vulnerable=$(cat "${vuln_file}")"
	fi

	# Create new dyad file
	"${dyad}" ${vulnerable_option} ${sha} > "${tmp_dyad}"
	result=$?

	if [[ "${result}" != 0 ]]; then
		echo -e "\n${txtred}Error:${txtrst} dyad failed for ${txtcyn}${cve}${txtrst}" >&2
		rm -f "${tmp_dyad}"
		return 1
	fi

	# Compare and update if needed
	if [[ ! -f "${root}.dyad" ]]; then
		mv -f "${tmp_dyad}" "${root}.dyad"
	else
		if ! diff -u "${root}.dyad" "${tmp_dyad}" | grep -v "dyad" | grep -v "^@@ " | grep -q "^[+|-]"; then
			rm "${tmp_dyad}"
		else
			mv -f "${tmp_dyad}" "${root}.dyad"
		fi
	fi

	# Update progress
	flock "${PROGRESS_FILE}" bash -c "
		echo >> '${PROGRESS_FILE}'
		current=\$(wc -l < '${PROGRESS_FILE}')
		$(declare -f draw_progress)
		draw_progress \${current} ${total}
	"
}
export -f process_single_file draw_progress

process_year() {
	local year=$1
	local threads=${2:-$(nproc)}
	local total_count

	cd "${DIR}/../" || exit 1

	# Get total count of CVEs for this year
	total_count=$(ls cve/published/${year}/*.sha1 2>/dev/null | wc -l)
	if [[ ${total_count} -eq 0 ]]; then
		echo "${txtred}No CVEs found for year ${year}${txtrst}"
		return 1
	fi

	echo "Processing ${txtcyn}${total_count}${txtrst} CVEs from ${txtgrn}${year}${txtrst}"

	# Clear progress file
	: > "${PROGRESS_FILE}"

	# Export necessary variables
	export SCRIPT dyad DIR PROGRESS_FILE txtred txtgrn txtylw txtblu txtcyn txtrst DEBUG
	export -f process_single_file draw_progress dbg

	# Process CVEs in parallel using xargs
	find "cve/published/${year}" -name "*.sha1" -print0 | \
		xargs -0 -P "${threads}" -I {} bash -c \
			"process_single_file '{}' ${total_count}"

	echo -e "\n${txtgrn}Completed processing ${year}${txtrst}"
}

process_single_cve() {
	local CVE=$1
	local found

	found=$(${DIR}/cve_search "${CVE}")
	if [[ $? -eq 0 ]]; then
		CVE_ROOT="${DIR}/../cve/"
		found=$(find "${CVE_ROOT}" -type f | grep -v testing | grep "${CVE}" | grep "sha1")
		if [[ -n "${found}" ]]; then
			process_single_file "cve/${found/#$CVE_ROOT}" 1
			return 0
		fi
	fi
	echo "${txtred}ERROR:${txtrst} ${txtcyn}${CVE}${txtrst} is not found or is not a year."
	return 1
}

main() {
	parse_args "$@"

	if [[ -z "${CVE}" ]]; then
		# Process all years
		for year_dir in cve/published/*; do
			[[ -d "${year_dir}" ]] || continue
			year=$(basename "${year_dir}")
			process_year "${year}"
			echo
		done
	elif [[ -d "cve/published/${CVE}" ]]; then
		# Process specific year
		process_year "${CVE}"
	else
		# Try to process specific CVE
		process_single_cve "${CVE}"
	fi
}

cd "${DIR}/../" || exit 1
main "$@"
