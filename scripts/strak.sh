#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2024 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
#
# strak - "fixed/tight" in Dutch.
#	  Given a specific git id, list all of the CVE ids that are NOT fixed
#	  in that release.
#
# Usage:
#	strak [options] GIT_SHA
#	For full options, see the help text below.
#
# Requires:
#  A kernel git tree with the SHA to be used in it

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
SCRIPT_VERSION=$(cd "${DIR}" && git ls-tree --abbrev=12 HEAD | grep "${SCRIPT}" | awk '{print $3}')

#############################
# help()
#	Print out help options and exit
#############################
help()
{
	echo "Usage: $0 [OPTIONS] GIT_SHA"
	echo "    List all CVE ids that are NOT fixed for this release."
	echo "    In other words, all of the public vulerabilities that this commit id has in it."
	echo ""
	echo "Arguments:"
	echo " -h, --help			This information"
	echo " --fixed=FIXED_VERSION		Kernel version to show what was fixed in it"
	echo " -v, --verbose			Show debugging information to stdout"
	echo ""
	exit 1
}

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

#############################
# info()
#	Print out a string as "information"
#	Does so with an initial "#" so it can be easily filtered out
# arguments:
#	"message to print"
#############################
info()
{
	echo "${txtgrn}# ${1}${txtrst}"
}

check_id()
{
	local git_id=$1
	local cve_id=$2
	local sha
	local cve
	local root
	local vuln_file
	local vulnerable_option
	local vulnerable_sha
	local dyad_out
	local dyad_entries
	local dyad_entry
	local found
	local must_look
	local is_in_vuln

	sha=$(cat "${cve_id}")
	cve=$(echo "${cve_id}" | cut -f 1 -d '.' | cut -f 4 -d '/')
	root=$(echo "${cve_id}" | cut -f 1 -d '.')

	dbg "checking ${cve}:"

	# Look to see if we have a "og_vuln" that is provided to us in a
	# published CVE.  This is used for when we can't determine it on our
	# own, but we have manually looked it up later on and added it to a
	# CVE-*.vulnerable file
	vuln_file="${root}.vulnerable"
	#echo "vuln_file=${vuln_file}"
	vulnerable_option=""
	vulnerable_sha=""
	if [[ -f "${vuln_file}" ]]; then
		vulnerable_sha=$(cat "${vuln_file}")
		vulnerable_option="--vulnerable=${vulnerable_sha}"
	fi

	sha_id=$(cat ${cve_id})

	# We want to call dyad without quotes for the arguments as we "know" these
	# arguments are ok, we just set them above explicitly.
	# shellcheck disable=SC2086
	dbg "${root}.dyad"
	dyad_out=$(cat "${root}.dyad" | grep -v "^#")
	#dyad_out=$("${dyad}" ${sha_id} | grep -v "^#")
	#dbg "dyad_out=${dyad_out}"
	dyad_entries=()

	for dyad_entry in ${dyad_out}; do
		dyad_entries+=("${dyad_entry}")
	done
	dbg "	dyad_entries: ${#dyad_entries[@]}"

	found=0
	must_look=0
	for entry in "${dyad_entries[@]}"; do
		x=(${entry//:/ })
		vuln=${x[0]}
		vuln_git=${x[1]}
		fix=${x[2]}
		fix_git=${x[3]}
		dbg "		dyad:	git_id=${git_id}	vuln_git=${vuln_git}	fix_git=${fix_git}"

		if [[ "${vuln_git}" == "0" ]]; then
			vuln_git="1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"
		fi
		is_in_vuln=$(cd "${KERNEL_TREE}" && git merge-base --is-ancestor ${vuln_git} ${git_id})
		if [[ $? -eq 0 ]]; then
			# This id is a root of our id, so let's dig further!
			must_look=1

			# first, if this is NOT fixed, then of course this is vulnerable
			if [[ "${fix_git}" == "0" ]]; then
				# not fixed, let's just move on
				continue
			fi

			# the "vulnerable id is a root of our id, see if it's been fixed!"
			is_in_vuln=$(cd "${KERNEL_TREE}" && git merge-base --is-ancestor ${fix_git} ${git_id})
			if [[ $? -eq 0 ]]; then
				# our id has this fixed!
				found=1
			fi
		fi
	done
	dbg "	must_look=${must_look} found=${found}"
	if [[ "${must_look}" == "1" ]]; then
		if [[ "${found}" == "0" ]]; then
			echo "${txtgrn}${git_id}${txtrst} is vulnerable to ${txtred}${cve}${txtrst}"
		fi
	fi

}

search_year()
{
	local git_id=$1
	local year=$2
	local threads=$(nproc)

	# get a count of ids for this year
	count=$(ls cve/published/${year}/*.sha1 | wc -l)

	dbg "Searching ${txtcyn}${count}${txtrst} CVE ids for ${txtgrn}${year}${txtrst} with ${txtcyn}${threads}${txtrst} processes..."
	for id in cve/published/${year}/*.sha1 ; do
		while :
		do
			if [[ $(jobs -p | wc -l) -lt ${threads} ]]; then
				dbg "git_id=${git_id} id=${id}"
				check_id "${git_id}" "${id}" &
				break
			else
				sleep 1
			fi
		done
	done
	wait
}

fixed_version()
{
	local fixed_version=$1
	local out
	local id
	local year
	local commit

	cd "cve/published/"
	out=$(git grep -i -l "fixed in ${fixed_version}" | cut -f 2 -d '/' | cut -f 1 -d '.')
	if [[ "${out}" != "" ]]; then
		while IFS= read -r id; do
			year=$(echo "${id}" | cut -f 2 -d '-')
			commit=$(cat ${year}/${id}.sha1)
			echo "${id} is fixed in ${1} with commit ${commit}"
		done <<< "${out}"
	else
		echo "${1} does not have any CVE ids assigned yet."
	fi
}


#############################
#############################
# "main" logic starts here
#############################
#############################

# Verify that some basic environment variables are set up
KERNEL_TREE=${CVEKERNELTREE}

if [[ ! -d "${KERNEL_TREE}" ]] ; then
	echo "${txtred}ERROR:${txtrst}"
	echo "	${txtblu}CVEKERNELTREE${txtrst} needs setting to the stable repo directory"
	echo -e "\nEither manually export them or add them to your .bashrc/.zshrc et al."
	echo -e "\nSee HOWTO in the root of this repo"
	exit 1
fi

# Parse the command line
short_opts="hv"
long_opts="help,verbose,fixed:"

FIXED_VERSION=""
TMP=$(getopt -o "${short_opts}" --long "${long_opts}" --name="${SCRIPT}" -- "$@")
eval set -- "${TMP}"
while :; do
	dbg "arg=${1}"
	case "${1}" in
		-h | --help	) help;;
		--fixed		) FIXED_VERSION="${2}";	shift 2 ;;
		-v | --verbose	) DEBUG=1;		shift ;;
		-- )		  shift; break ;;
	esac
done

# Rest of the command line argument is the git sha we are looking at
GIT_SHA=$1

if [[ "${GIT_SHA}" == "" && "${FIXED_VERSION}" == "" ]]; then
	help
	exit 1
fi

# Now we can test for unset variables, before we would have failed if someone
# forgot the git sha on the command line.
set -o nounset

cd "${DIR}"/../ || exit 1

if [[ "${FIXED_VERSION}" != "" ]]; then
	fixed_version "${FIXED_VERSION}"
	exit 0
fi

dbg "git id to look up = ${GIT_SHA}"

for y in cve/published/* ; do
	year=$(echo "${y}" | cut -f 3 -d '/')
	search_year ${GIT_SHA} ${year}
done
#search_year "${GIT_SHA}" 2020

exit 0
