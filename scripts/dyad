#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2024-2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
#
# dyad - create a listing of "pairs" of vulnerable:fixed kernels based on a
#	 specific git SHA that purports to fix an issue.  Used in combination
#	 with 'bippy' to create CVE entries for the Linux kernel.  Is VERY
#	 specific to how the Linux kernel has its stable branches and how it
#	 labels things.
#
# Usage:
#	dyad [options] GIT_SHA
#	For full options, see the help text below.
#
# Requires:
#  A kernel git tree with the SHA to be used in it
#  id_found_in - tool to find what kernel a specific SHA is in

# set to 1 to get some debugging logging messages (or use -v/--verbose option)
DEBUG=0

# Initialize our color variables if we are a normal terminal
if [[ -t 1 ]]; then
	txtred=$(tput setaf 1)	# Red
	txtgrn=$(tput setaf 2)	# Green
	txtblu=$(tput setaf 4)	# Blue
	txtcyn=$(tput setaf 6)	# Cyan
	txtrst=$(tput sgr0)	# Text reset
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
SCRIPT_VERSION=$(cd "${DIR}" && git ls-tree --abbrev=12 HEAD | grep -w "${SCRIPT}" | awk '{print $3}')

# Initialize some global variable arrays
fixed_set=()
vulnerable_set=()
fixed_pairs=()


#############################
#############################
# Functions for us to use, main flow starts below
#############################
#############################

#############################
# help()
#	Print out help options and exit
#############################
help()
{
	echo "Usage: $0 [OPTIONS] GIT_SHA"
	echo "Create a list of pairs of VULNERABLE:FIXED kernel versions and git ids based on a specific git sha value."
	echo ""
	echo "Arguments:"
	echo " --vulnerable=GIT_SHA		The kernel git sha1 that this issue became vulnerable at (optional)"
	echo " -h, --help			This information"
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

#############################
# get_kernel_version_type()
#   Determine the type of a kernel version (mainline, rc, queue, or stable)
# arguments:
#   "kernel version"
# returns:
#   Prints one of: "mainline", "rc", "queue", or "stable"
#############################
get_kernel_version_type() {
	local VERSION=$1

	# First check if it's a queue version since that's a simple string match
	if [[ "${VERSION}" =~ .*"queue" ]]; then
		echo "queue"
		return
	fi

	# Parse version number into components
	# shellcheck disable=SC2206
	local VERSION_PARTS=(${VERSION//./ })
	local MAJOR=${VERSION_PARTS[0]}

	# Check for -rc versions
	if [[ "${VERSION}" =~ .*"rc" ]]; then
		echo "rc"
		return
	fi

	# 2.6.X is just one more level "deep"
	if [[ "${MAJOR}" == "2" ]]; then
		if [[ "${#VERSION_PARTS[@]}" == "3" ]]; then
			echo "mainline"
			return
		fi
	fi

	# If version only has X.Y format (no .Z), it's mainline
	if [[ "${#VERSION_PARTS[@]}" == "2" ]]; then
		echo "mainline"
		return
	fi

	# Otherwise it's a stable release
	echo "stable"
}

#############################
# kernel_version_is_mainline()
#   Check if a kernel version is mainline
#   Note: Both pure mainline and rc versions are considered mainline
#
# Arguments:
#   $1: Kernel version string to check
#
# Returns:
#   1 if version is mainline or rc, 0 otherwise
#
# Example:
#   kernel_version_is_mainline "6.7"	  # Returns: 1
#   kernel_version_is_mainline "6.7-rc1"  # Returns: 1
#   kernel_version_is_mainline "6.7.1"	# Returns: 0
#############################
kernel_version_is_mainline() {
	local TYPE
	TYPE=$(get_kernel_version_type "$1")
	[[ "${TYPE}" == "mainline" || "${TYPE}" == "rc" ]] && return 1 || return 0
}

#############################
# kernel_version_match()
#   Compare two kernel version strings to see if they share the same major.minor
#   version numbers (X.Y), ignoring any patch version (Z). For example,
#   "4.9.1" and "4.9.2" match, while "4.9.1" and "4.10.1" don't.
#
# Arguments:
#   $1: First kernel version string (format: X.Y or X.Y.Z)
#   $2: Second kernel version string (format: X.Y or X.Y.Z)
#
# Returns:
#   1 if major.minor versions match
#   0 if they don't match
#
# Example:
#   kernel_version_match "4.9.1" "4.9.2"   # returns 1 (match)
#   kernel_version_match "4.9" "4.9.1"     # returns 1 (match)
#   kernel_version_match "4.9.1" "4.10.1"  # returns 0 (no match)
#############################
kernel_version_match()
{
    local v1=(${1//./ })
    local v2=(${2//./ })
    [[ "${v1[0]}" == "${v2[0]}" && "${v1[1]}" == "${v2[1]}" ]] && return 1 || return 0
}

#############################
# create_fix_set()
#	Adds a new "fixed set" of kernel_version:git_id that fixes the problem
#	we are tracking to the global list of fixed sets
# arguments:
#	"kernel version"
#	"git id"
#############################
create_fix_set()
{
	local f=$1
	local f_git=$2
	fixed_set+=("${f}:${f_git}")

	#dbg "fixed pair='${f}:${f_git}'"
}

#############################
# create_vulnerable_set()
#	Adds a new "vulnerable set" of kernel_version:git_id to the global list of
#	vulnerable sets we want to track
# arguments:
#	"kernel version"
#	"git id"
#############################
create_vulnerable_set()
{
	local v=$1
	local v_git=$2
	vulnerable_set+=("${v}:${v_git}")

	#dbg "vulnerable pair='${v}:${v_git}'"
}

#############################
# create_fixed_set()
#	Adds a new "fixed pair" of vulnerable:fixed kernel information to the
#	global list of fixes that we want to output.
# arguments:
#	"vulnerable_kernel:vulnerable_git"
#	"fixed_kernel:fixed_git"
#############################
create_fixed_pair()
{
	local v=$1
	local f=$2
	fixed_pairs+=("${v}:${f}")
	#dbg "v='${v}'	f='${f}'"
	#dbg "fixed pair = ${v}:${f}"
}

#############################
# git_full_id()
#	returns the "FULL" sha1 of the short git id passed in
# arguments
#	git-id ("subject")
# returns
#	"full git id" if found, "" if not found
# assumes:
#	KERNEL_TREE points to a valid Linux stable git tree
#############################
git_full_id()
{
	local arg="$@"
	local short_id=${arg%% *}
	local subject=${arg#* }
	local long_id
	local id=""

	long_id=($($git_cmd rev-parse --disambiguate="${short_id}" 2> /dev/null))
	if [ ${#long_id[@]} -eq 1 ]; then
		echo "${long_id[0]}"
		return
	fi
	if [ ${#long_id[@]} -eq 0 ]; then
		echo ""
		return
	fi

	# Otherwise, disambiguate the short id.

	# Strip the ("...") around the Subject.
	subject=$(echo "${subject}" | sed -e 's/("\(.*\)")[ \t]*$/\1/')
	for id in "${long_id[@]}"; do
		local id_subject=$($git_cmd log -1 --format="%s" "${id}")
		if [ "${id_subject}" == "${subject}" ]; then
			# Found the matching subject; stop here.
			echo "${id}"
			return
		fi
	done
}

#############################
# git_short_id()
#	returns the "SHORT" sha1 of the short git id passed in
# arguments
#	"git id"
# returns
#	"short git id" if found, "" if not found
# assumes:
#	KERNEL_TREE points to a valid Linux stable git tree
#############################
git_short_id()
{
	local id=${1}
	local short_id
	short_id=$($git_cmd log -1 --abbrev=12 --format="%h" "${id}" 2> /dev/null)
	echo "${short_id}"
}

#############################
# kernel_greater_than()
#	if kernel 1 is greater than kernel 2, then 1 is returned, otherwise 0
# arguments
#	"kernel 1"
#	"kernel 2"
#############################
kernel_greater_than()
{
	local k1=$1
	local k2=$2
	local temp
	local small

	temp=$(echo -e "${k1} \n")
	temp+=$(echo -e "${k2} \n")

	# ${temp} is not escaped on purpose, otherwise we end up with a
	# trailing space
	# shellcheck disable=SC2086
	small=$(printf "%s\n" ${temp} | sort -V | head -n 1)
	if [[ "${small}" == "${k1}" ]]; then
		return 0
	else
		return 1
	fi
}

#############################
#############################
# "main" logic starts here
#############################
#############################

# Verify that some basic environment variables are set up
KERNEL_TREE=${CVEKERNELTREE}
COMMIT_TREE=${CVECOMMITTREE}

# Try to find the most useful version of FOUND_IN:
# If we have one in our tools/ directory, then use that, otherwise fall back to
# the "old" version in the stand-alone repo.
if [[ -x "${DIR}/../tools/verhaal/id_find_active" ]]; then
	FOUND_IN="${DIR}/../tools/verhaal/id_find_active"
elif [[ -x "${DIR}/tools/verhaal/id_find_active" ]]; then
	FOUND_IN="${DIR}/tools/verhaal/id_find_active"
else
	echo "${txtred}ERROR: no version of ${txtcyn}id_find_active${txtrst} found"
	echo "	Usually this is in the verhaal directory, please be sure you have it somewhere for us to use"
	exit 1
fi

# Find our verhaal database
if [[ -f "${DIR}/../tools/verhaal/verhaal.db" ]]; then
	DB="${DIR}/../tools/verhaal/verhaal.db"
elif [[ -f "${DIR}/tools/verhaal/verhaal.db" ]]; then
	DB="${DIR}/tools/verhaal/verhaal.db"
else
	echo "${txtred}ERROR: no verhaal database file called ${txtcyn}id_is_revert${txtrst} found"
	echo "	Usually this is in the verhaal directory, please be sure you have it somewhere for us to use"
	exit 1
fi
SQL="sqlite3 ${DB}"

git_cmd="git --git-dir=${KERNEL_TREE}/.git"

if [[ ! -d "${KERNEL_TREE}" ]] || [[ ! -d "${COMMIT_TREE}" ]]; then
	echo "${txtred}ERROR:${txtrst}"
	echo "	${txtblu}CVEKERNELTREE${txtrst} needs setting to the stable repo directory"
	echo "	${txtblu}CVECOMMITTREE${txtrst} needs setting to the Stable commit tree"
	echo -e "\nEither manually export them or add them to your .bashrc/.zshrc et al."
	echo -e "\nSee HOWTO in the root of this repo"
	exit 1
fi

# Parse the command line
short_opts="hv"
long_opts="vulnerable:,help,verbose"
GIT_SHA=""
GIT_VULNERABLE=""

TMP=$(getopt -o "${short_opts}" --long "${long_opts}" --name="${SCRIPT}" -- "$@")
eval set -- "${TMP}"
while :; do
	dbg "arg=${1}"
	case "${1}" in
		-h | --help	) help;;
		-v | --verbose	) DEBUG=1;			shift ;;
		--vulnerable	) GIT_VULNERABLE="${2}";	shift 2 ;;
		-- )		  shift; break ;;
	esac
done

# Rest of the command line argument is the git sha we are looking at
GIT_SHA=$1

# Now we can test for unset variables, before we would have failed if someone
# forgot the git sha on the command line.
set -o nounset

# Verify we have a git sha on the command line
if [[ "${GIT_SHA}" == "" ]]; then
	help
fi

# Header boiler plate info to show what is happening
info "${SCRIPT} version: ${SCRIPT_VERSION}"

#
# See if the SHA given to us is a valid SHA in the git repo.
# This tests if we have a valid kernel tree, AND we need a full/long SHA1 for
# many of the searches we do later on.  If we stuck with a short one, some of
# the searches would give us false-positives as people use short shas in commit
# messages.
GIT_SHA_FULL=$(git_full_id "${GIT_SHA}")
if [[ "${GIT_SHA_FULL}" == "" ]] ; then
	echo "${txtred}ERROR:${txtrst} git id ${txtcyn}${GIT_SHA}${txtrst} is not found!"
	exit 1
fi

info "	getting vulnerable:fixed pairs for git id ${txtcyn}${GIT_SHA_FULL}${txtrst}"

# Grab a "real" 12 character short sha to use as well, we "know" this will not
# fail as the original id was valid.
GIT_SHA_SHORT=$(git_short_id "${GIT_SHA_FULL}")
dbg "GIT_SHA=${GIT_SHA}	GIT_SHA_FULL=${GIT_SHA_FULL}	GIT_SHA_SHORT=${GIT_SHA_SHORT}"

#
# Find all of the places (git id and release number) where this commit has been
# applied to.
#
# To do so we call ${FOUND_IN} to get the versions, and then we iterate over
# the branches to get the git ids.
#
# ${FOUND_IN} will give us version:commit_id pairs, so we don't have to do much afterward
fixed_kernels=$("${FOUND_IN}" "${GIT_SHA_FULL}")
dbg "fixed_kernels=${fixed_kernels}"

for kernel in ${fixed_kernels}; do
	kernel_split=(${kernel//:/ })
	kernel_split_version=${kernel_split[0]}
	kernel_split_id=${kernel_split[1]}

	# dbg "version=${kernel_split_version} id=${kernel_split_id}"
	create_fix_set "${kernel_split_version}" "${kernel_split_id}"
done

dbg "We have found ${#fixed_set[@]} sets of fixed kernels"
if [[ "${#fixed_set[@]}" == "0" ]] ; then
	echo "${txtred}ERROR:${txtrst} No vulnerable and then fixed pairs of kernels were found for commit ${txtcyn}${GIT_SHA_SHORT}${txtrst}"
	exit 1
fi
for fixed_entry in "${fixed_set[@]}"; do
	dbg "	${fixed_entry}"
done

#
# We have a set of where everything was fixed up, based on the original git id,
# so now let's try to determine where the problem first showed up (i.e. became
# vulnerable)
#
# If this is passed to us on the command line, it's easy, use that as the
# commit that will be deemed the "vulnerable" version (and might have been
# backported).
#
# Otherwise, try to dig in the changelog text and find any "Fixes:" lines and
# parse them to try to figure out where the issue first showed up at (i.e. what
# kernel version and git id caused the problem.)
#
# Kernel ids in a "Fixes:" line are almost always the the id in Linus's tree,
# so we need to dig through the stable branches to get the real git id for
# where the commit happened.  But note that sometimes they are the stable id.
# Rely on the regression tests to get this all correct.
v=()
if [[ "${GIT_VULNERABLE}" != "" ]]; then
	# We are asked to set the original vulnerable kernel to be a specific
	# one, so no need to look it up.
	full_id=$(git_full_id "${GIT_VULNERABLE}")
	if [[ "${full_id}" == "" ]]; then
		echo "${txtred}ERROR:${txtrst} Vulnerable git id ${txtcyn}${GIT_VULNERABLE}${txtrst} is not found!"
		exit 2
	fi

	kernel=$(${SQL} "SELECT release FROM commits WHERE id='${full_id}';")
	if [[ "${kernel}" == "" ]]; then
		echo "ERROR: Vulnerable git id ${txtcyn}${full_id}${txtrst} is not found in any version!"
		exit 2
	fi
	info "	Setting original vulnerable kernel to be kernel ${txtcyn}${kernel}${txtrst} and git id ${txtcyn}${full_id}${txtrst}"
	v+=("${full_id}")
else
	# rely on verhaal to have already parsed and fixed up the "Fixes:" lines for us
	vuln_lines=$(${SQL} "SELECT fixes FROM commits where id='${GIT_SHA_FULL}'")
	dbg "vuln_lines=${vuln_lines}"
	if [[ "${vuln_lines}" != "" ]] ; then
		# Break up our list of vulnerable kernels into an array, we
		# will sort them later
		for id in ${vuln_lines}; do
			full_id=$(git_full_id "${id}")
			if [[ "${full_id}" == "" ]]; then
				dbg "invalid fix entry of '${id}', skipping"
				continue
			fi
			v+=("${full_id}")
		done
	else
		# We do NOT have a fixes line, so let's try one last thing,
		# let's ask the database if this is a revert, and if so, what
		# commit it is reverting as we can imply that a revert is
		# actually "fixing" the original commit.
		#
		reverts=$(${SQL} "SELECT reverts FROM commits WHERE id='${GIT_SHA_FULL}';")
		if [[ "${reverts}" != "" ]]; then
			# Found a revert!
			dbg "sha is a revert of ${reverts}"
			v+=("${reverts}")
		fi
	fi
fi

# We now have a list of "vulnerable" kernels in v(), so walk them and create a
# bunch of matching "vulnerable : fixed" kernel pairs
dbg "	number in v: ${#v[@]}"
if [[ "${#v[@]}" == "0" ]]; then
	dbg "	nothing in v, skipping vuln lines check"
else
	# We have some vulnerable kernels, let's figure out where they are
	v_file=$(mktemp -t "${SCRIPT}".XXXX || exit 1)
	for id in "${v[@]}"; do
		dbg "		${id}"
		echo "${id}" >> "${v_file}"
	done
	# use 'tac' as it's faster than having git do --reverse for 'git rev-list'
	sort_order=$($git_cmd rev-list --topo-order $(cat "${v_file}") | grep --file "${v_file}" --max-count ${#v[@]} | tac)
	rm "${v_file}"
	# git rev-list --topo-order $(cat SET_OF_SHA1S) | grep --file SET_OF_SHA1S --max-count $(wc -l SET_OF_SHA1S)
	dbg "sort_order=${sort_order}"

	# figure out what kernels this commit fixes, (i.e. which are
	# vulnerable) and add them to a list of vulnerable sets.
	for id in ${sort_order}; do
		full_id=$(git_full_id "${id}")
		if [[ "${full_id}" == "" ]]; then
			dbg "invalid fix: ${id}"
			continue
		fi
		x=$("${FOUND_IN}" "${full_id}")
		for kernel in ${x}; do
			kernel_split=(${kernel//:/ })
			kernel_split_version=${kernel_split[0]}
			kernel_split_id=${kernel_split[1]}

			kernel_version_is_mainline "${kernel_split_version}"
			kernel_is_mainline=$?
			if [[ "${kernel_is_mainline}" == "0" ]]; then
				create_vulnerable_set "${kernel_split_version}" "${kernel_split_id}"
			else
				create_vulnerable_set "${kernel_split_version}" "${full_id}"
			fi
		done
	done
fi

dbg "Before winnowing we have found ${#vulnerable_set[@]} sets of vulnerable kernels"
for vuln_entry in "${vulnerable_set[@]}"; do
	dbg "	${vuln_entry}"
done

#
# Now that we have a list of vulnerable kernels, we need to find the "root"
# mainline version that had the oldest issue in it.  We might have many
# mainline kernels listed in here, but we only care about the "oldest" one, so
# throw away all the rest.
#
# To do this, we create 2 lists, one for mainline kernels, and one for stable
# kernels.  The stable kernel list we will keep "as is", but for the mainline
# kernel list, we will sort it and then throw away everything EXCEPT the oldest
# kernel.  After that, we will re-create the vulnerable set with the new
# information.
vulnerable_stable_set=()
vulnerable_mainline_set=()
for vuln_entry in "${vulnerable_set[@]}"; do
	# shellcheck disable=SC2206
	y=(${vuln_entry//:/ })
	vuln_version=${y[0]}
	vuln_git=${y[1]}

	kernel_version_is_mainline "${vuln_version}"
	kernel_is_mainline=$?
	if [[ "${kernel_is_mainline}" == "1" ]]; then
		vulnerable_mainline_set+=("${vuln_entry}")
	else
		vulnerable_stable_set+=("${vuln_entry}")
	fi
done

# Reset the list
vulnerable_set=()

dbg "	vuln_stable_set: ${#vulnerable_stable_set[@]}"
for vuln_entry in "${vulnerable_stable_set[@]}"; do
	dbg "		${vuln_entry}"
done
temp=""

#
# The "default" vulnerable point in mainline where this issue first showed up.
# We need this for any fix that happened in a stable branch that happened AFTER
# this point in time (i.e. fixed in 6.6.3 for an issue that showed up in 5.4).
vuln_mainline_pair=""
dbg "	vuln_mainline_set: ${#vulnerable_mainline_set[@]}"
if [[ "${#vulnerable_mainline_set[@]}" != "0" ]]; then
	for vuln_entry in "${vulnerable_mainline_set[@]}"; do
		# trailing space is important
		temp+=$(echo -e "${vuln_entry} \n")
		dbg "		${vuln_entry}"
	done
	# ${temp} is not escaped on purpose, otherwise we end up with a
	# trailing space
	# shellcheck disable=SC2086
	vuln_mainline_pair=$(printf "%s\n" ${temp} | sort -V | head -n 1)
	dbg "	vuln_mainline_pair=${vuln_mainline_pair}"
	vulnerable_set+=("${vuln_mainline_pair}")

	vm=("${vuln_mainline_pair}")
	vuln_mainline_version=${vm[0]}

	# iterate over all of the stable entries, and only add the ones that
	# are "older" than the mainline release.
	if [[ "${#vulnerable_stable_set[@]}" != "0" ]]; then
		for vuln_stable_entry in "${vulnerable_stable_set[@]}"; do
			# shellcheck disable=SC2206
			vs=(${vuln_stable_entry//:/ })
			vuln_stable_version=${vs[0]}

			kernel_greater_than "${vuln_mainline_version}" "${vuln_stable_version}"
			fixed_version_greater=$?
			if [[ "${fixed_version_greater}" == "1" ]] ; then
				vulnerable_set+=("${vuln_stable_entry}")
			fi
		done
	fi
else
	# No mainline vulnerable kernels, so just take all of the stable ones
	if [[ "${#vulnerable_stable_set[@]}" != "0" ]]; then
		for vuln_entry in "${vulnerable_stable_set[@]}"; do
			vulnerable_set+=("${vuln_entry}")
		done
	fi
fi

dbg "We have found ${#vulnerable_set[@]} sets of vulnerable kernels"
for vuln_entry in "${vulnerable_set[@]}"; do
	dbg "	${vuln_entry}"
done

#
# Now we have two lists, one where the kernel became vulnerable (could not be
# known, so we assume 0), and where it was fixed (the id originally passed to
# us and where it has been backported to.)  Take those two lists and start
# matching them up based on kernel versions in order to get a set of
# vulnerable:fixed pairs
#
# Iterate over all of the "fixed" kernel versions/ids and try to match them up
# with any vulnerable kernel entries (if any)
for fixed_entry in "${fixed_set[@]}" ; do
	create=0
	# shellcheck disable=SC2206
	x=(${fixed_entry//:/ })
	fixed_version=${x[0]}
	fixed_git=${x[1]}
	dbg "fixed_entry:	'${fixed_version}'	'${fixed_git}'"

	kernel_version_is_mainline "${fixed_version}"
	fixed_version_mainline=$?

	# See if we have ANY kernels where the vulnerability showed up.  If not, assume
	# that it "has always been there", so create our final set of vulnerable/fixed
	# pairs straight from the fixed list
	if [[ "${#vulnerable_set[@]}" == "0" ]] ; then
		create_fixed_pair "0:0" "${fixed_entry}"
		create=1
		continue
	fi

	# We have some vulnerable kernels set, so let's try to match them up
	for vuln_entry in "${vulnerable_set[@]}" ; do
		# shellcheck disable=SC2206
		y=(${vuln_entry//:/ })
		vuln_version=${y[0]}
		vuln_git=${y[1]}
		dbg "	vuln_entry:	'${vuln_version}'	'${vuln_git}'"

		# vulnerable and fixed in the same version.  Save this off as
		# it is needed for the git vulnerable information (small window
		# of where things went wrong).
		if [[ "${fixed_version}" == "${vuln_version}" ]]; then
			dbg "		${fixed_version} == ${vuln_version} save it"
			create_fixed_pair "${vuln_entry}" "${fixed_entry}"
			create=1
			break
		fi

		kernel_version_is_mainline "${vuln_version}"
		vuln_version_mainline=$?

		# If these are both mainline commits then create a matching pair
		if [[ "${vuln_version_mainline}" == "1" ]] ; then
			if [[ "${fixed_version_mainline}" == "1" ]]; then
				dbg "	${vuln_version} and ${fixed_version} are both mainline, save it"
				create_fixed_pair "${vuln_entry}" "${fixed_entry}"
				create=1
				break
			fi
		fi

		# if this is the same X.Y version, make a pair
		kernel_version_match "${vuln_version}" "${fixed_version}"
		match=$?
		if [[ "${match}" == "1" ]] ; then
			dbg "		${vuln_version} and ${fixed_version} are same major release, save it"
			create_fixed_pair "${vuln_entry}" "${fixed_entry}"
			create=1
			break
		fi
	done

	# We did not create any entry at all above, so we need to set the
	# "default" vulnerable point to the original vulnerable mainline pair
	# found way above as that's where the issue showed up (i.e before this
	# stable kernel branch was forked from mainline.)
	if [[ "${create}" == "0" ]]; then
		if [[ "${vuln_mainline_pair}" == "" ]]; then
			dbg "	no mainline pair vulnerable at this point in time (fix in the future?), so skipping ${fixed_version} for now"
		else
			dbg "	nothing found for ${fixed_version}, using default of ${vuln_mainline_pair}"
			create_fixed_pair "${vuln_mainline_pair}" "${fixed_entry}"
		fi
	fi
done

#
# Now the fun starts, which justified all of the hard work we did above.  We
# need to track the places where we are vulnerable, but NOT fixed.  So walk the
# vulnerable list, see if anything in the fixed_pair matches up, and if NOT,
# then add it to the list as an "unfixed" pair
for vuln_entry in "${vulnerable_set[@]}"; do
	found=0
	# shellcheck disable=SC2206
	y=(${vuln_entry//:/ })
	vuln_version=${y[0]}
	vuln_git=${y[1]}
	for fixed_entry in "${fixed_pairs[@]}"; do
		# shellcheck disable=SC2206
		x=(${fixed_entry//:/ })
		a=${x[0]}
		b=${x[1]}
		c=${x[2]}
		#d=${x[3]}
		# if the vulnerable version and git matches what is in the
		# list, mark this as found
		if [[ "${a}" == "${vuln_version}" ]]; then
			if [[ "${b}" == "${vuln_git}" ]]; then
				found=1
				break
			fi
		fi

		# If the fixed version matches the vuln version, mark this as
		# found
		if [[ "${c}" == "${vuln_version}" ]]; then
			found=1
			break
		fi
	done
	if [[ "${found}" == "0" ]]; then
		dbg "not found: ${vuln_entry}"
		create_fixed_pair "${vuln_entry}" "0:0"
	fi
done

#
# We are done!
# Print out the pairs we found so that bippy can do something with them.
dbg "Number of vulnerable / fixed kernel pairs: ${#fixed_pairs[@]}"
for entry in "${fixed_pairs[@]}" ; do
	echo "${txtgrn}${entry}${txtrst}"
done

exit 0
