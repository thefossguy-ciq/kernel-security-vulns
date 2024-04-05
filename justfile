#!/usr/bin/env -S just --justfile

# show the list of options
_help:
	@just --list

# Search for a specific git id in the list of published CVE ids
@cve_search GIT_ID:
	-scripts/cve_search {{GIT_ID}}


# Create a CVE for a specific Linux kernel git commit id
@cve_create GIT_ID *CVE_ID:
	-scripts/cve_create {{GIT_ID}} {{CVE_ID}}

# Create a bunch of CVEs that are contained, one per line, in FILENAME
@cve_create_batch FILENAME:
	-scripts/cve_create_batch {{FILENAME}}

# Update all, or just one, CVE entries with the latest version information
@cve_update *GIT_ID:
	scripts/cve_update {{GIT_ID}}


# Publish all modified .json files with the CVE server
@cve_publish_json:
	scripts/cve_publish_json


# Publish all modified .mbox messages with git-send-email
@cve_publish_mbox:
	scripts/cve_publish_mbox

# Reject a published/reserved CVE
@cve_reject CVE_ID:
	scripts/cve_reject {{CVE_ID}}

# Query the CVE server for the list of all ids assigned to us
@list_ids:
	cve -o Linux list


# List a summary of the ids at this point in time
summary:
	scripts/summary
