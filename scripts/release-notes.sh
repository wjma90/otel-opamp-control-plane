#!/usr/bin/env bash

set -euo pipefail

version=${1:?usage: release-notes.sh VERSION [CHANGELOG]}
changelog=${2:-CHANGELOG.md}

awk -v version="$version" '
  BEGIN {
    marker = "## [" version "]"
  }
  index($0, marker) == 1 {
    found = 1
    next
  }
  found && /^## \[/ {
    exit
  }
  found {
    print
    if ($0 !~ /^[[:space:]]*$/) {
      content = 1
    }
  }
  END {
    if (!found || !content) {
      exit 2
    }
  }
' "$changelog"
