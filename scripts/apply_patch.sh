#!/usr/bin/env bash
# Apply a unified diff generated from MASTERPLAN directly onto the repo.
# Example: ./scripts/apply_patch.sh masterplan.patch
set -euo pipefail
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <diff-file>" >&2
  exit 1
fi
patch -p1 --backup --suffix=.orig < "$1"
