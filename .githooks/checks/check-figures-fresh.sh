#!/usr/bin/env bash
# Warn (do not block) if any analysis/figures/*.png is older than the
# *_main.csv it was rendered alongside.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

stale=0
for fig in analysis/figures/*.png; do
  [ -f "$fig" ] || continue
  basename=$(basename "$fig" .png)
  # Match figure name prefix to a likely *_main.csv (e.g. rq1_*.png ↔ rq1_main.csv).
  prefix="${basename%%_*}"
  csv="analysis/tables/${prefix}_main.csv"
  [ -f "$csv" ] || continue
  if [ "$csv" -nt "$fig" ]; then
    echo "ADVISORY: $fig older than $csv (figure may be stale)" >&2
    stale=1
  fi
done
[ "$stale" -eq 0 ] && exit 0 || exit 0  # always exit 0 — advisory only
