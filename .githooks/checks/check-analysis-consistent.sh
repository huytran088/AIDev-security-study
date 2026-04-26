#!/usr/bin/env bash
# Verify that analysis/REPORT.md and analysis/tables/*_main.csv reference
# the current data_derived/latest/run_manifest.json.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

LATEST="data_derived/latest"
[ -L "$LATEST" ] || { echo "FAIL: $LATEST symlink missing" >&2; exit 1; }

CURRENT_RUN=$(basename "$(readlink "$LATEST")")
MANIFEST="$LATEST/run_manifest.json"
[ -f "$MANIFEST" ] || { echo "FAIL: $MANIFEST missing" >&2; exit 1; }

CURRENT_DATASET_SHA=$(jq -r '.aidev_dataset.version_commit // .aidev_dataset_sha // empty' "$MANIFEST")
[ -n "$CURRENT_DATASET_SHA" ] || { echo "FAIL: cannot read dataset SHA from manifest" >&2; exit 1; }

# Each *_main.csv must record the run_id it was generated against, in a
# leading comment row or in a sibling _provenance.json. We use the latter
# convention (rq{1,2,3}_compute.py writes it) — see SETUP.md §12.
fail=0
for csv in analysis/tables/*_main.csv; do
  [ -f "$csv" ] || continue
  prov="${csv%_main.csv}_provenance.json"
  if [ ! -f "$prov" ]; then
    echo "FAIL: $csv has no sibling _provenance.json" >&2
    fail=1; continue
  fi
  recorded_run=$(jq -r '.run_id // empty' "$prov")
  recorded_sha=$(jq -r '.aidev_dataset_sha // empty' "$prov")
  if [ "$recorded_run" != "$CURRENT_RUN" ] || [ "$recorded_sha" != "$CURRENT_DATASET_SHA" ]; then
    echo "FAIL: $csv was generated against run=$recorded_run / sha=${recorded_sha:0:12}; current=$CURRENT_RUN / ${CURRENT_DATASET_SHA:0:12}" >&2
    fail=1
  fi
done

# REPORT.md carries the same provenance in a YAML-frontmatter-like block
# that build_report.py emits at the very top.
REPORT="analysis/REPORT.md"
if [ -f "$REPORT" ]; then
  report_run=$(awk '/^_run_id:/ { print $2; exit }' "$REPORT")
  if [ "$report_run" != "$CURRENT_RUN" ]; then
    echo "FAIL: $REPORT generated against run=$report_run; current=$CURRENT_RUN" >&2
    fail=1
  fi
fi

[ "$fail" -eq 0 ] && exit 0 || exit 1
