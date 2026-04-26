#!/usr/bin/env bash
# build_all.sh — Phase E: compute -> notebooks -> report
set -euo pipefail
cd "$(dirname "$0")/../.."

# 1. Pre-flight power analysis (mandatory before any test).
uv run python analysis/scripts/power_analysis_pre.py

# 2. Canonical compute (analyst-owned).
for rq in rq1 rq2 rq3; do
  uv run python "analysis/scripts/${rq}_compute.py"
done
uv run python analysis/scripts/robustness.py

# 3. Post-hoc power against fitted SEs.
uv run python analysis/scripts/power_analysis_post.py

# 4. Display layer (reporter-owned).
bash analysis/scripts/render_notebooks.sh

# 5. Build REPORT.md.
uv run python analysis/scripts/build_report.py

echo "OK — Phase E complete as of $(date -u +%FT%TZ)"
echo "  Tables:    analysis/tables/"
echo "  Figures:   analysis/figures/"
echo "  Notebooks: analysis/notebooks/*.ipynb"
echo "  Report:    analysis/REPORT.md"
