#!/usr/bin/env bash
# render_notebooks.sh — refresh the four Jupytext-paired tutorial notebooks
# from their .py percent-format twins under analysis/notebooks/.
#
# Notebook contract:
#   - .py is the source of truth
#   - .ipynb is regenerated from .py via `jupytext --set-formats ipynb,py:percent`
#   - cells are then executed via `jupytext --execute` so the rendered
#     .ipynb has populated outputs against analysis/tables/ and
#     analysis/figures/
#
# This script must be idempotent: running it twice produces identical
# .ipynb output. All Python invocations go through `uv run`.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

NOTEBOOKS=(
  "analysis/notebooks/00_data_tour"
  "analysis/notebooks/01_rq1_adoption"
  "analysis/notebooks/02_rq2_ai_vs_control"
  "analysis/notebooks/03_rq3_interventions"
)

for nb in "${NOTEBOOKS[@]}"; do
  py="${nb}.py"
  ipynb="${nb}.ipynb"
  if [ ! -f "$py" ]; then
    echo "MISSING: $py — reporter must author the .py first" >&2
    exit 1
  fi
  echo ">>> pairing  $py"
  uv run jupytext --quiet --set-formats ipynb,py:percent "$py"
  echo ">>> sync     $py"
  uv run jupytext --quiet --sync "$py"
  echo ">>> execute  $ipynb"
  uv run jupytext --quiet --execute "$ipynb"
done

echo ""
echo "rendered notebooks:"
for nb in "${NOTEBOOKS[@]}"; do
  ipynb="${nb}.ipynb"
  if [ -f "$ipynb" ]; then
    cells=$(uv run python -c "import json,sys; print(len(json.load(open('$ipynb'))['cells']))")
    echo "  $ipynb  ($cells cells)"
  else
    echo "  $ipynb  (NOT GENERATED)"
  fi
done
