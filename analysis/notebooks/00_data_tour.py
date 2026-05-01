# ---
# jupyter:
#   jupytext:
#     formats: ipynb,py:percent
#     text_representation:
#       extension: .py
#       format_name: percent
#       format_version: '1.3'
#       jupytext_version: 1.19.1
#   kernelspec:
#     display_name: aidev-security-study
#     language: python
#     name: python3
# ---

# %% [markdown]
# # 00 — Data tour
#
# Tutorial notebook walking through the cohort sizes, configs versions,
# rule-set hashes, and dataset window for `data_derived/latest/`. This is
# the first thing a reader should look at — it answers "what data am I
# actually looking at?"
#
# **This notebook does no analysis.** It only loads canonical CSVs/JSONs
# produced by the analyst. If a number isn't here, it lives in
# `analysis/tables/`.

# %% [markdown]
# ## Provenance
#
# The cell below shows the `run_id`, AIDev dataset SHA, and the four
# config hashes pinned by this study. Verify these match what you expect
# before reading on.

# %%
from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = (
    Path(__file__).resolve().parents[2]
    if "__file__" in globals()
    else Path.cwd().parents[1]
)
TABLES = REPO_ROOT / "analysis" / "tables"
FIGURES = REPO_ROOT / "analysis" / "figures"
MANIFEST_PATH = REPO_ROOT / "data_derived" / "latest" / "run_manifest.json"


class MissingArtifact(FileNotFoundError):
    """Raised when a canonical artifact the analyst should have produced is missing."""


def load_json(path: Path) -> dict:
    if not path.exists():
        raise MissingArtifact(f"missing canonical JSON: {path}")
    return json.loads(path.read_text())


manifest = load_json(MANIFEST_PATH)
rq1_prov = load_json(TABLES / "rq1_provenance.json")

print(f"run_id               : {manifest['run_id']}")
print(f"aidev_dataset_sha    : {rq1_prov['aidev_dataset_sha']}")
print(f"seed                 : {manifest['seed']}")
print(
    f"window               : {manifest['window']['start']} -> {manifest['window']['end']}"
)
print()
print("configs:")
for name, info in manifest["configs"].items():
    print(f"  {name:32s}  sha256={info['sha256'][:16]}…  {info['version_header']}")

# %% [markdown]
# ## Cohort sizes (Phases A–D)
#
# These come directly from `run_manifest.json`. Phase B was resumed after
# a GitHub rate-limit hit, so the matched-control cohort grew from the
# pre-resume 693 pairs to the final 1,744 pairs.

# %%
import pandas as pd

cohort_rows = [
    (
        "Phase A: AI repos (curated AIDev, in-window)",
        manifest["outputs"]["ai_repos.csv"]["rows"],
    ),
    (
        "Phase A: agentic PRs (curated, in-window)",
        manifest["outputs"]["agentic_prs.parquet"]["rows"],
    ),
    (
        "Phase B: matched control repos",
        manifest["outputs"]["control_repos.csv"]["rows"],
    ),
    (
        "Phase B: 1:1 matched pairs",
        manifest["outputs"]["repo_matching_pairs.csv"]["rows"],
    ),
    ("Phase C: repos with adoption rows (long)", manifest["phase_c"]["long_form_rows"]),
    ("Phase C: repos × tools wide-form rows", manifest["phase_c"]["wide_form_rows"]),
    (
        "Phase D: human PR sample (rows)",
        manifest["outputs"]["human_pr_sample.parquet"]["rows"],
    ),
    (
        "Phase D: PR-level intervention rows",
        manifest["outputs"]["pr_interventions.parquet"]["rows"],
    ),
    ("Phase D: agentic PRs in scope", manifest["phase_d"]["n_agentic_prs_in_scope"]),
    (
        "Phase D: repos with agentic PRs",
        manifest["phase_d"]["n_repos_with_agentic_prs"],
    ),
    (
        "Phase D: repos with both PR types (FE pool)",
        manifest["phase_d"]["n_repos_with_both_pr_types"],
    ),
    (
        "Phase D: singleton-repos dropped pre-FE",
        manifest["phase_d"]["singleton_repos_post_filter"],
    ),
]
cohort_df = pd.DataFrame(cohort_rows, columns=["stage", "n"])
cohort_df

# %% [markdown]
# ### Try changing X
#
# `MANIFEST_PATH` points at `data_derived/latest/run_manifest.json`. If
# you have an older dated directory you want to inspect, set
# `MANIFEST_PATH = REPO_ROOT / "data_derived" / "<YYYY-MM-DD>" /
# "run_manifest.json"` and re-run. The notebook is otherwise pure-CSV.

# %% [markdown]
# ## Versioned rule-sets
#
# Four configs drive every detection in the study. The
# `security_bots.txt` and `security_patterns.yaml` files were revised
# **after** the first Phase D run (2026-04-26 audit) — see §9 of
# REPORT.md and the `phase_d.prior_run` block in `run_manifest.json`.

# %%
configs_df = pd.DataFrame(
    [
        {"config": name, "version": info["version_header"], "sha256": info["sha256"]}
        for name, info in manifest["configs"].items()
    ]
)
configs_df

# %% [markdown]
# ## Phase B match quality
#
# After 1:1 matching with replacement disabled and a 0.25-σ caliper, the
# worst absolute SMD on a core covariate is well under the 0.1 threshold.

# %%
match_stats = manifest["phase_b"]["match_stats"]
pd.Series(
    {
        "n_pairs": match_stats["n_pairs"],
        "n_unique_controls": match_stats["n_unique_controls"],
        "n_unmatched_ai_repos": match_stats["n_unmatched_ai"],
        "worst_post_match_abs_smd": round(match_stats["worst_post_match_abs_smd"], 4),
        "worst_post_match_covariate": match_stats["worst_post_match_covariate"],
    }
)

# %% [markdown]
# ## What's next
#
# - `01_rq1_adoption.ipynb` — adoption rates of each tool/category
#   inside the AI cohort.
# - `02_rq2_ai_vs_control.ipynb` — AI-vs-Control configured-rate
#   comparison with Fisher + adjusted GLM.
# - `03_rq3_interventions.ipynb` — within-repo agentic-vs-human PR
#   comparison with repo fixed effects.
