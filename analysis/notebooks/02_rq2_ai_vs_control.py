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
#     display_name: Python 3 (ipykernel)
#     language: python
#     name: python3
# ---

# %% [markdown]
# # 02 — RQ2: AI vs matched-control adoption rates
#
# RQ2 compares the **AI cohort** (n=2,803) against a **1:1 matched
# control cohort** (n=1,744) on whether each repo has each
# tool/category configured at the cutoff date.
#
# Per family (5 categories, 4 retained tools after sparse-band
# exclusion), the analyst computed:
#
# - Fisher exact OR with Haldane–Anscombe 0.5 continuity for empty
#   cells, plus 95% CI from log-OR ± 1.96·SE.
# - Adjusted GLM (Binomial logit) controlling for `log_stars`,
#   `language`, `repo_age`, `activity`, `owner_type`, with cluster-
#   robust HC1 SE on `owner` (3,750 clusters).
# - BH FDR correction within each family (categories: m=5; tools: m=4
#   after dropping 15 sparse-band tools).
#
# All numbers below come from `analysis/tables/rq2_*.csv` and
# `rq2_headline.json`.

# %% [markdown]
# ## Provenance

# %%
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

REPO_ROOT = (
    Path(__file__).resolve().parents[2]
    if "__file__" in globals()
    else Path.cwd().parents[1]
)
TABLES = REPO_ROOT / "analysis" / "tables"
FIGURES = REPO_ROOT / "analysis" / "figures"


class MissingArtifact(FileNotFoundError):
    pass


def load_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise MissingArtifact(f"missing canonical CSV: {path}")
    return pd.read_csv(path)


def load_json(path: Path) -> dict:
    if not path.exists():
        raise MissingArtifact(f"missing canonical JSON: {path}")
    return json.loads(path.read_text())


prov = load_json(TABLES / "rq2_provenance.json")
print(f"run_id            : {prov['run_id']}")
print(f"aidev_dataset_sha : {prov['aidev_dataset_sha']}")
print(f"compute_script    : {prov['compute_script']}")
print(f"generated_at_utc  : {prov['generated_at_utc']}")
print()
print("BH family definition:")
print(
    f"  alpha                                  : {prov['bh_family_definition']['alpha']}"
)
print(
    f"  bh_method                              : {prov['bh_family_definition']['bh_method']}"
)
print(
    f"  bh_family_size_categories              : {prov['bh_family_definition']['bh_family_size_categories']}"
)
print(
    f"  bh_family_size_tools_after_exclusion   : {prov['bh_family_definition']['bh_family_size_tools_after_exclusion']}"
)
print(
    f"  sparse_band_threshold                  : {prov['bh_family_definition']['sparse_band_threshold']}"
)
print(
    f"  sparse_band_threshold_basis            : {prov['bh_family_definition']['sparse_band_threshold_basis']}"
)
print()
print("configs hashes:")
for name, info in prov["configs_hashes"].items():
    print(f"  {name:32s}  {info['version_header']}  sha256={info['sha256'][:16]}…")

# %% [markdown]
# ## Sparse-band exclusion (read this before the forest plot)
#
# 15 tools have a control-arm adoption rate < 1%, so the BH family
# would be dominated by Haldane-shifted CIs that span orders of
# magnitude. The analyst excludes these from the BH family and reports
# them descriptively only. They appear in the per-tool table below
# **without** an adjusted p_value.
#
# Two RQ2 categories — `secrets` and `fuzzing` — are pre-declared
# underpowered (achieved power 0.36 and 0.20 respectively at OR=1.8 / 2.0
# vs the locked α=0.05; see `power_analysis.csv`). They appear in the
# headline table but their negative findings should be read as
# **not-informative**, not as evidence of "no effect".

# %%
headline = load_json(TABLES / "rq2_headline.json")
print(f"sparse-band excluded tools (n={headline['n_sparse_band_tools_excluded']}):")
for t in headline["sparse_band_excluded"]:
    print(f"  - {t}")
print()
print(
    f"underpowered families (pre-declared): n = {headline['n_underpowered_families']} (secrets, fuzzing)"
)

# %% [markdown]
# ## Headline: BH-significant categories and tools (AI > control)

# %%
print("BH-significant categories where AI > control:")
pd.DataFrame(headline["bh_sig_categories"])

# %%
print("BH-significant tools where AI > control (after sparse-band exclusion):")
pd.DataFrame(headline["bh_sig_tools"])

# %% [markdown]
# ## RQ2 main table
#
# `OR` is Fisher exact (or Haldane-shifted in empty cells; tools where
# Fisher could not be computed have a blank `OR_fisher`). `adj_OR` is
# the cluster-robust adjusted logit OR; `p_adj` is BH-corrected
# **within family** (categories or tools). Rows in the sparse-band have
# `bh_family_member=False` and are reported descriptively only.

# %%
rq2 = load_csv(TABLES / "rq2_main.csv")
rq2

# %% [markdown]
# ![RQ2 forest plot, BH family members](../figures/rq2_tool_forest.png)

# %% [markdown]
# ![RQ2 category configured rates](../figures/rq2_category_rates.png)

# %% [markdown]
# ## RQ2 robustness battery
#
# 30 robustness rows across pre-declared variants (per README §8):
#
# - `v1_strict_relaxed_fingerprints` — deferred, requires Phase B rerun
#   (would mutate the control cohort).
# - `v4_lang_strat` — re-run RQ2 within each top-7 language stratum.
# - other variants per the analyst's robustness.py.

# %%
robust = load_csv(TABLES / "rq2_robustness.csv")
print(f"total RQ2 robustness rows: {len(robust)}")
robust["variant"].value_counts()

# %% [markdown]
# ### Try changing X
#
# Filter `robust` to one variant at a time, e.g.
# `robust.query("variant == 'v4_lang_strat' and outcome == 'sast'")`,
# to inspect the per-language SAST robustness.

# %%
robust.query("variant == 'v4_lang_strat' and outcome == 'sast'")[
    [
        "stratum",
        "n_AI",
        "n_ctrl",
        "ai_rate",
        "ctrl_rate",
        "or_or_irr",
        "ci95_lo",
        "ci95_hi",
        "p_raw",
    ]
]
