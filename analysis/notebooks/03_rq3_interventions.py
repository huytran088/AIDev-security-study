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
# # 03 — RQ3: Within-repo agentic vs human PR comparison
#
# RQ3 asks, **inside repos that produced both PR types**, whether
# agentic PRs trigger more security-tool interventions and whether they
# get rejected more often. The analyst fits repo fixed-effects models
# on three primary outcomes:
#
# 1. `any_security_intervention` — logit FE
# 2. `security_intervention_count` — Poisson with cluster-robust SE
#    (NB fallback per README §7; `fit_regularized()` raised, so the
#    analyst fell back to quasi-Poisson)
# 3. `rejected` — logit FE, with `any_security_intervention` as a
#    covariate
#
# A fourth pre-declared outcome,
# `any_changes_requested_by_security_tool`, is **excluded by operator
# decision** because the human-arm baseline is structurally near-zero
# (0.024%) — see `rq3_provenance.json`.
#
# All numbers below come from `analysis/tables/rq3_*.csv` and
# `rq3_headline.json`.

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


prov = load_json(TABLES / "rq3_provenance.json")
print(f"run_id                              : {prov['run_id']}")
print(f"aidev_dataset_sha                   : {prov['aidev_dataset_sha']}")
print(f"compute_script                      : {prov['compute_script']}")
print(f"generated_at_utc                    : {prov['generated_at_utc']}")
print(
    f"outcome_skipped_per_operator_decision: {prov['outcome_skipped_per_operator_decision']}"
)
print()
print("FE diagnostics (singleton-repo drop):")
fed = prov["fe_diagnostics"]
print(f"  n_repos_before                    : {fed['n_repos_before']}")
print(f"  n_repos_dropped_singleton         : {fed['n_repos_dropped_singleton']}")
print(f"  n_repos_after                     : {fed['n_repos_after']}")
print(f"  n_rows_before                     : {fed['n_rows_before']}")
print(f"  n_rows_dropped_singleton          : {fed['n_rows_dropped_singleton']}")
print(f"  n_rows_after                      : {fed['n_rows_after']}")
print(f"  n_levels_dropped_task_type        : {fed['n_levels_dropped_task_type']}")
print()
print("configs hashes:")
for name, info in prov["configs_hashes"].items():
    print(f"  {name:32s}  {info['version_header']}  sha256={info['sha256'][:16]}…")

# %% [markdown]
# ## Lead with the singleton-repo drop
#
# Repo fixed-effects logit cannot identify on within-repo variation in
# repos that have only one PR type in the FE pool. The analyst drops
# 2,215 such repos before fitting; 588 repos / 13,249 PR-rows survive.
# This is the **canonical FE cohort** for every RQ3 number on this
# page.

# %%
headline = load_json(TABLES / "rq3_headline.json")
pd.Series(
    {
        "n_repos_dropped_singleton": headline["n_repos_dropped_singleton"],
        "n_repos_after_singleton_drop": headline["n_repos_after_singleton_drop"],
        "n_prs_after_singleton_drop": headline["n_prs_after_singleton_drop"],
    }
)

# %% [markdown]
# ### Note on `task_type` collinearity
#
# `task_type` was pre-declared as a within-repo control. In the actual
# FE pool, **AIDev does not assign `pr_task_type` to human PRs** — only
# to the curated agentic ones. That makes `task_type` perfectly
# collinear with the `agentic` indicator inside the FE design matrix
# and the analyst dropped it from the RHS. This is a **design choice
# forced by the dataset**, not a finding. See `rq3_compute.py` for the
# drop logic.

# %% [markdown]
# ## Three primary outcomes

# %%
rq3 = load_csv(TABLES / "rq3_main.csv")
rq3[
    [
        "outcome",
        "model",
        "n_obs",
        "n_repos",
        "or_or_irr",
        "ci95_lo",
        "ci95_hi",
        "p_raw",
        "fallback_to_poisson",
    ]
]

# %% [markdown]
# ### Reading the headline
#
# - `any_security_intervention` — agentic PRs are **less** likely to
#   draw any security-tool intervention than human PRs in the same
#   repo (OR=0.54, p=0.0012). This is the post-clean-configs result;
#   see §6 of REPORT.md for the direction-reversal vs the pre-clean
#   run.
# - `security_intervention_count` — agentic PRs trigger fewer
#   interventions per PR (IRR=0.69, p=0.031). The analyst's NB
#   fit raised, so this is the **Poisson + cluster-robust** fallback
#   per README §7.4.
# - `rejected` — agentic PRs are **6.7×** more likely to be rejected
#   than human PRs in the same repo (OR=6.72, p < 1e-22), even after
#   conditioning on `any_security_intervention`.

# %% [markdown]
# ![RQ3 outcomes forest](../figures/rq3_outcomes_forest.png)

# %% [markdown]
# ![RQ3 per-repo intervention rates](../figures/rq3_per_repo_rates.png)

# %% [markdown]
# ## Secondary: Mann–Whitney U + Cliff's δ on the count outcome

# %%
sec = headline["secondary"]
pd.Series(
    {
        "n_pairs": sec["mannwhitney_n_pairs"],
        "n_agentic_for_delta": sec["n_agentic_for_delta"],
        "n_human_for_delta": sec["n_human_for_delta"],
        "mannwhitney_u_count": sec["mannwhitney_u_count"],
        "mannwhitney_p_count": round(sec["mannwhitney_p_count"], 4),
        "cliffs_delta": round(sec["cliffs_delta_any_intervention"], 4),
        "cliffs_delta_magnitude": sec["cliffs_delta_any_intervention_magnitude"],
    }
)

# %% [markdown]
# ## RQ3 robustness battery

# %%
robust = load_csv(TABLES / "rq3_robustness.csv")
print(f"total RQ3 robustness rows: {len(robust)}")
robust["variant"].value_counts()

# %% [markdown]
# ### Variant 5: bot-identity-only (`v5_bot_identity_only`)
#
# This variant is the most direct probe of the **post-clean configs**
# change: it strips the security-keyword detector entirely and uses
# only the `security_bots.txt` author-list. The headline `rejected`
# OR is essentially unchanged (6.71 vs 6.72), but
# `any_security_intervention` flattens to 0.72 with p≈0.30 — i.e. once
# you remove keyword detection, the agentic-vs-human gap on
# *any* intervention is no longer significant. The analyst keeps the
# headline (keyword-inclusive) version as the primary, with v5 as the
# robustness control.

# %%
robust.query("variant == 'v5_bot_identity_only'")[
    [
        "outcome",
        "or_or_irr",
        "ci95_lo",
        "ci95_hi",
        "p_raw",
        "n_obs",
        "n_repos_fe",
        "n_rows_fe",
    ]
]

# %% [markdown]
# ### Try changing X
#
# `robust["variant"].unique()` shows every variant the analyst ran.
# Filter to one and inspect its three outcomes side-by-side.
