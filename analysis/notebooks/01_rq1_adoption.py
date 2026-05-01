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
# # 01 — RQ1: How widely do AI repos adopt security tools?
#
# RQ1 reports the **adoption rate** of each security tool / category /
# language slice inside the **AI cohort** (n=2,803 repos). It is a
# descriptive RQ — there is no comparison to controls here. RQ2
# (notebook 02) is the comparative RQ.
#
# All numbers come from `analysis/tables/rq1_*.csv` and
# `rq1_headline.json`. This notebook does not fit any models.

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


prov = load_json(TABLES / "rq1_provenance.json")
print(f"run_id            : {prov['run_id']}")
print(f"aidev_dataset_sha : {prov['aidev_dataset_sha']}")
print(f"compute_script    : {prov['compute_script']}")
print(f"generated_at_utc  : {prov['generated_at_utc']}")
print()
print("configs hashes:")
for name, info in prov["configs_hashes"].items():
    print(f"  {name:32s}  {info['version_header']}  sha256={info['sha256'][:16]}…")

# %% [markdown]
# ## Headline numbers

# %%
headline = load_json(TABLES / "rq1_headline.json")
pd.Series(
    {
        "n_AI_repos": headline["n_ai_repos"],
        "any_tool_adoption_pct": headline["any_tool_pct"],
        "top_category": f"{headline['top_category']['category']} ({headline['top_category']['adoption_pct']}%)",
        "bottom_category": f"{headline['bottom_category']['category']} ({headline['bottom_category']['adoption_pct']}%)",
        "top_tool": f"{headline['top3_tools'][0]['tool']} ({headline['top3_tools'][0]['adoption_pct']}%)",
        "second_tool": f"{headline['top3_tools'][1]['tool']} ({headline['top3_tools'][1]['adoption_pct']}%)",
        "third_tool": f"{headline['top3_tools'][2]['tool']} ({headline['top3_tools'][2]['adoption_pct']}%)",
    }
)

# %% [markdown]
# ## Adoption by tool (sorted, descending)
#
# Three tools dominate (`dependabot`, `codeql`, `renovate`); the
# remainder all sit under 5%. The long tail is real: 9 of 19 tools have
# adoption < 1%.

# %%
by_tool = load_csv(TABLES / "rq1_adoption_by_tool.csv")
by_tool

# %% [markdown]
# ![Adoption by tool](../figures/rq1_adoption_by_tool.png)

# %% [markdown]
# ## Adoption by category

# %%
by_category = load_csv(TABLES / "rq1_adoption_by_category.csv")
by_category

# %% [markdown]
# ![Adoption by category](../figures/rq1_adoption_by_category.png)

# %% [markdown]
# ## Adoption by primary language (top 10 languages by repo count)

# %%
by_language = load_csv(TABLES / "rq1_adoption_by_language.csv")
by_language

# %% [markdown]
# ![Adoption by language](../figures/rq1_adoption_by_language.png)

# %% [markdown]
# ## Adoption by stars-bin
#
# Adoption rises monotonically with repo popularity: the 1000+ stars
# bin is roughly 1.6× the 100–199 bin on `any_tool`.

# %%
by_stars = load_csv(TABLES / "rq1_adoption_by_stars.csv")
by_stars

# %% [markdown]
# ## Logit terms (per-category, AI-cohort only)
#
# Each row is one term in the per-category logit
# `configured ~ language_grp + owner_type_grp + log_stars +
# repo_age_days + log_days_since_push`. The `secrets` and `fuzzing`
# fits have many separated levels (NaN std-err, |coef| ≈ 25) and
# should be read with the headline category-rate table, not the term
# table.

# %%
logit = load_csv(TABLES / "rq1_logit_terms.csv")
logit.head(20)

# %% [markdown]
# ### Try changing X
#
# Change `head(20)` to `query("category == 'sast' and p_value < 0.05")`
# to see the SAST terms with p < 0.05. The full table is in
# `analysis/tables/rq1_logit_terms.csv`.
