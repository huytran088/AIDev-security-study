"""Emit per-figure source CSVs for the four figures the §12 audit flags
as missing same-stem siblings.

The audit rule: every `analysis/figures/<stem>.png` should have an
`analysis/tables/<stem>.csv` that documents exactly the rows/columns the
figure plots. Three of the four figures plot a slice of an existing main
CSV (Option A: emit a sliced CSV); one figure plots a per-repo aggregate
that is not in any main CSV (also Option A, but built fresh from the
intervention parquet under the same singleton-drop filter the FE model
uses); and one figure is a 1:1 rendering of `rq3_main.csv` itself
(Option B: symlink).

This script is a metadata/sidecar fix only - it does not refit any
model and does not touch `*_main.csv`, `*_provenance.json`, or
`*_robustness.csv`.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parents[2]
LATEST = REPO / "data_derived" / "latest"
TABLES = REPO / "analysis" / "tables"


def emit_rq2_category_rates() -> Path:
    """rq2_category_rates.png plots `level`, `ai_rate`, `ctrl_rate` for
    rows where `family == 'category'`. We emit exactly those columns."""
    main = pd.read_csv(TABLES / "rq2_main.csv")
    cat = main[main["family"] == "category"].copy()
    # The plot sorts ascending by ai_rate before drawing; emit the same
    # row ordering so the CSV row index matches the plot's y-axis.
    cat = cat.sort_values("ai_rate", ascending=True).reset_index(drop=True)
    out_cols = ["level", "n_AI", "n_ctrl", "ai_rate", "ctrl_rate", "OR", "p_adj"]
    out = cat[out_cols]
    target = TABLES / "rq2_category_rates.csv"
    out.to_csv(target, index=False)
    return target


def emit_rq2_tool_forest() -> Path:
    """rq2_tool_forest.png plots `level`, `OR`, `OR_lo`, `OR_hi` and
    color-codes by (`bh_family_member` AND `p_adj < 0.05`). We emit the
    full tool-family slice so the CSV is the audit trail."""
    main = pd.read_csv(TABLES / "rq2_main.csv")
    tool = main[main["family"] == "tool"].copy()
    tool = tool.sort_values("OR", ascending=True).reset_index(drop=True)
    out_cols = [
        "level",
        "n_AI",
        "n_ctrl",
        "ai_rate",
        "ctrl_rate",
        "OR",
        "OR_lo",
        "OR_hi",
        "p_raw",
        "p_adj",
        "bh_family_member",
    ]
    out = tool[out_cols]
    target = TABLES / "rq2_tool_forest.csv"
    out.to_csv(target, index=False)
    return target


def symlink_rq3_outcomes_forest() -> Path:
    """rq3_outcomes_forest.png plots `outcome`, `model`, `or_or_irr`,
    `ci95_lo`, `ci95_hi` for every row of `rq3_main.csv` where
    `or_or_irr.notna()`. With three FE outcomes all populating
    `or_or_irr`, that's the entire CSV. Symlink rather than duplicate."""
    target = TABLES / "rq3_outcomes_forest.csv"
    if target.is_symlink() or target.exists():
        target.unlink()
    # Relative symlink so it survives a repo move.
    target.symlink_to("rq3_main.csv")
    return target


def emit_rq3_per_repo_rates() -> Path:
    """rq3_per_repo_rates.png is a per-repo scatter of agentic vs human
    intervention rates, computed from `pr_interventions.parquet` after
    the same singleton-repo drop the FE model applies. The values are
    not in any *_main.csv - we recompute them deterministically here.

    Determinism guarantee: pure groupby on a frozen parquet, no random
    sampling, no model fit. Re-running this against the current
    `data_derived/latest/` will produce byte-identical output."""
    df = pd.read_parquet(LATEST / "pr_interventions.parquet")

    # Mirrors `prep_fe_frame` in rq3_compute.py exactly — singleton-repo drop.
    keep = df.groupby("repo_full_name")["pr_type"].nunique().loc[lambda s: s == 2].index
    df_fe = df[df["repo_full_name"].isin(keep)].copy()
    df_fe["any_security_intervention"] = df_fe["any_security_intervention"].astype(int)

    by_repo = (
        df_fe.groupby(["repo_full_name", "pr_type"])["any_security_intervention"]
        .mean()
        .unstack("pr_type")
        .dropna()
    )
    n_prs = (
        df_fe.groupby(["repo_full_name", "pr_type"])
        .size()
        .unstack("pr_type")
        .reindex(by_repo.index)
        .fillna(0)
        .astype(int)
    )

    out = (
        pd.DataFrame(
            {
                "repo_full_name": by_repo.index,
                "agentic_intervention_rate": by_repo["agentic"].values,
                "human_intervention_rate": by_repo["human"].values,
                "n_agentic_prs": n_prs["agentic"].values,
                "n_human_prs": n_prs["human"].values,
            }
        )
        .sort_values("repo_full_name")
        .reset_index(drop=True)
    )

    target = TABLES / "rq3_per_repo_rates.csv"
    out.to_csv(target, index=False)
    return target


def main() -> None:
    written: list[tuple[str, Path, str]] = []
    written.append(("A", emit_rq2_category_rates(), "sliced from rq2_main.csv"))
    written.append(("A", emit_rq2_tool_forest(), "sliced from rq2_main.csv"))
    written.append(
        (
            "B",
            symlink_rq3_outcomes_forest(),
            "symlink to rq3_main.csv (figure is a 1:1 rendering)",
        )
    )
    written.append(
        (
            "A",
            emit_rq3_per_repo_rates(),
            "computed from pr_interventions.parquet under FE singleton-drop",
        )
    )
    for option, path, note in written:
        rel = path.relative_to(REPO)
        kind = "symlink" if path.is_symlink() else "csv"
        print(f"[{option}] {rel}  ({kind}; {note})")


if __name__ == "__main__":
    main()
