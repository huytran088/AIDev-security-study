"""Rebuild analysis/figures/ from the existing analysis/tables/ CSVs.

Used when the parquets in data_derived/latest/ are absent but the canonical
tables are intact (e.g. figures are Git LFS stubs without git-lfs installed).
Replicates the matplotlib code from rq{1,2,3}_compute.py exactly.
"""

import numpy as np
import pandas as pd
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TABLES = REPO / "analysis" / "tables"
FIGS = REPO / "analysis" / "figures"

CATEGORIES = ["sast_any", "sca_any", "secrets_any", "fuzzing_any", "ci_hardening_any"]


def make_rq1_figures() -> None:
    by_tool = pd.read_csv(TABLES / "rq1_adoption_by_tool.csv")
    by_cat = pd.read_csv(TABLES / "rq1_adoption_by_category.csv")
    by_lang = pd.read_csv(TABLES / "rq1_adoption_by_language.csv")

    fig, ax = plt.subplots(figsize=(10, 6))
    bt = by_tool.sort_values("adoption_pct", ascending=True)
    ax.barh(bt["tool"], bt["adoption_pct"], color="#3b6db8")
    ax.set_xlabel("Adoption rate in AI repos (%)")
    ax.set_title(
        "Per-tool adoption among AI repos (n="
        f"{int(by_tool['n_ai_repos'].iloc[0])} repos)"
    )
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"rq1_adoption_by_tool.{ext}", dpi=300)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 4))
    bc = by_cat.sort_values("adoption_pct", ascending=True)
    ax.barh(bc["category"], bc["adoption_pct"], color="#3b9b7a")
    ax.set_xlabel("Adoption rate in AI repos (%)")
    ax.set_title("Category-level adoption among AI repos")
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"rq1_adoption_by_category.{ext}", dpi=300)
    plt.close(fig)

    cat_cols = [c.removesuffix("_any") + "_pct" for c in CATEGORIES]
    bl = by_lang.set_index("language")[cat_cols]
    fig, ax = plt.subplots(figsize=(10, 5))
    bl.plot(kind="bar", ax=ax, width=0.85)
    ax.set_ylabel("Adoption rate in AI repos (%)")
    ax.set_title("Category adoption by primary language (top-10)")
    ax.legend(title="category", bbox_to_anchor=(1.02, 1), loc="upper left")
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"rq1_adoption_by_language.{ext}", dpi=300)
    plt.close(fig)


def make_rq2_figures() -> None:
    main_df = pd.read_csv(TABLES / "rq2_main.csv")

    cat = main_df[main_df["family"] == "category"].copy()
    cat = cat.sort_values("ai_rate", ascending=True)
    fig, ax = plt.subplots(figsize=(8, 5))
    y = np.arange(len(cat))
    ax.barh(y - 0.2, 100 * cat["ai_rate"], height=0.4, color="#3b6db8", label="AI")
    ax.barh(
        y + 0.2, 100 * cat["ctrl_rate"], height=0.4, color="#9b9b9b", label="Control"
    )
    ax.set_yticks(y)
    ax.set_yticklabels(cat["level"])
    ax.set_xlabel("Adoption rate (%)")
    ax.set_title("Category-level adoption: AI vs Control")
    ax.legend()
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"rq2_category_rates.{ext}", dpi=300)
    plt.close(fig)

    tool = main_df[main_df["family"] == "tool"].copy()
    tool = tool.sort_values("OR", ascending=True)
    fig, ax = plt.subplots(figsize=(9, 8))
    y = np.arange(len(tool))
    or_vals = tool["OR"].values.astype(float)
    or_lo = tool["OR_lo"].values.astype(float)
    or_hi = tool["OR_hi"].values.astype(float)
    log_or = np.log(np.clip(or_vals, 1e-6, None))
    log_lo = np.log(np.clip(or_lo, 1e-6, None))
    log_hi = np.log(np.clip(or_hi, 1e-6, None))
    sig_mask = []
    for _, r in tool.iterrows():
        p_adj = r["p_adj"]
        sig = bool(r["bh_family_member"] and pd.notna(p_adj) and float(p_adj) < 0.05)
        sig_mask.append(sig)
    colors = ["#c0392b" if s else "#34495e" for s in sig_mask]
    ax.errorbar(
        log_or,
        y,
        xerr=[log_or - log_lo, log_hi - log_or],
        fmt="o",
        ecolor="#bbbbbb",
        capsize=2,
        elinewidth=0.8,
    )
    for xi, yi, ci in zip(log_or, y, colors, strict=True):
        ax.scatter(xi, yi, color=ci, zorder=3, s=30)
    ax.axvline(0.0, color="#888888", linestyle="--", linewidth=0.7)
    ax.set_yticks(y)
    ax.set_yticklabels(tool["level"])
    ax.set_xlabel("log(OR), AI vs Control  (red = BH-significant)")
    ax.set_title(
        "Per-tool odds ratios (Fisher's exact, BH within non-sparse subset)"
    )
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"rq2_tool_forest.{ext}", dpi=300)
    plt.close(fig)


def make_rq3_figures() -> None:
    main_df = pd.read_csv(TABLES / "rq3_main.csv")
    per_repo = pd.read_csv(TABLES / "rq3_per_repo_rates.csv")

    rows = main_df[main_df["or_or_irr"].notna()]
    y = np.arange(len(rows))[::-1]
    log_or = np.log(rows["or_or_irr"].astype(float).values)
    log_lo = np.log(rows["ci95_lo"].astype(float).values)
    log_hi = np.log(rows["ci95_hi"].astype(float).values)
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.errorbar(
        log_or,
        y,
        xerr=[log_or - log_lo, log_hi - log_or],
        fmt="o",
        ecolor="#888888",
        capsize=3,
        elinewidth=1,
        markersize=8,
        color="#34495e",
    )
    ax.axvline(0.0, color="#bbbbbb", linestyle="--", linewidth=0.8)
    labels = [f"{r['outcome']}\n({r['model']})" for _, r in rows.iterrows()]
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.set_xlabel("log(OR or IRR), agentic vs human (within repo)")
    ax.set_title("Within-repo effect of agentic authorship")
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"rq3_outcomes_forest.{ext}", dpi=300)
    plt.close(fig)

    # rq3_per_repo_rates.csv already carries the per-repo means that
    # make_figures() in rq3_compute.py derives via groupby/unstack.
    by_repo = per_repo.dropna(
        subset=["agentic_intervention_rate", "human_intervention_rate"]
    )
    fig, ax = plt.subplots(figsize=(6, 6))
    ax.scatter(
        100 * by_repo["human_intervention_rate"],
        100 * by_repo["agentic_intervention_rate"],
        alpha=0.5,
        s=15,
        color="#3b6db8",
    )
    lim = max(
        100 * by_repo["human_intervention_rate"].max(),
        100 * by_repo["agentic_intervention_rate"].max(),
        5,
    )
    ax.plot([0, lim], [0, lim], color="#aaaaaa", linestyle="--", linewidth=0.8)
    ax.set_xlabel("Human PR intervention rate (%)")
    ax.set_ylabel("Agentic PR intervention rate (%)")
    ax.set_title(f"Per-repo intervention rates (n={len(by_repo)} FE repos)")
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"rq3_per_repo_rates.{ext}", dpi=300)
    plt.close(fig)


if __name__ == "__main__":
    FIGS.mkdir(parents=True, exist_ok=True)
    make_rq1_figures()
    print("RQ1 figures done")
    make_rq2_figures()
    print("RQ2 figures done")
    make_rq3_figures()
    print("RQ3 figures done")
    print("All 14 figures rebuilt.")
