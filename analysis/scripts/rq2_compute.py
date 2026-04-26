"""RQ2 — AI vs Control adoption of security tooling.

Operator-locked decisions baked in (Phase E orchestration brief, 2026-04-26):
  - Sparse-band tools (control adoption rate < 1% in
    `repo_security_adoption_wide.parquet`) are reported descriptively only:
    raw OR + 95% CI, NO p-value, NO BH-adjusted p, `bh_family_member=False`.
    The remaining tools form the BH family; the correction is computed across
    that subset. The cutoff and excluded list are recorded in
    `rq2_provenance.json` under `bh_family_definition.sparse_band_excluded`.
  - Per-category Fisher gets full BH within the 5-category family.
  - rq2_secrets and rq2_fuzzing are flagged UNDERPOWERED via the
    pre-flight power table (still computed and reported).

Outputs:
    analysis/tables/rq2_main.csv
    analysis/tables/rq2_provenance.json
    analysis/tables/rq2_headline.json
    analysis/figures/rq2_*.{png,pdf}
"""

from __future__ import annotations

import json
import os
import warnings
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import statsmodels.api as sm
import statsmodels.formula.api as smf
from scipy.stats import fisher_exact
from statsmodels.stats.multitest import multipletests

from effect_sizes import odds_ratio_with_ci, smd_binary
from provenance import write_provenance

warnings.filterwarnings("ignore", category=RuntimeWarning)
warnings.filterwarnings("ignore", message=".*Maximum Likelihood optimization failed.*")
warnings.filterwarnings("ignore", message=".*PerfectSeparationWarning.*")

REPO = Path(__file__).resolve().parents[2]
LATEST = REPO / "data_derived" / "latest"
TABLES = REPO / "analysis" / "tables"
FIGS = REPO / "analysis" / "figures"

SEED = int(os.environ.get("RANDOM_SEED", "20260101"))
np.random.default_rng(SEED)

CATEGORIES = ["sast_any", "sca_any", "secrets_any", "fuzzing_any", "ci_hardening_any"]
TOOL_COLUMNS = [
    "tool_anchore",
    "tool_bandit",
    "tool_checkov",
    "tool_claude_code_security_review",
    "tool_codeql",
    "tool_dependabot",
    "tool_gitleaks",
    "tool_govulncheck",
    "tool_harden_runner",
    "tool_microsoft_security_devops",
    "tool_oss_fuzz",
    "tool_ossf_scorecard",
    "tool_renovate",
    "tool_semgrep",
    "tool_snyk",
    "tool_sonarqube",
    "tool_tfsec",
    "tool_trivy",
    "tool_trufflehog",
]

# Underpowered RQ2 categories per pre-flight (operator-locked).
UNDERPOWERED_CATEGORIES = {"secrets", "fuzzing"}

SPARSE_BAND_THRESHOLD = 0.01  # control adoption rate < 1% -> descriptive only


# --------------------------------------------------------------------------
# Covariate frame for the adjusted logit
# --------------------------------------------------------------------------
def stars_bin(stars: int) -> str:
    if stars < 200:
        return "100-199"
    if stars < 500:
        return "200-499"
    if stars < 1000:
        return "500-999"
    return "1000+"


def load_combined_features() -> pd.DataFrame:
    """AI ∪ Control covariate frame. Joins wide adoption to repo metadata."""
    wide = pd.read_parquet(LATEST / "repo_security_adoption_wide.parquet")

    ai_meta = pd.read_csv(LATEST / "ai_repos.csv")[
        ["repo_full_name", "stars", "language"]
    ]
    ai_enriched = pd.read_parquet(LATEST / "_ai_repos_enriched.parquet")[
        ["repo_full_name", "created_at_gh", "pushed_at_gh", "owner_type"]
    ].rename(
        columns={
            "created_at_gh": "created_at",
            "pushed_at_gh": "pushed_at",
        }
    )
    ai_meta = ai_meta.merge(ai_enriched, on="repo_full_name", how="left")
    ai_meta["cohort"] = "AI"

    ctrl_meta = pd.read_csv(LATEST / "control_repos.csv")[
        ["repo_full_name", "stars", "language", "created_at", "owner_type", "pushed_at"]
    ]
    ctrl_meta["created_at"] = pd.to_datetime(ctrl_meta["created_at"], utc=True)
    ctrl_meta["pushed_at"] = pd.to_datetime(ctrl_meta["pushed_at"], utc=True)
    ctrl_meta["cohort"] = "Control"

    meta = pd.concat([ai_meta, ctrl_meta], ignore_index=True)
    df = wide.merge(
        meta.drop(columns=["cohort"]),
        on="repo_full_name",
        how="left",
    )

    df["stars"] = df["stars"].fillna(0).astype(int)
    df["language"] = df["language"].fillna("Unknown")
    df["owner_type"] = df["owner_type"].fillna("Unknown")
    df["log_stars"] = np.log1p(df["stars"])
    df["stars_bin"] = df["stars"].map(stars_bin)
    window_end = pd.Timestamp(os.environ.get("WINDOW_END", "2025-07-31"), tz="UTC")
    df["repo_age_days"] = (window_end - df["created_at"]).dt.days.fillna(0)
    df["pushed_at"] = pd.to_datetime(df["pushed_at"], utc=True)
    days_since_push = (window_end - df["pushed_at"]).dt.days.fillna(365)
    df["log_days_since_push"] = np.log1p(days_since_push.clip(lower=0))
    df["AI"] = (df["cohort"] == "AI").astype(int)

    # owner identifier — owner is everything before the first "/" in repo_full_name.
    df["owner"] = df["repo_full_name"].str.split("/").str[0]

    # Group rare languages so the GLM has degrees of freedom.
    lang_counts = df["language"].value_counts()
    keep_langs = lang_counts[lang_counts >= 30].index
    df["language_grp"] = df["language"].where(
        df["language"].isin(keep_langs), other="Other"
    )
    df["owner_type_grp"] = df["owner_type"].where(
        df["owner_type"].isin(["User", "Organization"]),
        other="Other",
    )
    return df


# --------------------------------------------------------------------------
# Fisher + Wald-OR per (cohort, outcome)
# --------------------------------------------------------------------------
def fisher_2x2(treat_yes: int, treat_n: int, ctrl_yes: int, ctrl_n: int) -> dict:
    a = treat_yes
    b = treat_n - treat_yes
    c = ctrl_yes
    d = ctrl_n - ctrl_yes
    table = [[a, b], [c, d]]
    or_, p = fisher_exact(table, alternative="two-sided")
    or_wald, lo, hi = odds_ratio_with_ci(a, b, c, d)
    p1 = a / treat_n if treat_n else float("nan")
    p2 = c / ctrl_n if ctrl_n else float("nan")
    return {
        "n_AI": treat_n,
        "n_AI_yes": a,
        "ai_rate": p1,
        "n_ctrl": ctrl_n,
        "n_ctrl_yes": c,
        "ctrl_rate": p2,
        "OR_fisher": float(or_) if np.isfinite(or_) else float("nan"),
        "OR": or_wald,
        "OR_lo": lo,
        "OR_hi": hi,
        "p_raw": float(p),
        "smd": smd_binary(p1, p2),
    }


def fit_logit_for_outcome(df: pd.DataFrame, outcome: str) -> dict:
    """Return AI coef, OR, CI, p, n_obs, n_clusters, converged for the
    adjusted logit.  Cluster SE on owner if possible, else HC1.
    """
    n_clusters = df["owner"].nunique()
    if n_clusters >= 30:
        cov_kw = dict(cov_type="cluster", cov_kwds={"groups": df["owner"]})
    else:
        cov_kw = dict(cov_type="HC1")
    formula = (
        f"{outcome} ~ AI + log_stars + C(language_grp) + repo_age_days "
        f"+ log_days_since_push + C(owner_type_grp)"
    )
    try:
        m = smf.glm(formula, data=df, family=sm.families.Binomial()).fit(
            disp=False, **cov_kw
        )
        ci = m.conf_int().loc["AI"]
        return {
            "adj_OR": float(np.exp(m.params["AI"])),
            "adj_OR_lo": float(np.exp(ci[0])),
            "adj_OR_hi": float(np.exp(ci[1])),
            "adj_p": float(m.pvalues["AI"]),
            "adj_n_obs": int(m.nobs),
            "adj_n_clusters": int(n_clusters),
            "adj_converged": True,
            "adj_cov_type": cov_kw["cov_type"],
        }
    except Exception as e:  # noqa: BLE001
        return {
            "adj_OR": None,
            "adj_OR_lo": None,
            "adj_OR_hi": None,
            "adj_p": None,
            "adj_n_obs": None,
            "adj_n_clusters": int(n_clusters),
            "adj_converged": False,
            "adj_cov_type": cov_kw["cov_type"],
            "adj_error": str(e)[:200],
        }


# --------------------------------------------------------------------------
# Build the main RQ2 table
# --------------------------------------------------------------------------
def build_main(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Returns (main_df, bh_family_summary_dict)."""
    rows: list[dict] = []
    df_ai = df[df["cohort"] == "AI"]
    df_ctrl = df[df["cohort"] == "Control"]

    # ---- Per-category Fisher + adjusted logit (BH within category family of 5) ----
    cat_rows = []
    for col in CATEGORIES:
        cat_short = col.removesuffix("_any")
        a = int(df_ai[col].sum())
        c = int(df_ctrl[col].sum())
        s = fisher_2x2(a, len(df_ai), c, len(df_ctrl))
        adj = fit_logit_for_outcome(df, col)
        underpowered = cat_short in UNDERPOWERED_CATEGORIES
        cat_rows.append(
            {
                "family": "category",
                "level": cat_short,
                "n_AI": s["n_AI"],
                "n_ctrl": s["n_ctrl"],
                "ai_rate": round(s["ai_rate"], 6),
                "ctrl_rate": round(s["ctrl_rate"], 6),
                "OR": round(s["OR"], 4),
                "OR_lo": round(s["OR_lo"], 4),
                "OR_hi": round(s["OR_hi"], 4),
                "OR_fisher": round(s["OR_fisher"], 4),
                "p_raw": s["p_raw"],
                "p_adj": None,  # filled in below
                "bh_family_member": True,
                "adj_OR": (
                    round(adj["adj_OR"], 4) if adj["adj_OR"] is not None else None
                ),
                "adj_OR_lo": (
                    round(adj["adj_OR_lo"], 4) if adj["adj_OR_lo"] is not None else None
                ),
                "adj_OR_hi": (
                    round(adj["adj_OR_hi"], 4) if adj["adj_OR_hi"] is not None else None
                ),
                "adj_p": adj["adj_p"],
                "adj_cov_type": adj["adj_cov_type"],
                "adj_n_clusters": adj["adj_n_clusters"],
                "smd_summary": round(s["smd"], 4),
                "underpowered_flag": underpowered,
            }
        )
    # BH within category (m=5)
    cat_p = np.array([r["p_raw"] for r in cat_rows])
    if len(cat_p) > 0:
        _, cat_p_adj, _, _ = multipletests(cat_p, method="fdr_bh", alpha=0.05)
        for r, padj in zip(cat_rows, cat_p_adj, strict=True):
            r["p_adj"] = float(padj)
    rows.extend(cat_rows)

    # ---- Per-tool Fisher + adjusted logit (sparse-band excluded from BH) ----
    tool_rows = []
    sparse_excluded: list[str] = []
    for col in TOOL_COLUMNS:
        tool_short = col.removeprefix("tool_")
        a = int(df_ai[col].sum())
        c = int(df_ctrl[col].sum())
        s = fisher_2x2(a, len(df_ai), c, len(df_ctrl))
        ctrl_rate = s["ctrl_rate"]
        is_sparse = ctrl_rate < SPARSE_BAND_THRESHOLD
        if is_sparse:
            sparse_excluded.append(tool_short)
        adj = fit_logit_for_outcome(df, col)
        tool_rows.append(
            {
                "family": "tool",
                "level": tool_short,
                "n_AI": s["n_AI"],
                "n_ctrl": s["n_ctrl"],
                "ai_rate": round(s["ai_rate"], 6),
                "ctrl_rate": round(s["ctrl_rate"], 6),
                "OR": round(s["OR"], 4),
                "OR_lo": round(s["OR_lo"], 4),
                "OR_hi": round(s["OR_hi"], 4),
                "OR_fisher": (
                    round(s["OR_fisher"], 4) if np.isfinite(s["OR_fisher"]) else None
                ),
                "p_raw": s["p_raw"] if not is_sparse else float("nan"),
                "p_adj": None,
                "bh_family_member": (not is_sparse),
                "adj_OR": (
                    round(adj["adj_OR"], 4) if adj["adj_OR"] is not None else None
                ),
                "adj_OR_lo": (
                    round(adj["adj_OR_lo"], 4) if adj["adj_OR_lo"] is not None else None
                ),
                "adj_OR_hi": (
                    round(adj["adj_OR_hi"], 4) if adj["adj_OR_hi"] is not None else None
                ),
                "adj_p": adj["adj_p"],
                "adj_cov_type": adj["adj_cov_type"],
                "adj_n_clusters": adj["adj_n_clusters"],
                "smd_summary": round(s["smd"], 4),
                "underpowered_flag": False,  # tool-level not pre-declared underpowered
            }
        )
    # BH across the non-sparse tool subset.
    bh_subset_idx = [i for i, r in enumerate(tool_rows) if r["bh_family_member"]]
    bh_p = np.array([tool_rows[i]["p_raw"] for i in bh_subset_idx])
    if len(bh_p) > 0:
        _, bh_p_adj, _, _ = multipletests(bh_p, method="fdr_bh", alpha=0.05)
        for idx, padj in zip(bh_subset_idx, bh_p_adj, strict=True):
            # Surface raw fisher p as p_raw too (it was already set).
            tool_rows[idx]["p_adj"] = float(padj)
    # Sparse-band rows: leave p_adj as None — convert to NaN string for CSV later.
    rows.extend(tool_rows)

    main_df = pd.DataFrame(rows)
    bh_family = {
        "sparse_band_threshold": SPARSE_BAND_THRESHOLD,
        "sparse_band_threshold_basis": (
            "control adoption rate < 1% in repo_security_adoption_wide.parquet"
        ),
        "sparse_band_excluded": sorted(sparse_excluded),
        "bh_family_size_categories": len(CATEGORIES),
        "bh_family_size_tools_after_exclusion": len(TOOL_COLUMNS)
        - len(sparse_excluded),
        "bh_method": "fdr_bh",
        "alpha": 0.05,
    }
    return main_df, bh_family


# --------------------------------------------------------------------------
# Figures
# --------------------------------------------------------------------------
def make_figures(main_df: pd.DataFrame) -> None:
    FIGS.mkdir(parents=True, exist_ok=True)

    # 1) Per-category bar chart: AI vs Control adoption rate.
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
    ax.set_title("RQ2 — Category-level adoption: AI vs Control")
    ax.legend()
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"rq2_category_rates.{ext}", dpi=300)
    plt.close(fig)

    # 2) Per-tool forest plot: log-OR with 95% CI (BH-significant in red).
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
        sig = (
            r["bh_family_member"]
            and p_adj is not None
            and (isinstance(p_adj, float) and p_adj < 0.05)
        )
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
        "RQ2 — Per-tool odds ratios (Fisher's exact, BH within non-sparse subset)"
    )
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"rq2_tool_forest.{ext}", dpi=300)
    plt.close(fig)


# --------------------------------------------------------------------------
# Headline
# --------------------------------------------------------------------------
def write_headline(main_df: pd.DataFrame, bh_family: dict) -> dict:
    cat = main_df[main_df["family"] == "category"]
    tool = main_df[main_df["family"] == "tool"]

    bh_sig_cats = cat[
        (cat["p_adj"].notna())
        & (cat["p_adj"].astype(float) < 0.05)
        & (cat["OR"].astype(float) > 1.0)
    ]
    bh_sig_tools = tool[
        (tool["bh_family_member"])
        & (tool["p_adj"].notna())
        & (tool["p_adj"].astype(float) < 0.05)
        & (tool["OR"].astype(float) > 1.0)
    ]

    headline = {
        "n_AI_repos": int(cat["n_AI"].iloc[0]) if len(cat) else None,
        "n_ctrl_repos": int(cat["n_ctrl"].iloc[0]) if len(cat) else None,
        "n_categories_BH_sig_AI_gt_ctrl": int(len(bh_sig_cats)),
        "n_tools_BH_sig_AI_gt_ctrl": int(len(bh_sig_tools)),
        "n_underpowered_families": int(cat["underpowered_flag"].sum()),
        "n_sparse_band_tools_excluded": len(bh_family["sparse_band_excluded"]),
        "sparse_band_excluded": bh_family["sparse_band_excluded"],
        "bh_sig_categories": bh_sig_cats[
            ["level", "OR", "OR_lo", "OR_hi", "p_adj"]
        ].to_dict("records"),
        "bh_sig_tools": bh_sig_tools[
            ["level", "OR", "OR_lo", "OR_hi", "p_adj"]
        ].to_dict("records"),
    }
    (TABLES / "rq2_headline.json").write_text(
        json.dumps(headline, indent=2, sort_keys=True, default=float)
    )
    return headline


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main() -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    df = load_combined_features()
    main_df, bh_family = build_main(df)
    main_df.to_csv(TABLES / "rq2_main.csv", index=False)
    make_figures(main_df)
    headline = write_headline(main_df, bh_family)
    write_provenance(
        TABLES / "rq2_provenance.json",
        compute_script="analysis/scripts/rq2_compute.py",
        extra={"bh_family_definition": bh_family},
    )

    print(
        f"RQ2: n_AI={int(main_df.loc[main_df['family'] == 'category', 'n_AI'].iloc[0])} "
        f"n_ctrl={int(main_df.loc[main_df['family'] == 'category', 'n_ctrl'].iloc[0])}"
    )
    print(
        f"  categories BH-sig (AI > Ctrl): "
        f"{headline['n_categories_BH_sig_AI_gt_ctrl']} / {len(CATEGORIES)}"
    )
    print(
        f"  tools BH-sig (AI > Ctrl): "
        f"{headline['n_tools_BH_sig_AI_gt_ctrl']} / "
        f"{len(TOOL_COLUMNS) - len(bh_family['sparse_band_excluded'])} "
        f"(sparse-excluded: {len(bh_family['sparse_band_excluded'])})"
    )
    print(f"  underpowered families: {headline['n_underpowered_families']}")
    print(f"  sparse-band excluded: {bh_family['sparse_band_excluded']}")


if __name__ == "__main__":
    main()
