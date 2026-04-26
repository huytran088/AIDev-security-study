"""RQ1 — adoption of security tooling in AI repos.

Inputs:
    data_derived/latest/repo_security_adoption_wide.parquet  (cohort + flags)
    data_derived/latest/ai_repos.csv                          (stars, language)
    data_derived/latest/_ai_repos_enriched.parquet            (created_at,
                                                              owner_type,
                                                              pushed_at)

Outputs:
    analysis/tables/rq1_main.csv               -- per (tool, breakdown)
    analysis/tables/rq1_adoption_by_tool.csv
    analysis/tables/rq1_adoption_by_category.csv
    analysis/tables/rq1_adoption_by_language.csv
    analysis/tables/rq1_provenance.json
    analysis/tables/rq1_headline.json
    analysis/figures/rq1_adoption_by_tool.{png,pdf}
    analysis/figures/rq1_adoption_by_category.{png,pdf}
    analysis/figures/rq1_adoption_by_language.{png,pdf}
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

from provenance import write_provenance

warnings.filterwarnings("ignore", message=".*Maximum Likelihood optimization failed.*")
warnings.filterwarnings("ignore", category=RuntimeWarning, module="statsmodels.*")
warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*divide by zero.*")
warnings.filterwarnings(
    "ignore", category=RuntimeWarning, message=".*invalid value encountered.*"
)

REPO = Path(__file__).resolve().parents[2]
LATEST = REPO / "data_derived" / "latest"
TABLES = REPO / "analysis" / "tables"
FIGS = REPO / "analysis" / "figures"

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


def stars_bin(stars: int) -> str:
    if stars < 200:
        return "100-199"
    if stars < 500:
        return "200-499"
    if stars < 1000:
        return "500-999"
    return "1000+"


def load_ai_repo_features() -> pd.DataFrame:
    """Build the AI-repo covariate frame for the optional logit and the
    cross-tabs. Joins the wide adoption table to ai_repos.csv (for stars,
    language) and the enriched parquet (for created_at, owner_type)."""
    wide = pd.read_parquet(LATEST / "repo_security_adoption_wide.parquet")
    ai = wide[wide["cohort"] == "AI"].copy()

    meta = pd.read_csv(LATEST / "ai_repos.csv")
    enriched = pd.read_parquet(LATEST / "_ai_repos_enriched.parquet")
    enriched = enriched.rename(
        columns={
            "created_at_gh": "created_at",
            "language_gh": "language_gh",
            "stars_gh": "stars_gh",
        }
    )

    df = ai.merge(
        meta[["repo_full_name", "stars", "language"]], on="repo_full_name", how="left"
    )
    df = df.merge(
        enriched[["repo_full_name", "created_at", "owner_type", "pushed_at_gh"]],
        on="repo_full_name",
        how="left",
    )

    df["stars"] = df["stars"].fillna(0).astype(int)
    df["language"] = df["language"].fillna("Unknown")
    df["owner_type"] = df["owner_type"].fillna("Unknown")
    df["log_stars"] = np.log1p(df["stars"])
    df["stars_bin"] = df["stars"].map(stars_bin)
    # repo_age_days: window_end - created_at
    window_end = pd.Timestamp(os.environ.get("WINDOW_END", "2025-07-31"), tz="UTC")
    df["repo_age_days"] = (window_end - df["created_at"]).dt.days.fillna(0)
    # activity = days since pushed_at (lower = more active); use log days.
    df["pushed_at_gh"] = pd.to_datetime(df["pushed_at_gh"], utc=True)
    days_since_push = (window_end - df["pushed_at_gh"]).dt.days.fillna(365)
    df["log_days_since_push"] = np.log1p(days_since_push.clip(lower=0))
    return df


def adoption_by_tool(df_ai: pd.DataFrame) -> pd.DataFrame:
    n_ai = len(df_ai)
    rows = []
    for col in TOOL_COLUMNS:
        tool = col.removeprefix("tool_")
        n_yes = int(df_ai[col].sum())
        rate = n_yes / n_ai if n_ai else float("nan")
        rows.append(
            {
                "tool": tool,
                "n_ai_repos": n_ai,
                "n_configured": n_yes,
                "adoption_rate": round(rate, 6),
                "adoption_pct": round(100 * rate, 3),
            }
        )
    return (
        pd.DataFrame(rows)
        .sort_values("adoption_rate", ascending=False)
        .reset_index(drop=True)
    )


def adoption_by_category(df_ai: pd.DataFrame) -> pd.DataFrame:
    n_ai = len(df_ai)
    rows = []
    for col in CATEGORIES:
        category = col.removesuffix("_any")
        n_yes = int(df_ai[col].sum())
        rate = n_yes / n_ai if n_ai else float("nan")
        rows.append(
            {
                "category": category,
                "n_ai_repos": n_ai,
                "n_configured": n_yes,
                "adoption_rate": round(rate, 6),
                "adoption_pct": round(100 * rate, 3),
            }
        )
    return (
        pd.DataFrame(rows)
        .sort_values("adoption_rate", ascending=False)
        .reset_index(drop=True)
    )


def adoption_by_language(df_ai: pd.DataFrame, top_k: int = 10) -> pd.DataFrame:
    """Per top-K language: per-category and any_security_tool rate."""
    df_ai = df_ai.copy()
    df_ai["any_tool"] = df_ai[TOOL_COLUMNS].any(axis=1)
    counts = df_ai["language"].value_counts()
    top_langs = counts.head(top_k).index.tolist()
    rows = []
    for lang in top_langs:
        sub = df_ai[df_ai["language"] == lang]
        row = {
            "language": lang,
            "n_ai_repos": int(len(sub)),
            "any_tool_pct": round(100 * sub["any_tool"].mean(), 3),
        }
        for col in CATEGORIES:
            row[col.removesuffix("_any") + "_pct"] = round(100 * sub[col].mean(), 3)
        rows.append(row)
    return (
        pd.DataFrame(rows)
        .sort_values("n_ai_repos", ascending=False)
        .reset_index(drop=True)
    )


def cross_tab_stars(df_ai: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for sb in ["100-199", "200-499", "500-999", "1000+"]:
        sub = df_ai[df_ai["stars_bin"] == sb]
        if sub.empty:
            continue
        any_tool = sub[TOOL_COLUMNS].any(axis=1).mean()
        row = {
            "stars_bin": sb,
            "n_ai_repos": int(len(sub)),
            "any_tool_pct": round(100 * any_tool, 3),
        }
        for col in CATEGORIES:
            row[col.removesuffix("_any") + "_pct"] = round(100 * sub[col].mean(), 3)
        rows.append(row)
    return pd.DataFrame(rows)


def run_logit_optional(df_ai: pd.DataFrame) -> pd.DataFrame:
    """Logit per category: tool ~ log(stars) + language + repo_age + activity
    + owner_type, with HC1 robust SE. One row per (category, term)."""
    rows = []
    df = df_ai.copy()
    # Collapse rare languages to keep degrees of freedom sane.
    lang_counts = df["language"].value_counts()
    keep_langs = lang_counts[lang_counts >= 30].index
    df["language_grp"] = df["language"].where(
        df["language"].isin(keep_langs), other="Other"
    )
    df["owner_type_grp"] = df["owner_type"].where(
        df["owner_type"].isin(["User", "Organization"]),
        other="Other",
    )

    import statsmodels.formula.api as smf

    for col in CATEGORIES:
        try:
            m = smf.glm(
                f"{col} ~ log_stars + C(language_grp) + repo_age_days + "
                f"log_days_since_push + C(owner_type_grp)",
                data=df,
                family=sm.families.Binomial(),
            ).fit(cov_type="HC1", disp=False)
        except Exception as e:  # noqa: BLE001
            rows.append(
                {
                    "category": col.removesuffix("_any"),
                    "term": "FIT_FAILED",
                    "coef": None,
                    "std_err": None,
                    "p_value": None,
                    "or_": None,
                    "ci_lo": None,
                    "ci_hi": None,
                    "n_obs": int(len(df)),
                    "note": str(e)[:200],
                }
            )
            continue
        for term in m.params.index:
            ci = m.conf_int().loc[term]
            rows.append(
                {
                    "category": col.removesuffix("_any"),
                    "term": term,
                    "coef": float(m.params[term]),
                    "std_err": float(m.bse[term]),
                    "p_value": float(m.pvalues[term]),
                    "or_": float(np.exp(m.params[term])),
                    "ci_lo": float(np.exp(ci[0])),
                    "ci_hi": float(np.exp(ci[1])),
                    "n_obs": int(m.nobs),
                    "note": "",
                }
            )
    return pd.DataFrame(rows)


def make_figures(
    by_tool: pd.DataFrame, by_cat: pd.DataFrame, by_lang: pd.DataFrame
) -> None:
    FIGS.mkdir(parents=True, exist_ok=True)

    # 1) by tool
    fig, ax = plt.subplots(figsize=(10, 6))
    bt = by_tool.sort_values("adoption_pct", ascending=True)
    ax.barh(bt["tool"], bt["adoption_pct"], color="#3b6db8")
    ax.set_xlabel("Adoption rate in AI repos (%)")
    ax.set_title(
        "RQ1 — Per-tool adoption among AI repos (n="
        f"{int(by_tool['n_ai_repos'].iloc[0])} repos)"
    )
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"rq1_adoption_by_tool.{ext}", dpi=300)
    plt.close(fig)

    # 2) by category
    fig, ax = plt.subplots(figsize=(7, 4))
    bc = by_cat.sort_values("adoption_pct", ascending=True)
    ax.barh(bc["category"], bc["adoption_pct"], color="#3b9b7a")
    ax.set_xlabel("Adoption rate in AI repos (%)")
    ax.set_title("RQ1 — Category-level adoption among AI repos")
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"rq1_adoption_by_category.{ext}", dpi=300)
    plt.close(fig)

    # 3) by language (stacked categories)
    cat_cols = [c.removesuffix("_any") + "_pct" for c in CATEGORIES]
    bl = by_lang.set_index("language")[cat_cols]
    fig, ax = plt.subplots(figsize=(10, 5))
    bl.plot(kind="bar", ax=ax, width=0.85)
    ax.set_ylabel("Adoption rate in AI repos (%)")
    ax.set_title("RQ1 — Category adoption by primary language (top-10)")
    ax.legend(title="category", bbox_to_anchor=(1.02, 1), loc="upper left")
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"rq1_adoption_by_language.{ext}", dpi=300)
    plt.close(fig)


def assemble_main_csv(
    by_tool: pd.DataFrame,
    by_cat: pd.DataFrame,
    by_lang: pd.DataFrame,
    by_stars: pd.DataFrame,
    logit_df: pd.DataFrame,
) -> pd.DataFrame:
    """Long-form rq1_main.csv with one row per (breakdown, level)."""
    rows = []
    for r in by_tool.itertuples(index=False):
        rows.append(
            {
                "breakdown": "tool",
                "level": r.tool,
                "n_ai_repos": r.n_ai_repos,
                "n_configured": r.n_configured,
                "adoption_pct": r.adoption_pct,
            }
        )
    for r in by_cat.itertuples(index=False):
        rows.append(
            {
                "breakdown": "category",
                "level": r.category,
                "n_ai_repos": r.n_ai_repos,
                "n_configured": r.n_configured,
                "adoption_pct": r.adoption_pct,
            }
        )
    for r in by_lang.itertuples(index=False):
        rows.append(
            {
                "breakdown": "language",
                "level": r.language,
                "n_ai_repos": r.n_ai_repos,
                "n_configured": None,
                "adoption_pct": r.any_tool_pct,
            }
        )
    for r in by_stars.itertuples(index=False):
        rows.append(
            {
                "breakdown": "stars_bin",
                "level": r.stars_bin,
                "n_ai_repos": r.n_ai_repos,
                "n_configured": None,
                "adoption_pct": r.any_tool_pct,
            }
        )
    return pd.DataFrame(rows)


def write_headline(
    df_ai: pd.DataFrame,
    by_tool: pd.DataFrame,
    by_cat: pd.DataFrame,
    n_ai: int,
) -> None:
    sorted_tools = by_tool.sort_values("adoption_pct", ascending=False)
    top3 = sorted_tools.head(3)[["tool", "adoption_pct"]].to_dict("records")
    bot3 = sorted_tools.tail(3)[["tool", "adoption_pct"]].to_dict("records")
    sorted_cats = by_cat.sort_values("adoption_pct", ascending=False)
    any_tool_rate = df_ai[TOOL_COLUMNS].any(axis=1).mean()
    headline = {
        "n_ai_repos": int(n_ai),
        "any_tool_pct": float(round(100 * any_tool_rate, 3)),
        "top3_tools": top3,
        "bottom3_tools": bot3,
        "top_category": sorted_cats.iloc[0].to_dict() if len(sorted_cats) else {},
        "bottom_category": sorted_cats.iloc[-1].to_dict() if len(sorted_cats) else {},
    }
    (TABLES / "rq1_headline.json").write_text(
        json.dumps(headline, indent=2, sort_keys=True)
    )


def main() -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    df_ai = load_ai_repo_features()
    n_ai = len(df_ai)

    by_tool = adoption_by_tool(df_ai)
    by_cat = adoption_by_category(df_ai)
    by_lang = adoption_by_language(df_ai)
    by_stars = cross_tab_stars(df_ai)
    logit_df = run_logit_optional(df_ai)

    by_tool.to_csv(TABLES / "rq1_adoption_by_tool.csv", index=False)
    by_cat.to_csv(TABLES / "rq1_adoption_by_category.csv", index=False)
    by_lang.to_csv(TABLES / "rq1_adoption_by_language.csv", index=False)
    by_stars.to_csv(TABLES / "rq1_adoption_by_stars.csv", index=False)
    logit_df.to_csv(TABLES / "rq1_logit_terms.csv", index=False)

    main_df = assemble_main_csv(by_tool, by_cat, by_lang, by_stars, logit_df)
    main_df.to_csv(TABLES / "rq1_main.csv", index=False)

    make_figures(by_tool, by_cat, by_lang)
    write_headline(df_ai, by_tool, by_cat, n_ai)
    write_provenance(
        TABLES / "rq1_provenance.json",
        compute_script="analysis/scripts/rq1_compute.py",
    )

    print(f"RQ1: n_ai_repos={n_ai}")
    print(f"  by-tool: {len(by_tool)} rows")
    print(f"  by-cat:  {len(by_cat)} rows")
    print(f"  by-lang: {len(by_lang)} rows")
    print(f"  main:    {len(main_df)} rows")
    print(
        f"  top3 tools by AI %: "
        f"{by_tool.head(3)[['tool', 'adoption_pct']].to_dict('records')}"
    )
    print(
        f"  bot3 tools by AI %: "
        f"{by_tool.tail(3)[['tool', 'adoption_pct']].to_dict('records')}"
    )


if __name__ == "__main__":
    main()
