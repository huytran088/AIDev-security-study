"""Robustness battery for RQ2 and RQ3.

Per README §8 and the operator brief, runs a subset of robustness variants
and tabulates `delta_vs_primary` against the primary RQ2/RQ3 fits.

Variants implemented here:
  - V1 (deferred — data-miner): stricter vs relaxed agent_fingerprints.yaml
    for control screening. Recorded as `deferred — requires Phase B rerun`.
  - V2: drop dependency-update PRs (Dependabot/Renovate authors,
    is_dep_update==True) from RQ3 — refit primary models.
  - V3 (deferred — first_seen_at not collected in Phase C v1): time-aligned
    RQ3 (restrict each PR to repos where the relevant tool's
    first_seen_at <= PR creation).
  - V4: per-language stratification for RQ2 + RQ3 (top 5 languages).
  - V5: bot-identity-only intervention classifier (n_bot_identity_hits > 0
    only) vs primary bot+keyword for RQ3.

Outputs:
    analysis/tables/rq2_robustness.csv
    analysis/tables/rq3_robustness.csv
"""

from __future__ import annotations

import json
import os
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import patsy
import statsmodels.api as sm
import statsmodels.formula.api as smf
from scipy.stats import fisher_exact

from effect_sizes import odds_ratio_with_ci

warnings.filterwarnings("ignore", category=RuntimeWarning)
warnings.filterwarnings("ignore", message=".*Maximum Likelihood optimization failed.*")
warnings.filterwarnings("ignore", message=".*PerfectSeparationWarning.*")
warnings.filterwarnings("ignore", message=".*Inverting hessian failed.*")
warnings.filterwarnings("ignore", message=".*overflow encountered.*")

REPO = Path(__file__).resolve().parents[2]
LATEST = REPO / "data_derived" / "latest"
TABLES = REPO / "analysis" / "tables"

SEED = int(os.environ.get("RANDOM_SEED", "20260101"))

CATEGORIES = ["sast_any", "sca_any", "secrets_any", "fuzzing_any", "ci_hardening_any"]


# --------------------------------------------------------------------------
# RQ3 data prep (mirrors rq3_compute.prep_fe_frame)
# --------------------------------------------------------------------------
def prep_fe_frame(df_in: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    df = df_in.copy()
    keep = df.groupby("repo_full_name")["pr_type"].nunique().loc[lambda s: s == 2].index
    df = df[df["repo_full_name"].isin(keep)].copy()
    df["agentic"] = (df["pr_type"] == "agentic").astype(int)
    for col in ("any_security_intervention", "rejected"):
        if col in df.columns:
            df[col] = df[col].astype(int)
    df["log_churn"] = np.log1p(df["churn"].astype(float).clip(lower=0))
    df["time_idx"] = (
        df["created_at"] - pd.Timestamp("2025-01-01", tz="UTC")
    ).dt.days.astype(float)
    df["repo_id"] = df["repo_full_name"].astype("category").cat.codes
    df = df.sort_values(["repo_id", "created_at"]).reset_index(drop=True)
    diag = {
        "n_repos": int(df["repo_full_name"].nunique()),
        "n_rows": int(len(df)),
    }
    return df, diag


def fit_logit_fe_robust(
    df: pd.DataFrame, outcome: str, *, extra_terms: str = ""
) -> dict:
    g = df.groupby("repo_id")[outcome]
    has_var = g.transform("min") != g.transform("max")
    df_in = df.loc[has_var].copy()
    if df_in.empty or df_in["repo_id"].nunique() < 2:
        return {
            "or_or_irr": None,
            "ci95_lo": None,
            "ci95_hi": None,
            "p_raw": None,
            "n_obs": 0,
            "converged": False,
            "error": "no_within_variation",
        }
    extra = f" + {extra_terms}" if extra_terms else ""
    formula = f"{outcome} ~ agentic{extra} + log_churn + time_idx + C(repo_id)"
    try:
        m = smf.logit(formula, data=df_in).fit(
            cov_type="cluster",
            cov_kwds={"groups": df_in["repo_id"]},
            method="newton",
            maxiter=300,
            disp=False,
        )
        if not np.isfinite(m.bse.get("agentic", np.nan)):
            m = smf.logit(formula, data=df_in).fit(
                cov_type="HC1", method="newton", maxiter=300, disp=False
            )
        coef = float(m.params["agentic"])
        ci = m.conf_int().loc["agentic"]
        return {
            "or_or_irr": float(np.exp(coef)),
            "ci95_lo": float(np.exp(ci[0])),
            "ci95_hi": float(np.exp(ci[1])),
            "p_raw": float(m.pvalues["agentic"]),
            "n_obs": int(m.nobs),
            "converged": bool(m.mle_retvals.get("converged", True)),
            "error": None,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "or_or_irr": None,
            "ci95_lo": None,
            "ci95_hi": None,
            "p_raw": None,
            "n_obs": None,
            "converged": False,
            "error": str(e)[:200],
        }


def fit_count_fe_robust(df: pd.DataFrame, outcome: str) -> dict:
    formula = "agentic + log_churn + time_idx + C(repo_id)"
    try:
        X = patsy.dmatrix(formula, data=df, return_type="dataframe")
        y = df[outcome].astype(float).values
        m = sm.GLM(y, X, family=sm.families.Poisson()).fit(
            cov_type="cluster",
            cov_kwds={"groups": df["repo_id"]},
        )
        if not np.isfinite(m.bse.get("agentic", np.nan)):
            m = sm.GLM(y, X, family=sm.families.Poisson()).fit(cov_type="HC1")
        coef = float(m.params["agentic"])
        ci = m.conf_int().loc["agentic"]
        return {
            "or_or_irr": float(np.exp(coef)),
            "ci95_lo": float(np.exp(ci[0])),
            "ci95_hi": float(np.exp(ci[1])),
            "p_raw": float(m.pvalues["agentic"]),
            "n_obs": int(m.nobs),
            "converged": bool(m.converged),
            "error": None,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "or_or_irr": None,
            "ci95_lo": None,
            "ci95_hi": None,
            "p_raw": None,
            "n_obs": None,
            "converged": False,
            "error": str(e)[:200],
        }


# --------------------------------------------------------------------------
# Primary fits — for delta_vs_primary
# --------------------------------------------------------------------------
def primary_rq3() -> pd.DataFrame:
    df = pd.read_parquet(LATEST / "pr_interventions.parquet")
    df_fe, _ = prep_fe_frame(df)
    rows = []
    rows.append(
        {
            "outcome": "any_security_intervention",
            **fit_logit_fe_robust(df_fe, "any_security_intervention"),
        }
    )
    rows.append(
        {
            "outcome": "security_intervention_count",
            **fit_count_fe_robust(df_fe, "security_intervention_count"),
        }
    )
    rows.append(
        {
            "outcome": "rejected",
            **fit_logit_fe_robust(
                df_fe, "rejected", extra_terms="any_security_intervention"
            ),
        }
    )
    return pd.DataFrame(rows).set_index("outcome")


def primary_rq2() -> pd.DataFrame:
    """Per-category Fisher OR/CI on the full cohort."""
    wide = pd.read_parquet(LATEST / "repo_security_adoption_wide.parquet")
    rows = []
    for cat in CATEGORIES:
        ai = wide[wide["cohort"] == "AI"]
        ct = wide[wide["cohort"] == "Control"]
        a = int(ai[cat].sum())
        b = len(ai) - a
        c = int(ct[cat].sum())
        d = len(ct) - c
        or_, p = fisher_exact([[a, b], [c, d]])
        or_w, lo, hi = odds_ratio_with_ci(a, b, c, d)
        rows.append(
            {
                "category": cat.removesuffix("_any"),
                "or_or_irr": or_w,
                "ci95_lo": lo,
                "ci95_hi": hi,
                "p_raw": float(p),
                "ai_rate": a / max(len(ai), 1),
                "ctrl_rate": c / max(len(ct), 1),
                "n_AI": len(ai),
                "n_ctrl": len(ct),
            }
        )
    return pd.DataFrame(rows).set_index("category")


# --------------------------------------------------------------------------
# Variants
# --------------------------------------------------------------------------
def variant_v2_drop_dep_update_prs() -> list[dict]:
    """RQ3 refit after dropping is_dep_update==True PRs."""
    df = pd.read_parquet(LATEST / "pr_interventions.parquet")
    n_drop = int(df["is_dep_update"].sum())
    df = df[~df["is_dep_update"]].copy()
    df_fe, diag = prep_fe_frame(df)
    out = []
    for outcome, fitter, extra in [
        ("any_security_intervention", fit_logit_fe_robust, ""),
        ("security_intervention_count", fit_count_fe_robust, None),
        ("rejected", fit_logit_fe_robust, "any_security_intervention"),
    ]:
        if fitter is fit_count_fe_robust:
            res = fitter(df_fe, outcome)
        else:
            res = fitter(df_fe, outcome, extra_terms=extra)
        out.append(
            {
                "rq": "RQ3",
                "variant": "v2_drop_dep_update_prs",
                "outcome": outcome,
                "estimate_kind": "IRR" if "count" in outcome else "OR",
                "or_or_irr": res["or_or_irr"],
                "ci95_lo": res["ci95_lo"],
                "ci95_hi": res["ci95_hi"],
                "p_raw": res["p_raw"],
                "n_obs": res["n_obs"],
                "converged": res["converged"],
                "n_prs_dropped": n_drop,
                "n_repos_fe": diag["n_repos"],
                "n_rows_fe": diag["n_rows"],
                "error": res.get("error"),
            }
        )
    return out


def variant_v3_time_aligned() -> list[dict]:
    """Deferred — Phase C v1 did not collect first_seen_at."""
    return [
        {
            "rq": "RQ3",
            "variant": "v3_time_aligned",
            "outcome": outc,
            "estimate_kind": "IRR" if "count" in outc else "OR",
            "or_or_irr": None,
            "ci95_lo": None,
            "ci95_hi": None,
            "p_raw": None,
            "n_obs": None,
            "converged": False,
            "deferred": True,
            "deferred_reason": (
                "first_seen_at not collected in Phase C v1 — requires "
                "data-miner rerun with first_seen_at_collected=true"
            ),
        }
        for outc in (
            "any_security_intervention",
            "security_intervention_count",
            "rejected",
        )
    ]


def variant_v4_lang_strat_rq2(top_k: int = 5) -> list[dict]:
    """Per-language stratified RQ2 per-category Fisher."""
    wide = pd.read_parquet(LATEST / "repo_security_adoption_wide.parquet")

    ai_meta = pd.read_csv(LATEST / "ai_repos.csv")[["repo_full_name", "language"]]
    ctrl_meta = pd.read_csv(LATEST / "control_repos.csv")[
        ["repo_full_name", "language"]
    ]
    meta = pd.concat([ai_meta, ctrl_meta], ignore_index=True)
    df = wide.merge(meta, on="repo_full_name", how="left")
    df["language"] = df["language"].fillna("Unknown")

    top_langs = df["language"].value_counts().head(top_k).index.tolist()
    out = []
    for lang in top_langs:
        sub = df[df["language"] == lang]
        for cat in CATEGORIES:
            ai = sub[sub["cohort"] == "AI"]
            ct = sub[sub["cohort"] == "Control"]
            if len(ai) < 30 or len(ct) < 30:
                out.append(
                    {
                        "rq": "RQ2",
                        "variant": "v4_lang_strat",
                        "stratum": lang,
                        "outcome": cat.removesuffix("_any"),
                        "estimate_kind": "OR",
                        "or_or_irr": None,
                        "ci95_lo": None,
                        "ci95_hi": None,
                        "p_raw": None,
                        "n_AI": int(len(ai)),
                        "n_ctrl": int(len(ct)),
                        "skipped_reason": "n<30 in one arm",
                    }
                )
                continue
            a = int(ai[cat].sum())
            b = len(ai) - a
            c = int(ct[cat].sum())
            d = len(ct) - c
            try:
                _, p = fisher_exact([[a, b], [c, d]])
            except Exception:  # noqa: BLE001
                p = float("nan")
            or_w, lo, hi = odds_ratio_with_ci(a, b, c, d)
            out.append(
                {
                    "rq": "RQ2",
                    "variant": "v4_lang_strat",
                    "stratum": lang,
                    "outcome": cat.removesuffix("_any"),
                    "estimate_kind": "OR",
                    "or_or_irr": float(or_w),
                    "ci95_lo": float(lo),
                    "ci95_hi": float(hi),
                    "p_raw": float(p),
                    "n_AI": int(len(ai)),
                    "n_ctrl": int(len(ct)),
                    "ai_rate": a / max(len(ai), 1),
                    "ctrl_rate": c / max(len(ct), 1),
                }
            )
    return out


def variant_v4_lang_strat_rq3(top_k: int = 5) -> list[dict]:
    """Per-language stratified RQ3 (top-K language by repo count in FE cohort)."""
    df = pd.read_parquet(LATEST / "pr_interventions.parquet")
    ai_meta = pd.read_csv(LATEST / "ai_repos.csv")[["repo_full_name", "language"]]
    df = df.merge(ai_meta, on="repo_full_name", how="left")
    df["language"] = df["language"].fillna("Unknown")
    df_fe, _ = prep_fe_frame(df)
    top_langs = (
        df_fe.drop_duplicates("repo_full_name")["language"]
        .value_counts()
        .head(top_k)
        .index.tolist()
    )
    out = []
    for lang in top_langs:
        sub = df_fe[df_fe["language"] == lang].copy()
        # Re-run prep_fe_frame on the language slice to drop singletons that
        # became singletons after slicing.
        sub_fe, diag = prep_fe_frame(sub)
        for outcome, fitter, extra in [
            ("any_security_intervention", fit_logit_fe_robust, ""),
            ("security_intervention_count", fit_count_fe_robust, None),
            ("rejected", fit_logit_fe_robust, "any_security_intervention"),
        ]:
            if fitter is fit_count_fe_robust:
                res = fitter(sub_fe, outcome)
            else:
                res = fitter(sub_fe, outcome, extra_terms=extra)
            out.append(
                {
                    "rq": "RQ3",
                    "variant": "v4_lang_strat",
                    "stratum": lang,
                    "outcome": outcome,
                    "estimate_kind": "IRR" if "count" in outcome else "OR",
                    "or_or_irr": res["or_or_irr"],
                    "ci95_lo": res["ci95_lo"],
                    "ci95_hi": res["ci95_hi"],
                    "p_raw": res["p_raw"],
                    "n_obs": res["n_obs"],
                    "n_repos_fe": diag["n_repos"],
                    "n_rows_fe": diag["n_rows"],
                    "converged": res["converged"],
                    "error": res.get("error"),
                }
            )
    return out


def variant_v5_bot_identity_only() -> list[dict]:
    """Refit RQ3 with `is_intervention = is_known_security_bot` only — drop
    the secondary keyword signal. Reconstructs binary/count outcomes from
    n_bot_identity_hits."""
    df = pd.read_parquet(LATEST / "pr_interventions.parquet")
    df = df.copy()
    df["any_security_intervention"] = (df["n_bot_identity_hits"] > 0).astype(int)
    df["security_intervention_count"] = df["n_bot_identity_hits"].astype(int)
    df_fe, diag = prep_fe_frame(df)
    out = []
    for outcome, fitter, extra in [
        ("any_security_intervention", fit_logit_fe_robust, ""),
        ("security_intervention_count", fit_count_fe_robust, None),
        ("rejected", fit_logit_fe_robust, "any_security_intervention"),
    ]:
        if fitter is fit_count_fe_robust:
            res = fitter(df_fe, outcome)
        else:
            res = fitter(df_fe, outcome, extra_terms=extra)
        out.append(
            {
                "rq": "RQ3",
                "variant": "v5_bot_identity_only",
                "outcome": outcome,
                "estimate_kind": "IRR" if "count" in outcome else "OR",
                "or_or_irr": res["or_or_irr"],
                "ci95_lo": res["ci95_lo"],
                "ci95_hi": res["ci95_hi"],
                "p_raw": res["p_raw"],
                "n_obs": res["n_obs"],
                "converged": res["converged"],
                "n_repos_fe": diag["n_repos"],
                "n_rows_fe": diag["n_rows"],
                "error": res.get("error"),
            }
        )
    return out


def variant_v1_strict_relaxed_fingerprints() -> list[dict]:
    """Deferred — would require Phase B rerun."""
    return [
        {
            "rq": "RQ2",
            "variant": "v1_strict_relaxed_fingerprints",
            "outcome": cat.removesuffix("_any"),
            "estimate_kind": "OR",
            "or_or_irr": None,
            "ci95_lo": None,
            "ci95_hi": None,
            "p_raw": None,
            "deferred": True,
            "deferred_reason": (
                "requires Phase B rerun with stricter agent_fingerprints.yaml "
                "to regenerate the control cohort"
            ),
        }
        for cat in CATEGORIES
    ]


# --------------------------------------------------------------------------
# Compose final tables with delta_vs_primary
# --------------------------------------------------------------------------
def compose_rq3_table() -> pd.DataFrame:
    primary = primary_rq3()
    rows = []
    for batch in (
        variant_v2_drop_dep_update_prs(),
        variant_v3_time_aligned(),
        variant_v4_lang_strat_rq3(),
        variant_v5_bot_identity_only(),
    ):
        rows.extend(batch)
    df = pd.DataFrame(rows)

    # delta_vs_primary on log scale (so it's comparable for OR and IRR).
    def _delta(row):
        outc = row["outcome"]
        if outc not in primary.index:
            return None
        p = primary.loc[outc]
        if (
            row.get("or_or_irr") is None
            or pd.isna(row.get("or_or_irr"))
            or p["or_or_irr"] is None
            or pd.isna(p["or_or_irr"])
        ):
            return None
        return float(np.log(row["or_or_irr"]) - np.log(p["or_or_irr"]))

    df["delta_vs_primary_log"] = df.apply(_delta, axis=1)
    df["primary_or_or_irr"] = df["outcome"].map(primary["or_or_irr"])
    df["primary_p_raw"] = df["outcome"].map(primary["p_raw"])
    return df


def compose_rq2_table() -> pd.DataFrame:
    primary = primary_rq2()
    rows = []
    rows.extend(variant_v1_strict_relaxed_fingerprints())
    rows.extend(variant_v4_lang_strat_rq2())
    df = pd.DataFrame(rows)

    def _delta(row):
        cat = row["outcome"]
        if cat not in primary.index:
            return None
        p = primary.loc[cat]
        if (
            row.get("or_or_irr") is None
            or pd.isna(row.get("or_or_irr"))
            or p["or_or_irr"] is None
            or pd.isna(p["or_or_irr"])
        ):
            return None
        return float(np.log(row["or_or_irr"]) - np.log(p["or_or_irr"]))

    df["delta_vs_primary_log"] = df.apply(_delta, axis=1)
    df["primary_or_or_irr"] = df["outcome"].map(primary["or_or_irr"])
    df["primary_p_raw"] = df["outcome"].map(primary["p_raw"])
    return df


def main() -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    rq3_df = compose_rq3_table()
    rq2_df = compose_rq2_table()
    rq3_df.to_csv(TABLES / "rq3_robustness.csv", index=False)
    rq2_df.to_csv(TABLES / "rq2_robustness.csv", index=False)
    print(f"WROTE rq2_robustness.csv ({len(rq2_df)} rows)")
    print(f"WROTE rq3_robustness.csv ({len(rq3_df)} rows)")
    print()
    print("RQ3 robustness summary:")
    cols = ["variant", "outcome", "or_or_irr", "p_raw", "delta_vs_primary_log"]
    print(rq3_df[cols].to_string(index=False))


if __name__ == "__main__":
    main()
