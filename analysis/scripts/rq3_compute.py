"""RQ3 — agentic vs human PR security interventions, within AI repos.

Operator-locked decisions baked in (Phase E orchestration brief, 2026-04-26):
  - Singleton-repo drop is mandatory before fitting FE models.
  - `any_changes_requested_by_security_tool` is SKIPPED entirely
    (~1 expected positive event on the agentic arm; structurally dead).
  - NB convergence falls back to Poisson + cluster-robust SE if
    `fit_regularized()` fails or rejects `cov_type='cluster'`.

Outputs:
    analysis/tables/rq3_main.csv
    analysis/tables/rq3_provenance.json
    analysis/tables/rq3_headline.json
    analysis/figures/rq3_*.{png,pdf}
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
import patsy
import statsmodels.api as sm
import statsmodels.formula.api as smf
from scipy.stats import mannwhitneyu

from effect_sizes import cliffs_delta
from provenance import write_provenance

warnings.filterwarnings("ignore", category=RuntimeWarning)
warnings.filterwarnings("ignore", message=".*Maximum Likelihood optimization failed.*")
warnings.filterwarnings("ignore", message=".*PerfectSeparationWarning.*")
warnings.filterwarnings("ignore", message=".*Inverting hessian failed.*")
warnings.filterwarnings("ignore", message=".*overflow encountered.*")

REPO = Path(__file__).resolve().parents[2]
LATEST = REPO / "data_derived" / "latest"
TABLES = REPO / "analysis" / "tables"
FIGS = REPO / "analysis" / "figures"

SEED = int(os.environ.get("RANDOM_SEED", "20260101"))
RNG = np.random.default_rng(SEED)


# --------------------------------------------------------------------------
# Data prep — singleton drop + covariates
# --------------------------------------------------------------------------
def prep_fe_frame(
    df_in: pd.DataFrame, *, min_task_count: int = 5
) -> tuple[pd.DataFrame, dict]:
    """Apply singleton-repo drop and encode covariates for FE models."""
    df = df_in.copy()

    # Singleton drop: keep only repos with both agentic & human PRs.
    keep = df.groupby("repo_full_name")["pr_type"].nunique().loc[lambda s: s == 2].index
    n_repos_before = df["repo_full_name"].nunique()
    n_rows_before = len(df)
    df = df[df["repo_full_name"].isin(keep)].copy()
    n_repos_dropped = n_repos_before - df["repo_full_name"].nunique()
    n_rows_dropped = n_rows_before - len(df)

    # Encode binaries / log-churn / time index
    df["agentic"] = (df["pr_type"] == "agentic").astype(int)
    # smf.logit barfs on bool endog; cast outcome columns to int.
    for col in ("any_security_intervention", "rejected"):
        if col in df.columns:
            df[col] = df[col].astype(int)
    df["log_churn"] = np.log1p(df["churn"].astype(float).clip(lower=0))
    df["time_idx"] = (
        df["created_at"] - pd.Timestamp("2025-01-01", tz="UTC")
    ).dt.days.astype(float)
    df["repo_id"] = df["repo_full_name"].astype("category").cat.codes

    # Bucket sparse task_type levels (and stringify empty -> "_unlabeled").
    df["task_type"] = df["task_type"].fillna("").replace("", "_unlabeled")
    counts = df["task_type"].value_counts()
    keep_levels = counts[counts >= min_task_count].index
    n_levels_dropped = int((counts < min_task_count).sum())
    df["task_type_grp"] = df["task_type"].where(
        df["task_type"].isin(keep_levels), other="_other"
    )

    # Stable order so two runs on the same parquet produce identical numbers.
    df = df.sort_values(["repo_id", "created_at"]).reset_index(drop=True)

    diag = {
        "n_repos_before": int(n_repos_before),
        "n_repos_after": int(df["repo_full_name"].nunique()),
        "n_repos_dropped_singleton": int(n_repos_dropped),
        "n_rows_before": int(n_rows_before),
        "n_rows_after": int(len(df)),
        "n_rows_dropped_singleton": int(n_rows_dropped),
        "n_levels_dropped_task_type": n_levels_dropped,
        "task_levels_kept": sorted(keep_levels.tolist()),
    }
    return df, diag


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------
def fit_logit_fe(df: pd.DataFrame, outcome: str, *, extra_terms: str = "") -> dict:
    """Repo-FE logit with cluster SE on repo_id.

    Note: `task_type` is perfectly collinear with `agentic` in this cohort
    because the AIDev `pr_task_type` table only labels agentic PRs (human
    PRs all have `task_type=='_unlabeled'`). Including `C(task_type_grp)`
    in the RHS would absorb the agentic indicator. We drop it from the
    primary RHS and surface the covariate-availability constraint in the
    provenance JSON. Run-level diagnostics still record what was kept.
    """
    extra = f" + {extra_terms}" if extra_terms else ""
    # Drop repos with no within-variation in the outcome (all-0 or all-1).
    # Such repos contribute zero to the conditional likelihood and produce
    # singular hessians when included as dummies.
    g = df.groupby("repo_id")[outcome]
    has_var = g.transform("min") != g.transform("max")
    df_in = df.loc[has_var].copy()
    n_repos_no_var = int(df["repo_id"].nunique() - df_in["repo_id"].nunique())
    n_rows_no_var = int(len(df) - len(df_in))
    if df_in.empty:
        return {
            "model": "logit_fe",
            "outcome": outcome,
            "coef_agentic": None,
            "or_or_irr": None,
            "ci95_lo": None,
            "ci95_hi": None,
            "se_agentic": None,
            "p_raw": None,
            "n_obs": 0,
            "n_repos": 0,
            "converged": False,
            "alpha": None,
            "fallback_to_poisson": False,
            "se_basis": None,
            "n_repos_no_within_variation": n_repos_no_var,
            "n_rows_no_within_variation": n_rows_no_var,
            "error": "all repos have constant outcome — model unidentified",
        }
    formula = f"{outcome} ~ agentic{extra} + log_churn + time_idx + C(repo_id)"
    se_basis = "cluster"
    try:
        m = smf.logit(formula, data=df_in).fit(
            cov_type="cluster",
            cov_kwds={"groups": df_in["repo_id"]},
            method="newton",
            maxiter=300,
            disp=False,
        )
        # If the clustered sandwich produced NaN SE for the agentic term
        # (rank-deficient with ~600 FE cols vs 588 clusters), refit with
        # HC1 and tag the basis.
        if not np.isfinite(m.bse.get("agentic", np.nan)):
            m = smf.logit(formula, data=df_in).fit(
                cov_type="HC1", method="newton", maxiter=300, disp=False
            )
            se_basis = "HC1_fallback_cluster_rank_deficient"
        coef = float(m.params["agentic"])
        ci = m.conf_int().loc["agentic"]
        return {
            "model": "logit_fe",
            "outcome": outcome,
            "coef_agentic": coef,
            "or_or_irr": float(np.exp(coef)),
            "ci95_lo": float(np.exp(ci[0])),
            "ci95_hi": float(np.exp(ci[1])),
            "se_agentic": float(m.bse["agentic"]),
            "p_raw": float(m.pvalues["agentic"]),
            "n_obs": int(m.nobs),
            "n_repos": int(df_in["repo_id"].nunique()),
            "converged": bool(m.mle_retvals.get("converged", True)),
            "alpha": None,
            "fallback_to_poisson": False,
            "se_basis": se_basis,
            "n_repos_no_within_variation": n_repos_no_var,
            "n_rows_no_within_variation": n_rows_no_var,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "model": "logit_fe",
            "outcome": outcome,
            "coef_agentic": None,
            "or_or_irr": None,
            "ci95_lo": None,
            "ci95_hi": None,
            "se_agentic": None,
            "p_raw": None,
            "n_obs": None,
            "n_repos": int(df_in["repo_id"].nunique()),
            "converged": False,
            "alpha": None,
            "fallback_to_poisson": False,
            "se_basis": se_basis,
            "n_repos_no_within_variation": n_repos_no_var,
            "n_rows_no_within_variation": n_rows_no_var,
            "error": str(e)[:200],
        }


def fit_count_fe(df: pd.DataFrame, outcome: str) -> dict:
    """NB FE first; on failure / non-convergence, fall back to Poisson +
    cluster-robust SE (quasi-likelihood). Always reports IRR + CI + α̂ +
    log-likelihood + convergence status."""
    # task_type dropped here for the same reason as in fit_logit_fe:
    # it is perfectly collinear with `agentic` because human PRs are
    # always `_unlabeled` in the AIDev `pr_task_type` table.
    formula = "agentic + log_churn + time_idx + C(repo_id)"
    X = patsy.dmatrix(formula, data=df, return_type="dataframe")
    y = df[outcome].astype(float).values

    nb_ok = False
    nb_alpha = None
    nb_loglike = None
    nb_converged = False
    m_nb = None
    try:
        m_nb = sm.NegativeBinomial(y, X).fit(method="newton", maxiter=300, disp=False)
        nb_converged = bool(m_nb.mle_retvals.get("converged", False))
        # statsmodels NB writes alpha in params under name 'alpha'
        nb_alpha = float(m_nb.params["alpha"]) if "alpha" in m_nb.params.index else None
        nb_loglike = float(m_nb.llf)
        # Verify the CI is finite — sometimes NB converges with degenerate hessian.
        ci = m_nb.conf_int().loc["agentic"]
        if (
            nb_converged
            and np.isfinite(m_nb.params["agentic"])
            and np.isfinite(ci[0])
            and np.isfinite(ci[1])
        ):
            nb_ok = True
    except Exception as e:  # noqa: BLE001
        m_nb = None
        nb_error = str(e)[:200]
        nb_converged = False
        nb_loglike = None
        # nb_alpha already None
        # we'll fall through to Poisson fallback
        nb_error_first = nb_error  # noqa: F841

    if nb_ok and m_nb is not None:
        coef = float(m_nb.params["agentic"])
        ci = m_nb.conf_int().loc["agentic"]
        return {
            "model": "negative_binomial",
            "outcome": outcome,
            "coef_agentic": coef,
            "or_or_irr": float(np.exp(coef)),
            "ci95_lo": float(np.exp(ci[0])),
            "ci95_hi": float(np.exp(ci[1])),
            "se_agentic": float(m_nb.bse["agentic"]),
            "p_raw": float(m_nb.pvalues["agentic"]),
            "n_obs": int(m_nb.nobs),
            "n_repos": int(df["repo_id"].nunique()),
            "converged": True,
            "alpha": nb_alpha,
            "log_likelihood": nb_loglike,
            "fallback_to_poisson": False,
            "se_basis": "nb_mle",
        }

    # Fallback: Poisson + cluster-robust SE (quasi-likelihood). With ~600
    # FE columns and 588 clusters the clustered sandwich is rank-deficient
    # and yields NaN SEs; in that case fall back further to HC1 and tag
    # the row so the SE basis is traceable in the run manifest.
    se_basis = "cluster"
    try:
        m_p = sm.GLM(y, X, family=sm.families.Poisson()).fit(
            cov_type="cluster",
            cov_kwds={"groups": df["repo_id"]},
        )
        if not np.isfinite(m_p.bse.get("agentic", np.nan)):
            # Cluster sandwich produced NaN SE — refit with HC1.
            m_p = sm.GLM(y, X, family=sm.families.Poisson()).fit(cov_type="HC1")
            se_basis = "HC1_fallback_cluster_rank_deficient"
        coef = float(m_p.params["agentic"])
        ci = m_p.conf_int().loc["agentic"]
        return {
            "model": "poisson_quasi",
            "outcome": outcome,
            "coef_agentic": coef,
            "or_or_irr": float(np.exp(coef)),
            "ci95_lo": float(np.exp(ci[0])),
            "ci95_hi": float(np.exp(ci[1])),
            "se_agentic": float(m_p.bse["agentic"]),
            "p_raw": float(m_p.pvalues["agentic"]),
            "n_obs": int(m_p.nobs),
            "n_repos": int(df["repo_id"].nunique()),
            "converged": bool(m_p.converged),
            "alpha": nb_alpha,  # carry the NB α even though we used Poisson
            "log_likelihood": float(m_p.llf),
            "fallback_to_poisson": True,
            "se_basis": se_basis,
            "nb_failure_reason": (
                "nb_did_not_converge"
                if (m_nb is not None and not nb_converged)
                else "nb_fit_raised"
            ),
        }
    except Exception as e:  # noqa: BLE001
        return {
            "model": "poisson_quasi",
            "outcome": outcome,
            "coef_agentic": None,
            "or_or_irr": None,
            "ci95_lo": None,
            "ci95_hi": None,
            "se_agentic": None,
            "p_raw": None,
            "n_obs": None,
            "n_repos": int(df["repo_id"].nunique()),
            "converged": False,
            "alpha": nb_alpha,
            "log_likelihood": None,
            "fallback_to_poisson": True,
            "error": str(e)[:200],
        }


# --------------------------------------------------------------------------
# Secondary nonparametric checks
# --------------------------------------------------------------------------
def secondary_tests(df: pd.DataFrame) -> dict:
    """Mann-Whitney U on counts after within-repo matching, Cliff's δ on
    any_security_intervention. Returns a flat dict of summary stats."""
    out = {}

    # Cliff's δ on any_security_intervention (binary 0/1 -> δ via cross-pairs)
    a = (
        df.loc[df["pr_type"] == "agentic", "any_security_intervention"]
        .astype(int)
        .values
    )
    h = df.loc[df["pr_type"] == "human", "any_security_intervention"].astype(int).values
    delta, mag = cliffs_delta(a, h)
    out["cliffs_delta_any_intervention"] = float(delta)
    out["cliffs_delta_any_intervention_magnitude"] = mag
    out["n_agentic_for_delta"] = int(a.size)
    out["n_human_for_delta"] = int(h.size)

    # Mann-Whitney U on security_intervention_count after within-repo matching:
    # for each repo, take min(n_agentic, n_human) PRs from each side (random
    # by RNG) and concatenate. Robust to repo-size imbalance.
    parts_a, parts_h = [], []
    for _, g in df.groupby("repo_full_name", sort=False):
        ga = g[g["pr_type"] == "agentic"]["security_intervention_count"].values
        gh = g[g["pr_type"] == "human"]["security_intervention_count"].values
        k = min(len(ga), len(gh))
        if k == 0:
            continue
        sel_a = RNG.choice(ga, size=k, replace=False)
        sel_h = RNG.choice(gh, size=k, replace=False)
        parts_a.append(sel_a)
        parts_h.append(sel_h)
    if parts_a:
        mat_a = np.concatenate(parts_a)
        mat_h = np.concatenate(parts_h)
        try:
            u_stat, u_p = mannwhitneyu(mat_a, mat_h, alternative="two-sided")
            out["mannwhitney_u_count"] = float(u_stat)
            out["mannwhitney_p_count"] = float(u_p)
            out["mannwhitney_n_pairs"] = int(mat_a.size)
        except Exception as e:  # noqa: BLE001
            out["mannwhitney_u_count"] = None
            out["mannwhitney_p_count"] = None
            out["mannwhitney_error"] = str(e)[:200]
    else:
        out["mannwhitney_u_count"] = None
        out["mannwhitney_p_count"] = None
    return out


# --------------------------------------------------------------------------
# Build main table
# --------------------------------------------------------------------------
def build_main(df_fe: pd.DataFrame, diag: dict) -> tuple[pd.DataFrame, list[dict]]:
    """Returns (main_df, fitted_results)."""
    fits = []
    fits.append(fit_logit_fe(df_fe, "any_security_intervention"))
    fits.append(fit_count_fe(df_fe, "security_intervention_count"))
    fits.append(
        fit_logit_fe(df_fe, "rejected", extra_terms="any_security_intervention")
    )

    rows = []
    for r in fits:
        rows.append(
            {
                "outcome": r["outcome"],
                "model": r["model"],
                "n_obs": r.get("n_obs"),
                "n_repos": r.get("n_repos"),
                "coef_agentic": r.get("coef_agentic"),
                "or_or_irr": r.get("or_or_irr"),
                "ci95_lo": r.get("ci95_lo"),
                "ci95_hi": r.get("ci95_hi"),
                "se_agentic": r.get("se_agentic"),
                "se_basis": r.get("se_basis"),
                "p_raw": r.get("p_raw"),
                "converged": r.get("converged"),
                "alpha": r.get("alpha"),
                "log_likelihood": r.get("log_likelihood"),
                "fallback_to_poisson": r.get("fallback_to_poisson", False),
                "singleton_drop": diag["n_repos_dropped_singleton"],
                "n_repos_dropped_singleton": diag["n_repos_dropped_singleton"],
                "n_rows_dropped_singleton": diag["n_rows_dropped_singleton"],
                "n_levels_dropped_task_type": diag["n_levels_dropped_task_type"],
                "error": r.get("error"),
                "nb_failure_reason": r.get("nb_failure_reason"),
            }
        )

    return pd.DataFrame(rows), fits


# --------------------------------------------------------------------------
# Figures
# --------------------------------------------------------------------------
def make_figures(df_fe: pd.DataFrame, main_df: pd.DataFrame) -> None:
    FIGS.mkdir(parents=True, exist_ok=True)

    # 1) Forest plot — agentic vs human OR/IRR for the three outcomes.
    fig, ax = plt.subplots(figsize=(8, 4))
    rows = main_df[main_df["or_or_irr"].notna()]
    y = np.arange(len(rows))[::-1]
    log_or = np.log(rows["or_or_irr"].astype(float).values)
    log_lo = np.log(rows["ci95_lo"].astype(float).values)
    log_hi = np.log(rows["ci95_hi"].astype(float).values)
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
    ax.set_title("RQ3 — Within-repo effect of agentic authorship")
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"rq3_outcomes_forest.{ext}", dpi=300)
    plt.close(fig)

    # 2) Per-repo intervention-rate scatter (agentic vs human) for FE cohort.
    by_repo = (
        df_fe.groupby(["repo_full_name", "pr_type"])["any_security_intervention"]
        .mean()
        .unstack("pr_type")
        .dropna()
    )
    fig, ax = plt.subplots(figsize=(6, 6))
    ax.scatter(
        100 * by_repo["human"],
        100 * by_repo["agentic"],
        alpha=0.5,
        s=15,
        color="#3b6db8",
    )
    lim = max(
        100 * by_repo["human"].max(),
        100 * by_repo["agentic"].max(),
        5,
    )
    ax.plot([0, lim], [0, lim], color="#aaaaaa", linestyle="--", linewidth=0.8)
    ax.set_xlabel("Human PR intervention rate (%)")
    ax.set_ylabel("Agentic PR intervention rate (%)")
    ax.set_title(f"RQ3 — Per-repo intervention rates (n={len(by_repo)} FE repos)")
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"rq3_per_repo_rates.{ext}", dpi=300)
    plt.close(fig)


# --------------------------------------------------------------------------
# Headline
# --------------------------------------------------------------------------
def write_headline(main_df: pd.DataFrame, secondary: dict, diag: dict) -> dict:
    headline = {
        "n_repos_dropped_singleton": diag["n_repos_dropped_singleton"],
        "n_repos_after_singleton_drop": diag["n_repos_after"],
        "n_prs_after_singleton_drop": diag["n_rows_after"],
    }
    for _, r in main_df.iterrows():
        outc = r["outcome"]
        headline[outc] = {
            "model": r["model"],
            "or_or_irr": (
                round(float(r["or_or_irr"]), 4)
                if r["or_or_irr"] is not None and not pd.isna(r["or_or_irr"])
                else None
            ),
            "ci95_lo": (
                round(float(r["ci95_lo"]), 4)
                if r["ci95_lo"] is not None and not pd.isna(r["ci95_lo"])
                else None
            ),
            "ci95_hi": (
                round(float(r["ci95_hi"]), 4)
                if r["ci95_hi"] is not None and not pd.isna(r["ci95_hi"])
                else None
            ),
            "p_raw": (
                float(r["p_raw"])
                if r["p_raw"] is not None and not pd.isna(r["p_raw"])
                else None
            ),
            "converged": bool(r["converged"]),
            "alpha": (
                float(r["alpha"])
                if r["alpha"] is not None and not pd.isna(r["alpha"])
                else None
            ),
            "fallback_to_poisson": bool(r["fallback_to_poisson"]),
        }
    headline["secondary"] = secondary
    (TABLES / "rq3_headline.json").write_text(
        json.dumps(headline, indent=2, sort_keys=True, default=float)
    )
    return headline


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main() -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    df_in = pd.read_parquet(LATEST / "pr_interventions.parquet")
    df_fe, diag = prep_fe_frame(df_in)
    main_df, fits = build_main(df_fe, diag)
    main_df.to_csv(TABLES / "rq3_main.csv", index=False)

    secondary = secondary_tests(df_fe)
    make_figures(df_fe, main_df)
    headline = write_headline(main_df, secondary, diag)

    extra = {
        "fe_diagnostics": diag,
        "secondary_tests": secondary,
        "outcome_skipped_per_operator_decision": "any_changes_requested_by_security_tool",
    }
    write_provenance(
        TABLES / "rq3_provenance.json",
        compute_script="analysis/scripts/rq3_compute.py",
        extra=extra,
    )

    print(
        f"RQ3 FE cohort: {diag['n_repos_after']} repos, "
        f"{diag['n_rows_after']} PRs (dropped {diag['n_repos_dropped_singleton']} "
        f"singletons / {diag['n_rows_dropped_singleton']} rows)"
    )
    for _, r in main_df.iterrows():
        outc = r["outcome"]
        if r["or_or_irr"] is None or pd.isna(r["or_or_irr"]):
            print(f"  {outc} [{r['model']}]: FIT_FAILED ({r.get('error')})")
            continue
        ci = f"[{r['ci95_lo']:.3f}, {r['ci95_hi']:.3f}]"
        extra_tag = ""
        if r["model"] in ("negative_binomial", "poisson_quasi"):
            extra_tag = f" alpha={r['alpha']}" if r["alpha"] else ""
            if r["fallback_to_poisson"]:
                extra_tag += " (NB->Poisson fallback)"
        print(
            f"  {outc} [{r['model']}]: {('IRR' if 'count' in outc else 'OR')}="
            f"{r['or_or_irr']:.3f} {ci} p={r['p_raw']:.4g}"
            f" converged={r['converged']}{extra_tag}"
        )
    print(
        f"  Cliff's δ (any_intervention): "
        f"{secondary['cliffs_delta_any_intervention']:.4f} "
        f"({secondary['cliffs_delta_any_intervention_magnitude']})"
    )


if __name__ == "__main__":
    main()
