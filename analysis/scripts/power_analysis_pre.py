"""Pre-flight MDE power table for Phase E (operator-locked, post-sign-off).

Operator decisions baked in (see Phase E orchestration brief, 2026-04-26):
  1. RQ2 MDEs unchanged, including rq2_secrets (OR=1.8) and rq2_fuzzing (OR=2.0).
     Both will be flagged UNDERPOWERED — that is by design, with the stipulation
     that any null result for these two families must be reported as
     "not informative — pre-flight power < 0.80" in REPORT.md §7.
  2. rq3_changes_requested is DROPPED entirely (~1 expected positive event on
     the agentic arm; structurally dead-on-arrival). It is not in TARGETS and
     `rq3_compute.py` does not fit the model.
  3. Sparse-band tools (control adoption rate < 1%) are excluded from the
     RQ2 BH-correction family — handled in `rq2_compute.py`, not here.

Closed-form math is identical to the candidate scratch script: two-proportion
power for binary outcomes with optional Kish design effect for clustered
RQ3 binary outcomes; closed-form Poisson IRR power inflated by the Kish
design effect for the RQ3 count outcome.

Each row is also tagged with `decision_locked_at_run_id`, set to the
`run_id` from `data_derived/latest/run_manifest.json`, so reviewers can
trace the MDE freeze to the Phase D rerun that informed it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import norm
from statsmodels.stats.power import NormalIndPower

REPO = Path(__file__).resolve().parents[2]
LATEST = REPO / "data_derived" / "latest"
TABLES = REPO / "analysis" / "tables"

SEED = int(os.environ.get("RANDOM_SEED", "20260101"))
np.random.default_rng(SEED)


# --------------------------------------------------------------------------
# Closed-form power helpers
# --------------------------------------------------------------------------
def cohens_h_from_or(p1: float, target_or: float) -> tuple[float, float]:
    odds1 = p1 / (1.0 - p1)
    odds2 = target_or * odds1
    p2 = odds2 / (1.0 + odds2)
    h = 2.0 * (np.arcsin(np.sqrt(p2)) - np.arcsin(np.sqrt(p1)))
    return p2, h


def two_prop_power(
    p1: float, target_or: float, n1: int, n2: int, alpha: float
) -> tuple[float, float]:
    if n1 < 30 or n2 < 30:
        return float("nan"), float("nan")
    p2, h = cohens_h_from_or(p1, target_or)
    analysis = NormalIndPower()
    achieved = analysis.solve_power(
        effect_size=abs(h),
        nobs1=n1,
        ratio=n2 / n1,
        alpha=alpha,
        alternative="two-sided",
    )
    return p2, float(achieved)


def design_effect(m_bar: float, rho: float) -> float:
    return 1.0 + (m_bar - 1.0) * rho


def two_prop_power_clustered(
    p1: float,
    target_or: float,
    n1: int,
    n2: int,
    alpha: float,
    m_bar: float,
    rho: float,
) -> tuple[float, float, float]:
    deff = design_effect(m_bar, rho)
    n1_eff = n1 / deff
    n2_eff = n2 / deff
    p2, ach = two_prop_power(
        p1, target_or, int(round(n1_eff)), int(round(n2_eff)), alpha
    )
    return p2, deff, ach


def nb_irr_power_clustered(
    mu_ctrl: float, irr: float, n1: int, n2: int, alpha: float, m_bar: float, rho: float
) -> tuple[float, float]:
    deff = design_effect(m_bar, rho)
    mu_treat = irr * mu_ctrl
    if mu_treat <= 0 or mu_ctrl <= 0:
        return deff, float("nan")
    var = (1.0 / (n1 * mu_treat) + 1.0 / (n2 * mu_ctrl)) * deff
    se = float(np.sqrt(var))
    z_alpha = norm.ppf(1.0 - alpha / 2.0)
    z_stat = abs(np.log(irr)) / se
    power = float(norm.cdf(z_stat - z_alpha) + norm.cdf(-z_stat - z_alpha))
    return deff, power


# --------------------------------------------------------------------------
# Cohort facts from data_derived/latest/
# --------------------------------------------------------------------------
def cohort_facts() -> dict:
    manifest = json.loads((LATEST / "run_manifest.json").read_text())
    rq2_baselines = manifest["phase_c"]["category_configured_rate_by_cohort"]["Control"]
    rq2_ai = manifest["phase_c"]["category_configured_rate_by_cohort"]["AI"]

    df = pd.read_parquet(LATEST / "pr_interventions.parquet")
    keep = df.groupby("repo_full_name")["pr_type"].nunique().loc[lambda s: s == 2].index
    df_fe = df[df["repo_full_name"].isin(keep)].copy()
    n_repos_fe = int(df_fe["repo_full_name"].nunique())
    n_agentic_fe = int((df_fe["pr_type"] == "agentic").sum())
    n_human_fe = int((df_fe["pr_type"] == "human").sum())
    n_total_fe = n_agentic_fe + n_human_fe
    m_bar = n_total_fe / max(n_repos_fe, 1)

    h = df_fe[df_fe["pr_type"] == "human"]
    base_any = float(h["any_security_intervention"].mean())
    base_rejected = float(h["rejected"].mean())
    base_count_mean = float(h["security_intervention_count"].mean())

    return {
        "n_ai_repos": int(manifest["outputs"]["ai_repos.csv"]["rows"]),
        "n_ctrl_repos": int(manifest["outputs"]["control_repos.csv"]["rows"]),
        "rq2_baselines_ctrl": rq2_baselines,
        "rq2_baselines_ai": rq2_ai,
        "n_repos_fe": n_repos_fe,
        "n_agentic_fe": n_agentic_fe,
        "n_human_fe": n_human_fe,
        "n_total_fe": n_total_fe,
        "m_bar_fe": m_bar,
        "base_any": base_any,
        "base_rejected": base_rejected,
        "base_count_mean": base_count_mean,
        "decision_locked_at_run_id": manifest["run_id"],
    }


# --------------------------------------------------------------------------
# Pre-declared targets (operator-locked, 22 rows after dropping
# rq3_changes_requested)
# --------------------------------------------------------------------------
RQ2_CATEGORY_TARGETS = [
    ("rq2_sast", "configured", 1.5, "OR", 0.80, "sast_any"),
    ("rq2_sca", "configured", 1.4, "OR", 0.80, "sca_any"),
    ("rq2_secrets", "configured", 1.8, "OR", 0.80, "secrets_any"),
    ("rq2_fuzzing", "configured", 2.0, "OR", 0.80, "fuzzing_any"),
    ("rq2_ci_hardening", "configured", 2.0, "OR", 0.80, "ci_hardening_any"),
]

RQ2_TOOL_NAMES = [
    "codeql",
    "semgrep",
    "sonarqube",
    "bandit",
    "checkov",
    "tfsec",
    "microsoft_security_devops",
    "dependabot",
    "renovate",
    "snyk",
    "trivy",
    "anchore",
    "govulncheck",
    "gitleaks",
    "trufflehog",
    "ossf_scorecard",
    "harden_runner",
    "oss_fuzz",
    "claude_code_security_review",
]

# RQ3 binary targets — `rq3_changes_requested` REMOVED per operator decision #2.
RQ3_BINARY_TARGETS = [
    ("rq3_any_intervention", "any_security_intervention", 1.5, "OR", 0.80, "base_any"),
    ("rq3_rejected", "rejected", 1.6, "OR", 0.80, "base_rejected"),
]

RQ3_COUNT_TARGETS = [
    (
        "rq3_intervention_count",
        "security_intervention_count",
        1.4,
        "IRR",
        0.80,
        "base_count_mean",
    ),
]

RHO_GRID = [0.01, 0.05, 0.10]
ALPHA_BASE = 0.05


# --------------------------------------------------------------------------
# Build pre-flight table
# --------------------------------------------------------------------------
def build_table(facts: dict) -> pd.DataFrame:
    rows: list[dict] = []
    n_ai = facts["n_ai_repos"]
    n_ctrl = facts["n_ctrl_repos"]
    locked_run = facts["decision_locked_at_run_id"]

    # ---- RQ2 per-category (BH within category — m=1, alpha=0.05) ----
    for fam, outcome, target, kind, tgt_power, base_key in RQ2_CATEGORY_TARGETS:
        p1 = float(facts["rq2_baselines_ctrl"][base_key])
        alpha_eff = ALPHA_BASE
        p2, ach = two_prop_power(p1, target, n_ai, n_ctrl, alpha_eff)
        status = "OK" if (ach == ach and ach >= tgt_power) else "UNDERPOWERED"
        rows.append(
            {
                "family": fam,
                "subfamily": "rq2_within_category",
                "outcome": outcome,
                "n_treat": n_ai,
                "n_ctrl": n_ctrl,
                "baseline_rate_or_mean": round(p1, 6),
                "expected_treat_rate_or_mean": round(p2, 6) if p2 == p2 else None,
                "mde_specified": target,
                "mde_units": kind,
                "alpha": alpha_eff,
                "alpha_basis": "BH within category (m=1, alpha=0.05)",
                "two_sided": True,
                "design_effect": 1.0,
                "rho_assumed": None,
                "achieved_power_pre": round(ach, 4) if ach == ach else None,
                "achieved_power_post": None,
                "achieved_power_uncorrected": None,
                "target_power": tgt_power,
                "power_status": status,
                "phase": "pre-flight",
                "decision_locked_at_run_id": locked_run,
                "notes": (
                    "two-proportion approximation; n_AI vs n_ctrl repos; "
                    "baseline = Phase C control-arm category rate"
                ),
            }
        )

    # ---- RQ2 per-tool (BH across 19 tools, Bonferroni-equiv worst case) ----
    m_tools = len(RQ2_TOOL_NAMES)
    alpha_tool_bh_worst = ALPHA_BASE / m_tools
    for stand_in_name, p1 in [
        ("popular_tool_standin_ctrl_5pct", 0.05),
        ("sparse_tool_standin_ctrl_0p5pct", 0.005),
    ]:
        for target_or in [1.5, 2.0, 3.0]:
            p2, ach_worst = two_prop_power(
                p1, target_or, n_ai, n_ctrl, alpha_tool_bh_worst
            )
            _, ach_uncorr = two_prop_power(p1, target_or, n_ai, n_ctrl, ALPHA_BASE)
            status = (
                "OK"
                if (ach_worst == ach_worst and ach_worst >= 0.80)
                else "UNDERPOWERED"
            )
            rows.append(
                {
                    "family": "rq2_per_tool",
                    "subfamily": stand_in_name,
                    "outcome": "tool_configured",
                    "n_treat": n_ai,
                    "n_ctrl": n_ctrl,
                    "baseline_rate_or_mean": p1,
                    "expected_treat_rate_or_mean": round(p2, 6) if p2 == p2 else None,
                    "mde_specified": target_or,
                    "mde_units": "OR",
                    "alpha": alpha_tool_bh_worst,
                    "alpha_basis": (
                        f"BH across {m_tools} tools, Bonferroni-equiv worst case "
                        f"(alpha/{m_tools})"
                    ),
                    "two_sided": True,
                    "design_effect": 1.0,
                    "rho_assumed": None,
                    "achieved_power_pre": round(ach_worst, 4)
                    if ach_worst == ach_worst
                    else None,
                    "achieved_power_post": None,
                    "achieved_power_uncorrected": round(ach_uncorr, 4)
                    if ach_uncorr == ach_uncorr
                    else None,
                    "target_power": 0.80,
                    "power_status": status,
                    "phase": "pre-flight",
                    "decision_locked_at_run_id": locked_run,
                    "notes": (
                        "stand-in baseline since per-tool Phase C rates not yet "
                        "tabulated; worst-case BH bound shown alongside uncorrected"
                    ),
                }
            )

    # ---- RQ3 binary FE outcomes (cluster SE on repo) ----
    n1 = facts["n_agentic_fe"]
    n2 = facts["n_human_fe"]
    m_bar = facts["m_bar_fe"]
    for fam, outcome, target, kind, tgt_power, base_key in RQ3_BINARY_TARGETS:
        p1 = float(facts[base_key])
        for rho in RHO_GRID:
            p2, deff, ach = two_prop_power_clustered(
                p1, target, n1, n2, ALPHA_BASE, m_bar, rho
            )
            status = "OK" if (ach == ach and ach >= tgt_power) else "UNDERPOWERED"
            rows.append(
                {
                    "family": fam,
                    "subfamily": f"rho_{rho:.2f}",
                    "outcome": outcome,
                    "n_treat": n1,
                    "n_ctrl": n2,
                    "baseline_rate_or_mean": round(p1, 6),
                    "expected_treat_rate_or_mean": round(p2, 6) if p2 == p2 else None,
                    "mde_specified": target,
                    "mde_units": kind,
                    "alpha": ALPHA_BASE,
                    "alpha_basis": (
                        "RQ3 family, no multiple-test penalty across binary outcomes "
                        "(2 tests; BH bound at alpha/2 reported in notes)"
                    ),
                    "two_sided": True,
                    "design_effect": round(deff, 3),
                    "rho_assumed": rho,
                    "achieved_power_pre": round(ach, 4) if ach == ach else None,
                    "achieved_power_post": None,
                    "achieved_power_uncorrected": None,
                    "target_power": tgt_power,
                    "power_status": status,
                    "phase": "pre-flight",
                    "decision_locked_at_run_id": locked_run,
                    "notes": (
                        f"FE cohort: {facts['n_repos_fe']} repos, "
                        f"{facts['n_total_fe']} PRs after singleton-repo drop. "
                        f"m_bar={m_bar:.2f}. Baseline = human-arm rate in FE cohort. "
                        f"Worst-case BH-adj across 2 RQ3 binary outcomes: "
                        f"alpha={ALPHA_BASE / 2:.4f}."
                    ),
                }
            )

    # ---- RQ3 count (NB / Poisson, cluster SE) ----
    for fam, outcome, target, kind, tgt_power, base_key in RQ3_COUNT_TARGETS:
        mu = float(facts[base_key])
        for rho in RHO_GRID:
            deff, ach = nb_irr_power_clustered(
                mu, target, n1, n2, ALPHA_BASE, m_bar, rho
            )
            status = "OK" if (ach == ach and ach >= tgt_power) else "UNDERPOWERED"
            rows.append(
                {
                    "family": fam,
                    "subfamily": f"rho_{rho:.2f}",
                    "outcome": outcome,
                    "n_treat": n1,
                    "n_ctrl": n2,
                    "baseline_rate_or_mean": round(mu, 6),
                    "expected_treat_rate_or_mean": round(target * mu, 6),
                    "mde_specified": target,
                    "mde_units": kind,
                    "alpha": ALPHA_BASE,
                    "alpha_basis": "RQ3 family, single count outcome",
                    "two_sided": True,
                    "design_effect": round(deff, 3),
                    "rho_assumed": rho,
                    "achieved_power_pre": round(ach, 4) if ach == ach else None,
                    "achieved_power_post": None,
                    "achieved_power_uncorrected": None,
                    "target_power": tgt_power,
                    "power_status": status,
                    "phase": "pre-flight",
                    "decision_locked_at_run_id": locked_run,
                    "notes": (
                        f"Closed-form Poisson IRR power inflated by Kish design "
                        f"effect. NB overdispersion will further inflate SE; flag "
                        f"as rough upper bound on power. mu_human={mu:.4f}, "
                        f"mu_agentic={(target * mu):.4f}."
                    ),
                }
            )

    return pd.DataFrame(rows)


def main() -> None:
    facts = cohort_facts()
    df = build_table(facts)
    out = TABLES / "power_analysis.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    print(f"WROTE {out} ({len(df)} rows, all phase=pre-flight)")
    print(f"  decision_locked_at_run_id = {facts['decision_locked_at_run_id']}")
    under = df[df["power_status"] == "UNDERPOWERED"]
    print(f"  UNDERPOWERED rows: {len(under)} of {len(df)}")
    if not under.empty:
        cols = [
            "family",
            "subfamily",
            "mde_specified",
            "mde_units",
            "baseline_rate_or_mean",
            "achieved_power_pre",
            "rho_assumed",
        ]
        print(under[cols].to_string(index=False))


if __name__ == "__main__":
    main()
