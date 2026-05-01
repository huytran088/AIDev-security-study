"""Post-hoc achieved power per RQ family using realized effect sizes from
the fitted models (read off `analysis/tables/{rq2,rq3}_main.csv`).

Power is computed against the **pre-declared** target effect (MDE), using
the realized standard error from the fit. This is honest: it tells you
how likely you would have detected the pre-declared MDE given the noise
the data actually delivered.

  power = 1 - Φ(z_{1-α/2} - log(target) / SE_log)
        + Φ(-z_{1-α/2} - log(target) / SE_log)   # two-sided

Appends `phase=post-hoc` rows to `analysis/tables/power_analysis.csv`.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import norm

REPO = Path(__file__).resolve().parents[2]
LATEST = REPO / "data_derived" / "latest"
TABLES = REPO / "analysis" / "tables"

ALPHA = 0.05


def power_two_sided(target_or: float, se_log: float, alpha: float) -> float:
    if se_log is None or not np.isfinite(se_log) or se_log <= 0:
        return float("nan")
    z = norm.ppf(1.0 - alpha / 2.0)
    log_t = abs(np.log(target_or))
    return float(norm.cdf(log_t / se_log - z) + norm.cdf(-log_t / se_log - z))


def main() -> None:
    pre = pd.read_csv(TABLES / "power_analysis.csv")
    rq2_main = pd.read_csv(TABLES / "rq2_main.csv")
    rq3_main = pd.read_csv(TABLES / "rq3_main.csv")
    manifest = json.loads((LATEST / "run_manifest.json").read_text())
    locked_run_id = manifest["run_id"]

    posthoc_rows = []

    # --- RQ2 per-category --- match pre-flight family rows ---
    rq2_cat = rq2_main[rq2_main["family"] == "category"].set_index("level")
    pre_cat = pre[
        (pre["phase"] == "pre-flight")
        & (pre["family"].str.startswith("rq2_"))
        & (pre["subfamily"] == "rq2_within_category")
    ]
    for _, r in pre_cat.iterrows():
        cat_short = r["family"].removeprefix("rq2_")
        if cat_short not in rq2_cat.index:
            continue
        fit = rq2_cat.loc[cat_short]
        # SE on log(OR) approximated from CI: (log(hi) - log(lo)) / (2 * z)
        z = norm.ppf(1.0 - ALPHA / 2.0)
        try:
            se_log = (np.log(float(fit["OR_hi"])) - np.log(float(fit["OR_lo"]))) / (
                2 * z
            )
        except Exception:  # noqa: BLE001
            se_log = None
        ach = power_two_sided(float(r["mde_specified"]), se_log, ALPHA)
        new = r.to_dict()
        new["phase"] = "post-hoc"
        new["achieved_power_post"] = round(ach, 4) if ach == ach else None
        # achieved_power_pre stays as before (carry forward)
        new["realized_or_or_irr"] = float(fit["OR"])
        new["realized_p_raw"] = float(fit["p_raw"])
        new["realized_p_adj"] = float(fit["p_adj"]) if pd.notna(fit["p_adj"]) else None
        new["se_log_realized"] = se_log
        new["decision_locked_at_run_id"] = locked_run_id
        posthoc_rows.append(new)

    # --- RQ3 binary outcomes & count outcome ---
    rq3_idx = rq3_main.set_index("outcome")
    pre_rq3 = pre[
        (pre["phase"] == "pre-flight") & (pre["family"].str.startswith("rq3_"))
    ]
    for _, r in pre_rq3.iterrows():
        outc = r["outcome"]
        if outc not in rq3_idx.index:
            continue
        fit = rq3_idx.loc[outc]
        if pd.isna(fit["se_agentic"]):
            se_log = None
        else:
            se_log = float(fit["se_agentic"])  # SE is on log scale already
        ach = power_two_sided(float(r["mde_specified"]), se_log, ALPHA)
        new = r.to_dict()
        new["phase"] = "post-hoc"
        new["achieved_power_post"] = round(ach, 4) if ach == ach else None
        new["realized_or_or_irr"] = (
            float(fit["or_or_irr"]) if pd.notna(fit["or_or_irr"]) else None
        )
        new["realized_p_raw"] = float(fit["p_raw"]) if pd.notna(fit["p_raw"]) else None
        new["se_log_realized"] = se_log
        new["decision_locked_at_run_id"] = locked_run_id
        posthoc_rows.append(new)

    posthoc = pd.DataFrame(posthoc_rows)
    # Re-emit canonical CSV: pre-flight rows + post-hoc rows.
    # Allow new columns to appear in post-hoc rows (realized_*).
    out = pd.concat([pre, posthoc], ignore_index=True, sort=False)
    out.to_csv(TABLES / "power_analysis.csv", index=False)

    print(f"WROTE {TABLES / 'power_analysis.csv'} ({len(out)} rows total)")
    print(f"  pre-flight rows: {(out['phase'] == 'pre-flight').sum()}")
    print(f"  post-hoc rows:   {(out['phase'] == 'post-hoc').sum()}")
    under = posthoc[posthoc["achieved_power_post"].fillna(0).astype(float) < 0.80]
    if not under.empty:
        cols = [
            "family",
            "subfamily",
            "outcome",
            "mde_specified",
            "achieved_power_pre",
            "achieved_power_post",
        ]
        cols = [c for c in cols if c in under.columns]
        print(f"  post-hoc UNDERPOWERED rows: {len(under)}")
        print(under[cols].to_string(index=False))
    else:
        print("  post-hoc: all families >= 0.80")


if __name__ == "__main__":
    main()
