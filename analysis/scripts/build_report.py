"""build_report.py — render analysis/REPORT.md from the Jinja template.

Reads:
  - analysis/tables/{rq1,rq2,rq3}_main.csv
  - analysis/tables/{rq1,rq2,rq3}_headline.json
  - analysis/tables/{rq1,rq2,rq3}_provenance.json
  - analysis/tables/rq1_adoption_by_{tool,category,language,stars}.csv
  - analysis/tables/{rq2,rq3}_robustness.csv
  - analysis/tables/power_analysis.csv
  - data_derived/latest/run_manifest.json
  - analysis/report/REPORT.md.j2

Writes:
  - analysis/REPORT.md

The template is the source of truth for prose; this script just feeds
it numbers. No hypothesis tests, no model fits.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pandas as pd
from jinja2 import Environment, FileSystemLoader, StrictUndefined

REPO_ROOT = Path(__file__).resolve().parents[2]
TABLES = REPO_ROOT / "analysis" / "tables"
REPORT_DIR = REPO_ROOT / "analysis" / "report"
MANIFEST_PATH = REPO_ROOT / "data_derived" / "latest" / "run_manifest.json"
TEMPLATE_PATH = REPORT_DIR / "REPORT.md.j2"
OUT_PATH = REPO_ROOT / "analysis" / "REPORT.md"


REQUIRED_FILES = [
    TABLES / "rq1_main.csv",
    TABLES / "rq1_headline.json",
    TABLES / "rq1_provenance.json",
    TABLES / "rq1_adoption_by_tool.csv",
    TABLES / "rq1_adoption_by_category.csv",
    TABLES / "rq1_adoption_by_language.csv",
    TABLES / "rq1_adoption_by_stars.csv",
    TABLES / "rq2_main.csv",
    TABLES / "rq2_headline.json",
    TABLES / "rq2_provenance.json",
    TABLES / "rq2_robustness.csv",
    TABLES / "rq3_main.csv",
    TABLES / "rq3_headline.json",
    TABLES / "rq3_provenance.json",
    TABLES / "rq3_robustness.csv",
    TABLES / "power_analysis.csv",
    MANIFEST_PATH,
    TEMPLATE_PATH,
]


def round_sci(x, sig: int = 3) -> str:
    """Format a small p-value in scientific notation with `sig` digits."""
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return "—"
    try:
        x = float(x)
    except (TypeError, ValueError):
        return str(x)
    if x == 0:
        return "0"
    if x >= 0.001:
        return f"{x:.3g}"
    return f"{x:.{sig - 1}e}"


def df_to_records_clean(df: pd.DataFrame) -> list[dict]:
    """to_dict('records') but with NaN replaced by None so Jinja '... is none' works."""
    out: list[dict] = []
    for row in df.to_dict("records"):
        cleaned = {}
        for k, v in row.items():
            if isinstance(v, float) and math.isnan(v):
                cleaned[k] = None
            else:
                cleaned[k] = v
        out.append(cleaned)
    return out


def main() -> None:
    missing_inputs = [p for p in REQUIRED_FILES if not p.exists()]
    if missing_inputs:
        print("MissingArtifact: cannot render REPORT.md without:")
        for p in missing_inputs:
            print(f"  - {p}")
        raise SystemExit(2)

    manifest = json.loads(MANIFEST_PATH.read_text())

    # RQ1
    rq1_main = pd.read_csv(TABLES / "rq1_main.csv")
    rq1_headline = json.loads((TABLES / "rq1_headline.json").read_text())
    rq1_prov = json.loads((TABLES / "rq1_provenance.json").read_text())
    rq1_by_tool = pd.read_csv(TABLES / "rq1_adoption_by_tool.csv")
    rq1_by_category = pd.read_csv(TABLES / "rq1_adoption_by_category.csv")
    rq1_by_language = pd.read_csv(TABLES / "rq1_adoption_by_language.csv")
    rq1_by_stars = pd.read_csv(TABLES / "rq1_adoption_by_stars.csv")

    rq1 = {
        "main": df_to_records_clean(rq1_main),
        "headline": rq1_headline,
        "by_tool": df_to_records_clean(rq1_by_tool),
        "by_category": df_to_records_clean(rq1_by_category),
        "by_language": df_to_records_clean(rq1_by_language),
        "by_stars": df_to_records_clean(rq1_by_stars),
        "lang_lookup": {r["language"]: r for r in df_to_records_clean(rq1_by_language)},
        "top3": rq1_headline["top3_tools"],
    }

    # RQ2
    rq2_main = pd.read_csv(TABLES / "rq2_main.csv")
    rq2_headline = json.loads((TABLES / "rq2_headline.json").read_text())
    rq2_robust = pd.read_csv(TABLES / "rq2_robustness.csv")

    rq2_main_records = df_to_records_clean(rq2_main)
    rq2 = {
        "main": rq2_main_records,
        "main_lookup": {
            r["level"]: r for r in rq2_main_records if r["family"] == "category"
        },
        "headline": rq2_headline,
        "bh_cat_lookup": {r["level"]: r for r in rq2_headline["bh_sig_categories"]},
        "robust_variant_counts": rq2_robust["variant"].value_counts().to_dict(),
    }

    # RQ3
    rq3_main = pd.read_csv(TABLES / "rq3_main.csv")
    rq3_headline = json.loads((TABLES / "rq3_headline.json").read_text())
    rq3_prov = json.loads((TABLES / "rq3_provenance.json").read_text())
    rq3_robust = pd.read_csv(TABLES / "rq3_robustness.csv")

    rq3_main_records = df_to_records_clean(rq3_main)

    # robust_v5 lookup table — three primary outcomes for v5_bot_identity_only
    v5 = rq3_robust[rq3_robust["variant"] == "v5_bot_identity_only"]
    rq3_robust_v5 = df_to_records_clean(v5)

    # robustness_lookup[v5_bot_identity_only][rejected] for the rejected paragraph
    robustness_lookup: dict[str, dict[str, dict]] = {}
    for variant, sub in rq3_robust.groupby("variant"):
        robustness_lookup[variant] = {}
        for _, row in sub.iterrows():
            d = {
                k: (None if isinstance(v, float) and math.isnan(v) else v)
                for k, v in row.items()
            }
            robustness_lookup[variant].setdefault(d["outcome"], d)

    rq3 = {
        "main": rq3_main_records,
        "headline": rq3_headline,
        "fe_diagnostics": rq3_prov["fe_diagnostics"],
        "robust_variant_counts": rq3_robust["variant"].value_counts().to_dict(),
        "robust_v5": rq3_robust_v5,
        "robustness_lookup": robustness_lookup,
    }

    # Power analysis
    power = pd.read_csv(TABLES / "power_analysis.csv")
    underpowered_pre = power[
        (power["phase"] == "pre-flight") & (power["power_status"] == "UNDERPOWERED")
    ].copy()
    # Pull achieved_power_post from the matching post-hoc row when available.
    posthoc = power[power["phase"] == "post-hoc"].set_index(
        ["family", "subfamily", "outcome"]
    )
    posthoc_pwr_col: list[float | None] = []
    for _, r in underpowered_pre.iterrows():
        key = (r["family"], r["subfamily"], r["outcome"])
        if key in posthoc.index:
            posthoc_pwr_col.append(posthoc.loc[key, "achieved_power_post"])
        else:
            posthoc_pwr_col.append(None)
    underpowered_pre["achieved_power_post"] = posthoc_pwr_col
    underpowered_pre_records = df_to_records_clean(underpowered_pre)

    # Lookup keys for §7 narrative — match family + subfamily
    def _power_lookup_key(family: str, subfamily: str) -> str:
        return f"{family}_{subfamily}".replace(".", "_")

    power_lookup: dict[str, dict] = {}
    for r in df_to_records_clean(power):
        key = _power_lookup_key(r["family"], r["subfamily"])
        # Prefer post-hoc rows when both phases present
        if r["phase"] == "post-hoc" or key not in power_lookup:
            power_lookup[key] = r

    # Decision lock — first non-empty value across the table
    decision_lock = power["decision_locked_at_run_id"].dropna().iloc[0]

    # Render
    env = Environment(
        loader=FileSystemLoader(str(REPORT_DIR)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["round_sci"] = round_sci

    template = env.get_template("REPORT.md.j2")
    out = template.render(
        manifest=manifest,
        rq1_prov=rq1_prov,
        rq1=rq1,
        rq2=rq2,
        rq3=rq3,
        power={"underpowered_pre": underpowered_pre_records},
        power_lookup=power_lookup,
        power_decision_lock=decision_lock,
        missing_artifacts=[],
    )
    OUT_PATH.write_text(out)
    print(f"wrote {OUT_PATH}")
    line_count = len(out.splitlines())
    review_blocks = out.count("[HUMAN REVIEW:")
    print(f"  lines              : {line_count}")
    print(f"  [HUMAN REVIEW] blocks: {review_blocks}")


if __name__ == "__main__":
    main()
