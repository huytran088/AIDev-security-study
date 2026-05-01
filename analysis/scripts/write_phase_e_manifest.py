"""Phase E sidecar manifest writer.

Emits `analysis/tables/run_manifest.json`. This is the Phase E twin of
`data_derived/latest/run_manifest.json` (which covers Phases A-D). Both
manifests share `run_id`, `seed`, `window`, `aidev_dataset`, `configs`,
and `uv` so a reviewer can cross-reference them, but the Phase E sidecar
adds:

  * `test_families` - which statistical tests ran in RQ1/RQ2/RQ3
  * `bh_correction_groupings` - which p-values were BH-corrected together
  * `robustness_variants` - distinct `variant` values present in
    `rq{2,3}_robustness.csv`
  * `file_hashes` - SHA256 of every file under `analysis/tables/` and
    `analysis/figures/`

Design choice: this writer is read-only with respect to Phase A-D - it
does not touch `data_derived/latest/run_manifest.json`, only inherits
fields from it.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LATEST = REPO / "data_derived" / "latest"
TABLES = REPO / "analysis" / "tables"
FIGURES = REPO / "analysis" / "figures"
OUT = TABLES / "run_manifest.json"


def sha256_of(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _file_hashes(directory: Path) -> dict[str, dict[str, int | str]]:
    """Hash every regular file in `directory` (non-recursive)."""
    out: dict[str, dict[str, int | str]] = {}
    if not directory.is_dir():
        return out
    for p in sorted(directory.iterdir()):
        # Skip the manifest itself and anything that is not a regular file
        # we own (e.g., symlinks are hashed via their target).
        if p.name == "run_manifest.json":
            continue
        if not p.is_file():
            continue
        out[p.name] = {
            "sha256": sha256_of(p),
            "bytes": p.stat().st_size,
        }
    return out


def _robustness_variants() -> dict[str, list[str]]:
    """Return distinct `variant` values per RQ from the robustness CSVs."""
    import csv

    variants: dict[str, list[str]] = {}
    for rq_label, csv_name in [
        ("RQ2", "rq2_robustness.csv"),
        ("RQ3", "rq3_robustness.csv"),
    ]:
        path = TABLES / csv_name
        if not path.is_file():
            variants[rq_label] = []
            continue
        seen: set[str] = set()
        with path.open(newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                v = row.get("variant", "").strip()
                if v:
                    seen.add(v)
        variants[rq_label] = sorted(seen)
    return variants


def _bh_groupings_from_rq2() -> dict[str, object]:
    """Pull the BH family definition the RQ2 compute already recorded."""
    prov = TABLES / "rq2_provenance.json"
    if not prov.is_file():
        return {}
    p = json.loads(prov.read_text())
    return p.get("bh_family_definition", {})


def main() -> Path:
    if not LATEST.is_dir():
        raise SystemExit(f"Cannot find {LATEST}; Phase A-D manifest is required.")
    parent = LATEST / "run_manifest.json"
    if not parent.is_file():
        raise SystemExit(f"Cannot find Phase A-D manifest at {parent}.")
    parent_doc = json.loads(parent.read_text())

    test_families = {
        "RQ1": [
            "per_tool_adoption_rate",
            "per_category_adoption_rate",
            "cross_tab_by_language",
            "cross_tab_by_stars_bin",
            "logit_tool_configured_on_ai_covariates",
        ],
        "RQ2": [
            "fisher_exact_per_tool",
            "fisher_exact_per_category",
            "logit_configured_on_AI_plus_covariates_cluster_SE",
        ],
        "RQ3": [
            "logit_FE_any_security_intervention",
            "negbin_FE_security_intervention_count",
            "poisson_quasi_FE_fallback_when_NB_diverges",
            "logit_FE_rejected_with_any_intervention_covariate",
        ],
    }

    bh_definition = _bh_groupings_from_rq2()
    bh_correction_groupings = {
        "RQ2_primary": {
            "description": (
                "BH (fdr_bh) correction within RQ2 category family AND within "
                "the non-sparse subset of the tool family. Sparse-band tools "
                "(control adoption rate < 1%) are excluded from BH because their "
                "Fisher p-values are dominated by zero-cell continuity."
            ),
            "method": bh_definition.get("bh_method", "fdr_bh"),
            "alpha": bh_definition.get("alpha", 0.05),
            "category_family_size": bh_definition.get("bh_family_size_categories"),
            "tool_family_size_after_sparse_exclusion": bh_definition.get(
                "bh_family_size_tools_after_exclusion"
            ),
            "sparse_band_threshold": bh_definition.get("sparse_band_threshold"),
            "sparse_band_excluded": bh_definition.get("sparse_band_excluded", []),
        },
        "RQ3_primary": {
            "description": (
                "No multi-test BH adjustment applied across the three RQ3 "
                "outcomes; each outcome (any_intervention, intervention_count, "
                "rejected) is reported with its raw p from the FE model."
            ),
            "method": "none",
        },
    }

    robustness_variants = _robustness_variants()

    extra = {
        "phase": ["A", "B", "C", "D", "E"],
        "agent": "analyst",
        "phase_e": {
            "agent": "analyst",
            "generated_at_utc": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "compute_scripts": [
                "analysis/scripts/rq1_compute.py",
                "analysis/scripts/rq2_compute.py",
                "analysis/scripts/rq3_compute.py",
                "analysis/scripts/robustness.py",
                "analysis/scripts/power_analysis_pre.py",
                "analysis/scripts/power_analysis_post.py",
            ],
            "test_families": test_families,
            "bh_correction_groupings": bh_correction_groupings,
            "robustness_variants": robustness_variants,
            "stats_libs_note": (
                "Library versions are inherited from the parent Phase A-D "
                "manifest's `uv.frozen_packages` block. Key entries: "
                "statsmodels, scipy, pandas, numpy, patsy."
            ),
            "file_hashes": {
                "analysis/tables": _file_hashes(TABLES),
                "analysis/figures": _file_hashes(FIGURES),
            },
            "parent_manifest_path": "data_derived/latest/run_manifest.json",
            "parent_manifest_sha256": sha256_of(parent),
        },
    }

    # Inherit cross-reference fields from the Phase A-D manifest verbatim
    # so a reviewer can confirm the two manifests describe the same run.
    inherit_keys = (
        "schema_version",
        "run_id",
        "seed",
        "window",
        "aidev_dataset",
        "configs",
        "uv",
    )
    manifest: dict = {k: parent_doc[k] for k in inherit_keys if k in parent_doc}
    manifest.update(extra)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return OUT


if __name__ == "__main__":
    path = main()
    print(f"wrote {path}")
