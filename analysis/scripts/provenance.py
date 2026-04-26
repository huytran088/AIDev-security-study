"""Provenance JSON writer for analyst compute scripts.

Per `.claude/agents/analyst.md`, every `rq{1,2,3}_compute.py` (and
`robustness.py`) must write a sibling `*_provenance.json` for each
`*_main.csv` it emits, with:

    run_id              -- BASENAME of the data_derived/latest symlink
                           target (the dated directory name, e.g.
                           "2026-04-25"). The pre-commit hook compares
                           this against `basename(readlink latest)` —
                           NOT the manifest's ISO `run_id` field.
    aidev_dataset_sha   -- manifest.aidev_dataset.version_commit
                           (or `aidev_dataset_sha` for older manifests)
    compute_script      -- relative path to the script writing the
                           provenance file
    configs_hashes      -- manifest.configs (sha256 + version_header)
    generated_at_utc    -- now, ISO-8601 with seconds precision
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LATEST = REPO / "data_derived" / "latest"


def _resolve_run_id() -> str:
    """Return the symlink-target basename used by the pre-commit hook."""
    target = os.readlink(LATEST)
    return Path(target).name


def write_provenance(
    out_path: Path,
    *,
    compute_script: str,
    extra: dict | None = None,
) -> None:
    """Write a `*_provenance.json` next to the matching CSV(s).

    `compute_script` is the source script's path relative to the repo root,
    e.g. "analysis/scripts/rq1_compute.py".
    """
    manifest = json.loads((LATEST / "run_manifest.json").read_text())
    payload: dict = {
        "run_id": _resolve_run_id(),
        "aidev_dataset_sha": (
            manifest.get("aidev_dataset", {}).get("version_commit")
            or manifest.get("aidev_dataset_sha")
        ),
        "compute_script": compute_script,
        "configs_hashes": manifest.get("configs", {}),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if extra:
        payload.update(extra)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
