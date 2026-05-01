"""Reusable run-manifest writer.

Implements the recipe in `.claude/skills/run-manifest/SKILL.md`. Every phase
(A/B/C via data-miner, D via intervention-classifier, E via analyst) imports
this helper rather than hand-rolling a manifest, so the schema stays uniform.

Differences from the skill sketch:
- `data_raw/aidev/` is a Hugging Face parquet drop, not a git working tree,
  so we fall back to the `AIDEV_DATASET_VERSION` env var (set in `.env`).
- The skill says version_header should come from a `# YYYY-MM-DD` comment
  on line 1 of each config; for plain `.txt` files we still use line 1
  (which is itself a `# date` comment per the security_bots.txt header
  convention) and tolerate non-comment headers.
- `aidev_dataset.hf_commit` is populated from `logs/aidev_dataset_version.txt`
  (40-char hex from the Hugging Face dataset commit), separately from the
  human-readable `version_commit` tag (e.g. "v3"). If the log file is
  missing or malformed we set `hf_commit: null` and warn rather than
  failing — the writer must remain robust for future runs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_HF_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def sha256_of(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _aidev_version(repo: Path) -> str:
    """Return the AIDev dataset version pin.

    Order: git sha of `data_raw/aidev` if it's a git tree, otherwise
    `AIDEV_DATASET_VERSION` from env, otherwise empty string.
    """
    aidev_dir = repo / "data_raw" / "aidev"
    git_dir = aidev_dir / ".git"
    if git_dir.exists():
        try:
            return subprocess.check_output(
                ["git", "-C", str(aidev_dir), "rev-parse", "HEAD"],
                text=True,
            ).strip()
        except subprocess.CalledProcessError:
            pass
    return os.environ.get("AIDEV_DATASET_VERSION", "")


def _aidev_hf_commit(repo: Path) -> str | None:
    """Return the Hugging Face dataset commit SHA from `logs/aidev_dataset_version.txt`.

    The log is expected to contain a single 40-char hex sha (optionally
    surrounded by whitespace). Returns None if the file is missing,
    unreadable, or malformed — never raises, so the manifest writer keeps
    working even when the log hasn't been refreshed.
    """
    log_path = repo / "logs" / "aidev_dataset_version.txt"
    try:
        text = log_path.read_text()
    except FileNotFoundError:
        logger.warning("aidev_dataset_version.txt not found at %s", log_path)
        return None
    except OSError as e:
        logger.warning("could not read %s: %s", log_path, e)
        return None
    for line in text.splitlines():
        token = line.strip()
        if _HF_COMMIT_RE.match(token):
            return token
    logger.warning("no 40-char hex commit found in %s (got %r)", log_path, text[:120])
    return None


def _config_entries(repo: Path) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for p in sorted((repo / "configs").iterdir()):
        if not p.is_file():
            continue
        first_line = ""
        try:
            first_line = p.read_text().splitlines()[0]
        except (UnicodeDecodeError, IndexError):
            first_line = ""
        out[p.name] = {
            "sha256": sha256_of(p),
            "version_header": first_line.lstrip("# ").strip(),
        }
    return out


def write_manifest(
    out_dir: Path,
    *,
    phase: str | list[str],
    agent: str,
    outputs: dict[str, int],
    extra: dict | None = None,
) -> Path:
    """Write `out_dir/run_manifest.json`.

    `outputs` maps filename (relative to out_dir) -> row count. The helper
    re-hashes each file and emits the standard schema_version=1 manifest.
    Any phase-specific keys (e.g. intervention_source_choice, stats_libs)
    should be passed via `extra`.
    """
    repo = Path(__file__).resolve().parents[2]
    frozen = subprocess.check_output(["uv", "pip", "freeze"], text=True)
    manifest: dict = {
        "schema_version": "1",
        "run_id": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "phase": phase,
        "agent": agent,
        "window": {
            "start": os.environ["WINDOW_START"],
            "end": os.environ["WINDOW_END"],
        },
        "seed": int(os.environ["RANDOM_SEED"]),
        "aidev_dataset": {
            "version_commit": _aidev_version(repo),
            "hf_commit": _aidev_hf_commit(repo),
            "doi": os.environ.get("AIDEV_DATASET_DOI", ""),
            "record_id": os.environ.get("AIDEV_DATASET_RECORD_ID", ""),
        },
        "configs": _config_entries(repo),
        "uv": {
            "lockfile_sha256": sha256_of(repo / "uv.lock"),
            "python_version": sys.version.split()[0],
            "frozen_packages": frozen,
        },
        "outputs": {
            name: {
                "rows": int(rows),
                "sha256": sha256_of(out_dir / name),
            }
            for name, rows in outputs.items()
        },
    }
    if extra:
        manifest.update(extra)
    target = out_dir / "run_manifest.json"
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return target
