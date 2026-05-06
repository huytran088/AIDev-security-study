"""Phase A — AI repo cohort + agentic PR table.

Run via: `uv run python analysis/scripts/phase_a_cohort.py`

Inputs (read-only):
  data_raw/aidev/pull_request.parquet     (33,596 curated agentic PRs)
  data_raw/aidev/repository.parquet       (2,807 curated repos)
  data_raw/aidev/pr_commits.parquet       (PR -> commit shas)
  data_raw/aidev/pr_commit_details.parquet (per-file diff stats)

Outputs (under data_derived/<today>/):
  ai_repos.csv          — one row per unique repo_full_name in the window,
                          left-joined to repository.parquet for stars/language.
                          Phase B will need these covariates for matching.
  agentic_prs.parquet   — one row per in-window PR with agent identity, state
                          timestamps, churn (additions+deletions), changed_files.
  run_manifest.json     — via the run-manifest skill helper.

Notes on AIDev schema (verified at runtime, not assumed):
- `pull_request` columns are: id, number, title, body, agent, user_id, user,
  state, created_at (string ISO-8601 'Z'), closed_at, merged_at, repo_id,
  repo_url, html_url. There is NO additions/deletions/changed_files column;
  those have to be aggregated from `pr_commit_details` keyed by `pr_id`.
- `repository` has: id, url, license, full_name, language, forks, stars.
  There is NO `created_at` or `owner_type` — Phase B will pull those from
  the GitHub API. ai_repos.csv carries forward what AIDev does have.
- repo_full_name is the canonical key. We derive it from `repo_url` on the
  PR side ("https://api.github.com/repos/owner/name" -> "owner/name") and
  cross-check against `repository.full_name` via `repo_id`.

The script does not touch GitHub. Phase A is AIDev-local only.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pyarrow.dataset as ds
from dotenv import load_dotenv

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "analysis" / "scripts"))
from write_manifest import write_manifest  # noqa: E402

DSET = REPO / "data_raw" / "aidev"
LOGS = REPO / "logs"


# ---------- helpers ---------------------------------------------------------


def _setup_logger() -> logging.Logger:
    LOGS.mkdir(parents=True, exist_ok=True)
    log_path = LOGS / "phase_a.log"
    logger = logging.getLogger("phase_a")
    logger.setLevel(logging.INFO)
    # Prevent duplicate handlers if reloaded.
    logger.handlers.clear()
    fh = logging.FileHandler(log_path, mode="a")
    fh.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ"
        )
    )
    sh = logging.StreamHandler()
    sh.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger


def _log_table(logger: logging.Logger, name: str, df: pd.DataFrame) -> None:
    logger.info("table=%s shape=%s", name, df.shape)
    logger.info("table=%s head=\n%s", name, df.head(5).to_string(index=False))


def _full_name_from_repo_url(url: object) -> str | None:
    """Map "https://api.github.com/repos/owner/name" -> "owner/name".

    Called via pandas .map(), so non-string (NaN) values must be guarded.
    """
    if not isinstance(url, str):
        return None
    marker = "/repos/"
    i = url.find(marker)
    if i < 0:
        return None
    return url[i + len(marker) :].strip("/")


# ---------- core build ------------------------------------------------------


def main() -> None:
    load_dotenv(REPO / ".env")
    window_start = pd.Timestamp(os.environ["WINDOW_START"], tz="UTC")
    # WINDOW_END is the last day inclusive — interpret as end-of-day UTC so a
    # PR opened at 23:59 on 2025-08-31 is included.
    window_end = pd.Timestamp(os.environ["WINDOW_END"], tz="UTC") + pd.Timedelta(
        days=1, microseconds=-1
    )

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_dir = REPO / "data_derived" / today
    out_dir.mkdir(parents=True, exist_ok=True)

    logger = _setup_logger()
    logger.info(
        "=== Phase A run_id=%s window=[%s, %s] out=%s ===",
        today,
        window_start.isoformat(),
        window_end.isoformat(),
        out_dir,
    )

    # ---- load curated AIDev tables ----------------------------------------

    pr = ds.dataset(str(DSET / "pull_request.parquet")).to_table().to_pandas()
    repo = ds.dataset(str(DSET / "repository.parquet")).to_table().to_pandas()
    logger.info("loaded pull_request rows=%d repository rows=%d", len(pr), len(repo))

    # Timestamps in AIDev parquet are stored as ISO-8601 strings ("...Z").
    for col in ("created_at", "closed_at", "merged_at"):
        pr[col] = pd.to_datetime(pr[col], utc=True, errors="coerce")

    # Derive repo_full_name on PR side (always available even if a repo
    # somehow isn't in `repository.parquet`).
    pr["repo_full_name"] = pr["repo_url"].map(_full_name_from_repo_url)
    n_missing_full_name = int(pr["repo_full_name"].isna().sum())
    if n_missing_full_name:
        logger.warning(
            "could not derive repo_full_name for %d PR rows", n_missing_full_name
        )

    # ---- window filter -----------------------------------------------------

    in_window = (pr["created_at"] >= window_start) & (pr["created_at"] <= window_end)
    pr_w = pr.loc[in_window].copy()
    logger.info(
        "window filter: %d -> %d PRs (dropped %d outside window)",
        len(pr),
        len(pr_w),
        len(pr) - len(pr_w),
    )

    # ---- churn aggregation from pr_commit_details --------------------------
    # pr_commit_details has one row per file per commit per PR: additions,
    # deletions, changes (floats; null for binary). changed_files = unique
    # filenames per PR. Sum additions/deletions across rows.

    pcd = ds.dataset(str(DSET / "pr_commit_details.parquet")).to_table().to_pandas()
    logger.info("loaded pr_commit_details rows=%d", len(pcd))

    # Limit to in-window PR ids to keep memory down.
    in_window_ids = pr_w["id"].to_numpy()
    pcd = pcd[pcd["pr_id"].isin(in_window_ids)]
    logger.info("pr_commit_details restricted to in-window PRs rows=%d", len(pcd))

    churn = pcd.groupby("pr_id", as_index=False).agg(
        additions=("additions", lambda s: int(s.fillna(0).sum())),
        deletions=("deletions", lambda s: int(s.fillna(0).sum())),
        changed_files=("filename", lambda s: int(s.dropna().nunique())),
    )
    logger.info("churn aggregated rows=%d", len(churn))

    # ---- assemble agentic_prs ---------------------------------------------

    agentic = pr_w.merge(churn, left_on="id", right_on="pr_id", how="left")
    # Fill missing churn (PRs with no commit-details rows) with 0.
    for c in ("additions", "deletions", "changed_files"):
        agentic[c] = agentic[c].fillna(0).astype("int64")
    agentic["churn"] = (agentic["additions"] + agentic["deletions"]).astype("int64")

    agentic = agentic.rename(columns={"number": "pr_number", "user": "user_login"})
    agentic_cols = [
        "repo_full_name",
        "pr_number",
        "id",
        "repo_id",
        "agent",
        "user_login",
        "state",
        "created_at",
        "merged_at",
        "closed_at",
        "additions",
        "deletions",
        "changed_files",
        "churn",
        "title",
        "html_url",
    ]
    agentic = agentic[agentic_cols].copy()
    _log_table(logger, "agentic_prs", agentic)

    agentic_path = out_dir / "agentic_prs.parquet"
    agentic.to_parquet(agentic_path, index=False)
    logger.info("wrote %s rows=%d", agentic_path, len(agentic))

    # ---- assemble ai_repos -------------------------------------------------
    # One row per unique repo_full_name in the window, with PR-level summary
    # stats and a left-join to repository.parquet for stars/language so
    # Phase B has matching covariates already on hand.

    pr_summary = agentic.groupby("repo_full_name", as_index=False).agg(
        n_agentic_prs_in_window=("pr_number", "size"),
        n_merged_in_window=("merged_at", lambda s: int(s.notna().sum())),
        n_agents_distinct=("agent", "nunique"),
        first_agentic_pr_at=("created_at", "min"),
        last_agentic_pr_at=("created_at", "max"),
        agents=(
            "agent",
            lambda s: ",".join(sorted({str(x) for x in s.dropna().unique()})),
        ),
    )

    repo_join = repo.rename(columns={"full_name": "repo_full_name"})[
        ["repo_full_name", "id", "language", "stars", "forks", "license", "url"]
    ].rename(columns={"id": "repo_id", "url": "repo_url"})

    ai_repos = pr_summary.merge(repo_join, on="repo_full_name", how="left")
    n_no_meta = int(ai_repos["repo_id"].isna().sum())
    if n_no_meta:
        logger.warning(
            "%d AI repos have no row in repository.parquet (left-join NaN)", n_no_meta
        )
    # Phase-B-friendly types.
    ai_repos["stars"] = ai_repos["stars"].astype("Int64")
    ai_repos["forks"] = ai_repos["forks"].astype("Int64")
    ai_repos = ai_repos.sort_values("repo_full_name").reset_index(drop=True)
    _log_table(logger, "ai_repos", ai_repos)

    ai_repos_path = out_dir / "ai_repos.csv"
    ai_repos.to_csv(ai_repos_path, index=False)
    logger.info("wrote %s rows=%d", ai_repos_path, len(ai_repos))

    # ---- date bounds (sanity) ---------------------------------------------
    cmin, cmax = agentic["created_at"].min(), agentic["created_at"].max()
    logger.info("agentic_prs.created_at bounds: min=%s max=%s", cmin, cmax)

    # ---- manifest ----------------------------------------------------------

    write_manifest(
        out_dir,
        phase="A",
        agent="data-miner",
        outputs={
            ai_repos_path.name: len(ai_repos),
            agentic_path.name: len(agentic),
        },
    )
    logger.info("wrote %s", out_dir / "run_manifest.json")

    # ---- flip the latest symlink ------------------------------------------

    latest = REPO / "data_derived" / "latest"
    if latest.is_symlink() or latest.exists():
        latest.unlink()
    # Relative target so the symlink survives directory moves.
    latest.symlink_to(today, target_is_directory=True)
    logger.info("symlink data_derived/latest -> %s", today)

    print(
        f"Phase A complete. ai_repos rows={len(ai_repos)} agentic_prs rows={len(agentic)}"
    )
    print(f"created_at bounds: {cmin} .. {cmax}")
    print(f"output dir: {out_dir}")


if __name__ == "__main__":
    main()
