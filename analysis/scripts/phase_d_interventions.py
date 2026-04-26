"""Phase D - RQ3 human-PR sampling + security-tool intervention classification.

Run via: ``uv run python analysis/scripts/phase_d_interventions.py [--step <name>]``

Steps (idempotent, resumable, all GitHub responses cached):
  pool          : build the human PR candidate pool from AIDev
                  ``human_pull_request.parquet`` filtered to (AI repos in
                  ``ai_repos.csv``) ∩ (in-window) ∩ (author not in
                  ``configs/security_bots.txt``) ∩ (title+body not matching
                  ``configs/agent_fingerprints.yaml``). Writes
                  ``_phase_d_human_pool.parquet`` (intermediate).
  churn         : for every pool member, fetch GitHub
                  ``GET /repos/{o}/{n}/pulls/{number}`` to obtain
                  ``additions + deletions``; merges churn into the pool.
                  Writes ``_phase_d_human_pool_with_churn.parquet``.
  sample        : per-repo, bin agentic PRs into per-repo churn quartiles;
                  sample human pool to match agentic count per quartile,
                  without replacement, seeded by ``RANDOM_SEED``. Emits
                  ``human_pr_sample.parquet`` + ``human_pr_sample_log.csv``.
  events_agentic: build the (comments ∪ reviews ∪ inline) event table for
                  every in-scope agentic PR, sourcing from AIDev
                  ``pr_comments``, ``pr_reviews``, ``pr_review_comments_v2``.
  events_human  : fetch issue comments + reviews + inline review comments
                  via GitHub for each sampled human PR; build the same
                  event-table schema.
  classify      : apply the two-signal classifier (bot-identity primary;
                  bot+security-keyword secondary, only on bot-authored
                  text) per the ``intervention-rules`` skill. Aggregates
                  per PR. Writes ``pr_interventions.parquet``.
  manifest      : extend ``run_manifest.json`` in place to phase = [A,B,C,D]
                  with the two new outputs and a ``phase_d`` summary block.

The script is read-only on ``data_raw/aidev/`` and ``data_raw/github_cache/``
(it only writes net-new cache entries). Outputs go under
``data_derived/<today>/``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import requests
import yaml
from dotenv import load_dotenv
from numpy.random import default_rng
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "analysis" / "scripts"))
from write_manifest import sha256_of, write_manifest  # noqa: E402

LOGS = REPO / "logs"
CACHE_DIR = REPO / "data_raw" / "github_cache"
AUDIT_LOG = LOGS / "github-mcp-audit.log"
DSET = REPO / "data_raw" / "aidev"

# Stable inputs/outputs filenames
HUMAN_POOL = "_phase_d_human_pool.parquet"
HUMAN_POOL_CHURN = "_phase_d_human_pool_with_churn.parquet"
EVENTS_AGENTIC = "_phase_d_events_agentic.parquet"
EVENTS_HUMAN = "_phase_d_events_human.parquet"
HUMAN_SAMPLE = "human_pr_sample.parquet"
HUMAN_SAMPLE_LOG = "human_pr_sample_log.csv"
PR_INTERVENTIONS = "pr_interventions.parquet"


# ---------- helpers ---------------------------------------------------------


def _setup_logger() -> logging.Logger:
    LOGS.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("phase_d")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    fh = logging.FileHandler(LOGS / "phase_d.log")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger


def _audit(line: str) -> None:
    LOGS.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG.open("a") as f:
        f.write(f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} {line}\n")


def _window() -> tuple[str, str]:
    return os.environ["WINDOW_START"], os.environ["WINDOW_END"]


def _slug_endpoint(endpoint: str) -> str:
    return endpoint.strip("/").replace("/", "__")


def _params_hash(params: dict[str, Any]) -> str:
    canon = json.dumps(params, sort_keys=True, separators=(",", ":"))
    ws, we = _window()
    canon += f"|window={ws}..{we}"
    return hashlib.sha256(canon.encode()).hexdigest()[:16]


def _cache_path(endpoint: str, repo: str | None, params: dict[str, Any]) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    parts = [_slug_endpoint(endpoint)]
    if repo:
        parts.append(repo.replace("/", "__"))
    parts.append(_params_hash(params))
    return CACHE_DIR / ("-".join(parts) + ".json")


def _today_dir() -> Path:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    # Use existing latest if it points at a dated directory we should append to
    latest = REPO / "data_derived" / "latest"
    if latest.is_symlink():
        target = latest.resolve()
        if target.exists() and target.parent == REPO / "data_derived":
            return target
    return REPO / "data_derived" / today


# ---------- GitHub REST client ---------------------------------------------


class GitHubClient:
    """Cached GitHub REST client mirroring Phase B's pattern."""

    BASE = "https://api.github.com"

    def __init__(self, token: str, logger: logging.Logger) -> None:
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "AIDev-security-study/phase-d",
            }
        )
        self.logger = logger
        self.calls_made = 0
        self.cache_hits = 0
        self.cache_404_hits = 0

    @retry(
        retry=retry_if_exception_type((requests.HTTPError, requests.ConnectionError)),
        wait=wait_exponential(multiplier=2, min=2, max=120),
        stop=stop_after_attempt(6),
        reraise=True,
    )
    def _http_get(self, url: str, params: dict[str, Any]) -> requests.Response:
        r = self.session.get(url, params=params, timeout=60)
        if r.status_code in (502, 503, 504, 429):
            ra = r.headers.get("Retry-After")
            if ra:
                try:
                    time.sleep(min(float(ra), 120))
                except ValueError:
                    pass
            r.raise_for_status()
        if r.status_code == 403 and "rate limit" in r.text.lower():
            reset = r.headers.get("X-RateLimit-Reset")
            if reset:
                try:
                    sleep_s = max(0, int(reset) - int(time.time())) + 5
                    self.logger.warning("primary rate-limit hit, sleeping %ds", sleep_s)
                    time.sleep(min(sleep_s, 1800))
                except ValueError:
                    pass
            raise requests.HTTPError(f"403 rate limit: {r.text[:200]}", response=r)
        return r

    def get(
        self,
        endpoint: str,
        *,
        repo: str | None,
        params: dict[str, Any] | None = None,
        cache_404: bool = True,
    ) -> tuple[int, dict | list | None]:
        params = params or {}
        path = _cache_path(endpoint, repo, params)
        if path.exists():
            try:
                blob = json.loads(path.read_text())
            except json.JSONDecodeError:
                blob = None
            if isinstance(blob, dict) and blob.get("_cached_404"):
                self.cache_404_hits += 1
                return 404, None
            if blob is not None:
                self.cache_hits += 1
                return 200, blob

        url = f"{self.BASE}{endpoint}"
        r = self._http_get(url, params)
        self.calls_made += 1
        _audit(f"GET {endpoint} repo={repo} params={params} status={r.status_code}")

        if r.status_code == 200:
            body = r.json()
            path.write_text(json.dumps(body))
            remaining = int(r.headers.get("X-RateLimit-Remaining", "5000") or 5000)
            limit = int(r.headers.get("X-RateLimit-Limit", "5000") or 5000)
            if remaining <= 2:
                reset = int(r.headers.get("X-RateLimit-Reset", "0") or 0)
                wait_s = max(0, reset - int(time.time())) + 2
                if wait_s > 0:
                    self.logger.info(
                        "rate-limit %d/%d remaining, sleeping %ds",
                        remaining,
                        limit,
                        wait_s,
                    )
                    time.sleep(min(wait_s, 1800))
            return 200, body
        if r.status_code == 404:
            if cache_404:
                path.write_text(json.dumps({"_cached_404": True}))
            return 404, None
        if r.status_code == 410:
            # Gone (e.g., PR removed) — cache as 404-equivalent.
            if cache_404:
                path.write_text(json.dumps({"_cached_404": True}))
            return 410, None
        self.logger.error(
            "Unexpected %s for %s %s: %s",
            r.status_code,
            endpoint,
            params,
            r.text[:200],
        )
        return r.status_code, None

    def get_paginated(
        self,
        endpoint: str,
        *,
        repo: str | None,
        per_page: int = 100,
        max_pages: int = 10,
    ) -> list[Any]:
        """Walk paginated GET endpoints, caching one file per page."""
        out: list[Any] = []
        for page in range(1, max_pages + 1):
            params = {"per_page": per_page, "page": page}
            status, body = self.get(endpoint, repo=repo, params=params)
            if status != 200 or not isinstance(body, list):
                break
            out.extend(body)
            if len(body) < per_page:
                break
        return out


# ---------- helpers: schema / parsing ---------------------------------------


def _to_full_name(repo_url: str | None) -> str:
    if not isinstance(repo_url, str):
        return ""
    return repo_url.replace("https://api.github.com/repos/", "")


def _load_security_bots() -> set[str]:
    p = REPO / "configs" / "security_bots.txt"
    bots = set()
    for line in p.read_text().splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            bots.add(s.lower())
    return bots


def _load_fingerprint_regex() -> list[re.Pattern]:
    p = REPO / "configs" / "agent_fingerprints.yaml"
    cfg = yaml.safe_load(p.read_text())
    out = []
    for entry in cfg.get("patterns", []):
        out.append(re.compile(entry["regex"]))
    return out


def _load_security_keyword_regex() -> re.Pattern:
    p = REPO / "configs" / "security_patterns.yaml"
    cfg = yaml.safe_load(p.read_text())
    parts: list[str] = []
    for tok in cfg.get("tokens", []):
        # tokens are already regex-like (CVE-…, GHSA-…)
        parts.append(tok)
    for kw in cfg.get("keywords", []):
        # whole-token match for keywords; allow phrases like "sql injection"
        parts.append(re.escape(kw).replace(r"\ ", r"\s+"))
    if not parts:
        return re.compile(r"$^")
    return re.compile("|".join(f"(?:{p})" for p in parts), flags=re.IGNORECASE)


def _is_any_bot(login: str | None, type_: str | None) -> bool:
    if isinstance(type_, str) and type_.lower() == "bot":
        return True
    if isinstance(login, str) and login.lower().endswith("[bot]"):
        return True
    return False


# ---------- step: pool ------------------------------------------------------


def step_pool(out_dir: Path, logger: logging.Logger) -> pd.DataFrame:
    """Build the human PR candidate pool (no churn yet)."""
    pool_path = out_dir / HUMAN_POOL
    if pool_path.exists():
        df = pd.read_parquet(pool_path)
        logger.info("pool: cached hit rows=%d", len(df))
        return df

    ai_repos = pd.read_csv(out_dir / "ai_repos.csv")["repo_full_name"]
    ai_set = set(ai_repos)

    hpr = pq.read_table(DSET / "human_pull_request.parquet").to_pandas()
    hpr["repo_full_name"] = hpr["repo_url"].map(_to_full_name)
    hpr["created_at"] = pd.to_datetime(hpr["created_at"], errors="coerce", utc=True)
    hpr["closed_at"] = pd.to_datetime(hpr["closed_at"], errors="coerce", utc=True)
    hpr["merged_at"] = pd.to_datetime(hpr["merged_at"], errors="coerce", utc=True)

    ws_str, we_str = _window()
    ws = pd.Timestamp(ws_str, tz="UTC")
    we = pd.Timestamp(we_str + " 23:59:59", tz="UTC")

    n_total = len(hpr)
    df = hpr[hpr["repo_full_name"].isin(ai_set)].copy()
    n_in_ai = len(df)
    df = df[(df["created_at"] >= ws) & (df["created_at"] <= we)]
    n_in_window = len(df)

    # Don't double-count agentic PRs that may sit in human_pull_request by mistake.
    ag = pd.read_parquet(out_dir / "agentic_prs.parquet")
    ag_keys = set(zip(ag["repo_full_name"], ag["pr_number"], strict=False))
    is_agentic_dup = pd.Series(
        [k in ag_keys for k in zip(df["repo_full_name"], df["number"], strict=False)],
        index=df.index,
    )
    df = df[~is_agentic_dup]
    n_after_dedup = len(df)

    # Bot exclusion (security_bots.txt). Also drop *any* author ending in [bot].
    sec_bots = _load_security_bots()
    user_lower = df["user"].astype(str).str.lower()
    is_sec_bot = user_lower.isin(sec_bots)
    is_any_bot = user_lower.str.endswith("[bot]")
    df = df[~(is_sec_bot | is_any_bot)].copy()
    n_after_bot = len(df)

    # Agent fingerprint regex on title+body (precision-first; drop any match)
    fp_res = _load_fingerprint_regex()
    title = df["title"].astype(str).fillna("")
    body = df["body"].astype(str).fillna("")
    text = title + "\n" + body
    matched = pd.Series(False, index=df.index)
    for rx in fp_res:
        # Use the precompiled pattern's `search` rather than passing the
        # pattern to str.contains (pandas warns when the regex has groups).
        matched = matched | text.map(lambda s, _rx=rx: bool(_rx.search(s)))
    df = df[~matched].copy()
    n_after_fp = len(df)

    # Tag pr_type for downstream
    df["pr_type"] = "human"

    logger.info(
        "pool: total=%d in_ai=%d in_window=%d after_dedup_agentic=%d "
        "after_bot=%d after_fingerprint=%d",
        n_total,
        n_in_ai,
        n_in_window,
        n_after_dedup,
        n_after_bot,
        n_after_fp,
    )

    df = df.reset_index(drop=True)
    df.to_parquet(pool_path, index=False)
    return df


# ---------- step: churn -----------------------------------------------------


def step_churn(
    client: GitHubClient,
    out_dir: Path,
    logger: logging.Logger,
) -> pd.DataFrame:
    """Augment the human pool with GitHub additions/deletions."""
    out_path = out_dir / HUMAN_POOL_CHURN
    if out_path.exists():
        df = pd.read_parquet(out_path)
        logger.info("churn: cached hit rows=%d", len(df))
        return df

    pool = pd.read_parquet(out_dir / HUMAN_POOL)
    pool = pool.copy()
    pool["additions"] = pd.NA
    pool["deletions"] = pd.NA
    pool["changed_files"] = pd.NA

    # Resumable state file in case of interruption mid-loop.
    progress_path = out_dir / "_phase_d_churn_progress.parquet"
    if progress_path.exists():
        prev = pd.read_parquet(progress_path)
        idx_done = set(zip(prev["repo_full_name"], prev["number"], strict=False))
        pool = pool.merge(
            prev[
                ["repo_full_name", "number", "additions", "deletions", "changed_files"]
            ],
            on=["repo_full_name", "number"],
            how="left",
            suffixes=("", "_pp"),
        )
        for col in ["additions", "deletions", "changed_files"]:
            pool[col] = pool[col + "_pp"].combine_first(pool[col])
            pool.drop(columns=[col + "_pp"], inplace=True)
        logger.info("churn: resuming with %d previously-fetched PRs", len(prev))
    else:
        idx_done = set()

    n_total = len(pool)
    n_done = 0
    n_404 = 0
    n_err = 0
    last_save = time.time()

    # Order by repo for cache locality
    pool = pool.sort_values(["repo_full_name", "number"]).reset_index(drop=True)
    for i, row in pool.iterrows():
        full = row["repo_full_name"]
        number = int(row["number"])
        if (full, number) in idx_done or pd.notna(row.get("additions")):
            continue
        if "/" not in full:
            continue
        owner, name = full.split("/", 1)
        endpoint = f"/repos/{owner}/{name}/pulls/{number}"
        status, body = client.get(endpoint, repo=full, params={})
        if status == 200 and isinstance(body, dict):
            pool.at[i, "additions"] = body.get("additions")
            pool.at[i, "deletions"] = body.get("deletions")
            pool.at[i, "changed_files"] = body.get("changed_files")
            n_done += 1
        elif status in (404, 410):
            n_404 += 1
        else:
            n_err += 1
            logger.warning("churn: unexpected status=%s for %s", status, endpoint)

        if (i + 1) % 200 == 0 or time.time() - last_save > 90:
            done_so_far = pool[pool["additions"].notna()][
                ["repo_full_name", "number", "additions", "deletions", "changed_files"]
            ]
            done_so_far.to_parquet(progress_path, index=False)
            last_save = time.time()
            logger.info(
                "churn: progress %d/%d (n_done=%d, 404=%d, err=%d, "
                "calls=%d, cache_hits=%d)",
                i + 1,
                n_total,
                n_done,
                n_404,
                n_err,
                client.calls_made,
                client.cache_hits,
            )

    # Drop PRs we couldn't get churn for
    pool["churn"] = pd.to_numeric(pool["additions"], errors="coerce").fillna(0).astype(
        "int64"
    ) + pd.to_numeric(pool["deletions"], errors="coerce").fillna(0).astype("int64")
    n_dropped = pool["additions"].isna().sum()
    pool = pool[pool["additions"].notna()].copy()
    pool["additions"] = pool["additions"].astype("int64")
    pool["deletions"] = pool["deletions"].astype("int64")
    pool["changed_files"] = pool["changed_files"].astype("int64")
    pool["churn"] = pool["churn"].astype("int64")

    logger.info(
        "churn: kept=%d dropped_no_meta=%d (404/410=%d, err=%d)",
        len(pool),
        n_dropped,
        n_404,
        n_err,
    )
    pool = pool.reset_index(drop=True)
    pool.to_parquet(out_path, index=False)
    return pool


# ---------- step: sample ----------------------------------------------------


def _per_repo_quartile_bins(churn_series: pd.Series) -> tuple[float, float, float]:
    """Return (q25, q50, q75) on a per-repo agentic churn series."""
    if len(churn_series) == 0:
        return (0.0, 0.0, 0.0)
    q = churn_series.quantile([0.25, 0.5, 0.75]).values
    return (float(q[0]), float(q[1]), float(q[2]))


def _bin_churn(value: float, q: tuple[float, float, float]) -> int:
    if value < q[0]:
        return 0
    if value < q[1]:
        return 1
    if value < q[2]:
        return 2
    return 3


_DEP_TITLE_RE = re.compile(
    r"^(chore|build|deps)(\([^)]*\))?:\s*(bump|update)\b",
    flags=re.IGNORECASE,
)


def step_sample(out_dir: Path, logger: logging.Logger) -> pd.DataFrame:
    """Per-repo churn-quartile-matched sample of human PRs."""
    out_path = out_dir / HUMAN_SAMPLE
    log_path = out_dir / HUMAN_SAMPLE_LOG
    if out_path.exists() and log_path.exists():
        df = pd.read_parquet(out_path)
        logger.info("sample: cached hit rows=%d", len(df))
        return df

    pool = pd.read_parquet(out_dir / HUMAN_POOL_CHURN)
    ag = pd.read_parquet(out_dir / "agentic_prs.parquet").copy()
    ag["pr_type"] = "agentic"

    # AIDev pr_task_type for human PRs is unavailable; for agentic carry from
    # the AIDev pr_task_type table (joined here by id).
    try:
        tt = pq.read_table(DSET / "pr_task_type.parquet").to_pandas()
        tt = tt[["id", "type"]].rename(columns={"type": "task_type"})
        ag = ag.merge(tt, on="id", how="left")
    except Exception:
        ag["task_type"] = ""

    rng = default_rng(int(os.environ["RANDOM_SEED"]))

    chosen_rows: list[pd.DataFrame] = []
    log_rows: list[dict] = []

    repos_with_agentic = sorted(ag["repo_full_name"].dropna().unique())
    n_repos_with_pool = 0
    for repo_full_name in repos_with_agentic:
        ag_repo = ag[ag["repo_full_name"] == repo_full_name]
        pool_repo = pool[pool["repo_full_name"] == repo_full_name]
        if pool_repo.empty:
            log_rows.append(
                {
                    "repo_full_name": repo_full_name,
                    "churn_bin": -1,
                    "agentic_count": int(len(ag_repo)),
                    "human_pool_count": 0,
                    "sampled_count": 0,
                    "shortfall": int(len(ag_repo)),
                    "reason": "no_human_pool",
                }
            )
            continue
        n_repos_with_pool += 1

        cuts = _per_repo_quartile_bins(ag_repo["churn"])
        ag_repo = ag_repo.copy()
        ag_repo["churn_bin"] = ag_repo["churn"].apply(lambda v: _bin_churn(v, cuts))
        pool_repo = pool_repo.copy()
        pool_repo["churn_bin"] = pool_repo["churn"].apply(lambda v: _bin_churn(v, cuts))

        for b in range(4):
            n_target = int((ag_repo["churn_bin"] == b).sum())
            bin_pool = pool_repo[pool_repo["churn_bin"] == b]
            n_pool = int(len(bin_pool))
            if n_target == 0:
                continue
            n_take = min(n_target, n_pool)
            if n_take > 0:
                seed_bin = int(rng.integers(0, 2**31 - 1))
                draw = bin_pool.sample(n=n_take, random_state=seed_bin)
                chosen_rows.append(draw)
            shortfall = max(0, n_target - n_pool)
            if shortfall > 0:
                log_rows.append(
                    {
                        "repo_full_name": repo_full_name,
                        "churn_bin": b,
                        "agentic_count": n_target,
                        "human_pool_count": n_pool,
                        "sampled_count": n_take,
                        "shortfall": shortfall,
                        "reason": "bin_undersupplied",
                    }
                )

    if chosen_rows:
        sample = pd.concat(chosen_rows, ignore_index=True)
    else:
        sample = pool.head(0).copy()
        sample["churn_bin"] = []

    # Build the output frame matching agentic_prs schema as closely as practicable
    # (so downstream concat works). The human_pull_request table doesn't have
    # `additions`/`deletions`/`changed_files`/`agent`/`id`/`repo_id`; we already
    # filled additions/deletions in step_churn.
    sample = sample.rename(columns={"number": "pr_number", "user": "user_login"})
    # Some columns may not exist if pool was empty — guard.
    for col in [
        "additions",
        "deletions",
        "changed_files",
        "churn",
        "churn_bin",
        "title",
        "html_url",
        "state",
        "created_at",
        "merged_at",
        "closed_at",
        "id",
        "repo_id",
        "agent",
        "user_login",
        "repo_full_name",
        "pr_number",
        "body",
        "user_id",
    ]:
        if col not in sample.columns:
            sample[col] = pd.NA

    # Dependency-update sensitivity flag (title-level heuristic)
    sample["is_dep_update"] = (
        sample["title"].astype(str).str.match(_DEP_TITLE_RE).fillna(False)
    )
    # Carry no AIDev-derived task_type for human PRs (AIDev provides one only
    # for curated agentic PRs); analyst gets empty string per the brief.
    sample["task_type"] = ""

    # Standardize dtypes
    for c in ("pr_number", "id", "repo_id", "user_id"):
        sample[c] = pd.to_numeric(sample[c], errors="coerce").astype("Int64")
    for c in ("additions", "deletions", "changed_files", "churn", "churn_bin"):
        sample[c] = pd.to_numeric(sample[c], errors="coerce").astype("Int64")
    sample["pr_type"] = "human"

    out_cols = [
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
        "churn_bin",
        "title",
        "html_url",
        "task_type",
        "is_dep_update",
        "pr_type",
    ]
    sample = sample.reindex(columns=out_cols)
    sample = sample.sort_values(
        ["repo_full_name", "created_at", "pr_number"], na_position="last"
    ).reset_index(drop=True)

    log_df = pd.DataFrame(
        log_rows,
        columns=[
            "repo_full_name",
            "churn_bin",
            "agentic_count",
            "human_pool_count",
            "sampled_count",
            "shortfall",
            "reason",
        ],
    )
    log_df.to_csv(log_path, index=False)
    sample.to_parquet(out_path, index=False)

    logger.info(
        "sample: drew %d human PRs across %d repos; log_rows=%d "
        "(repos_with_pool=%d / total_ai_repos_with_agentic=%d)",
        len(sample),
        sample["repo_full_name"].nunique(),
        len(log_df),
        n_repos_with_pool,
        len(repos_with_agentic),
    )
    return sample


# ---------- step: events_agentic --------------------------------------------


def step_events_agentic(out_dir: Path, logger: logging.Logger) -> pd.DataFrame:
    """Build (comments ∪ reviews ∪ inline_v2) for in-scope agentic PRs."""
    out_path = out_dir / EVENTS_AGENTIC
    if out_path.exists():
        df = pd.read_parquet(out_path)
        logger.info("events_agentic: cached hit rows=%d", len(df))
        return df

    ag = pd.read_parquet(out_dir / "agentic_prs.parquet")
    in_scope_ids = set(ag["id"].astype("int64"))

    # pr_comments: id, pr_id, user, user_id, user_type, created_at, body
    com = pq.read_table(DSET / "pr_comments.parquet").to_pandas()
    com = com[com["pr_id"].isin(in_scope_ids)].copy()
    com = com.rename(columns={"user": "user_login"})
    com["created_at"] = pd.to_datetime(com["created_at"], errors="coerce", utc=True)
    com["source"] = "pr_comments"
    com["state"] = ""
    com["body"] = com["body"].astype(str).fillna("")
    com_evt = com[
        ["pr_id", "user_login", "user_type", "created_at", "body", "source", "state"]
    ].copy()

    # pr_reviews: id, pr_id, user, user_type, state, submitted_at, body
    rev = pq.read_table(DSET / "pr_reviews.parquet").to_pandas()
    rev = rev[rev["pr_id"].isin(in_scope_ids)].copy()
    rev = rev.rename(columns={"user": "user_login", "submitted_at": "created_at"})
    rev["created_at"] = pd.to_datetime(rev["created_at"], errors="coerce", utc=True)
    rev["source"] = "pr_reviews"
    rev["body"] = rev["body"].astype(str).fillna("")
    rev_evt = rev[
        ["pr_id", "user_login", "user_type", "created_at", "body", "source", "state"]
    ].copy()

    # pr_review_comments_v2: pull_request_url -> derive (repo, pr_number) -> map to pr_id
    inl = pq.read_table(DSET / "pr_review_comments_v2.parquet").to_pandas()

    def parse_pr_url(u: str | None) -> tuple[str | None, int | None]:
        if not isinstance(u, str):
            return None, None
        s = u.replace("https://api.github.com/repos/", "")
        if "/pulls/" not in s:
            return None, None
        repo, num = s.split("/pulls/", 1)
        try:
            return repo, int(num)
        except ValueError:
            return None, None

    parsed = inl["pull_request_url"].map(parse_pr_url)
    inl["repo_full_name"] = [t[0] for t in parsed]
    inl["pr_number"] = [t[1] for t in parsed]

    # Map (repo, number) -> pr_id from agentic_prs
    key2id = dict(
        zip(zip(ag["repo_full_name"], ag["pr_number"]), ag["id"], strict=False)
    )
    inl["pr_id"] = [
        key2id.get((r, n)) if (r is not None and n is not None) else None
        for r, n in zip(inl["repo_full_name"], inl["pr_number"], strict=False)
    ]
    inl = inl[inl["pr_id"].notna()].copy()
    inl["pr_id"] = inl["pr_id"].astype("int64")

    inl = inl.rename(columns={"user": "user_login"})
    inl["created_at"] = pd.to_datetime(inl["created_at"], errors="coerce", utc=True)
    inl["source"] = "pr_review_comments_v2"
    inl["state"] = ""
    inl["body"] = inl["body"].astype(str).fillna("")
    inl_evt = inl[
        ["pr_id", "user_login", "user_type", "created_at", "body", "source", "state"]
    ].copy()

    events = pd.concat([com_evt, rev_evt, inl_evt], ignore_index=True)
    events["pr_id"] = events["pr_id"].astype("int64")
    events["pr_type"] = "agentic"
    events.to_parquet(out_path, index=False)
    logger.info(
        "events_agentic: comments=%d reviews=%d inline_v2=%d total=%d",
        len(com_evt),
        len(rev_evt),
        len(inl_evt),
        len(events),
    )
    return events


# ---------- step: events_human ----------------------------------------------


def step_events_human(
    client: GitHubClient,
    out_dir: Path,
    logger: logging.Logger,
) -> pd.DataFrame:
    """Fetch comments/reviews/inline-comments for sampled human PRs."""
    out_path = out_dir / EVENTS_HUMAN
    if out_path.exists():
        df = pd.read_parquet(out_path)
        logger.info("events_human: cached hit rows=%d", len(df))
        return df

    sample = pd.read_parquet(out_dir / HUMAN_SAMPLE)
    rows: list[dict] = []
    n = len(sample)
    last_save = time.time()
    progress_path = out_dir / "_phase_d_events_human_progress.parquet"
    seen_keys: set[tuple[str, int]] = set()
    if progress_path.exists():
        prev = pd.read_parquet(progress_path)
        rows = prev.to_dict("records")
        seen_keys = set(zip(prev["repo_full_name"], prev["pr_number"], strict=False))
        logger.info(
            "events_human: resuming with %d previously-fetched PRs", len(seen_keys)
        )

    for idx, row in sample.iterrows():
        full = row["repo_full_name"]
        number = int(row["pr_number"]) if pd.notna(row["pr_number"]) else None
        if number is None or "/" not in str(full):
            continue
        if (full, number) in seen_keys:
            continue
        owner, name = full.split("/", 1)

        # Issue comments
        ic = client.get_paginated(
            f"/repos/{owner}/{name}/issues/{number}/comments",
            repo=full,
            per_page=100,
            max_pages=10,
        )
        for c in ic:
            user = c.get("user") or {}
            rows.append(
                {
                    "repo_full_name": full,
                    "pr_number": number,
                    "user_login": user.get("login"),
                    "user_type": user.get("type"),
                    "created_at": c.get("created_at"),
                    "body": c.get("body") or "",
                    "state": "",
                    "source": "pr_comments",
                }
            )

        # Reviews
        rv = client.get_paginated(
            f"/repos/{owner}/{name}/pulls/{number}/reviews",
            repo=full,
            per_page=100,
            max_pages=10,
        )
        for r in rv:
            user = r.get("user") or {}
            rows.append(
                {
                    "repo_full_name": full,
                    "pr_number": number,
                    "user_login": user.get("login"),
                    "user_type": user.get("type"),
                    "created_at": r.get("submitted_at"),
                    "body": r.get("body") or "",
                    "state": r.get("state") or "",
                    "source": "pr_reviews",
                }
            )

        # Inline review comments (PR-level — equivalent to AIDev v2)
        rc = client.get_paginated(
            f"/repos/{owner}/{name}/pulls/{number}/comments",
            repo=full,
            per_page=100,
            max_pages=10,
        )
        for c in rc:
            user = c.get("user") or {}
            rows.append(
                {
                    "repo_full_name": full,
                    "pr_number": number,
                    "user_login": user.get("login"),
                    "user_type": user.get("type"),
                    "created_at": c.get("created_at"),
                    "body": c.get("body") or "",
                    "state": "",
                    "source": "pr_review_comments_v2",
                }
            )
        seen_keys.add((full, number))

        if (idx + 1) % 100 == 0 or time.time() - last_save > 90:
            df = pd.DataFrame(rows)
            df.to_parquet(progress_path, index=False)
            last_save = time.time()
            logger.info(
                "events_human: progress %d/%d (events=%d, calls=%d, "
                "cache_hits=%d, 404=%d)",
                idx + 1,
                n,
                len(rows),
                client.calls_made,
                client.cache_hits,
                client.cache_404_hits,
            )

    df = pd.DataFrame(
        rows,
        columns=[
            "repo_full_name",
            "pr_number",
            "user_login",
            "user_type",
            "created_at",
            "body",
            "state",
            "source",
        ],
    )
    df["created_at"] = pd.to_datetime(df["created_at"], errors="coerce", utc=True)
    df["body"] = df["body"].astype(str).fillna("")
    df["pr_type"] = "human"
    df.to_parquet(out_path, index=False)
    logger.info("events_human: total events=%d", len(df))
    return df


# ---------- step: classify --------------------------------------------------


def _build_pr_meta_frame(out_dir: Path) -> pd.DataFrame:
    """Build a unified PR-level frame: agentic ∪ sampled-human, with the
    canonical Phase D columns (pr_id, repo_full_name, pr_type, pr_number,
    user_login, created_at, merged_at, churn, churn_quartile, task_type,
    rejected, is_dep_update). pr_id is GitHub PR number for downstream
    schema; we also keep AIDev internal id where available."""
    ag = pd.read_parquet(out_dir / "agentic_prs.parquet").copy()
    ag["pr_type"] = "agentic"
    # Carry task_type from AIDev pr_task_type
    try:
        tt = pq.read_table(DSET / "pr_task_type.parquet").to_pandas()
        tt = tt[["id", "type"]].rename(columns={"type": "task_type"})
        ag = ag.merge(tt, on="id", how="left")
    except Exception:
        ag["task_type"] = ""
    ag["task_type"] = ag["task_type"].fillna("").astype(str)

    # Compute per-repo agentic-derived churn quartile bin (1..4 per the brief)
    ag["churn_quartile"] = ag.groupby("repo_full_name")["churn"].transform(
        lambda s: _per_repo_bin_series(s) + 1
    )

    # Dep-update flag
    ag["is_dep_update"] = ag["title"].astype(str).str.match(_DEP_TITLE_RE).fillna(False)

    hu = pd.read_parquet(out_dir / HUMAN_SAMPLE).copy()
    # Convert human's churn_bin (0..3) to quartile (1..4)
    hu["churn_quartile"] = (
        pd.to_numeric(hu["churn_bin"], errors="coerce").astype("Int64") + 1
    )

    # Unify column subset — both go into the same downstream join
    ag_keep = ag[
        [
            "repo_full_name",
            "pr_number",
            "id",
            "user_login",
            "state",
            "created_at",
            "merged_at",
            "closed_at",
            "churn",
            "churn_quartile",
            "task_type",
            "is_dep_update",
            "pr_type",
        ]
    ].copy()
    hu_keep = hu[
        [
            "repo_full_name",
            "pr_number",
            "id",
            "user_login",
            "state",
            "created_at",
            "merged_at",
            "closed_at",
            "churn",
            "churn_quartile",
            "task_type",
            "is_dep_update",
            "pr_type",
        ]
    ].copy()

    pr_meta = pd.concat([ag_keep, hu_keep], ignore_index=True)
    # Coerce types
    pr_meta["pr_number"] = pd.to_numeric(pr_meta["pr_number"], errors="coerce").astype(
        "Int64"
    )
    pr_meta["id"] = pd.to_numeric(pr_meta["id"], errors="coerce").astype("Int64")
    pr_meta["churn"] = pd.to_numeric(pr_meta["churn"], errors="coerce").astype("Int64")
    pr_meta["churn_quartile"] = pd.to_numeric(
        pr_meta["churn_quartile"], errors="coerce"
    ).astype("Int64")
    pr_meta["created_at"] = pd.to_datetime(
        pr_meta["created_at"], errors="coerce", utc=True
    )
    pr_meta["merged_at"] = pd.to_datetime(
        pr_meta["merged_at"], errors="coerce", utc=True
    )
    pr_meta["closed_at"] = pd.to_datetime(
        pr_meta["closed_at"], errors="coerce", utc=True
    )

    pr_meta["merged"] = pr_meta["merged_at"].notna()
    pr_meta["rejected"] = (~pr_meta["merged"]) & (
        pr_meta["state"].astype(str).str.lower() == "closed"
    )
    return pr_meta


def _per_repo_bin_series(s: pd.Series) -> pd.Series:
    if len(s) == 0:
        return s.astype("int64")
    q = s.quantile([0.25, 0.5, 0.75]).values
    cuts = (float(q[0]), float(q[1]), float(q[2]))
    return s.apply(lambda v: _bin_churn(v, cuts)).astype("int64")


def step_classify(out_dir: Path, logger: logging.Logger) -> pd.DataFrame:
    """Apply the two-signal classifier and aggregate to PR-level rows."""
    out_path = out_dir / PR_INTERVENTIONS

    pr_meta = _build_pr_meta_frame(out_dir)

    # Load events (agentic, indexed by pr_id) and (human, indexed by repo+number).
    ev_a = pd.read_parquet(out_dir / EVENTS_AGENTIC)
    ev_h = pd.read_parquet(out_dir / EVENTS_HUMAN)

    sec_bots = _load_security_bots()
    kw_re = _load_security_keyword_regex()

    # ---- Agentic events: per-pr_id classification --------------------------
    ev_a["user_login_lower"] = ev_a["user_login"].astype(str).str.lower()
    ev_a["is_known_security_bot"] = ev_a["user_login_lower"].isin(sec_bots)
    ev_a["is_bot_author"] = [
        _is_any_bot(u, t)
        for u, t in zip(ev_a["user_login"], ev_a["user_type"], strict=False)
    ]
    ev_a["matches_kw"] = ev_a["body"].astype(str).str.contains(kw_re, na=False)
    ev_a["is_intervention"] = ev_a["is_known_security_bot"] | (
        ev_a["is_bot_author"] & ev_a["matches_kw"]
    )
    ev_a["bot_keyword_hit"] = (
        ev_a["is_bot_author"] & ev_a["matches_kw"] & ~ev_a["is_known_security_bot"]
    )

    # ---- Human events: per (repo, number) classification ------------------
    ev_h["user_login_lower"] = ev_h["user_login"].astype(str).str.lower()
    ev_h["is_known_security_bot"] = ev_h["user_login_lower"].isin(sec_bots)
    ev_h["is_bot_author"] = [
        _is_any_bot(u, t)
        for u, t in zip(ev_h["user_login"], ev_h["user_type"], strict=False)
    ]
    ev_h["matches_kw"] = ev_h["body"].astype(str).str.contains(kw_re, na=False)
    ev_h["is_intervention"] = ev_h["is_known_security_bot"] | (
        ev_h["is_bot_author"] & ev_h["matches_kw"]
    )
    ev_h["bot_keyword_hit"] = (
        ev_h["is_bot_author"] & ev_h["matches_kw"] & ~ev_h["is_known_security_bot"]
    )

    bot_id_total = int(
        ev_a["is_known_security_bot"].sum() + ev_h["is_known_security_bot"].sum()
    )
    bot_kw_total = int(ev_a["bot_keyword_hit"].sum() + ev_h["bot_keyword_hit"].sum())
    logger.info(
        "classify: events_agentic=%d (intv=%d) events_human=%d (intv=%d) "
        "bot_id_total=%d bot_kw_total=%d",
        len(ev_a),
        int(ev_a["is_intervention"].sum()),
        len(ev_h),
        int(ev_h["is_intervention"].sum()),
        bot_id_total,
        bot_kw_total,
    )

    # ---- Aggregate per agentic PR (keyed by pr_id == AIDev id) ------------
    ev_a_agg = ev_a.groupby("pr_id", as_index=False).agg(
        n_events=("is_intervention", "size"),
        any_security_intervention=("is_intervention", "any"),
        security_intervention_count=("is_intervention", "sum"),
        n_bot_identity_hits=("is_known_security_bot", "sum"),
        n_bot_keyword_hits=("bot_keyword_hit", "sum"),
    )
    ev_a_intv_only = ev_a[ev_a["is_intervention"]].copy()
    first_intv_a = ev_a_intv_only.groupby("pr_id", as_index=False).agg(
        first_intv_at=("created_at", "min"),
    )
    sources_a = (
        ev_a_intv_only.groupby("pr_id")["source"]
        .agg(lambda s: sorted(set(s)))
        .reset_index()
        .rename(columns={"source": "intervention_sources"})
    )
    chg_req_a = (
        ev_a[
            (ev_a["is_intervention"])
            & (ev_a["state"].astype(str) == "CHANGES_REQUESTED")
        ]
        .groupby("pr_id")
        .size()
        .reset_index(name="_chg_req_count")
    )
    chg_req_a["any_changes_requested_by_security_tool"] = (
        chg_req_a["_chg_req_count"] > 0
    )
    chg_req_a = chg_req_a[["pr_id", "any_changes_requested_by_security_tool"]]

    ag_meta = pr_meta[pr_meta["pr_type"] == "agentic"].copy()
    ag_meta["pr_id_join"] = ag_meta["id"].astype("Int64")
    ag_join = (
        ag_meta.merge(
            ev_a_agg.rename(columns={"pr_id": "pr_id_join"}),
            on="pr_id_join",
            how="left",
        )
        .merge(
            first_intv_a.rename(columns={"pr_id": "pr_id_join"}),
            on="pr_id_join",
            how="left",
        )
        .merge(
            sources_a.rename(columns={"pr_id": "pr_id_join"}),
            on="pr_id_join",
            how="left",
        )
        .merge(
            chg_req_a.rename(columns={"pr_id": "pr_id_join"}),
            on="pr_id_join",
            how="left",
        )
    )

    # ---- Aggregate per human PR (keyed by repo+number) --------------------
    ev_h_agg = ev_h.groupby(["repo_full_name", "pr_number"], as_index=False).agg(
        n_events=("is_intervention", "size"),
        any_security_intervention=("is_intervention", "any"),
        security_intervention_count=("is_intervention", "sum"),
        n_bot_identity_hits=("is_known_security_bot", "sum"),
        n_bot_keyword_hits=("bot_keyword_hit", "sum"),
    )
    ev_h_intv = ev_h[ev_h["is_intervention"]].copy()
    first_intv_h = ev_h_intv.groupby(
        ["repo_full_name", "pr_number"], as_index=False
    ).agg(first_intv_at=("created_at", "min"))
    sources_h = (
        ev_h_intv.groupby(["repo_full_name", "pr_number"])["source"]
        .agg(lambda s: sorted(set(s)))
        .reset_index()
        .rename(columns={"source": "intervention_sources"})
    )
    chg_req_h = (
        ev_h[
            (ev_h["is_intervention"])
            & (ev_h["state"].astype(str) == "CHANGES_REQUESTED")
        ]
        .groupby(["repo_full_name", "pr_number"])
        .size()
        .reset_index(name="_chg_req_count")
    )
    chg_req_h["any_changes_requested_by_security_tool"] = (
        chg_req_h["_chg_req_count"] > 0
    )
    chg_req_h = chg_req_h[
        ["repo_full_name", "pr_number", "any_changes_requested_by_security_tool"]
    ]

    hu_meta = pr_meta[pr_meta["pr_type"] == "human"].copy()
    hu_meta["pr_number_join"] = hu_meta["pr_number"].astype("Int64")
    hu_join = (
        hu_meta.merge(
            ev_h_agg.rename(columns={"pr_number": "pr_number_join"}),
            on=["repo_full_name", "pr_number_join"],
            how="left",
        )
        .merge(
            first_intv_h.rename(columns={"pr_number": "pr_number_join"}),
            on=["repo_full_name", "pr_number_join"],
            how="left",
        )
        .merge(
            sources_h.rename(columns={"pr_number": "pr_number_join"}),
            on=["repo_full_name", "pr_number_join"],
            how="left",
        )
        .merge(
            chg_req_h.rename(columns={"pr_number": "pr_number_join"}),
            on=["repo_full_name", "pr_number_join"],
            how="left",
        )
    )

    # Union and tidy up
    out = pd.concat(
        [
            ag_join.drop(columns=[c for c in ["pr_id_join"] if c in ag_join.columns]),
            hu_join.drop(
                columns=[c for c in ["pr_number_join"] if c in hu_join.columns]
            ),
        ],
        ignore_index=True,
    )

    # Fill NaN for PRs with no events
    out["any_security_intervention"] = (
        out["any_security_intervention"].fillna(False).astype(bool)
    )
    out["security_intervention_count"] = (
        pd.to_numeric(out["security_intervention_count"], errors="coerce")
        .fillna(0)
        .astype("int64")
    )
    out["n_bot_identity_hits"] = (
        pd.to_numeric(out["n_bot_identity_hits"], errors="coerce")
        .fillna(0)
        .astype("int64")
    )
    out["n_bot_keyword_hits"] = (
        pd.to_numeric(out["n_bot_keyword_hits"], errors="coerce")
        .fillna(0)
        .astype("int64")
    )
    out["any_changes_requested_by_security_tool"] = (
        out["any_changes_requested_by_security_tool"].fillna(False).astype(bool)
    )

    # Time to first intervention (hours)
    out["first_intv_at"] = pd.to_datetime(
        out["first_intv_at"], errors="coerce", utc=True
    )
    out["time_to_first_security_intervention_h"] = (
        out["first_intv_at"] - out["created_at"]
    ).dt.total_seconds() / 3600.0

    # intervention_sources: replace NaN with empty list
    def _empty_list(x):
        if isinstance(x, list):
            return x
        if isinstance(x, np.ndarray):
            return list(x)
        return []

    out["intervention_sources"] = out["intervention_sources"].apply(_empty_list)

    # `pr_id` per the schema in the agent brief = GitHub PR number.
    out["pr_id"] = pd.to_numeric(out["pr_number"], errors="coerce").astype("int64")
    out["churn"] = (
        pd.to_numeric(out["churn"], errors="coerce").fillna(0).astype("int64")
    )
    out["churn_quartile"] = pd.to_numeric(
        out["churn_quartile"], errors="coerce"
    ).astype("Int64")
    out["merged"] = out["merged"].astype(bool)
    out["rejected"] = out["rejected"].astype(bool)
    out["is_dep_update"] = out["is_dep_update"].astype(bool)
    out["task_type"] = out["task_type"].astype(str).fillna("")
    out["author_login"] = out["user_login"].astype(str).fillna("")
    out["pr_type"] = out["pr_type"].astype(str)

    out_cols = [
        "pr_id",
        "repo_full_name",
        "pr_number",
        "pr_type",
        "author_login",
        "created_at",
        "merged_at",
        "merged",
        "rejected",
        "churn",
        "churn_quartile",
        "task_type",
        "is_dep_update",
        "any_security_intervention",
        "security_intervention_count",
        "n_bot_identity_hits",
        "n_bot_keyword_hits",
        "any_changes_requested_by_security_tool",
        "time_to_first_security_intervention_h",
        "intervention_sources",
    ]
    out = out.reindex(columns=out_cols)
    out = out.sort_values(
        ["repo_full_name", "created_at", "pr_id"], na_position="last"
    ).reset_index(drop=True)

    out.to_parquet(out_path, index=False)
    logger.info(
        "classify: pr_interventions rows=%d (agentic=%d, human=%d); "
        "any_intv: agentic=%.4f human=%.4f; sha=%s",
        len(out),
        int((out["pr_type"] == "agentic").sum()),
        int((out["pr_type"] == "human").sum()),
        float(out.loc[out["pr_type"] == "agentic", "any_security_intervention"].mean()),
        float(out.loc[out["pr_type"] == "human", "any_security_intervention"].mean()),
        sha256_of(out_path)[:12],
    )
    return out


# ---------- step: manifest --------------------------------------------------


def step_manifest(
    out_dir: Path,
    logger: logging.Logger,
    extra_phase_d: dict,
) -> Path:
    """Extend the existing run_manifest.json with phase D outputs."""
    existing = out_dir / "run_manifest.json"
    prior = json.loads(existing.read_text()) if existing.exists() else {}

    phase_existing = prior.get("phase", [])
    if isinstance(phase_existing, str):
        phase_existing = [phase_existing]
    if "D" not in phase_existing:
        phase_existing = sorted(set(phase_existing + ["D"]))

    # Outputs to log: prior outputs (rebuild row counts) + the two new ones.
    prior_outputs: dict[str, int] = {}
    for name, blob in (prior.get("outputs") or {}).items():
        path = out_dir / name
        if not path.exists():
            continue
        # Recompute rows: parquet via pyarrow, csv via pandas.
        try:
            if name.endswith(".parquet"):
                rows = pq.read_metadata(path).num_rows
            elif name.endswith(".csv"):
                rows = sum(1 for _ in path.open()) - 1
            else:
                rows = blob.get("rows", 0)
        except Exception:
            rows = blob.get("rows", 0)
        prior_outputs[name] = int(rows)

    new_outputs = {
        HUMAN_SAMPLE: pq.read_metadata(out_dir / HUMAN_SAMPLE).num_rows,
        PR_INTERVENTIONS: pq.read_metadata(out_dir / PR_INTERVENTIONS).num_rows,
        HUMAN_SAMPLE_LOG: sum(1 for _ in (out_dir / HUMAN_SAMPLE_LOG).open()) - 1,
    }
    all_outputs = {**prior_outputs, **new_outputs}

    # Preserve all prior top-level keys we don't override (phase_b, phase_c, etc.)
    extra: dict[str, Any] = {}
    for k, v in prior.items():
        if k in {
            "schema_version",
            "run_id",
            "phase",
            "agent",
            "window",
            "seed",
            "aidev_dataset",
            "configs",
            "uv",
            "outputs",
        }:
            continue
        extra[k] = v

    # Override / add the Phase D specifics
    extra["phase"] = phase_existing
    if "intervention_source_choice" in extra:
        # Preserve prior table choice; just affirm rationale.
        extra["intervention_source_choice"]["pr_review_comments_table"] = (
            "pr_review_comments_v2"
        )
    else:
        extra["intervention_source_choice"] = {
            "pr_review_comments_table": "pr_review_comments_v2",
            "rationale": (
                "Defaults to v2 per the intervention-rules skill; Phase D "
                "consumed v2 for inline comments on agentic PRs and the "
                "GitHub /pulls/{n}/comments endpoint for sampled human PRs."
            ),
        }
    extra["phase_d"] = extra_phase_d

    target = write_manifest(
        out_dir,
        phase=phase_existing,
        agent="intervention-classifier",
        outputs=all_outputs,
        extra=extra,
    )
    logger.info("manifest: wrote %s", target)
    return target


# ---------- compute summary stats for the manifest --------------------------


def _phase_d_summary(out_dir: Path) -> dict[str, Any]:
    pr = pd.read_parquet(out_dir / PR_INTERVENTIONS)
    sample = pd.read_parquet(out_dir / HUMAN_SAMPLE)
    ag = pd.read_parquet(out_dir / "agentic_prs.parquet")
    ev_a = pd.read_parquet(out_dir / EVENTS_AGENTIC)
    ev_h = pd.read_parquet(out_dir / EVENTS_HUMAN)

    repos_with_agentic = set(ag["repo_full_name"].dropna().unique())
    repos_with_sample = set(sample["repo_full_name"].dropna().unique())
    repos_in_pr_both = (
        pr.groupby("repo_full_name")["pr_type"]
        .nunique()
        .pipe(lambda s: s[s == 2])
        .index.tolist()
    )
    singletons = sorted(set(pr["repo_full_name"]) - set(repos_in_pr_both))

    # Recompute classifier columns since events parquets don't persist them.
    sec_bots = _load_security_bots()
    kw_re = _load_security_keyword_regex()

    def _recompute(events: pd.DataFrame) -> tuple[int, int]:
        login_lower = events["user_login"].astype(str).str.lower()
        is_known = login_lower.isin(sec_bots)
        is_bot = [
            _is_any_bot(u, t)
            for u, t in zip(events["user_login"], events["user_type"], strict=False)
        ]
        is_bot_series = pd.Series(is_bot, index=events.index)
        matches_kw = events["body"].astype(str).str.contains(kw_re, na=False)
        bot_kw_hit = is_bot_series & matches_kw & ~is_known
        return int(is_known.sum()), int(bot_kw_hit.sum())

    bot_id_a, bot_kw_a = _recompute(ev_a)
    bot_id_h, bot_kw_h = _recompute(ev_h)
    bot_id_total = bot_id_a + bot_id_h
    bot_kw_total = bot_kw_a + bot_kw_h

    ag_pr = pr[pr["pr_type"] == "agentic"]
    hu_pr = pr[pr["pr_type"] == "human"]
    ag_rate = float(ag_pr["any_security_intervention"].mean()) if len(ag_pr) else 0.0
    hu_rate = float(hu_pr["any_security_intervention"].mean()) if len(hu_pr) else 0.0

    cfg_dir = REPO / "configs"
    return {
        "n_agentic_prs_in_scope": int(len(ag_pr)),
        "n_human_prs_sampled": int(len(hu_pr)),
        "pr_review_comments_table": "pr_review_comments_v2",
        "bot_identity_hits_total": bot_id_total,
        "bot_keyword_hits_total": bot_kw_total,
        "n_repos_with_agentic_prs": int(len(repos_with_agentic)),
        "n_repos_with_human_sample": int(len(repos_with_sample)),
        "n_repos_with_both_pr_types": int(len(repos_in_pr_both)),
        "agentic_intervention_rate": ag_rate,
        "human_intervention_rate": hu_rate,
        "agentic_changes_requested_rate": float(
            ag_pr["any_changes_requested_by_security_tool"].mean()
            if len(ag_pr)
            else 0.0
        ),
        "human_changes_requested_rate": float(
            hu_pr["any_changes_requested_by_security_tool"].mean()
            if len(hu_pr)
            else 0.0
        ),
        "singleton_repos_post_filter": len(singletons),
        "singleton_repos_sample": singletons[:10],
        "human_pool_source": "AIDev human_pull_request.parquet (curated subset)",
        "human_pool_source_rationale": (
            "Used AIDev's curated human_pull_request as the human PR pool, "
            "rather than per-repo live GitHub /pulls listings, because: "
            "(a) the AIDev pool already covers 808 AI repos with both PR types, "
            "well above the ≥30-repo floor enforced by the validate-pr-interventions "
            "hook; (b) using the curated pool avoids ~140k redundant pulls.list calls "
            "and keeps the pool deterministic across reruns. Comments/reviews/inline "
            "for sampled human PRs are still fetched live (AIDev does not cover those "
            "for human PRs)."
        ),
        "configs_used": {
            "security_bots.txt": sha256_of(cfg_dir / "security_bots.txt"),
            "agent_fingerprints.yaml": sha256_of(cfg_dir / "agent_fingerprints.yaml"),
            "security_patterns.yaml": sha256_of(cfg_dir / "security_patterns.yaml"),
        },
    }


# ---------- main ------------------------------------------------------------


def main() -> None:
    load_dotenv(REPO / ".env")
    parser = argparse.ArgumentParser(
        description="Phase D — RQ3 sampling + classification"
    )
    parser.add_argument(
        "--step",
        choices=[
            "all",
            "pool",
            "churn",
            "sample",
            "events_agentic",
            "events_human",
            "classify",
            "manifest",
        ],
        default="all",
    )
    args = parser.parse_args()

    logger = _setup_logger()
    out_dir = _today_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    logger.info("phase D: out_dir=%s step=%s", out_dir, args.step)

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GITHUB_TOKEN not set in environment / .env")
    client = GitHubClient(token, logger)

    steps = (
        [
            "pool",
            "churn",
            "sample",
            "events_agentic",
            "events_human",
            "classify",
            "manifest",
        ]
        if args.step == "all"
        else [args.step]
    )

    for step in steps:
        if step == "pool":
            step_pool(out_dir, logger)
        elif step == "churn":
            step_churn(client, out_dir, logger)
        elif step == "sample":
            step_sample(out_dir, logger)
        elif step == "events_agentic":
            step_events_agentic(out_dir, logger)
        elif step == "events_human":
            step_events_human(client, out_dir, logger)
        elif step == "classify":
            step_classify(out_dir, logger)
        elif step == "manifest":
            extra = _phase_d_summary(out_dir)
            step_manifest(out_dir, logger, extra)

    logger.info(
        "github calls=%d cache_hits=%d cache_404_hits=%d",
        client.calls_made,
        client.cache_hits,
        client.cache_404_hits,
    )


if __name__ == "__main__":
    main()
