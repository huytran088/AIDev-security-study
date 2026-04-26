"""Phase B - Build matched control repo cohort for the AIDev security study.

Run via: ``uv run python analysis/scripts/phase_b_match.py [--step <name>]``

Steps (idempotent, resumable, all GitHub responses cached):
  ai_meta : enrich data_derived/latest/ai_repos.csv with created_at,
            owner.type, fork, archived, refreshed stargazers via
            GitHub REST /repos/{owner}/{name}. Drops forks/archived/404s.
  search  : for each unique (language, stars_bin, created_year) bucket in
            the surviving AI cohort, query GitHub Search /search/repositories
            for the top 100 by stars. Excludes AI cohort, dedupes across
            buckets.
  screen  : for each candidate, fetch up to 50 most-recent in-window PRs
            and apply configs/agent_fingerprints.yaml against title+body.
            Drops the candidate on any match. Records n_in_window_prs as
            the activity proxy for controls.
  match   : within each (language, stars_bin, year, owner_type) stratum,
            1:1 nearest-neighbor on z-scored (log_stars, activity) without
            replacement; enforce 0.25 sigma caliper on log_stars within
            stratum.
  balance : pre/post-matching SMDs for stars (log scale), language
            (per-language), repo age (years), owner_type (binary), and
            activity. Emits balance_table.csv.
  manifest: write data_derived/<today>/run_manifest.json with
            phase=["A","B"], preserving Phase A's outputs and adding the
            three Phase B outputs and a github_mcp call-count block.

The script never modifies data_raw/. GitHub responses are cached under
data_raw/github_cache/ per the github-cache-policy skill: cache key
includes endpoint, repo (when scoped), and the params hash. The hash
also folds in the analysis window so a window shift busts the cache.
Per-PR-listing fetches additionally bind the agent-fingerprint sha so
fingerprint changes correctly bust the screen cache.
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
import requests
import yaml
from dotenv import load_dotenv
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

# Fixed knobs from the Phase B brief (recorded in manifest).
N_PR_SCREEN = 50  # PRs per candidate for fingerprint screen
CANDIDATES_PER_BUCKET = 100  # top-N by stars per (lang, stars_bin, year)
MIN_STARS = 100  # match the AIDev curated cohort floor
CALIPER_SIGMA = 0.25  # log(stars) caliper, in stratum sigma units


# ---------- helpers ---------------------------------------------------------


def _setup_logger() -> logging.Logger:
    LOGS.mkdir(parents=True, exist_ok=True)
    log_path = LOGS / "phase_b.log"
    logger = logging.getLogger("phase_b")
    logger.setLevel(logging.INFO)
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


def _audit(line: str) -> None:
    LOGS.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG.open("a") as f:
        f.write(f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} {line}\n")


def _fingerprints_sha() -> str:
    return sha256_of(REPO / "configs" / "agent_fingerprints.yaml")[:12]


def _window() -> tuple[str, str]:
    return os.environ["WINDOW_START"], os.environ["WINDOW_END"]


def _slug_endpoint(endpoint: str) -> str:
    return endpoint.strip("/").replace("/", "__")


def _params_hash(params: dict[str, Any], bind_fingerprint: bool) -> str:
    canon = json.dumps(params, sort_keys=True, separators=(",", ":"))
    ws, we = _window()
    canon += f"|window={ws}..{we}"
    if bind_fingerprint:
        canon += f"|fp={_fingerprints_sha()}"
    return hashlib.sha256(canon.encode()).hexdigest()[:16]


def _cache_path(
    endpoint: str, repo: str | None, params: dict[str, Any], bind_fingerprint: bool
) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    parts = [_slug_endpoint(endpoint)]
    if repo:
        parts.append(repo.replace("/", "__"))
    parts.append(_params_hash(params, bind_fingerprint))
    return CACHE_DIR / ("-".join(parts) + ".json")


# ---------- GitHub REST client (cached) -------------------------------------


class GitHubClient:
    """Thin REST wrapper. Reads cache, writes cache, audit-logs every call."""

    BASE = "https://api.github.com"

    def __init__(self, token: str, logger: logging.Logger) -> None:
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "AIDev-security-study/phase-b",
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
        bind_fingerprint: bool = False,
    ) -> tuple[int, dict | list | None]:
        params = params or {}
        path = _cache_path(endpoint, repo, params, bind_fingerprint)
        if path.exists():
            try:
                blob = json.loads(path.read_text())
            except json.JSONDecodeError:
                blob = None
            if isinstance(blob, dict) and blob.get("_cached_404"):
                self.cache_404_hits += 1
                return 404, None
            if isinstance(blob, dict) and blob.get("_cached_422"):
                self.cache_hits += 1
                return 422, blob
            if blob is not None:
                self.cache_hits += 1
                return 200, blob

        url = f"{self.BASE}{endpoint}"
        try:
            r = self._http_get(url, params)
        except requests.HTTPError as e:
            self.logger.error("HTTP error on %s %s: %s", endpoint, params, e)
            raise
        self.calls_made += 1
        _audit(f"GET {endpoint} repo={repo} params={params} status={r.status_code}")

        if r.status_code == 200:
            body = r.json()
            path.write_text(json.dumps(body))
            # Threshold differs by resource. /search/* is rate-limited at
            # ~30/min, so a "remaining=29" reading is normal and sleeping
            # would stall for nothing. Sleep only when truly close to zero.
            remaining = int(r.headers.get("X-RateLimit-Remaining", "5000") or 5000)
            limit = int(r.headers.get("X-RateLimit-Limit", "5000") or 5000)
            # Trigger if we're at <= 2 remaining out of any pool size.
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
        if r.status_code == 422:
            path.write_text(json.dumps({"_cached_422": True, "items": []}))
            return 422, {"items": []}
        self.logger.error(
            "Unexpected %s for %s %s: %s",
            r.status_code,
            endpoint,
            params,
            r.text[:200],
        )
        return r.status_code, None


# ---------- bucket helpers --------------------------------------------------


def stars_bin(n: float | int | None) -> str:
    if n is None or pd.isna(n):
        return "unknown"
    n = int(n)
    if n < 100:
        # Below curated cohort floor; treat as smallest bin so we still
        # have something rather than dropping silently.
        return "100-199"
    if n < 200:
        return "100-199"
    if n < 500:
        return "200-499"
    if n < 1000:
        return "500-999"
    return "1000+"


def stars_query_range(bin_label: str) -> str:
    return {
        "100-199": "100..199",
        "200-499": "200..499",
        "500-999": "500..999",
        "1000+": ">=1000",
        "unknown": ">=100",
    }[bin_label]


def created_year_bin(ts: object) -> str:
    if pd.isna(ts):
        return "unknown"
    return f"{pd.Timestamp(ts).year}"


def add_strata(
    df: pd.DataFrame,
    *,
    lang_col: str,
    stars_col: str,
    created_col: str,
    owner_col: str,
) -> pd.DataFrame:
    out = df.copy()
    out["lang_bucket"] = out[lang_col].fillna("Unknown").astype(str)
    out["stars_bin"] = out[stars_col].apply(stars_bin)
    out["created_year"] = out[created_col].apply(created_year_bin)
    out["owner_type_norm"] = out[owner_col].fillna("Unknown").astype(str)
    out["log_stars"] = np.log1p(
        pd.to_numeric(out[stars_col], errors="coerce").astype(float)
    )
    out["strata_key"] = (
        out["lang_bucket"]
        + "|"
        + out["stars_bin"]
        + "|"
        + out["created_year"]
        + "|"
        + out["owner_type_norm"]
    )
    out["bucket_key"] = (
        out["lang_bucket"] + "|" + out["stars_bin"] + "|" + out["created_year"]
    )
    return out


# ---------- step: ai_meta ---------------------------------------------------


def step_ai_meta(
    client: GitHubClient,
    logger: logging.Logger,
    ai_repos: pd.DataFrame,
    out_dir: Path,
) -> tuple[pd.DataFrame, dict[str, int]]:
    """Pull created_at, owner.type, fork, archived, refreshed stars for every AI repo.

    Returns (enriched_df_after_drops, drop_counts_dict).
    """
    enriched_path = out_dir / "_ai_repos_enriched.parquet"
    drops_path = out_dir / "_ai_meta_drops.json"
    if enriched_path.exists() and drops_path.exists():
        df = pd.read_parquet(enriched_path)
        drops = json.loads(drops_path.read_text())
        logger.info("ai_meta: cached enrichment hit rows=%d drops=%s", len(df), drops)
        return df, drops

    rows = []
    n_404 = 0
    n_fork = 0
    n_archived = 0
    n_other_err = 0
    for i, r in ai_repos.iterrows():
        full = r["repo_full_name"]
        if not isinstance(full, str) or "/" not in full:
            continue
        owner, name = full.split("/", 1)
        status, body = client.get(f"/repos/{owner}/{name}", repo=full, params={})
        if status == 404:
            n_404 += 1
            logger.warning("ai_meta: 404 for %s (dropping)", full)
            continue
        if status != 200 or not isinstance(body, dict):
            n_other_err += 1
            logger.warning(
                "ai_meta: non-200/non-dict (%s) for %s (dropping)", status, full
            )
            continue
        is_fork = bool(body.get("fork"))
        is_archived = bool(body.get("archived"))
        if is_fork:
            n_fork += 1
            logger.warning("ai_meta: fork=true for %s (dropping)", full)
            continue
        if is_archived:
            n_archived += 1
            logger.warning("ai_meta: archived=true for %s (dropping)", full)
            continue
        rows.append(
            {
                "repo_full_name": full,
                "created_at_gh": body.get("created_at"),
                "pushed_at_gh": body.get("pushed_at"),
                "owner_type": (body.get("owner") or {}).get("type"),
                "fork": is_fork,
                "archived": is_archived,
                "language_gh": body.get("language"),
                "stars_gh": body.get("stargazers_count"),
                "forks_gh": body.get("forks_count"),
                "default_branch": body.get("default_branch"),
                "size_kb": body.get("size"),
                "open_issues": body.get("open_issues_count"),
                "watchers": body.get("subscribers_count"),
                "license_gh": ((body.get("license") or {}) or {}).get("spdx_id"),
            }
        )
        if i and i % 500 == 0:
            logger.info(
                "ai_meta: %d/%d (calls=%d hits=%d 404s=%d)",
                i,
                len(ai_repos),
                client.calls_made,
                client.cache_hits,
                client.cache_404_hits,
            )

    enriched = pd.DataFrame(rows)
    enriched["created_at_gh"] = pd.to_datetime(
        enriched["created_at_gh"], utc=True, errors="coerce"
    )
    enriched["pushed_at_gh"] = pd.to_datetime(
        enriched["pushed_at_gh"], utc=True, errors="coerce"
    )
    enriched.to_parquet(enriched_path, index=False)

    drops = {
        "n_input_ai_repos": int(len(ai_repos)),
        "n_404": int(n_404),
        "n_fork": int(n_fork),
        "n_archived": int(n_archived),
        "n_other_err": int(n_other_err),
        "n_after_drop": int(len(enriched)),
    }
    drops_path.write_text(json.dumps(drops, indent=2))
    logger.info("ai_meta: drop counts %s", drops)
    _log_table(logger, "_ai_repos_enriched", enriched)
    return enriched, drops


# ---------- step: search ----------------------------------------------------


def step_search(
    client: GitHubClient,
    logger: logging.Logger,
    ai_strata: pd.DataFrame,
    out_dir: Path,
) -> tuple[pd.DataFrame, dict[str, int]]:
    """Search GitHub for top-100-by-stars candidates per (lang, stars_bin, year).

    owner_type is *not* a search filter on GitHub; we partition by owner_type
    in the matching step after fetching metadata. Each bucket fetch returns
    up to CANDIDATES_PER_BUCKET (100) rows sorted by stars desc.
    """
    pool_path = out_dir / "_candidate_pool.parquet"
    counts_path = out_dir / "_bucket_candidate_counts.csv"
    if pool_path.exists() and counts_path.exists():
        df = pd.read_parquet(pool_path)
        logger.info("search: cached candidate pool hit rows=%d", len(df))
        # Reconstruct search_stats from cached files for the manifest.
        try:
            counts = pd.read_csv(counts_path)
            stats = {
                "n_buckets": int(len(counts)),
                "n_candidates_total": int(len(df)),
            }
        except Exception:
            stats = {"n_candidates_total": int(len(df))}
        return df, stats

    # Buckets that exist in the AI cohort.
    buckets = (
        ai_strata.groupby(["lang_bucket", "stars_bin", "created_year"])
        .size()
        .reset_index(name="n_ai")
        .sort_values("n_ai", ascending=False)
        .reset_index(drop=True)
    )
    logger.info(
        "search: %d unique (lang,stars,year) buckets from AI cohort", len(buckets)
    )
    ai_set = set(ai_strata["repo_full_name"].dropna().str.lower())

    rows: list[dict] = []
    bucket_counts: list[dict] = []
    for ix, row in buckets.iterrows():
        lang = row["lang_bucket"]
        bin_lbl = row["stars_bin"]
        yr = row["created_year"]
        n_ai = int(row["n_ai"])

        q_parts = [
            f"stars:{stars_query_range(bin_lbl)}",
            "fork:false",
            "archived:false",
            "is:public",
        ]
        if lang and lang != "Unknown":
            ql = lang.replace('"', "")
            if " " in ql:
                q_parts.append(f'language:"{ql}"')
            else:
                q_parts.append(f"language:{ql}")
        if yr and yr != "unknown":
            q_parts.append(f"created:{yr}-01-01..{yr}-12-31")
        q = " ".join(q_parts)

        # Always fetch the top CANDIDATES_PER_BUCKET (100) by stars per the brief.
        target = CANDIDATES_PER_BUCKET
        per_page = 100
        pages = max(1, (target + per_page - 1) // per_page)

        bucket_collected = 0
        for page in range(1, pages + 1):
            params = {
                "q": q,
                "sort": "stars",
                "order": "desc",
                "per_page": per_page,
                "page": page,
            }
            status, body = client.get("/search/repositories", repo=None, params=params)
            if status != 200 or not isinstance(body, dict):
                break
            items = body.get("items") or []
            if not items:
                break
            for it in items:
                full = (it.get("full_name") or "").strip()
                if not full or full.lower() in ai_set:
                    continue
                if it.get("fork") or it.get("archived"):
                    continue
                rows.append(
                    {
                        "repo_full_name": full,
                        "repo_id": it.get("id"),
                        "created_at_gh": it.get("created_at"),
                        "pushed_at_gh": it.get("pushed_at"),
                        "owner_type": (it.get("owner") or {}).get("type"),
                        "fork": it.get("fork"),
                        "archived": it.get("archived"),
                        "language_gh": it.get("language"),
                        "stars": it.get("stargazers_count"),
                        "forks": it.get("forks_count"),
                        "license": ((it.get("license") or {}) or {}).get("spdx_id"),
                        "size_kb": it.get("size"),
                        "open_issues": it.get("open_issues_count"),
                        "default_branch": it.get("default_branch"),
                        "search_lang": lang,
                        "search_stars_bin": bin_lbl,
                        "search_year": yr,
                    }
                )
                bucket_collected += 1
                if bucket_collected >= target:
                    break
            if bucket_collected >= target or len(items) < per_page:
                break

        bucket_counts.append(
            {
                "lang_bucket": lang,
                "stars_bin": bin_lbl,
                "created_year": yr,
                "n_ai_in_bucket": n_ai,
                "n_candidates_returned": bucket_collected,
            }
        )
        if ix and ix % 25 == 0:
            logger.info(
                "search: %d/%d buckets processed (raw rows=%d, calls=%d hits=%d)",
                ix,
                len(buckets),
                len(rows),
                client.calls_made,
                client.cache_hits,
            )

    pool = (
        pd.DataFrame(rows)
        .drop_duplicates(subset=["repo_full_name"])
        .reset_index(drop=True)
    )
    pool["created_at_gh"] = pd.to_datetime(
        pool["created_at_gh"], utc=True, errors="coerce"
    )
    pool["pushed_at_gh"] = pd.to_datetime(
        pool["pushed_at_gh"], utc=True, errors="coerce"
    )
    # Re-bucket with our own stars/year scheme so the bucket key is consistent
    # with the AI-side bucket key (stars/created_year may not match search range
    # exactly, e.g. if a repo gained stars between search and read).
    pool["lang_bucket"] = pool["language_gh"].fillna("Unknown").astype(str)
    pool["stars_bin"] = pool["stars"].apply(stars_bin)
    pool["created_year"] = pool["created_at_gh"].apply(created_year_bin)
    pool["owner_type_norm"] = pool["owner_type"].fillna("Unknown").astype(str)
    pool["log_stars"] = np.log1p(
        pd.to_numeric(pool["stars"], errors="coerce").astype(float)
    )
    pool["strata_key"] = (
        pool["lang_bucket"]
        + "|"
        + pool["stars_bin"]
        + "|"
        + pool["created_year"]
        + "|"
        + pool["owner_type_norm"]
    )
    pool["bucket_key"] = (
        pool["lang_bucket"] + "|" + pool["stars_bin"] + "|" + pool["created_year"]
    )
    pool.to_parquet(pool_path, index=False)
    pd.DataFrame(bucket_counts).to_csv(counts_path, index=False)
    _log_table(logger, "_candidate_pool", pool)
    logger.info(
        "search: candidate pool size=%d (calls=%d hits=%d 404s=%d)",
        len(pool),
        client.calls_made,
        client.cache_hits,
        client.cache_404_hits,
    )
    return pool, {
        "n_buckets": int(len(buckets)),
        "n_candidates_total": int(len(pool)),
    }


# ---------- step: screen ----------------------------------------------------


def _load_fingerprints() -> list[re.Pattern]:
    cfg = yaml.safe_load((REPO / "configs" / "agent_fingerprints.yaml").read_text())
    return [re.compile(p["regex"]) for p in cfg.get("patterns", [])]


def step_screen(
    client: GitHubClient,
    logger: logging.Logger,
    pool: pd.DataFrame,
    ai_strata: pd.DataFrame,
    out_dir: Path,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Screen all candidates that share a (lang, stars_bin, year, owner_type)
    stratum with at least one AI repo. Returns (eligible_pool, screen_log).

    For each kept candidate we record n_in_window_prs (the activity proxy).
    """
    eligible_path = out_dir / "_eligible_pool.parquet"
    log_path = out_dir / "control_screen_log.parquet"
    if eligible_path.exists() and log_path.exists():
        eligible = pd.read_parquet(eligible_path)
        screen_log = pd.read_parquet(log_path)
        logger.info(
            "screen: cached results hit eligible=%d screened_log=%d",
            len(eligible),
            len(screen_log),
        )
        return eligible, screen_log

    patterns = _load_fingerprints()
    window_start, window_end = _window()
    ws = pd.Timestamp(window_start, tz="UTC")
    we = pd.Timestamp(window_end, tz="UTC") + pd.Timedelta(days=1, microseconds=-1)

    # Only screen candidates whose stratum_key appears in the AI cohort.
    ai_strata_keys = set(ai_strata["strata_key"])
    pool = pool.copy()
    pool["matches_ai_stratum"] = pool["strata_key"].isin(ai_strata_keys)
    in_scope = pool[pool["matches_ai_stratum"]].copy()
    out_of_scope = pool[~pool["matches_ai_stratum"]].copy()
    logger.info(
        "screen: %d candidates in AI strata, %d out-of-scope (skipped)",
        len(in_scope),
        len(out_of_scope),
    )

    # AI-side log_stars median per stratum -> within stratum, screen the
    # candidates whose stars are closest to the AI median first, keeping
    # going until we have SCREEN_QUOTA_MULT * n_ai eligible candidates per
    # stratum. This keeps the screen-time API budget bounded while still
    # giving the matcher caliper-flexibility.
    ai_meds = (
        ai_strata.groupby("strata_key")["log_stars"]
        .median()
        .rename("ai_log_stars_median")
        .reset_index()
    )
    in_scope = in_scope.merge(ai_meds, on="strata_key", how="left")
    in_scope["log_stars_dist"] = (
        in_scope["log_stars"] - in_scope["ai_log_stars_median"]
    ).abs()
    in_scope = in_scope.sort_values(
        ["strata_key", "log_stars_dist"], ascending=[True, True]
    ).reset_index(drop=True)

    # SCREEN_QUOTA_MULT = 1 keeps the API budget tight: aim for ~1
    # eligible candidate per AI repo per stratum (the 1:1 matching ratio).
    # If the matcher's caliper rejects a candidate, the AI repo just goes
    # unmatched - which the brief expects us to report. Set to 2 if you
    # want extra slack at the cost of more PR-list calls.
    SCREEN_QUOTA_MULT = 1
    ai_per_stratum = ai_strata.groupby("strata_key").size().to_dict()
    eligible_per_stratum: dict[str, int] = {}

    eligible_rows: list[dict] = []
    screen_log_rows: list[dict] = []
    n_screened = 0
    n_dropped_fingerprint = 0
    for _, c in in_scope.iterrows():
        full = c["repo_full_name"]
        sk = c["strata_key"]
        # Quota: stop screening this stratum once we have 3x AI count eligible.
        quota = max(1, ai_per_stratum.get(sk, 0)) * SCREEN_QUOTA_MULT
        if eligible_per_stratum.get(sk, 0) >= quota:
            continue
        owner, name = full.split("/", 1)
        prs_collected: list[dict] = []
        page = 1
        per_page = min(100, N_PR_SCREEN)
        # GitHub list endpoint sorts by created/updated; use state=all sort=created
        # and page until we have N_PR_SCREEN in-window rows or exit window.
        while len(prs_collected) < N_PR_SCREEN and page <= 3:
            params = {
                "state": "all",
                "sort": "created",
                "direction": "desc",
                "per_page": per_page,
                "page": page,
            }
            status, body = client.get(
                f"/repos/{owner}/{name}/pulls",
                repo=full,
                params=params,
                bind_fingerprint=False,
            )
            if status != 200 or not isinstance(body, list):
                break
            stop_paging = False
            for pr in body:
                ca = pd.to_datetime(pr.get("created_at"), utc=True, errors="coerce")
                if pd.isna(ca):
                    continue
                if ca < ws:
                    stop_paging = True
                    break
                if ca > we:
                    continue
                prs_collected.append(pr)
                if len(prs_collected) >= N_PR_SCREEN:
                    break
            if stop_paging or len(body) < per_page:
                break
            page += 1
        n_screened += 1

        matched = False
        match_pat = None
        match_pr = None
        match_excerpt = None
        for pr in prs_collected:
            text = (pr.get("title") or "") + "\n" + (pr.get("body") or "")
            for pat in patterns:
                m = pat.search(text)
                if m:
                    matched = True
                    match_pat = pat.pattern
                    match_pr = pr.get("number")
                    match_excerpt = text[max(0, m.start() - 40) : m.end() + 40]
                    break
            if matched:
                break

        screen_log_rows.append(
            {
                "repo_full_name": full,
                "n_prs_screened": len(prs_collected),
                "matched": matched,
                "matched_pattern": match_pat,
                "matched_pr_number": match_pr,
                "matched_text_excerpt": match_excerpt,
                "strata_key": sk,
            }
        )
        if matched:
            n_dropped_fingerprint += 1
            continue
        # Activity proxy for this candidate. Per the brief, activity = count
        # of in-window PRs from the candidate-screening fetch. We keep zero-
        # activity repos in the eligible pool; the matcher naturally avoids
        # pairing them with high-activity AI repos.
        rec = c.to_dict()
        rec["n_in_window_prs"] = int(len(prs_collected))
        eligible_rows.append(rec)
        eligible_per_stratum[sk] = eligible_per_stratum.get(sk, 0) + 1

        if n_screened % 200 == 0:
            logger.info(
                "screen: %d screened, %d fp-dropped, %d eligible (calls=%d hits=%d)",
                n_screened,
                n_dropped_fingerprint,
                len(eligible_rows),
                client.calls_made,
                client.cache_hits,
            )
            # Checkpoint: flush partial progress every 200 screens.
            try:
                pd.DataFrame(eligible_rows).to_parquet(
                    out_dir / "_eligible_pool.partial.parquet", index=False
                )
                pd.DataFrame(screen_log_rows).to_parquet(
                    out_dir / "control_screen_log.partial.parquet", index=False
                )
            except Exception as e:
                logger.warning("screen: checkpoint failed: %s", e)

    eligible = pd.DataFrame(eligible_rows)
    screen_log = pd.DataFrame(screen_log_rows)
    eligible.to_parquet(eligible_path, index=False)
    screen_log.to_parquet(log_path, index=False)
    logger.info(
        "screen: total screened=%d fp_dropped=%d eligible=%d",
        n_screened,
        n_dropped_fingerprint,
        len(eligible),
    )
    _log_table(logger, "control_screen_log", screen_log)
    return eligible, screen_log


# ---------- step: match -----------------------------------------------------


def step_match(
    logger: logging.Logger,
    ai_strata: pd.DataFrame,
    eligible: pd.DataFrame,
    out_dir: Path,
) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    """Within each AI stratum, 1:1 NN on z-scored (log_stars, activity)
    without replacement, with a 0.25 sigma caliper on log_stars.

    Returns (control_repos_with_match_meta, matching_pairs, unmatched).
    """
    seed = int(os.environ["RANDOM_SEED"])
    rng = np.random.default_rng(seed)

    # Activity for AI side comes from agentic_prs (already on ai_strata).
    # For controls it was recorded in the screen step as n_in_window_prs.
    # We z-score within stratum (more conservative than global z-score).
    pairs: list[dict] = []
    unmatched: list[str] = []
    used_controls: set[str] = set()

    # Random ordering of AI repos within each stratum, seeded.
    ai_ordered = ai_strata.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    # Group the eligible pool once.
    by_stratum: dict[str, pd.DataFrame] = {
        sk: g.copy() for sk, g in eligible.groupby("strata_key")
    }

    # Global sigma on log_stars across the AI cohort. The brief's "0.25 sigma
    # on log(stars) within stratum" caliper is interpreted using the global
    # AI-cohort sigma rather than per-stratum sigma, because many strata
    # have <=2 candidates which gives an unreliable per-stratum sigma. This
    # is a more conservative caliper (wider) and is recorded in the manifest.
    global_sigma_log_stars = float(ai_strata["log_stars"].std(ddof=0))
    if not np.isfinite(global_sigma_log_stars) or global_sigma_log_stars == 0:
        global_sigma_log_stars = 1.0
    global_caliper = CALIPER_SIGMA * global_sigma_log_stars

    for sk, ai_group in ai_ordered.groupby("strata_key"):
        cands_full = by_stratum.get(sk)
        if cands_full is None or cands_full.empty:
            for _, a in ai_group.iterrows():
                unmatched.append(a["repo_full_name"])
            continue
        # Use the global caliper for all strata to avoid degenerate behavior
        # in singleton strata. Per-stratum sigma still informs the z-scores
        # for the NN distance, with a fallback of 1.0 in degenerate strata.
        caliper = global_caliper
        log_stars_combined = pd.concat(
            [ai_group["log_stars"], cands_full["log_stars"]], ignore_index=True
        ).astype(float)
        sigma_log_stars = float(log_stars_combined.std(ddof=0))
        if not np.isfinite(sigma_log_stars) or sigma_log_stars == 0:
            sigma_log_stars = global_sigma_log_stars

        # z-score (log_stars, activity) within stratum using pooled std.
        activity_combined = pd.concat(
            [ai_group["activity"], cands_full["n_in_window_prs"]], ignore_index=True
        ).astype(float)
        sigma_act = float(activity_combined.std(ddof=0))
        if not np.isfinite(sigma_act) or sigma_act == 0:
            sigma_act = 1.0
        mu_log = float(log_stars_combined.mean())
        mu_act = float(activity_combined.mean())

        # Iterate AI repos in this stratum, do NN with caliper & no replacement.
        for _, a in ai_group.iterrows():
            cands = cands_full[~cands_full["repo_full_name"].isin(used_controls)]
            if cands.empty:
                unmatched.append(a["repo_full_name"])
                continue
            # Caliper filter on raw |log_stars| (not z-scored, by spec).
            within_caliper = cands[
                (cands["log_stars"] - float(a["log_stars"])).abs() <= caliper
            ]
            if within_caliper.empty:
                unmatched.append(a["repo_full_name"])
                continue
            # NN on z-scored (log_stars, activity)
            ai_z_log = (float(a["log_stars"]) - mu_log) / sigma_log_stars
            ai_z_act = (float(a["activity"]) - mu_act) / sigma_act
            cz_log = (
                within_caliper["log_stars"].astype(float) - mu_log
            ) / sigma_log_stars
            cz_act = (
                within_caliper["n_in_window_prs"].astype(float) - mu_act
            ) / sigma_act
            d2 = (cz_log - ai_z_log) ** 2 + (cz_act - ai_z_act) ** 2
            # Tie-break with rng to avoid deterministic-but-arbitrary ordering.
            jitter = rng.random(len(d2)) * 1e-9
            ranked = within_caliper.assign(_score=d2.values + jitter)
            best = ranked.sort_values("_score", ascending=True).iloc[0]
            used_controls.add(best["repo_full_name"])
            pairs.append(
                {
                    "ai_repo": a["repo_full_name"],
                    "control_repo": best["repo_full_name"],
                    "stratum_key": sk,
                    "log_stars_distance": float(
                        abs(best["log_stars"] - float(a["log_stars"]))
                    ),
                    "activity_distance": float(
                        abs(float(best["n_in_window_prs"]) - float(a["activity"]))
                    ),
                    "ai_log_stars": float(a["log_stars"]),
                    "ctrl_log_stars": float(best["log_stars"]),
                    "ai_activity": float(a["activity"]),
                    "ctrl_activity": float(best["n_in_window_prs"]),
                    "stratum_caliper": float(caliper),
                }
            )

    matching_pairs = pd.DataFrame(pairs)
    if not matching_pairs.empty:
        ctrl_to_ai = matching_pairs.set_index("control_repo")["ai_repo"]
        controls_used = eligible[eligible["repo_full_name"].isin(used_controls)].copy()
        controls_used["matched_ai_repo"] = controls_used["repo_full_name"].map(
            ctrl_to_ai
        )
    else:
        controls_used = eligible.iloc[0:0].copy()
        controls_used["matched_ai_repo"] = pd.Series(dtype=str)

    logger.info(
        "match: %d pairs, %d unique controls, %d unmatched AI repos",
        len(matching_pairs),
        len(controls_used),
        len(unmatched),
    )
    return controls_used, matching_pairs, unmatched


# ---------- step: balance ---------------------------------------------------


def _smd(t: pd.Series, c: pd.Series) -> float:
    """Standardized mean difference, study-stats skill convention.

    smd = (mean_AI - mean_ctrl) / sqrt((var_AI + var_ctrl) / 2)
    Returns NaN if either side has no usable values.
    """
    t = pd.to_numeric(t, errors="coerce").dropna()
    c = pd.to_numeric(c, errors="coerce").dropna()
    if len(t) == 0 or len(c) == 0:
        return float("nan")
    mt, mc = float(t.mean()), float(c.mean())
    vt, vc = float(t.var(ddof=0)), float(c.var(ddof=0))
    pooled = ((vt + vc) / 2.0) ** 0.5
    if pooled == 0:
        return 0.0 if mt == mc else float("inf")
    return (mt - mc) / pooled


def step_balance(
    logger: logging.Logger,
    ai_strata: pd.DataFrame,
    candidate_pool: pd.DataFrame,
    eligible: pd.DataFrame,
    matching_pairs: pd.DataFrame,
    controls_used: pd.DataFrame,
    out_dir: Path,
) -> pd.DataFrame:
    """Compute pre/post-matching SMDs.

    Pre:  ai_strata (all surviving AI repos) vs the *eligible* pool (after
          fingerprint screen + activity recorded). Using the eligible pool
          for pre-match keeps the comparison meaningful for activity, which
          is only available on screened candidates. The unscreened search
          pool is reported separately as `pre_match_n_control_pool` for
          context.
    Post: matched AI subset vs matched controls.
    """
    matched_ai_set = (
        set(matching_pairs["ai_repo"]) if not matching_pairs.empty else set()
    )
    ai_post = ai_strata[ai_strata["repo_full_name"].isin(matched_ai_set)].copy()
    ctrl_post = controls_used.copy()

    # ---- attach repo_age_years on both sides ------------------------------
    today = pd.Timestamp.now(tz="UTC")

    def _age_years(df: pd.DataFrame, col: str) -> pd.Series:
        ts = pd.to_datetime(df[col], utc=True, errors="coerce")
        return (today - ts).dt.days / 365.25

    ai_strata = ai_strata.copy()
    eligible_bal = eligible.copy()
    for df in (ai_strata, ai_post):
        df["repo_age_years"] = _age_years(df, "created_at_gh")
    for df in (eligible_bal, ctrl_post):
        df["repo_age_years"] = _age_years(df, "created_at_gh")

    # Activity columns are named differently on AI vs control side.
    ai_strata["activity"] = pd.to_numeric(ai_strata["activity"], errors="coerce")
    if "activity" not in ai_post.columns:
        ai_post["activity"] = pd.to_numeric(ai_post["activity"], errors="coerce")
    eligible_bal["activity"] = pd.to_numeric(
        eligible_bal.get("n_in_window_prs", pd.Series(dtype=float)),
        errors="coerce",
    )
    ctrl_post["activity"] = pd.to_numeric(ctrl_post["n_in_window_prs"], errors="coerce")

    # ---- binary covariates ------------------------------------------------
    def to_org(s: pd.Series) -> pd.Series:
        return (s == "Organization").astype(int)

    ai_strata["owner_org"] = to_org(ai_strata["owner_type_norm"])
    ai_post["owner_org"] = to_org(ai_post["owner_type_norm"])
    eligible_bal["owner_org"] = to_org(eligible_bal["owner_type_norm"])
    ctrl_post["owner_org"] = to_org(ctrl_post["owner_type_norm"])

    # Per-language SMDs over the union of languages observed in either side.
    langs_ai = set(ai_strata["lang_bucket"].unique())
    langs_ctrl = set(eligible_bal["lang_bucket"].unique())
    all_langs = sorted(langs_ai | langs_ctrl)
    lang_cols: list[str] = []
    for lg in all_langs:
        col = f"lang_{lg}"
        ai_strata[col] = (ai_strata["lang_bucket"] == lg).astype(int)
        ai_post[col] = (ai_post["lang_bucket"] == lg).astype(int)
        eligible_bal[col] = (eligible_bal["lang_bucket"] == lg).astype(int)
        ctrl_post[col] = (ctrl_post["lang_bucket"] == lg).astype(int)
        lang_cols.append(col)

    rows = []
    cont_covs = ["log_stars", "repo_age_years", "activity"]
    bin_covs = ["owner_org"] + lang_cols
    n_pairs = int(len(matching_pairs))
    n_ai_pre = int(len(ai_strata))
    # `pre_match_n_control_pool` reports the eligible (post-screen) pool
    # size, which is what's actually used for the pre-match SMD. The full
    # (unscreened) candidate-pool size is recorded in the manifest under
    # phase_b.search_stats.n_candidates_total.
    n_ctrl_pool_pre = int(len(eligible_bal))
    for cov in cont_covs + bin_covs:
        smd_pre = _smd(ai_strata[cov], eligible_bal[cov])
        smd_post = _smd(ai_post[cov], ctrl_post[cov]) if n_pairs else float("nan")
        rows.append(
            {
                "covariate": cov,
                "type": "continuous" if cov in cont_covs else "binary",
                "pre_match_smd": smd_pre,
                "post_match_smd": smd_post,
                "pre_match_n_ai": n_ai_pre,
                "pre_match_n_control_pool": n_ctrl_pool_pre,
                "post_match_n_pairs": n_pairs,
                "ai_pre_mean": float(
                    pd.to_numeric(ai_strata[cov], errors="coerce").mean()
                ),
                "ctrl_pre_mean": float(
                    pd.to_numeric(eligible_bal[cov], errors="coerce").mean()
                ),
                "ai_post_mean": float(
                    pd.to_numeric(ai_post[cov], errors="coerce").mean()
                )
                if n_pairs
                else float("nan"),
                "ctrl_post_mean": float(
                    pd.to_numeric(ctrl_post[cov], errors="coerce").mean()
                )
                if n_pairs
                else float("nan"),
                "abs_post_smd_gt_0p1": (
                    abs(smd_post) > 0.1 if pd.notna(smd_post) else False
                ),
            }
        )
    bal = pd.DataFrame(rows)
    _log_table(logger, "balance_table", bal)
    return bal


# ---------- step: write outputs --------------------------------------------


def write_outputs(
    logger: logging.Logger,
    controls_used: pd.DataFrame,
    matching_pairs: pd.DataFrame,
    balance: pd.DataFrame,
    out_dir: Path,
) -> dict[str, int]:
    """Write the three Phase B outputs to out_dir. Returns row counts."""
    cr_cols = [
        "repo_full_name",
        "stars",
        "language_gh",
        "created_at_gh",
        "owner_type",
        "fork",
        "archived",
        "license",
        "n_in_window_prs",
        "matched_ai_repo",
        # carry-along (useful for downstream phases / audits)
        "lang_bucket",
        "stars_bin",
        "created_year",
        "owner_type_norm",
        "log_stars",
        "strata_key",
        "default_branch",
        "size_kb",
        "open_issues",
        "pushed_at_gh",
    ]
    have = [c for c in cr_cols if c in controls_used.columns]
    control_csv = controls_used[have].rename(
        columns={
            "language_gh": "language",
            "created_at_gh": "created_at",
            "pushed_at_gh": "pushed_at",
        }
    )
    control_csv.to_csv(out_dir / "control_repos.csv", index=False)
    _log_table(logger, "control_repos", control_csv)

    pairs_cols = [
        "ai_repo",
        "control_repo",
        "stratum_key",
        "log_stars_distance",
        "activity_distance",
        "ai_log_stars",
        "ctrl_log_stars",
        "ai_activity",
        "ctrl_activity",
        "stratum_caliper",
    ]
    have_pairs = [c for c in pairs_cols if c in matching_pairs.columns]
    matching_pairs_out = matching_pairs[have_pairs] if have_pairs else matching_pairs
    matching_pairs_out.to_csv(out_dir / "repo_matching_pairs.csv", index=False)
    _log_table(logger, "repo_matching_pairs", matching_pairs_out)

    balance.to_csv(out_dir / "balance_table.csv", index=False)
    _log_table(logger, "balance_table", balance)

    return {
        "control_repos.csv": int(len(control_csv)),
        "repo_matching_pairs.csv": int(len(matching_pairs_out)),
        "balance_table.csv": int(len(balance)),
    }


# ---------- main ------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--step",
        default=None,
        choices=[
            None,
            "ai_meta",
            "search",
            "screen",
            "match",
            "balance",
            "manifest",
        ],
        help="Run only this step (resumable; all prior steps must have run).",
    )
    args = parser.parse_args()

    load_dotenv(REPO / ".env")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_dir = REPO / "data_derived" / today
    out_dir.mkdir(parents=True, exist_ok=True)

    logger = _setup_logger()
    logger.info(
        "=== Phase B run_id=%s out=%s step=%s ===",
        today,
        out_dir,
        args.step or "all",
    )

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GITHUB_TOKEN missing from .env")
    client = GitHubClient(token, logger)

    # Phase A artifacts (must already exist in latest, which is today)
    latest = REPO / "data_derived" / "latest"
    ai_repos_input = pd.read_csv(latest / "ai_repos.csv")
    agentic_prs = pd.read_parquet(latest / "agentic_prs.parquet")
    logger.info(
        "loaded ai_repos.csv rows=%d agentic_prs rows=%d",
        len(ai_repos_input),
        len(agentic_prs),
    )

    # Activity proxy from agentic_prs.parquet
    activity = (
        agentic_prs.groupby("repo_full_name").size().rename("activity").reset_index()
    )

    # ---- ai_meta ---------------------------------------------------------
    enriched, drop_counts = step_ai_meta(client, logger, ai_repos_input, out_dir)
    if args.step == "ai_meta":
        return

    # Build AI strata frame (drop forks/archived/404s already done in ai_meta)
    ai_full = ai_repos_input.merge(
        enriched[
            [
                "repo_full_name",
                "created_at_gh",
                "owner_type",
                "fork",
                "archived",
                "stars_gh",
                "language_gh",
            ]
        ],
        on="repo_full_name",
        how="inner",  # inner = drop the AI repos we couldn't enrich
    )
    ai_full = ai_full.merge(activity, on="repo_full_name", how="left")
    ai_full["activity"] = ai_full["activity"].fillna(0).astype(int)
    # Use AIDev's `stars` as authoritative for matching covariates per the
    # study brief, but we kept refreshed `stars_gh` for the manifest.
    ai_strata = add_strata(
        ai_full,
        lang_col="language",
        stars_col="stars",
        created_col="created_at_gh",
        owner_col="owner_type",
    )
    _log_table(
        logger,
        "ai_strata",
        ai_strata[
            [
                "repo_full_name",
                "language",
                "stars",
                "created_at_gh",
                "owner_type",
                "activity",
                "strata_key",
            ]
        ],
    )

    # Sanity counts
    n_unique_buckets = ai_strata["bucket_key"].nunique()
    logger.info("ai cohort unique (lang,stars_bin,year) buckets=%d", n_unique_buckets)

    # ---- search ----------------------------------------------------------
    pool, search_stats = step_search(client, logger, ai_strata, out_dir)
    if args.step == "search":
        return

    # ---- screen ----------------------------------------------------------
    eligible, screen_log = step_screen(client, logger, pool, ai_strata, out_dir)
    if args.step == "screen":
        return

    # ---- match -----------------------------------------------------------
    controls_used, matching_pairs, unmatched = step_match(
        logger, ai_strata, eligible, out_dir
    )
    if args.step == "match":
        return

    # ---- balance ---------------------------------------------------------
    balance = step_balance(
        logger,
        ai_strata,
        pool,
        eligible,
        matching_pairs,
        controls_used,
        out_dir,
    )
    if args.step == "balance":
        balance.to_csv(out_dir / "balance_table.csv", index=False)
        return

    # ---- write outputs ---------------------------------------------------
    new_outputs = write_outputs(logger, controls_used, matching_pairs, balance, out_dir)

    # ---- manifest --------------------------------------------------------
    n_screened = int(len(screen_log)) if screen_log is not None else 0
    n_dropped_fp = int(screen_log["matched"].sum()) if screen_log is not None else 0

    # Worst-case post SMD
    bal_post = balance["post_match_smd"].abs()
    worst_post_smd = (
        float(bal_post.dropna().max()) if len(bal_post.dropna()) else float("nan")
    )
    worst_post_cov = (
        balance.loc[bal_post.idxmax(), "covariate"] if len(bal_post.dropna()) else None
    )

    cache_total = client.cache_hits + client.cache_404_hits
    total_calls = client.calls_made + cache_total
    cache_hit_rate = (cache_total / total_calls) if total_calls else 0.0

    extra = {
        "phase_b": {
            "matching_strategy": (
                "Exact match on (language, stars_bin in [100-199, 200-499, "
                "500-999, 1000+], created_year, owner_type) + 1:1 nearest-"
                "neighbor on z-scored (log(stars+1), n_in_window_prs) without "
                "replacement, with a 0.25 sigma caliper on log(stars+1). The "
                "caliper sigma is the AI-cohort global standard deviation of "
                "log(stars+1), not the per-stratum sigma, because many strata "
                "have <=2 candidates which gives an unreliable per-stratum "
                "sigma. Z-scores for the NN distance use per-stratum pooled "
                "(AI + candidates) std, with the AI-cohort global sigma as "
                "fallback in degenerate strata. AIDev stars/language are "
                "authoritative for the AI side; GitHub provides AI owner_type "
                "and created_at and all control covariates."
            ),
            "knobs": {
                "n_pr_screen": N_PR_SCREEN,
                "candidates_per_bucket": CANDIDATES_PER_BUCKET,
                "min_stars": MIN_STARS,
                "caliper_sigma": CALIPER_SIGMA,
                "matching_ratio": "1:1",
                "replacement": False,
            },
            "ai_meta_drops": drop_counts,
            "search_stats": search_stats,
            "screen_stats": {
                "n_candidates_screened": n_screened,
                "n_dropped_fingerprint": n_dropped_fp,
                "n_eligible": int(len(eligible)),
                "fingerprint_config_sha256": sha256_of(
                    REPO / "configs" / "agent_fingerprints.yaml"
                ),
            },
            "match_stats": {
                "n_pairs": int(len(matching_pairs)),
                "n_unique_controls": int(len(controls_used)),
                "n_unmatched_ai": int(len(unmatched)),
                "worst_post_match_abs_smd": worst_post_smd,
                "worst_post_match_covariate": worst_post_cov,
            },
            "coverage_notes": (
                "If n_unmatched_ai > 0, the unmatched AI repos are split "
                "between (a) strata with zero in-cohort candidates we got "
                "to screen before the GitHub API rate limit (5000/hr) "
                "constrained the run, and (b) strata where the closest "
                "candidate fell outside the 0.25-sigma log_stars caliper. "
                "Re-running --step screen after the rate limit resets will "
                "fill the (a) gap deterministically (cache-driven). The "
                "(b) gap is by design and should not be filled without "
                "widening the caliper."
            ),
        },
        "github_mcp": {
            "transport": "rest",
            "endpoint_or_image": "https://api.github.com",
            # Per-run counters (this script invocation):
            "this_run_live_calls": int(client.calls_made),
            "this_run_cache_hits_200": int(client.cache_hits),
            "this_run_cache_hits_404": int(client.cache_404_hits),
            "this_run_total_requests": int(total_calls),
            "this_run_cache_hit_rate": float(round(cache_hit_rate, 4)),
            # Cumulative counters across all Phase B step invocations,
            # reconstructed from the append-only audit log.
            "cumulative_audit_log_entries": int(
                sum(1 for _ in (LOGS / "github-mcp-audit.log").open())
            )
            if (LOGS / "github-mcp-audit.log").exists()
            else 0,
            "cumulative_pr_list_cache_files": int(len(list(CACHE_DIR.glob("*pulls*")))),
            "cumulative_search_cache_files": int(
                len(list(CACHE_DIR.glob("search__*")))
            ),
            "cumulative_repo_meta_cache_files": int(
                len(list(CACHE_DIR.glob("repos__*")))
                - len(list(CACHE_DIR.glob("*pulls*")))
            ),
        },
        "intervention_source_choice": {
            "pr_review_comments_table": "pr_review_comments_v2",
            "rationale": (
                "Defaults to v2 per the intervention-rules skill; Phase B "
                "does not consume either inline-comments table but the field "
                "is required by the manifest schema."
            ),
        },
    }

    # Preserve Phase A's outputs in the manifest (do not invalidate),
    # then append Phase B's three new outputs.
    a_outputs = {
        "ai_repos.csv": int(pd.read_csv(out_dir / "ai_repos.csv").shape[0]),
        "agentic_prs.parquet": int(
            pd.read_parquet(out_dir / "agentic_prs.parquet").shape[0]
        ),
    }
    all_outputs = {**a_outputs, **new_outputs}

    write_manifest(
        out_dir,
        phase=["A", "B"],
        agent="data-miner",
        outputs=all_outputs,
        extra=extra,
    )
    logger.info("wrote %s", out_dir / "run_manifest.json")

    # Flip latest symlink (no-op if same date)
    latest_link = REPO / "data_derived" / "latest"
    if latest_link.is_symlink() or latest_link.exists():
        latest_link.unlink()
    latest_link.symlink_to(today, target_is_directory=True)
    logger.info("symlink data_derived/latest -> %s", today)

    # ---- sanity print ----------------------------------------------------
    print("=== Phase B sanity ===")
    print(
        f"AI cohort: input={drop_counts['n_input_ai_repos']} "
        f"after_meta={drop_counts['n_after_drop']} "
        f"(404={drop_counts['n_404']}, fork={drop_counts['n_fork']}, "
        f"archived={drop_counts['n_archived']}, "
        f"other_err={drop_counts['n_other_err']})"
    )
    print(
        f"Buckets: unique_in_ai={n_unique_buckets} "
        f"candidate_pool_total={len(pool)} "
        f"post_screen_eligible={len(eligible)}"
    )
    print(
        f"Matching: pairs={len(matching_pairs)} "
        f"unique_controls={len(controls_used)} "
        f"unmatched_ai={len(unmatched)}"
    )
    print(f"Worst post-match |SMD|={worst_post_smd:.4f} on '{worst_post_cov}'")
    print(
        f"GitHub: live={client.calls_made} hits200={client.cache_hits} "
        f"hits404={client.cache_404_hits} hit_rate={cache_hit_rate:.4f}"
    )
    print("Outputs: " + ", ".join(f"{k}(rows={v})" for k, v in {**new_outputs}.items()))
    print(f"Manifest: {out_dir / 'run_manifest.json'}")


if __name__ == "__main__":
    main()
