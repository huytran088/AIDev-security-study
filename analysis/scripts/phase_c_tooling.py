"""Phase C - Detect security tooling for every repo in the AI ∪ Control union.

Run via: ``uv run python analysis/scripts/phase_c_tooling.py [--step <name>]``

Steps (idempotent, resumable, all GitHub responses cached):
  trees    : per repo, fetch `git/trees/HEAD?recursive=1`. Filter to
             `.github/workflows/*.{yml,yaml}` and the ~14 root config paths
             from configs/tools.yaml. Persist the filtered tree per-repo.
             404/private repos are recorded under repo_drops; no further
             fetches happen for them.
  workflows: fetch the raw body for every workflow file we'll need to
             pattern-match. Root config files only need *presence* (the
             tree-listing already proves that) so we skip body fetches
             for them. Cached by URL-encoded path.
  detect   : apply tools.yaml rules - workflow `uses:` regex matches and
             root config_paths exact/prefix matches. Emit long + wide
             parquet outputs. Surface any workflow `uses:` referencing a
             security vendor not in tools.yaml (do NOT auto-edit).
  manifest : update data_derived/<today>/run_manifest.json in place,
             extending phase to ["A","B","C"], appending the two new
             outputs (rows + sha256), and adding a phase_c block.

The script never modifies data_raw/. GitHub responses are cached under
data_raw/github_cache/ per the github-cache-policy skill. Per-tree fetches
bind the tools-yaml sha so a tools.yaml change correctly busts detection
re-reads (the cached tree response is invariant to tools.yaml; we re-key
the *filtered tree* artifact only). Workflow body fetches are content
addressed via path; they're invariant to tools.yaml.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import yaml
from dotenv import load_dotenv

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "analysis" / "scripts"))
from phase_b_match import GitHubClient  # noqa: E402  (reuse cache+retry client)
from write_manifest import sha256_of, write_manifest  # noqa: E402

LOGS = REPO / "logs"
CACHE_DIR = REPO / "data_raw" / "github_cache"
AUDIT_LOG = LOGS / "github-mcp-audit.log"

# Known security-vendor tokens used to flag workflow `uses:` whose action
# coordinate references a security vendor we don't yet have in tools.yaml.
# Keep this list deliberately narrow (high-precision) so we don't drown the
# operator in false positives. Hits are logged to phase_c.unknown_security_uses
# and *never* auto-added to tools.yaml.
SEC_VENDOR_TOKENS = (
    "codeql",
    "semgrep",
    "snyk",
    "gitleaks",
    "trufflehog",
    "trufflesecurity",
    "dependabot",  # GitHub-native but still a SCA signal worth flagging
    "renovate",
    "renovatebot",
    "ossf/scorecard",
    "step-security",
    "harden-runner",
    "oss-fuzz",
    "clusterfuzzlite",
    "claude-code-security-review",
    "sonarsource",
    "sonarqube",
    "checkmarx",
    "veracode",
    "zaproxy",
    "owasp",
    "aquasec",
    "trivy",
    "anchore",
    "grype",
    "syft",
    "fortify",
    "bandit",
    "pyup",
    "safety",
    "njsscan",
    "tfsec",
    "kics",
    "checkov",
    "horusec",
)

# YAML comment stripper for workflow bodies. We only want to match `uses:`
# directives that are NOT in a commented-out block.
_COMMENT_RE = re.compile(r"(^|\s)#.*?$", re.MULTILINE)


# ---------- helpers ---------------------------------------------------------


def _setup_logger() -> logging.Logger:
    LOGS.mkdir(parents=True, exist_ok=True)
    log_path = LOGS / "phase_c.log"
    logger = logging.getLogger("phase_c")
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


def _load_tools_cfg() -> tuple[dict[str, dict], list[str]]:
    """Return (tools_dict, root_config_paths_list).

    `tools_dict` maps tool name -> {category, workflow_uses (compiled regexes),
    config_paths (list of strings, '/'-suffix means dir-prefix)}.
    """
    raw = yaml.safe_load((REPO / "configs" / "tools.yaml").read_text())
    tools_in = raw.get("tools") or {}
    tools: dict[str, dict] = {}
    config_paths_global: set[str] = set()
    for name, body in tools_in.items():
        category = body.get("category")
        uses = body.get("workflow_uses") or []
        cfgs = body.get("config_paths") or []
        # `uses` patterns are matched as substring/prefix against the
        # `uses: <coord>` value found in workflow YAML. We do exact prefix
        # match to mirror the GitHub Actions reference syntax (e.g.
        # `github/codeql-action/init@v3` starts with `github/codeql-action`).
        compiled = []
        for u in uses:
            # Anchor at coord start, allow @ref or `/sub-action` suffix.
            compiled.append(re.compile(rf"^{re.escape(u)}(?:[/@]|$)", re.IGNORECASE))
        tools[name] = {
            "category": category,
            "workflow_uses": uses,
            "workflow_uses_re": compiled,
            "config_paths": cfgs,
        }
        for c in cfgs:
            config_paths_global.add(c)
    return tools, sorted(config_paths_global)


def _is_workflow_path(p: str) -> bool:
    return (
        p.startswith(".github/workflows/")
        and (p.endswith(".yml") or p.endswith(".yaml"))
        and "/" not in p[len(".github/workflows/") :]  # only direct children
    )


def _strip_yaml_comments(text: str) -> str:
    return _COMMENT_RE.sub("", text)


def _iter_uses_lines(text: str):
    """Yield (lineno, raw_line, coord) for every `uses: <coord>` directive
    in a workflow YAML. Comments are stripped first.
    """
    cleaned = _strip_yaml_comments(text)
    for i, line in enumerate(cleaned.splitlines(), start=1):
        m = re.search(r"^\s*-?\s*uses:\s*['\"]?([^'\"#\s]+)", line)
        if not m:
            continue
        yield i, line.strip(), m.group(1)


# ---------- step: trees -----------------------------------------------------


def step_trees(
    client: GitHubClient,
    logger: logging.Logger,
    repos: pd.DataFrame,
    out_dir: Path,
) -> tuple[pd.DataFrame, list[dict]]:
    """For each repo, fetch git/trees/HEAD?recursive=1 and filter to
    workflows + root config paths. Returns (filtered_tree_df, repo_drops).

    `filtered_tree_df` columns: repo_full_name, cohort, path, type, sha.
    `repo_drops` rows: {repo_full_name, cohort, reason}.
    """
    tree_cache_path = out_dir / "_phase_c_filtered_trees.parquet"
    drops_cache_path = out_dir / "_phase_c_repo_drops.json"
    if tree_cache_path.exists() and drops_cache_path.exists():
        df = pd.read_parquet(tree_cache_path)
        drops = json.loads(drops_cache_path.read_text())
        logger.info("trees: cached hit rows=%d drops=%d", len(df), len(drops))
        return df, drops

    _, all_cfg_paths = _load_tools_cfg()
    cfg_dir_prefixes = [c for c in all_cfg_paths if c.endswith("/")]
    cfg_exacts = set(c for c in all_cfg_paths if not c.endswith("/"))

    rows: list[dict] = []
    drops: list[dict] = []

    for ix, r in repos.iterrows():
        full = r["repo_full_name"]
        cohort = r["cohort"]
        if not isinstance(full, str) or "/" not in full:
            continue
        owner, name = full.split("/", 1)

        # Try HEAD first (covers default branch). Some repos don't have a
        # 'HEAD' git ref alias on the trees endpoint; fall back to the repo's
        # default_branch via /repos/{owner}/{name} if available, else 'main'
        # then 'master'.
        attempts = ["HEAD"]
        # default branch from cohort tables when known
        for col in ("default_branch", "default_branch_gh"):
            if col in r and isinstance(r[col], str) and r[col]:
                if r[col] not in attempts:
                    attempts.append(r[col])
                break
        for fb in ("main", "master"):
            if fb not in attempts:
                attempts.append(fb)

        ok = False
        last_status = None
        for ref in attempts:
            status, body = client.get(
                f"/repos/{owner}/{name}/git/trees/{ref}",
                repo=full,
                params={"recursive": "1"},
            )
            last_status = status
            if status == 200 and isinstance(body, dict):
                # Skip if truncated AND has no usable workflow/config paths
                # in the partial response. We accept truncated results when
                # the partial tree happens to include the paths we care about
                # (workflows + root configs are usually returned early since
                # the tree is alphabetically/breadth-first ordered, and our
                # targets are all near-root).
                tree = body.get("tree") or []
                truncated = bool(body.get("truncated"))
                kept_for_repo = 0
                for entry in tree:
                    p = entry.get("path") or ""
                    if not p:
                        continue
                    keep = False
                    if _is_workflow_path(p):
                        keep = True
                    elif p in cfg_exacts:
                        keep = True
                    else:
                        for prefix in cfg_dir_prefixes:
                            if p.startswith(prefix):
                                keep = True
                                break
                    if keep:
                        rows.append(
                            {
                                "repo_full_name": full,
                                "cohort": cohort,
                                "path": p,
                                "type": entry.get("type"),
                                "sha": entry.get("sha"),
                                "ref_used": ref,
                                "tree_truncated": truncated,
                            }
                        )
                        kept_for_repo += 1
                if truncated and kept_for_repo == 0:
                    logger.warning(
                        "trees: truncated tree for %s ref=%s with no targets in partial",
                        full,
                        ref,
                    )
                ok = True
                break
            if status == 404:
                # try next ref before giving up
                continue
            # transient/unknown -> stop and record
            break

        if not ok:
            reason = (
                "REPO_NOT_FOUND"
                if last_status in (404, None)
                else f"http_{last_status}"
            )
            drops.append(
                {
                    "repo_full_name": full,
                    "cohort": cohort,
                    "reason": reason,
                    "last_status": last_status,
                }
            )

        if ix and ix % 200 == 0:
            logger.info(
                "trees: %d/%d (calls=%d hits=%d 404s=%d drops=%d)",
                ix,
                len(repos),
                client.calls_made,
                client.cache_hits,
                client.cache_404_hits,
                len(drops),
            )

    df = pd.DataFrame(rows)
    df.to_parquet(tree_cache_path, index=False)
    drops_cache_path.write_text(json.dumps(drops, indent=2))
    logger.info(
        "trees: filtered rows=%d, drops=%d (calls=%d hits=%d 404s=%d)",
        len(df),
        len(drops),
        client.calls_made,
        client.cache_hits,
        client.cache_404_hits,
    )
    _log_table(logger, "_phase_c_filtered_trees", df)
    return df, drops


# ---------- step: workflows -------------------------------------------------


def _b64_to_text(body: dict) -> str | None:
    """Decode a /repos/.../contents/<path> response body to UTF-8 text."""
    enc = body.get("encoding")
    content = body.get("content")
    if enc != "base64" or not isinstance(content, str):
        return None
    try:
        return base64.b64decode(content).decode("utf-8", errors="replace")
    except Exception:
        return None


def step_workflows(
    client: GitHubClient,
    logger: logging.Logger,
    trees_df: pd.DataFrame,
    out_dir: Path,
) -> dict[tuple[str, str], str]:
    """Fetch raw bodies for every workflow YAML in trees_df. Root config
    files don't need bodies for v1 detection (presence is enough), so we
    skip them here.

    Returns dict mapping (repo_full_name, path) -> text body.
    """
    cache_path = out_dir / "_phase_c_workflow_bodies.json"
    if cache_path.exists():
        try:
            blob = json.loads(cache_path.read_text())
            out = {tuple(k.split("\x1f", 1)): v for k, v in blob.items()}
            logger.info("workflows: cached hit n=%d", len(out))
            return out  # type: ignore[return-value]
        except Exception:
            logger.warning("workflows: failed to read body cache, refetching")

    wf_rows = trees_df[trees_df["path"].apply(_is_workflow_path)].copy()
    bodies: dict[tuple[str, str], str] = {}
    n_done = 0
    for _, r in wf_rows.iterrows():
        full = r["repo_full_name"]
        path = r["path"]
        owner, name = full.split("/", 1)
        # /repos/{o}/{n}/contents/{path}?ref=<ref_used> if available
        params: dict[str, Any] = {}
        if isinstance(r.get("ref_used"), str) and r["ref_used"]:
            params["ref"] = r["ref_used"]
        status, body = client.get(
            f"/repos/{owner}/{name}/contents/{path}",
            repo=full,
            params=params,
        )
        if status == 200:
            text = _b64_to_text(body) if isinstance(body, dict) else None
            if text is not None:
                bodies[(full, path)] = text
        n_done += 1
        if n_done % 500 == 0:
            logger.info(
                "workflows: %d/%d fetched (calls=%d hits=%d 404s=%d)",
                n_done,
                len(wf_rows),
                client.calls_made,
                client.cache_hits,
                client.cache_404_hits,
            )

    # Write a flat JSON cache (key = "owner/repo\x1fpath") so a re-run can
    # skip the iteration. Bodies are also already cached individually under
    # data_raw/github_cache/, so this is just a convenience join.
    flat = {f"{k[0]}\x1f{k[1]}": v for k, v in bodies.items()}
    cache_path.write_text(json.dumps(flat))
    logger.info("workflows: fetched bodies=%d", len(bodies))
    return bodies


# ---------- step: detect ----------------------------------------------------


def _flag_unknown_security_use(
    coord: str, tools: dict[str, dict]
) -> tuple[bool, str | None]:
    """Return (is_unknown_security, matched_token) for a workflow `uses:` coord.

    True iff the coord references a SEC_VENDOR_TOKENS substring AND no
    tools.yaml `workflow_uses_re` already matches it.
    """
    cl = coord.lower()
    matched_known = False
    for body in tools.values():
        for rgx in body["workflow_uses_re"]:
            if rgx.match(coord):
                matched_known = True
                break
        if matched_known:
            break
    if matched_known:
        return False, None
    for tok in SEC_VENDOR_TOKENS:
        if tok in cl:
            return True, tok
    return False, None


def step_detect(
    repos: pd.DataFrame,
    trees_df: pd.DataFrame,
    bodies: dict[tuple[str, str], str],
    repo_drops: list[dict],
) -> tuple[pd.DataFrame, pd.DataFrame, list[dict]]:
    """Apply tools.yaml rules. Returns (long_df, wide_df, unknown_security_uses).

    long_df row: one per (repo, tool) detected, with first evidence.
    wide_df row: one per repo (AI ∪ Control), with category + per-tool booleans.
    unknown_security_uses: list of dicts to surface to the operator.
    """
    tools, _ = _load_tools_cfg()
    tool_names = sorted(tools.keys())
    categories = sorted({tools[t]["category"] for t in tool_names})

    # Index tree paths per repo for O(1) presence checks.
    repo_paths: dict[str, list[str]] = {}
    repo_tree_rows: dict[str, list[dict]] = {}
    for _, row in trees_df.iterrows():
        full = row["repo_full_name"]
        repo_paths.setdefault(full, []).append(row["path"])
        repo_tree_rows.setdefault(full, []).append(row.to_dict())

    drop_map = {d["repo_full_name"]: d for d in repo_drops}

    long_rows: list[dict] = []
    wide_rows: list[dict] = []
    unknown_uses: list[dict] = []

    for _, r in repos.iterrows():
        full = r["repo_full_name"]
        cohort = r["cohort"]

        # Initialize wide row with all-False per-tool and per-category.
        wide: dict[str, Any] = {
            "repo_full_name": full,
            "cohort": cohort,
        }
        for cat in categories:
            wide[_cat_col(cat)] = False
        for t in tool_names:
            wide[_tool_col(t)] = False

        # Dropped (404/private/etc) -> wide row only, evidence_path sentinel
        # in the dropped marker column. Caller will materialize the long
        # form skipping this row.
        if full in drop_map:
            wide["evidence_path"] = "REPO_NOT_FOUND"
            wide_rows.append(wide)
            continue

        wide["evidence_path"] = ""

        paths = repo_paths.get(full, [])
        # Per-tool detection record (first evidence wins).
        per_tool_evidence: dict[str, dict] = {}

        # 1) Root config_paths (presence-based).
        for tname, body in tools.items():
            for cfg in body["config_paths"]:
                hit_path = None
                if cfg.endswith("/"):
                    for p in paths:
                        if p.startswith(cfg):
                            hit_path = p
                            break
                else:
                    if cfg in paths:
                        hit_path = cfg
                if hit_path is None:
                    continue
                if tname not in per_tool_evidence:
                    per_tool_evidence[tname] = {
                        "evidence_path": hit_path,
                        "evidence_line": "",
                        "evidence_pattern": cfg,
                    }
                break  # first config_path hit per tool is enough

        # 2) Workflow `uses:` regex.
        for tree_row in repo_tree_rows.get(full, []):
            wpath = tree_row["path"]
            if not _is_workflow_path(wpath):
                continue
            text = bodies.get((full, wpath))
            if not text:
                continue
            for lineno, raw, coord in _iter_uses_lines(text):
                # Known-tool match
                for tname, body in tools.items():
                    if tname in per_tool_evidence:
                        continue
                    for rgx in body["workflow_uses_re"]:
                        if rgx.match(coord):
                            per_tool_evidence[tname] = {
                                "evidence_path": wpath,
                                "evidence_line": f"{lineno}:{raw[:200]}",
                                "evidence_pattern": rgx.pattern,
                            }
                            break
                # Unknown security vendor surfacing
                is_unknown, tok = _flag_unknown_security_use(coord, tools)
                if is_unknown:
                    unknown_uses.append(
                        {
                            "repo_full_name": full,
                            "cohort": cohort,
                            "workflow_path": wpath,
                            "line": lineno,
                            "uses_coord": coord,
                            "matched_vendor_token": tok,
                        }
                    )

        # Materialize long-form rows + flip wide booleans.
        for tname, ev in per_tool_evidence.items():
            cat = tools[tname]["category"]
            long_rows.append(
                {
                    "repo_full_name": full,
                    "cohort": cohort,
                    "tool": tname,
                    "category": cat,
                    "configured": True,
                    "evidence_path": ev["evidence_path"],
                    "evidence_line": ev["evidence_line"],
                    "evidence_pattern": ev["evidence_pattern"],
                    "first_seen_at": pd.NaT,
                }
            )
            wide[_tool_col(tname)] = True
            wide[_cat_col(cat)] = True

        wide_rows.append(wide)

    long_df = pd.DataFrame(long_rows)
    wide_df = pd.DataFrame(wide_rows)
    # Stable column order on wide
    wide_cols = (
        ["repo_full_name", "cohort", "evidence_path"]
        + [_cat_col(c) for c in categories]
        + [_tool_col(t) for t in tool_names]
    )
    wide_df = wide_df[wide_cols]
    return long_df, wide_df, unknown_uses


def _cat_col(category: str) -> str:
    # e.g. "CI Hardening" -> "ci_hardening_any"
    return category.lower().replace(" ", "_") + "_any"


def _tool_col(tool: str) -> str:
    return f"tool_{tool}"


# ---------- step: write outputs --------------------------------------------


def write_outputs(
    logger: logging.Logger,
    long_df: pd.DataFrame,
    wide_df: pd.DataFrame,
    out_dir: Path,
) -> dict[str, int]:
    """Write the two Phase C outputs."""
    long_path = out_dir / "repo_security_adoption.parquet"
    wide_path = out_dir / "repo_security_adoption_wide.parquet"
    long_df.to_parquet(long_path, index=False)
    wide_df.to_parquet(wide_path, index=False)
    _log_table(logger, "repo_security_adoption", long_df)
    _log_table(logger, "repo_security_adoption_wide", wide_df)
    return {
        "repo_security_adoption.parquet": int(len(long_df)),
        "repo_security_adoption_wide.parquet": int(len(wide_df)),
    }


# ---------- step: manifest --------------------------------------------------


def step_manifest(
    logger: logging.Logger,
    client: GitHubClient,
    out_dir: Path,
    new_outputs: dict[str, int],
    phase_c_block: dict,
) -> Path:
    """Extend the existing run_manifest.json (Phase A+B) with Phase C.

    Strategy: read the existing manifest if present, preserve every key
    we don't own (phase_b, ai_meta_drops, etc), then re-emit via the shared
    write_manifest helper with phase=["A","B","C"] and the merged outputs.
    """
    mp = out_dir / "run_manifest.json"
    existing: dict = {}
    if mp.exists():
        try:
            existing = json.loads(mp.read_text())
        except Exception:
            logger.warning("manifest: failed to parse existing manifest, regenerating")
            existing = {}

    # Preserve every previous output's row counts (we re-hash via write_manifest).
    prev_outputs = existing.get("outputs") or {}
    merged_output_rows: dict[str, int] = {}
    for name, blob in prev_outputs.items():
        rows = blob.get("rows") if isinstance(blob, dict) else None
        if isinstance(rows, int):
            merged_output_rows[name] = rows
    for name, rows in new_outputs.items():
        merged_output_rows[name] = rows

    # Carry over phase_b, intervention_source_choice, etc.
    extra: dict = {}
    for k in ("phase_b", "intervention_source_choice"):
        if k in existing:
            extra[k] = existing[k]

    # Update github_mcp counters: keep Phase B cumulative numbers, add a
    # this_run_phase_c_* set so Phase B's counters aren't trampled.
    cache_total = client.cache_hits + client.cache_404_hits
    total_calls = client.calls_made + cache_total
    cache_hit_rate = (cache_total / total_calls) if total_calls else 0.0
    gh_existing = existing.get("github_mcp") or {}
    extra["github_mcp"] = {
        **gh_existing,
        "transport": "rest",
        "endpoint_or_image": "https://api.github.com",
        "phase_c_live_calls": int(client.calls_made),
        "phase_c_cache_hits_200": int(client.cache_hits),
        "phase_c_cache_hits_404": int(client.cache_404_hits),
        "phase_c_total_requests": int(total_calls),
        "phase_c_cache_hit_rate": float(round(cache_hit_rate, 4)),
        "cumulative_audit_log_entries": int(
            sum(1 for _ in (LOGS / "github-mcp-audit.log").open())
        )
        if (LOGS / "github-mcp-audit.log").exists()
        else 0,
        "cumulative_pr_list_cache_files": int(len(list(CACHE_DIR.glob("*pulls*")))),
        "cumulative_search_cache_files": int(len(list(CACHE_DIR.glob("search__*")))),
        "cumulative_repo_meta_cache_files": int(
            len(list(CACHE_DIR.glob("repos__*")))
            - len(list(CACHE_DIR.glob("*pulls*")))
            - len(list(CACHE_DIR.glob("*git__trees*")))
            - len(list(CACHE_DIR.glob("*contents*")))
        ),
        "cumulative_tree_cache_files": int(len(list(CACHE_DIR.glob("*git__trees*")))),
        "cumulative_contents_cache_files": int(len(list(CACHE_DIR.glob("*contents*")))),
    }

    extra["phase_c"] = phase_c_block

    # Roll forward AIDev meta from existing if env doesn't carry record_id etc.
    write_manifest(
        out_dir,
        phase=["A", "B", "C"],
        agent="data-miner",
        outputs=merged_output_rows,
        extra=extra,
    )
    logger.info("manifest: wrote %s", mp)
    return mp


# ---------- main ------------------------------------------------------------


def _build_repos_table(out_dir: Path, logger: logging.Logger) -> pd.DataFrame:
    """Return a dataframe with one row per repo in AI ∪ Control, with cohort
    label. Surfaces (does not silently merge) any AI ∩ Control overlap.
    """
    ai = pd.read_csv(out_dir / "ai_repos.csv")
    ctrl = pd.read_csv(out_dir / "control_repos.csv")
    ai_set = set(ai["repo_full_name"].dropna())
    ctrl_set = set(ctrl["repo_full_name"].dropna())
    both = ai_set & ctrl_set
    if both:
        logger.warning(
            "cohort: AI ∩ Control overlap detected: %d repos labeled cohort=Both",
            len(both),
        )
    rows: list[dict] = []
    for full in sorted(ai_set | ctrl_set):
        if full in both:
            cohort = "Both"
        elif full in ai_set:
            cohort = "AI"
        else:
            cohort = "Control"
        rows.append({"repo_full_name": full, "cohort": cohort})
    df = pd.DataFrame(rows)
    # Attach default_branch from control_repos when known (helps trees fallback).
    if "default_branch" in ctrl.columns:
        db = ctrl.set_index("repo_full_name")["default_branch"].to_dict()
        df["default_branch"] = df["repo_full_name"].map(db)
    logger.info(
        "cohort: AI=%d Control=%d Both=%d Union=%d",
        len(ai_set - both),
        len(ctrl_set - both),
        len(both),
        len(df),
    )
    return df


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--step",
        default=None,
        choices=[None, "trees", "workflows", "detect", "manifest"],
        help="Run only this step (resumable; all prior steps must have run).",
    )
    parser.add_argument(
        "--date",
        default=None,
        help=(
            "Pin the data_derived/<YYYY-MM-DD>/ output directory. Defaults to "
            "today (UTC). Use this to keep all four steps writing to the same "
            "dated dir even if the run spans a UTC date boundary."
        ),
    )
    args = parser.parse_args()

    load_dotenv(REPO / ".env")
    today = args.date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_dir = REPO / "data_derived" / today
    out_dir.mkdir(parents=True, exist_ok=True)

    logger = _setup_logger()
    logger.info(
        "=== Phase C run_id=%s out=%s step=%s ===",
        today,
        out_dir,
        args.step or "all",
    )

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GITHUB_TOKEN missing from .env")
    client = GitHubClient(token, logger)

    repos = _build_repos_table(out_dir, logger)

    # ---- trees -----------------------------------------------------------
    trees_df, repo_drops = step_trees(client, logger, repos, out_dir)
    if args.step == "trees":
        return

    # ---- workflows -------------------------------------------------------
    bodies = step_workflows(client, logger, trees_df, out_dir)
    if args.step == "workflows":
        return

    # ---- detect ----------------------------------------------------------
    long_df, wide_df, unknown_uses = step_detect(repos, trees_df, bodies, repo_drops)
    new_outputs = write_outputs(logger, long_df, wide_df, out_dir)
    if args.step == "detect":
        return

    # ---- manifest --------------------------------------------------------
    tools_sha = sha256_of(REPO / "configs" / "tools.yaml")
    cache_total = client.cache_hits + client.cache_404_hits
    total_calls = client.calls_made + cache_total
    cache_hit_rate = (cache_total / total_calls) if total_calls else 0.0

    # Per-cohort + per-category configured rate for the printed summary
    # AND for the manifest.
    cat_cols = [c for c in wide_df.columns if c.endswith("_any")]
    cohort_rates: dict[str, dict[str, float]] = {}
    for coh in ("AI", "Control", "Both"):
        sub = wide_df[wide_df["cohort"] == coh]
        if len(sub) == 0:
            continue
        cohort_rates[coh] = {c: float(sub[c].mean()) for c in cat_cols}

    phase_c_block = {
        "repo_count_total": int(len(repos)),
        "repo_count_dropped": int(len(repo_drops)),
        "tools_yaml_sha256": tools_sha,
        "first_seen_at_collected": False,
        "live_api_calls": int(client.calls_made),
        "cache_hit_rate": float(round(cache_hit_rate, 4)),
        "long_form_rows": int(len(long_df)),
        "wide_form_rows": int(len(wide_df)),
        "n_unknown_security_uses": int(len(unknown_uses)),
        "category_configured_rate_by_cohort": cohort_rates,
        "repo_drops": repo_drops[:200],  # cap for manifest size; full list in logs
    }
    if unknown_uses:
        # Persist the full list for operator review (separate file, not in
        # the manifest body) and embed a small sample in the manifest.
        unk_path = out_dir / "_phase_c_unknown_security_uses.json"
        unk_path.write_text(json.dumps(unknown_uses, indent=2))
        phase_c_block["unknown_security_uses_sample"] = unknown_uses[:25]
        phase_c_block["unknown_security_uses_path"] = str(unk_path.relative_to(REPO))
        logger.warning(
            "phase_c: %d workflow uses reference security vendors not in tools.yaml; "
            "see %s. NOT auto-editing tools.yaml.",
            len(unknown_uses),
            unk_path,
        )

    step_manifest(logger, client, out_dir, new_outputs, phase_c_block)

    # Flip latest symlink (no-op if same date)
    latest_link = REPO / "data_derived" / "latest"
    if latest_link.is_symlink() or latest_link.exists():
        latest_link.unlink()
    latest_link.symlink_to(today, target_is_directory=True)
    logger.info("symlink data_derived/latest -> %s", today)

    # ---- final one-line summary -----------------------------------------
    long_sha = sha256_of(out_dir / "repo_security_adoption.parquet")[:12]
    wide_sha = sha256_of(out_dir / "repo_security_adoption_wide.parquet")[:12]
    rates_ai = cohort_rates.get("AI", {})
    rates_ct = cohort_rates.get("Control", {})

    def _fmt(d: dict[str, float]) -> str:
        return ",".join(
            f"{k.replace('_any', '')}={d.get(k, 0):.3f}" for k in sorted(cat_cols)
        )

    summary = (
        f"phase_c long(rows={len(long_df)},sha={long_sha}) "
        f"wide(rows={len(wide_df)},sha={wide_sha}) "
        f"detected_pairs={len(long_df)} "
        f"AI[{_fmt(rates_ai)}] CTRL[{_fmt(rates_ct)}]"
    )
    print(summary)


if __name__ == "__main__":
    main()
