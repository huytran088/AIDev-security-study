# Study Design — Security Tooling Adoption & Intervention in AI-Assisted Software Development (AIDev)

> This document is the full study protocol: research questions, operational
> definitions, runbook, statistical plan, rule sets, robustness checks, and
> threats to validity. It was previously the project's top-level `README.md`
> and is preserved here verbatim. The repository's `README.md` now serves
> as a research-repo landing page (intro, results overview, reproduction
> instructions); see it for the entry point. The end-to-end pipeline runner
> is `analysis/scripts/build_all.sh`; the `.githooks/` pre-commit chain
> blocks commits where `analysis/REPORT.md` or `analysis/tables/*_main.csv`
> disagree with `data_derived/latest/`.

## 0) Scope and goals
This project studies **security tooling configuration (adoption)** at the repository level and **security automation intervention** at the pull-request (PR) level, using:
- **AIDev** dataset: https://huggingface.co/datasets/hao-li/AIDev
    - Paper: https://arxiv.org/abs/2602.09185
- A **matched control set of repositories without observed agentic PRs**, collected via GitHub REST API.
- A **within-repo PR comparison** between agentic PRs and human-authored PRs.

This project **does not claim ground-truth vulnerabilities**. It measures:
- **Configured tooling** (presence of config/workflow artifacts),
- **Observed interventions** (bots/tools commenting/reviewing in PRs),
- **PR outcomes** (merged vs closed), as governance proxies.

---

## 1) Research questions (RQ1–RQ3)

### RQ1 — Configured security tooling landscape (AI repos)
**RQ1:** How widely are security tools **configured** across repositories represented in the AIDev agentic-PR cohort?

- Unit: **Repository**
- Construct: **Configured adoption** (tool setup detectable via repo files)

### RQ2 — AI repos vs matched repos without observed agentic PRs
**RQ2:** Are security tools **configured at different rates** in repositories with observed agentic PR activity (AI repos) compared to matched repositories with **no observed agentic PR activity** under a defined detection rule (control repos)?

- Unit: **Repository**
- Construct: configured adoption; adjusted for repo characteristics

### RQ3 — Security automation intervention: agentic PRs vs human PRs (within the same repos)
**RQ3:** Do agentic PRs receive different rates/volumes of **security automation intervention** than human-authored PRs, within the same repositories and time window?

- Unit: **Pull request**
- Construct: **Observed intervention** (security tool/bot comments/reviews/inline comments)

---

## 2) Operational definitions (write these verbatim in your paper)

### 2.1 AI repository (AI repo)
A GitHub repository that appears in the **AIDev curated agentic-PR set** (i.e., contains ≥1 agentic PR in the curated subset).

### 2.2 Control repository (non-AI repo; "no observed agentic PRs")
A GitHub repository that:
1) **Does not** appear in the AI repo list, and  
2) In a sampled set of PRs within the analysis window, has **no PR** whose title/body matches your **agentic fingerprint rules** (Section 6.2).

> Important: This is "no observed agentic PRs under our detection strategy," not proof of absence.

### 2.3 Configured adoption (repo-level)
A tool is **configured** if the repository contains **one or more identifiable configuration artifacts**, such as:
- GitHub Actions workflows in `.github/workflows/*.yml|yaml` referencing the tool, and/or
- Tool-specific config files (e.g., `.github/dependabot.yml`, `renovate.json`, `.semgrep.yml`, `gitleaks.toml`, etc.).

### 2.4 Observed intervention (PR-level)
A PR has a **security automation intervention** if, during its lifecycle, any of the following occurs:
- A comment/review/inline review comment authored by a **known security tool identity** (bot login list), or
- A bot-authored message matching **security-related patterns** (CVE/GHSA/CWE tokens, "vulnerability", "secret", etc.) per your rule set.

---

## 3) Inputs and outputs

### Inputs
- **AIDev dataset tables** (Parquet): at minimum
  - agentic PR metadata (e.g., `pull_request`)
  - comments/reviews/inline comments (e.g., `pr_comments`, `pr_reviews`, `pr_review_comments_v2`)
  - repo metadata (e.g., `all_repository`)
  - (optional) commit/file metadata (e.g., `pr_commits`, `pr_commit_details`) for matching by churn
- **GitHub REST API** access (PAT token) to fetch:
  - repository files (workflow/config detection)
  - control repos (search + metadata)
  - human PRs in AI repos (for within-repo comparisons)
  - PR bodies/titles for agent fingerprint screening

### Outputs (recommended derived tables)
1) `repo_security_adoption.parquet`  
   - repo_id/full_name, cohort (AI/control), covariates, tool flags, category flags
2) `pr_interventions.parquet`  
   - pr_id/url, repo_full_name, pr_type (agentic/human), intervention flags/counts, outcomes
3) `matching_diagnostics.parquet`  
   - cohort balance statistics (SMDs), matched pair IDs, sample sizes

---

## 4) Study design overview (phases)

### Phase A — Prepare AI repo cohort and agentic PR set
Goal: Build the AI repo list and agentic PR list for the time window.

### Phase B — Build matched control repo cohort (RQ1)
Goal: Identify repos not in AI cohort; match to AI repos on key covariates; screen for no observed agentic PRs.

### Phase C — Detect configured security tooling (RQ1, RQ2)
Goal: For all AI and control repos, detect security tool configuration via workflow/config artifacts.

### Phase D — Sample human PRs in AI repos and measure interventions (RQ3)
Goal: Compare intervention rates on agentic PRs vs human PRs within the same repos/time window.

### Phase E — Statistics, corrections, robustness checks, and reporting
Goal: Run Fisher/OR, regressions, BH correction; run robustness checks and document threats to validity.

---

## 5) Step-by-step runbook

### Step 0 — Environment & reproducibility setup

The bullets below are the *requirements* for the environment. Concrete setup uses `uv` for Python and the `hf` CLI for AIDev dataset download.

1) Create a repo for the study with:
   - `README.md` (this project)
   - `configs/` (tool identity lists, regex rules, search queries)
   - `data_raw/` (AIDev parquets, cached API JSON)
   - `data_derived/` (derived tables)
   - `analysis/` (notebooks/scripts)
2) Set a random seed used everywhere (sampling, matching).
3) Set GitHub auth:
   - `GITHUB_TOKEN` with read-only scopes sufficient for repo contents and PR metadata.
4) Implement caching for GitHub API responses to avoid rate-limit failures:
   - Cache key: `{endpoint}-{repo}-{params_hash}.json`
5) Record per-run provenance in `data_derived/<YYYY-MM-DD>/run_manifest.json`:
   - dataset version (AIDev DOI hash),
   - date of API collection,
   - rule-set SHAs (`configs/*.yaml`/`*.txt`),
   - seed, window, library versions (`uv pip freeze`), `uv.lock` SHA,
   - inline-comment table choice (`pr_review_comments_v2` by default; see
     §6.1 below),
   - row counts of every output table.

   `analysis/scripts/write_manifest.py` ships the canonical schema and a
   `write_manifest()` helper; every phase calls it before exiting.

---

### Step 1 — Construct AI repo cohort from AIDev
1) Load the curated agentic PR table(s).
2) Filter agentic PRs to your analysis window:
   - Recommended window: PR created/updated timestamps up to **Jul 31, 2025** (the AIDev v3 dataset cutoff).
3) Extract AI repo list:
   - `AI_REPOS = unique(repo_full_name)` from curated agentic PR set.
4) Extract PR outcomes for agentic PRs:
   - merged vs closed (and timestamps if available).

**Deliverable:** `ai_repos.csv`, `agentic_prs.parquet`

---

### Step 2 — Build matched control repo cohort (RQ1)

#### Choose matching covariates (repo-level)
Minimum recommended covariates:
- `stars` (log scale or binned),
- `primary_language`,
- `repo_age` (created_at),
- `activity` proxy (e.g., pushes last N months or PR count in window),
- `owner_type` (org vs user).

Optional but helpful:
- `fork` status (exclude forks),
- `archived` status (exclude archived),
- `license` (optional).

#### Sample candidate control repos via GitHub Search API
1) For each AI repo, define a "matching bucket":
   - language = AI repo language
   - stars bin (e.g., 100–199, 200–499, 500–999, 1000+)
   - created_at bin (e.g., year)
2) Query GitHub Search API for repos in that bucket.
3) Exclude any repo whose `full_name` is in `AI_REPOS`.
4) Deduplicate across buckets.

#### Screen candidates for "no observed agentic PRs"
For each candidate control repo:
1) Fetch up to `N_PR` PRs in the analysis window (e.g., 30–50 most recent merged/closed in-window).
2) Apply **agent fingerprint rules** to PR title/body (Section 6.2).
3) If **any** PR matches fingerprints, drop the repo.
4) Otherwise, keep as eligible control.

#### Match AI repos to control repos
Recommended matching approach (robust and simple to defend):
- **Coarsened Exact Matching (CEM)** or exact matching on:
  - language,
  - stars bin,
  - repo age bin,
  - owner type,
- then within strata pick nearest neighbors on continuous covariates (e.g., log(stars), activity).

Diagnostics:
- Compute **standardized mean differences (SMD)** for all covariates pre/post match.
- Target: SMD < 0.1 for core covariates.

**Deliverable:** `control_repos.csv`, `repo_matching_pairs.csv`, `balance_table.csv`

---

### Step 3 — Detect configured security tooling (RQ1, RQ2)

#### Define tool taxonomy and detection signatures
Maintain a config file `configs/tools.yaml` with:
- tool name
- category (SAST/SCA/Secrets/Fuzzing/CI hardening)
- detection patterns:
  - workflow `uses:` strings (preferred),
  - config filenames,
  - known action names.

Example detection signals (non-exhaustive):
- CodeQL: workflow references `github/codeql-action`
- Dependabot: `.github/dependabot.yml`
- Renovate: `renovate.json`, `.renovaterc*`, or workflow usage
- Semgrep: workflow uses Semgrep action or `.semgrep.yml`
- Gitleaks: workflow uses gitleaks action or `gitleaks.toml`
- Scorecard: workflow uses OpenSSF Scorecard action
- StepSecurity harden-runner: workflow uses `step-security/harden-runner`

#### Collect repo file evidence
For each repo (AI + control):
1) Fetch list of files under:
   - `.github/workflows/`
   - repository root for known config filenames
2) For each workflow YAML file:
   - parse as text
   - search for `uses:` patterns
3) Set tool flags and category flags.

> Strong recommendation: also store "evidence strings" (which file/pattern triggered detection) for auditability.

#### Time alignment (optional but recommended)
If feasible, avoid look-ahead bias by estimating adoption timing:
- Find the first commit that introduced the config/workflow file (via commits API on that path).
- Mark tool as "active" only for PRs created after that commit date.

**Deliverable:** `repo_security_adoption.parquet` (tool/category booleans + evidence)

---

### Step 4 — Sample human PRs in AI repos and measure interventions (RQ3)

#### Sample human PRs (same repos, same time window)
For each AI repo:
1) Fetch PRs in the analysis window.
2) Exclude:
   - PRs authored by known bots (type Bot / login ends with `[bot]`),
   - dependency update bots if you want to avoid skew (optional sensitivity analysis).
3) Sample human PRs with stratification:
   - match distribution of PR sizes to agentic PRs using churn proxies (files changed, additions, deletions),
   - optionally match by task type if available.

> **Canonical recipe:** per-repo churn-quartile binning, sampling
> without replacement via `numpy.random.default_rng(RANDOM_SEED)`, with
> shortfall logging to `human_pr_sample_log.csv`. Implementation lives
> in `analysis/scripts/phase_d_interventions.py`.

**Deliverable:** `human_pr_sample.parquet`

#### Extract intervention signals from AIDev PR artifacts
For **agentic PRs** and **sampled human PRs**, compute:
- `any_security_intervention` (0/1)
- `security_intervention_count`
- `any_changes_requested_by_security_tool` (0/1), if review state available
- optional: `time_to_first_security_intervention`

Intervention sources (in priority order):
1) Known tool identities (bot login list) in:
   - PR comments (`pr_comments`)
   - PR reviews (`pr_reviews`)
   - PR review comments — inline (`pr_review_comments_v2`, **not** v1)
2) Bot-authored text matching security patterns (Section 6.3)

> **Inline-comment table choice:** AIDev ships both `pr_review_comments`
> (the v1 19,450-row table) and `pr_review_comments_v2`. Default to
> `pr_review_comments_v2` for Phase D and record the choice (and row
> count) in `run_manifest.json`.

> Keep a mapping file `configs/security_bots.txt` listing logins for Dependabot, Renovate, etc., plus any discovered tool bots.

#### Extract PR outcomes
For each PR:
- merged vs closed (rejected)
- timestamps if available (for controlling time trends)

**Deliverable:** `pr_interventions.parquet`

---

## 6) Rule sets (keep these versioned)

### 6.1 Tool identity list (interventions)
Create `configs/security_bots.txt` with logins (examples):
- dependabot[bot]
- renovate[bot]
- semgrep[bot] (if present in your data)
- snyk-bot / snyk[bot] (if present)
- gitleaks / trufflehog bots (if present)
- openssf-scorecard / scorecard bots (if present)

**Procedure to expand list:**
1) From AIDev comment/review authors, list top bot accounts.
2) Manually label which are security-related.
3) Freeze into a versioned list.

### 6.2 Agent fingerprint rules (for control repo screening)
Create `configs/agent_fingerprints.yaml` with conservative regex patterns for PR title/body such as:
- "Generated by"
- "Created with Cursor"
- "Devin"
- "Claude Code"
- "Codex"
- "AI-assisted"
- "Automated PR"
- known agent footers/templates (your curated list)

**Policy:** prioritize precision over recall for control cohort cleanliness.

### 6.3 Security text patterns (backup intervention classifier)
Create `configs/security_patterns.yaml`:
- tokens: `CVE-\d{4}-\d+`, `GHSA-[\w-]+`, `CWE-\d+`
- keywords: `vulnerability`, `injection`, `XSS`, `SSRF`, `RCE`, `secret`, `credential`, `token`, `leak`, `unsafe`, `path traversal`, `sql injection`, `command injection`
- keep as a "secondary signal" only when author is Bot (or when combined with tool config presence)

---

## 7) Statistical analysis plan (mapped to RQs)

### RQ1 — Adoption rates in AI repos
Report:
- `% AI repos with tool configured` (per tool and per category)
- breakdown by language and stars bins (descriptive)

Optional modeling:
- logistic regression: `tool_configured ~ log(stars) + language + repo_age + activity + owner_type`

### RQ2 — AI repos vs control repos (configured adoption)
For each tool/category:
1) **Fisher's exact test** on 2x2 table (AI vs control × configured yes/no)
2) **Odds ratio** with 95% CI
3) **Logistic regression**:
   - `tool_configured ~ AI_indicator + log(stars) + language + repo_age + activity + owner_type`
   - Use robust SE; consider clustering by owner/org if feasible.
4) **Benjamini–Hochberg** correction across the set of tools (define your family):
   - Option A: BH within each category
   - Option B: BH across all tools (more conservative)

### RQ3 — Intervention differences (agentic PRs vs human PRs within AI repos)
Outcomes:
- Binary: `any_security_intervention`
- Count: `security_intervention_count`
- Binary: `rejected` (closed without merge)

> **Singleton-repo drop (mandatory for FE validity):** before fitting any
> repo-FE model, drop repos that don't contain both `pr_type=='agentic'`
> and `pr_type=='human'` rows in the analysis frame. The FE coefficient is
> degenerate otherwise (all variation lives in the omitted category).
> `analysis/scripts/rq3_compute.py` applies the filter and documents the
> singleton drop count in `analysis/tables/rq3_main.csv`.

Recommended models:
- Binary: logistic regression with **repo fixed effects** (or random intercept):
  - `any_intervention ~ agentic + churn + task_type + time + C(repo)`
  - Cluster-robust SE on `repo_full_name` in addition to `C(repo)` — the
    two are not redundant (FE absorb level differences, cluster SE handle
    within-repo correlation in residuals).
- Counts: **negative binomial regression** (preferred over Mann–Whitney due to zeros and clustering):
  - `intervention_count ~ agentic + churn + task_type + time + C(repo)`
  - If `statsmodels.NegativeBinomial.fit_regularized()` fails to converge
    or refuses `cov_type='cluster'`, fall back to **Poisson with
    cluster-robust SE** as a quasi-likelihood approximation, and report
    fit diagnostics (α̂, log-likelihood, convergence status) regardless.
- Rejection: logistic regression:
  - `rejected ~ agentic + any_intervention + churn + task_type + time + C(repo)`
  - (Interpretation: association, not causation.)
- Effect-size reporting: incidence rate ratio (IRR) for NB, odds ratio
  (OR) for logit, both with cluster-robust 95% CI.

If you keep your nonparametric/effect-size stack (acceptable as secondary):
- Mann–Whitney U for counts **after within-repo matching**
- Cliff's delta for `any_security_concern` (binary)

---

## 8) Robustness checks (do at least 3)
1) **Alternative control screening strictness:**
   - stricter fingerprint list vs relaxed list; verify RQ2 stability.
2) **Exclude dependency update PRs** (Dependabot/Renovate as authors) in RQ3 sensitivity runs.
3) **Time alignment sensitivity** (if you implement adoption timestamps):
   - restrict PRs to those created after observed adoption.
4) **Language stratification**:
   - repeat RQ2/RQ3 for top languages separately.
5) **Bot identity ablation**:
   - measure interventions using only known bot identities vs bot+keyword patterns.

---

## 9) Threats to validity (pre-write these)
- **Configured adoption vs enforcement:** presence of configs/workflows may not imply consistent execution.
- **Control cohort misclassification:** cannot prove absence of agentic PRs; only "no observed" under rules.
- **Selection bias in interventions:** tools intervene more on riskier PRs; interpret RQ3 as correlation.
- **Clustering:** PRs are nested in repos; use fixed effects/random intercepts or matched analyses.
- **Look-ahead bias:** detecting tooling from the current repo state can misattribute past PRs; mitigate with adoption timestamps or sensitivity restrictions.

---

## 10) Reporting checklist (what to include in the final paper)
- Exact dataset version and tables used (including the inline-comment
  table choice — `pr_review_comments_v2` by default — recorded in
  `run_manifest.json`)
- Exact API endpoints and rate-limit handling
- Exact rule sets (tools, bots, fingerprints, security keywords), versioned
- Matching method + balance diagnostics (SMD table)
- Primary models + effect sizes + BH-adjusted p-values
- Singleton-repo drop count for RQ3 FE models (logged in
  `analysis/tables/rq3_main.csv`)
- Pre-declared minimum detectable effect sizes (MDEs) per test family,
  recorded in `analysis/tables/power_analysis.csv` with both `pre-flight`
  and `post-hoc` rows. Underpowered families (achieved power < 0.80) are
  flagged in `analysis/REPORT.md §6`.
- Sensitivity analyses summary (≥3 from §8)
- Reproducibility: seed, caching strategy, derived data schema, and a
  passing reproducibility audit against `data_derived/latest`.
- `analysis/REPORT.md` is generated by `analysis/scripts/build_report.py`
  from the Jinja template + canonical CSVs; the pre-commit hook refuses
  to commit a `REPORT.md` whose `_run_id` frontmatter doesn't match
  `data_derived/latest/`.

---

## 11) References
- MSR 2026: Mining Challenge: https://2026.msrconf.org/track/msr-2026-mining-challenge#Call-for-Mining-Challenge-Papers
- AIDev Dataset Preprint: https://arxiv.org/abs/2507.15003
- Dataset DOI: https://zenodo.org/records/16919272
- Who Said CVE? How Vulnerability Identifiers Are Mentioned by Humans, Bots, and Agents in Pull Requests: Rooijendijk et al. https://arxiv.org/abs/2601.19636
- Security in the Age of AI Teammates: An Empirical Study of Agentic Pull Requests on GitHub: https://arxiv.org/abs/2601.00477
- Agentic AI Security: Threats, Defenses, Evaluation, and Open Challenges: Chhabra et al. https://arxiv.org/abs/2510.23883
- Claude Code security review: https://github.com/anthropics/claude-code-security-review
