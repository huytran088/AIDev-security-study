# Security Tooling Adoption & Intervention in AI-Assisted Software Development

Empirical study of how security tooling is **configured** at the repository
level and how security automation **intervenes** at the pull-request level
when AI coding agents (Claude Code, Devin, Cursor, Codex, …) ship code.
Built on the [AIDev v3 dataset](https://huggingface.co/datasets/hao-li/AIDev)
(current subset: ≥100-star repos, from 2025-01-01 to 2025-07-31)
plus a matched control cohort of repositories with no observed agentic
PRs, fetched from GitHub API.

The study answers three questions:

- **RQ1** — How widely are security tools configured across repositories
  with agentic PR activity?
- **RQ2** — Are security tools configured at *different* rates in AI repos
  versus matched non-AI controls?
- **RQ3** — Do agentic PRs receive different security interventions (and
  outcomes) than human PRs in the same repos?

Design is matched at the repo level (RQ2, CEM on language × stars × age ×
owner type) and within-repo at the PR level (RQ3, repo fixed effects on
agentic vs human PRs). All hypothesis tests pre-declared in
[`docs/STUDY_DESIGN.md #7`](docs/STUDY_DESIGN.md). The full report
is at [`analysis/REPORT.md`](analysis/REPORT.md).

---

## Results

Numbers below are read directly from the headline JSONs under
`analysis/tables/`. The cohort is **2,803 AI repos** + **1,744 matched
controls**, with **13,249 PRs** entering the within-repo RQ3 frame after
the singleton-repo drop.

### RQ1 — Configured adoption (AI repos)

40.4% of AI repos configure ≥1 security tool. Source:
[`rq1_headline.json`](analysis/tables/rq1_headline.json).

| Category | Adoption |
|---|---|
| SCA (top) | **34.8%** |
| SAST | 17.5% |
| CI hardening | 3.5% |
| Secrets scanning | 1.0% |
| Fuzzing (bottom) | **0.4%** |

Top-3 tools: Dependabot 29.7%, CodeQL 16.7%, Renovate 5.3%.

<p align="center">
  <img src="analysis/figures/rq1_adoption_by_category.png" alt="Adoption by category" width="500"/>
</p>

### RQ2 — AI repos vs matched controls

3 categories and 4 tools are significantly more common in AI repos
(Benjamini–Hochberg-adjusted Fisher's exact, all p_adj < 1e-4). Source:
[`rq2_headline.json`](analysis/tables/rq2_headline.json).

| Tool | OR (95% CI) | p_adj |
|---|---|---|
| Renovate | 3.86 (2.52, 5.92) | 3.4e-12 |
| CodeQL | 3.13 (2.51, 3.90) | 7.2e-28 |
| Dependabot | 3.12 (2.65, 3.69) | 4.1e-46 |
| OSSF Scorecard | 2.57 (1.57, 4.20) | 7.0e-05 |

Categories with the same direction: **SCA** (OR 3.36), **SAST** (OR 3.12),
**CI hardening** (OR 2.87). 15 sparse-band tools (e.g., Semgrep, Snyk,
Trivy, Gitleaks) were excluded from BH testing for low cell counts; as shown in the figures below.

<p align="center">
  <img src="analysis/figures/rq2_category_rates.png" alt="Category-level adoption" width="49%"/>
  <img src="analysis/figures/rq2_tool_forest.png" alt="Per-tool odds ratios" width="49%"/>
</p>

### RQ3 — Agentic vs human PRs (same repos)

Agentic PRs receive **fewer** security interventions than human PRs in the
same repos, but are **far more likely to be rejected**. Source:
[`rq3_headline.json`](analysis/tables/rq3_headline.json).

| Outcome | Effect | 95% CI | p | Model |
|---|---|---|---|---|
| any security intervention | **OR = 0.54** | (0.37, 0.79) | 0.0012 | logit + repo FE |
| security intervention count | **IRR = 0.69** | (0.49, 0.97) | 0.031 | Poisson (NB fallback) |
| PR rejected (closed unmerged) | **OR = 6.72** | (4.59, 9.84) | 1.2e-22 | logit + repo FE |

<p align="center">
  <img src="analysis/figures/rq3_outcomes_forest.png" alt="Within-repo effects of agent authorship" width="500"/>
</p>

### Figures

All figures are in [`analysis/figures/`](analysis/figures/) directory as paired
PNG + PDF.

- RQ1: [adoption by category](analysis/figures/rq1_adoption_by_category.png) ·
  [adoption by tool](analysis/figures/rq1_adoption_by_tool.png) ·
  [adoption by language](analysis/figures/rq1_adoption_by_language.png)
- RQ2: [category rates](analysis/figures/rq2_category_rates.png) ·
  [tool forest plot](analysis/figures/rq2_tool_forest.png)
- RQ3: [outcomes forest plot](analysis/figures/rq3_outcomes_forest.png) ·
  [per-repo intervention rates](analysis/figures/rq3_per_repo_rates.png)

---

## Requirements

- **Python 3.11+** managed by [`uv`](https://docs.astral.sh/uv/) — `uv.lock`
  is committed and is part of the reproducibility contract.
- **[Git-LFS](https://git-lfs.com/)** — figures and the canonical
  `data_derived/2026-04-25/` parquets ship via LFS. Run `git lfs install`
  once, then `git lfs pull` after cloning.
- **GitHub personal access token** (`public_repo` scope) for the control
  cohort + tooling-detection passes.
- **Hugging Face token** with read access to the AIDev dataset.
- **~30 GB free disk** for the AIDev parquet snapshot
  (`data_raw/aidev/`) and the GitHub response cache
  (`data_raw/github_cache/`).
---

## Instructions

### 1. Clone and install

```bash
git clone https://github.com/huytran088/AIDev-security-study.git # HTTPS
cd AIDev-security-study
uv sync           # installs pinned deps from uv.lock
```

### 2. Configure environment

Create `.env` at the repo root with the following starter content. Fill in
the token and dataset-record fields with your own values; the seed and
window are the published defaults and should not be changed for a
reproduction run.

```dotenv
# Authentication
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
HF_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Reproducibility
RANDOM_SEED=42
WINDOW_START=2025-01-01
WINDOW_END=2025-07-31

# AIDev dataset pinning (see https://zenodo.org/records/16919272)
AIDEV_DATASET_VERSION=v3
AIDEV_DATASET_RECORD_ID=16919272
AIDEV_DATASET_DOI=10.5281/zenodo.16919272
```

### 3. Pull the AIDev dataset from Hugging Face

```bash
mkdir data_raw/  # Make one if you don't have the folder
uv run python -c "
from huggingface_hub import snapshot_download
snapshot_download(
    repo_id='hao-li/AIDev',
    repo_type='dataset',
    local_dir='data_raw/aidev',
    revision='v3',
)
"
```

This populates `data_raw/aidev/*.parquet` (`pull_request`,
`pr_comments`, `pr_reviews`, `pr_review_comments_v2`, `all_repository`, etc.)

### 4. Run the phases

Each phase writes to `data_derived/<YYYY-MM-DD>/` and updates the
`data_derived/latest` symlink. GitHub responses are cached under
`data_raw/github_cache/`, so re-runs hit cache by default.

```bash
# Phase A — AI cohort + agentic PR table
uv run python analysis/scripts/phase_a_cohort.py

# Phase B — matched control cohort (CEM + SMD diagnostics)
uv run python analysis/scripts/phase_b_match.py

# Phase C — security tooling detection on AI + control repos
uv run python analysis/scripts/phase_c_tooling.py

# Phase D — RQ3 within-repo human PR sample + intervention classification
uv run python analysis/scripts/phase_d_interventions.py

# Phase E — analysis: power, RQ1/2/3 tables, robustness, post-hoc power, report
uv run python analysis/scripts/power_analysis_pre.py
uv run python analysis/scripts/rq1_compute.py
uv run python analysis/scripts/rq2_compute.py
uv run python analysis/scripts/rq3_compute.py
uv run python analysis/scripts/robustness.py
uv run python analysis/scripts/power_analysis_post.py
uv run python analysis/scripts/build_report.py
```

Or run end-to-end in one shot:

```bash
bash analysis/scripts/build_all.sh
```

After the pipeline completes, headline tables land under
[`analysis/tables/`](analysis/tables/), figures under
[`analysis/figures/`](analysis/figures/), and the rendered narrative at
[`analysis/REPORT.md`](analysis/REPORT.md).

---

## Pre-built derived data

Re-running Phases A–D end-to-end against the GitHub API takes several
hours and burns rate-limit budget. To skip them, the canonical
`data_derived/2026-04-25/` tree (16 parquets, ~70 MB) ships in this
repository via [Git-LFS](https://git-lfs.com/), alongside the CSVs,
JSONs, and `data_derived/latest` symlink that are tracked in plain git.

```bash
git lfs install      
git clone https://github.com/huytran088/AIDev-security-study.git
cd AIDev-security-study
git lfs pull     
```

After `git lfs pull`, you can skip directly to Phase E
(`rq{1,2,3}_compute.py` etc.) and reproduce all tables, figures, and
`REPORT.md` locally in a few minutes — no GitHub or Hugging Face token
required for the analysis stage.

> **Mirror:** If GitHub LFS bandwidth is exhausted (free tier: 1 GB
> / month), download the data from [Google Drive
> archive](https://drive.google.com/drive/folders/1md1_Unw-_H6gwIlfc8Y1JNNakPIVPZKh?usp=sharing).

---

## Repository layout

```
analysis/
  scripts/      Phase A–E pipeline scripts
  tables/       Headline CSVs + *_headline.json files
  figures/      Paired PNG + PDF for every figure
  REPORT.md     Generated Report (Jinja template + canonical CSVs)
configs/        Versioned rule sets (tools, bots, fingerprints, patterns)
data_raw/
  aidev/        AIDev parquet snapshot (download target, gitignored)
  github_cache/ Cached GitHub API responses (gitignored)
data_derived/   Per-run outputs; <YYYY-MM-DD>/ + 'latest' symlink
docs/           STUDY_DESIGN.md (full protocol)
notebooks/      Tutorial notebooks (Jupytext-paired)
```

---

## Study design and citation

The full protocol (research questions, operational definitions, runbook,
statistical plan, rule sets, robustness checks, threats to validity) is
in [`docs/STUDY_DESIGN.md`](docs/STUDY_DESIGN.md). Pre-registered tests
are listed in section 7 of that document.

If you build on this work, please cite the AIDev dataset along with this
study:

```bibtex
@misc{aidev-security-study,
  title  = {{Security Tooling Adoption \& Intervention in AI-Assisted Software Development}},
  author = {Huy Tran},
  year   = {2026},
  note   = {Anonymous submission},
}

@misc{li2025aiteammates,
      title={The Rise of AI Teammates in Software Engineering (SE) 3.0: How Autonomous Coding Agents Are Reshaping Software Engineering}, 
      author={Hao Li and Haoxiang Zhang and Ahmed E. Hassan},
      year={2025},
      eprint={2507.15003},
      archivePrefix={arXiv},
      primaryClass={cs.SE},
      url={https://arxiv.org/abs/2507.15003}, 
}
```

---

## License

MIT — see [`LICENSE`](LICENSE). The AIDev dataset itself is released under
CC BY 4.0 by its authors and remains subject to the original repositories'
licenses; see [`AIDev's GitHub`](https://github.com/SAILResearch/AI_Teammates_in_SE3) for
details.
