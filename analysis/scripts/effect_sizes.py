"""Effect-size helpers used by RQ2/RQ3 compute scripts.

- `cliffs_delta(x, y)` returns Romano-binned Cliff's δ (negligible / small /
  medium / large) for two arrays of comparable observations.
- `odds_ratio_with_ci(table)` Haldane–Anscombe-corrected OR + 95% CI for a
  2x2 table given as ((a, b), (c, d)) where a/b = treatment yes/no,
  c/d = control yes/no.
- `smd_binary(p1, p2)` standardized mean difference for two proportions.
"""

from __future__ import annotations

import numpy as np


def cliffs_delta(x: np.ndarray, y: np.ndarray) -> tuple[float, str]:
    """Cliff's δ = P(X>Y) - P(X<Y) over all cross-pairs.

    Returns (delta, magnitude_bin) using Romano thresholds:
        |δ| < 0.147 -> negligible
        |δ| < 0.33  -> small
        |δ| < 0.474 -> medium
        else        -> large
    """
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)
    if x.size == 0 or y.size == 0:
        return float("nan"), "nan"
    # Pair-counting via sort (O(n log n)) for memory friendliness.
    nx, ny = x.size, y.size
    # Use mergesort-like rank approach: count(X>Y) for each x using searchsorted.
    y_sorted = np.sort(y)
    gt = np.searchsorted(y_sorted, x, side="left").sum()  # count y < x
    lt_eq = np.searchsorted(y_sorted, x, side="right").sum()  # count y <= x
    n_gt = int(gt)
    n_lt = int(nx * ny - lt_eq)
    delta = (n_gt - n_lt) / (nx * ny)
    a = abs(delta)
    if a < 0.147:
        bin_ = "negligible"
    elif a < 0.33:
        bin_ = "small"
    elif a < 0.474:
        bin_ = "medium"
    else:
        bin_ = "large"
    return float(delta), bin_


def odds_ratio_with_ci(
    a: int, b: int, c: int, d: int, alpha: float = 0.05
) -> tuple[float, float, float]:
    """Haldane–Anscombe 0.5-corrected OR with Wald 95% CI.

    Layout:
        treat: a yes, b no
        ctrl:  c yes, d no

    Returns (OR, ci_lo, ci_hi). OR > 1 means treat is more likely yes.
    Any zero cell triggers the 0.5 continuity correction.
    """
    if min(a, b, c, d) == 0:
        a_, b_, c_, d_ = a + 0.5, b + 0.5, c + 0.5, d + 0.5
    else:
        a_, b_, c_, d_ = float(a), float(b), float(c), float(d)
    or_ = (a_ * d_) / (b_ * c_)
    se = float(np.sqrt(1.0 / a_ + 1.0 / b_ + 1.0 / c_ + 1.0 / d_))
    log_or = np.log(or_)
    from scipy.stats import norm

    z = norm.ppf(1.0 - alpha / 2.0)
    return float(or_), float(np.exp(log_or - z * se)), float(np.exp(log_or + z * se))


def smd_binary(p1: float, p2: float) -> float:
    """Standardized mean difference for two proportions (pooled SD)."""
    var = (p1 * (1.0 - p1) + p2 * (1.0 - p2)) / 2.0
    if var <= 0:
        return 0.0
    return float((p1 - p2) / np.sqrt(var))
