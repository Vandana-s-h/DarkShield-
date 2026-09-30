"""
risk_engine.py — explainable heuristic scoring. This is NOT a trained ML model.

Score = technical + social + behavioral (each capped) + a combination bonus.

Why caps and a bonus?
  * A suspicious domain, a pushy sales page, or a normal login form are each
    common on legitimate sites, so a single category can never reach HIGH.
  * Real phishing tends to combine deception + pressure + a data request, so
    when several categories are meaningfully present the risk is raised.
"""

from typing import Any, Dict, List

Signal = Dict[str, Any]

# Max points each category may contribute. Behavioral is capped below the
# MEDIUM threshold, so a normal login/checkout page alone stays LOW.
CATEGORY_CAPS = {"technical": 40, "social": 40, "behavioral": 30}

# A category only counts as "present" for the bonus at or above this many points.
MIN_MEANINGFUL_POINTS = 8

# Bonus by number of meaningfully-present categories.
COMBINATION_BONUS = {2: 10, 3: 25}

# (minimum score, severity), checked from highest to lowest.
SEVERITY_BANDS = [(80, "CRITICAL"), (60, "HIGH"), (35, "MEDIUM"), (0, "LOW")]
MEDIUM_MIN_SCORE = 35

RECOMMENDATIONS = {
    "LOW": "No major indicators detected.",
    "MEDIUM": "Review the detected signals before continuing.",
    "HIGH": "Proceed with extreme caution and verify the website.",
    "CRITICAL": "Do not enter credentials or payment information.",
}


def _points(signals: List[Signal]) -> int:
    return sum(int(s["weight"]) for s in signals)


def severity_for(score: int) -> str:
    for minimum, name in SEVERITY_BANDS:
        if score >= minimum:
            return name
    return "LOW"


def compute_risk(
    technical: List[Signal], social: List[Signal], behavioral: List[Signal]
) -> Dict[str, Any]:
    technical_pts = min(_points(technical), CATEGORY_CAPS["technical"])
    social_pts = min(_points(social), CATEGORY_CAPS["social"])
    behavioral_pts = min(_points(behavioral), CATEGORY_CAPS["behavioral"])

    categories_present = sum(
        1 for pts in (technical_pts, social_pts, behavioral_pts) if pts >= MIN_MEANINGFUL_POINTS
    )
    bonus = COMBINATION_BONUS.get(categories_present, 0)

    score = max(0, min(100, technical_pts + social_pts + behavioral_pts + bonus))
    severity = severity_for(score)

    return {
        "risk_score": score,
        "severity": severity,
        "recommendation": RECOMMENDATIONS[severity],
        "score_breakdown": {
            "technical": technical_pts,
            "social": social_pts,
            "behavioral": behavioral_pts,
            "combination_bonus": bonus,
            "categories_present": categories_present,
        },
    }