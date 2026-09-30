"""
ai_analysis.py — human-readable explanation of a result.

Default: a deterministic template built from the detected evidence, so the demo
works with no external service and no API key.

Adding an AI provider later:
    1. Write a function  (context: dict) -> str  that calls your provider.
       Read any API key from an environment variable inside that function.
       Never hardcode keys.
    2. Register it:  register_provider("myprovider", my_function)
    3. Start the server with  DARKSHIELD_AI_PROVIDER=myprovider

If the provider is missing, errors, or returns nothing, the deterministic
explanation is used.

SECURITY: providers only receive sanitized metadata (ids, labels, weights,
intent). Raw page text and matched snippets are excluded, because that text is
untrusted and could contain prompt-injection attempts.
"""

import logging
import os
from typing import Any, Callable, Dict, List

logger = logging.getLogger("darkshield.ai")

Context = Dict[str, Any]
AIProvider = Callable[[Context], str]

_PROVIDERS: Dict[str, AIProvider] = {}  # intentionally empty: nothing fake registered


def register_provider(name: str, provider: AIProvider) -> None:
    _PROVIDERS[name.strip().lower()] = provider


def _join(items: List[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _labels(signals: List[Dict[str, Any]], limit: int) -> List[str]:
    ordered = sorted(signals, key=lambda s: -int(s["weight"]))
    return [s["label"] for s in ordered[:limit]]


_INTENT_SENTENCES = {
    "Credential Theft": "These signals indicate a possible attempt to pressure the user into submitting login credentials or other identifying information.",
    "Financial Information Theft": "These signals indicate a possible attempt to pressure the user into submitting payment card or banking details.",
    "Social Engineering": "These signals indicate a possible social-engineering attempt designed to rush the user into acting without verifying the page.",
    "Suspicious Activity": "These signals are unusual and worth verifying before interacting with the page.",
}


def deterministic_explanation(ctx: Context) -> str:
    technical = ctx["technical_signals"]
    social = ctx["social_signals"]
    behavioral = ctx["behavioral_signals"]
    score, severity = ctx["risk_score"], ctx["severity"]

    if not (technical or social or behavioral):
        return ("DarkShield did not detect notable indicators of deceptive URLs, manipulative "
                "language, or sensitive-data requests on this page. This is a heuristic check "
                "and does not guarantee the page is safe.")

    if severity == "LOW":
        minor = _join(_labels(technical + social + behavioral, 4))
        return (f"DarkShield noted only minor indicators ({minor}), which are not enough in "
                f"combination to suggest a phishing or social-engineering attempt "
                f"(risk score {score}/100). This is a heuristic check and does not guarantee "
                f"the page is safe.")

    parts: List[str] = []
    if technical:
        parts.append("suspicious domain or URL characteristics")
    if social:
        parts.extend(_labels(social, 3))
    if behavioral:
        parts.append("requests for sensitive information (" + _join(_labels(behavioral, 3)) + ")")

    intent_sentence = _INTENT_SENTENCES.get(ctx["attack_intent"], "")
    return (f"DarkShield detected a combination of {_join(parts)}. {intent_sentence} "
            f"This is a heuristic assessment (risk score {score}/100, {severity}) and not "
            f"proof that the site is malicious.").replace("  ", " ")


def _sanitize_for_provider(ctx: Context) -> Context:
    signals = []
    for category in ("technical_signals", "social_signals", "behavioral_signals"):
        for s in ctx[category]:
            signals.append({
                "category": category.replace("_signals", ""),
                "id": s["id"], "label": s["label"], "weight": s["weight"],
            })
    return {
        "risk_score": ctx["risk_score"],
        "severity": ctx["severity"],
        "attack_intent": ctx["attack_intent"],
        "secondary_intents": ctx["secondary_intents"],
        "signals": signals,
    }


def generate_explanation(ctx: Context) -> str:
    name = os.getenv("DARKSHIELD_AI_PROVIDER", "").strip().lower()
    if name:
        provider = _PROVIDERS.get(name)
        if provider is None:
            logger.warning("DARKSHIELD_AI_PROVIDER=%s is not registered; using fallback.", name)
        else:
            try:
                text = provider(_sanitize_for_provider(ctx))
                if isinstance(text, str) and text.strip():
                    return text.strip()[:1500]
            except Exception:  # never let an AI failure break the API
                logger.exception("AI provider '%s' failed; using fallback.", name)
    return deterministic_explanation(ctx)