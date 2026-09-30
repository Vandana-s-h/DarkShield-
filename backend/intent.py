"""
intent.py — infer the most likely attack goal and build the manipulation map.

Primary-intent rule (avoids "everything with a login is Credential Theft"):
  1. Add up credential evidence and financial evidence separately.
  2. Whichever has more weight becomes the primary intent (ties go to
     Financial, since payment loss is usually more severe).
  3. The losing theft intent is kept as a SECONDARY intent, not discarded.
"""

from typing import Any, Dict, List, Set

from risk_engine import MEDIUM_MIN_SCORE

Signal = Dict[str, Any]

CREDENTIAL_IDS: Set[str] = {
    "password_field", "email_collection", "login_request",
    "account_verification", "sensitive_action",
}
FINANCIAL_IDS: Set[str] = {"payment_collection", "card_number", "cvv_collection"}

CREDENTIAL_THEFT = "Credential Theft"
FINANCIAL_THEFT = "Financial Information Theft"
SOCIAL_ENGINEERING = "Social Engineering"
SUSPICIOUS_ACTIVITY = "Suspicious Activity"
NONE_DETECTED = "None Detected"  # used when the score is LOW

# Each chain: ordered stages, each with the signal ids that would evidence it.
_CHAINS: Dict[str, List[tuple]] = {
    CREDENTIAL_THEFT: [
        ("CREATE TRUST", {"brand_impersonation", "fake_popularity", "social_proof"}),
        ("CREATE URGENCY", {"urgency", "limited_time", "fear_threat", "account_suspension", "pressure_to_act"}),
        ("REQUEST LOGIN", {"login_request", "verification_request", "account_verification"}),
        ("COLLECT CREDENTIALS", {"password_field", "email_collection", "sensitive_action"}),
    ],
    FINANCIAL_THEFT: [
        ("BUILD TRUST", {"brand_impersonation", "fake_popularity", "social_proof"}),
        ("CREATE URGENCY", {"urgency", "limited_time", "fear_threat", "account_suspension"}),
        ("CREATE SCARCITY", {"scarcity", "limited_time"}),
        ("PUSH TRANSACTION", {"pressure_to_act", "payment_collection"}),
        ("COLLECT PAYMENT DATA", {"payment_collection", "card_number", "cvv_collection"}),
    ],
    SOCIAL_ENGINEERING: [
        ("GAIN ATTENTION", {"urgency", "scarcity", "limited_time", "social_proof", "fake_popularity", "brand_impersonation"}),
        ("CREATE EMOTIONAL PRESSURE", {"fear_threat", "account_suspension", "urgency"}),
        ("PUSH USER ACTION", {"pressure_to_act", "verification_request", "login_request"}),
    ],
}
_CHAINS[SUSPICIOUS_ACTIVITY] = _CHAINS[SOCIAL_ENGINEERING]  # generic chain


def _weight(signals: List[Signal], ids: Set[str]) -> int:
    return sum(int(s["weight"]) for s in signals if s["id"] in ids)


def _total(signals: List[Signal]) -> int:
    return sum(int(s["weight"]) for s in signals)


def infer_intent(
    technical: List[Signal], social: List[Signal], behavioral: List[Signal], risk_score: int
) -> Dict[str, Any]:
    # Below MEDIUM we don't label an "attack intent": signals are still returned as evidence.
    if risk_score < MEDIUM_MIN_SCORE:
        return {"attack_intent": NONE_DETECTED, "secondary_intents": []}

    credential = _weight(behavioral, CREDENTIAL_IDS)
    financial = _weight(behavioral, FINANCIAL_IDS)
    secondary: List[str] = []

    if credential and financial:
        if financial >= credential:
            primary, other = FINANCIAL_THEFT, CREDENTIAL_THEFT
        else:
            primary, other = CREDENTIAL_THEFT, FINANCIAL_THEFT
        secondary.append(other)  # preserve the other theft intent
    elif financial:
        primary = FINANCIAL_THEFT
    elif credential:
        primary = CREDENTIAL_THEFT
    elif _total(social) >= 20 or len(social) >= 2:
        primary = SOCIAL_ENGINEERING
    else:
        primary = SUSPICIOUS_ACTIVITY

    if _total(technical) >= 15:
        secondary.append("Technical Deception")
    if _total(social) >= 15 and primary != SOCIAL_ENGINEERING:
        secondary.append("Psychological Manipulation")
    if behavioral:
        secondary.append("Sensitive Action Requested")

    return {"attack_intent": primary, "secondary_intents": secondary}


def build_manipulation_map(
    attack_intent: str, technical: List[Signal], social: List[Signal], behavioral: List[Signal]
) -> List[Dict[str, Any]]:
    """Ordered attack chain; each stage says whether evidence for it was observed."""
    chain = _CHAINS.get(attack_intent)
    if chain is None:
        return []
    present = {s["id"] for s in technical + social + behavioral}
    return [
        {
            "stage": stage,
            "observed": bool(present & ids),
            "evidence": sorted(present & ids),
        }
        for stage, ids in chain
    ]