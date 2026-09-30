"""
main.py — DarkShield API.

Run from the backend/ folder:
    python3 -m uvicorn main:app --reload --port 8000

Security notes: this service never fetches URLs, never executes page content,
and never submits credentials or payments. It only analyses the JSON it is given.
"""

from typing import List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ai_analysis import generate_explanation
from detector import (
    detect_behavioral_signals,
    detect_social_signals,
    detect_technical_signals,
)
from intent import build_manipulation_map, infer_intent
from risk_engine import compute_risk

VERSION = "1.0.0"


# ---------------------------- Request models -------------------------------

class FormInfo(BaseModel):
    type: str = Field("unknown", max_length=50)
    password: bool = False
    email: bool = False
    payment: bool = False
    card: bool = False   # optional extras, default False so the base contract still works
    cvv: bool = False


class PageInput(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    title: str = Field("", max_length=300)
    text: str = Field("", max_length=20000)
    forms: List[FormInfo] = Field(default_factory=list, max_length=20)


# ---------------------------- Response models ------------------------------

class Signal(BaseModel):
    id: str
    label: str
    description: str
    weight: int
    evidence: List[str] = []


class ManipulationStep(BaseModel):
    stage: str
    observed: bool
    evidence: List[str] = []


class ScoreBreakdown(BaseModel):
    technical: int
    social: int
    behavioral: int
    combination_bonus: int
    categories_present: int


class AnalysisResult(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    severity: str
    technical_signals: List[Signal]
    social_signals: List[Signal]
    behavioral_signals: List[Signal]
    attack_intent: str
    secondary_intents: List[str]
    manipulation_map: List[ManipulationStep]
    recommendation: str
    explanation: str
    score_breakdown: ScoreBreakdown  # additive field; explains how the score was built


# ------------------------------ Pipeline -----------------------------------

def run_analysis(page: PageInput) -> AnalysisResult:
    forms = [f.model_dump() for f in page.forms]

    technical = detect_technical_signals(page.url, forms)
    social = detect_social_signals(page.title, page.text)
    behavioral = detect_behavioral_signals(forms, page.title, page.text)

    risk = compute_risk(technical, social, behavioral)
    intent = infer_intent(technical, social, behavioral, risk["risk_score"])
    manipulation_map = build_manipulation_map(
        intent["attack_intent"], technical, social, behavioral
    )

    explanation = generate_explanation({
        "risk_score": risk["risk_score"],
        "severity": risk["severity"],
        "attack_intent": intent["attack_intent"],
        "secondary_intents": intent["secondary_intents"],
        "technical_signals": technical,
        "social_signals": social,
        "behavioral_signals": behavioral,
    })

    return AnalysisResult(
        risk_score=risk["risk_score"],
        severity=risk["severity"],
        technical_signals=technical,
        social_signals=social,
        behavioral_signals=behavioral,
        attack_intent=intent["attack_intent"],
        secondary_intents=intent["secondary_intents"],
        manipulation_map=manipulation_map,
        recommendation=risk["recommendation"],
        explanation=explanation,
        score_breakdown=risk["score_breakdown"],
    )


# ------------------------------- App ---------------------------------------

app = FastAPI(
    title="DarkShield API",
    version=VERSION,
    description="Heuristic detection of technical deception, social engineering and "
                "sensitive-data requests. Results are risk indicators, not verdicts.",
)

# The Chrome extension's content script calls from the visited page's origin, so
# origins must be open. This is acceptable because the API is stateless, holds
# no secrets, and uses no cookies (allow_credentials=False).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
    allow_credentials=False,
)


@app.get("/")
def root() -> dict:
    return {"name": "DarkShield", "status": "online", "version": VERSION}


@app.post("/analyze", response_model=AnalysisResult)
def analyze(page: PageInput) -> AnalysisResult:
    return run_analysis(page)