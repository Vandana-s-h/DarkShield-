"""
Local tests. No extra dependencies needed:

    python3 test_detection.py          # prints a summary line per test
    python3 -m pytest -s test_detection.py   # optional, if pytest is installed
"""

import json
import os
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The test suite must never call a real LLM, even if a key is exported in the shell.
os.environ.pop("LLM_API_KEY", None)

from pydantic import ValidationError

from backend import ai_analysis
from backend.main import FormInfo, PageInput, run_analysis

def analyze(label, url, title="", text="", forms=None):
    page = PageInput(url=url, title=title, text=text, forms=forms or [])
    result = run_analysis(page)
    print(f"{label}: score={result.risk_score} severity={result.severity} "
          f"intent={result.attack_intent} secondary={result.secondary_intents}")
    return result


LOGIN_FORM = FormInfo(type="login", password=True, email=True)
PAYMENT_FORM = FormInfo(type="payment", payment=True, card=True, cvv=True)


def test_1_benign_page():
    r = analyze("benign", "https://www.python.org/about/", "About Python",
                "Python is a programming language that lets you work quickly.")
    assert r.severity == "LOW" and r.risk_score == 0
    assert r.attack_intent == "None Detected"
    assert r.recommendation == "No major indicators detected."


def test_2_suspicious_shopping_page():
    r = analyze("shopping", "http://super-deals-shop.xyz/product/123", "Super Deals Shop",
                "Only 2 left! Limited time offer. Act now! 1,200 people are viewing this item.")
    ids = {s.id for s in r.social_signals}
    assert {"scarcity", "limited_time", "pressure_to_act", "social_proof"} <= ids
    assert r.technical_signals and not r.behavioral_signals
    assert r.severity in ("MEDIUM", "HIGH")
    assert r.attack_intent == "Social Engineering"


def test_3a_normal_login_page_not_flagged():
    r = analyze("normal login", "https://example.com/login", "Login",
                "Sign in to your account. Enter your email and password.", [LOGIN_FORM])
    assert r.severity == "LOW"
    assert {s.id for s in r.behavioral_signals} >= {"password_field", "email_collection"}
    assert r.attack_intent == "None Detected"


def test_3b_phishing_login_page():
    r = analyze("phishing login", "http://accounts-google-verify.top/login", "Sign in - Google",
                "Security alert: unusual sign-in detected. Verify your account within 24 hours "
                "or your account will be suspended. Act now!", [LOGIN_FORM])
    assert r.severity == "CRITICAL"
    assert r.attack_intent == "Credential Theft"
    assert r.recommendation == "Do not enter credentials or payment information."
    assert any(step.observed for step in r.manipulation_map)


def test_4_payment_page_card_cvv():
    r = analyze("payment", "http://secure-checkout-pay.top/pay", "Secure Payment",
                "Enter card number and CVV to complete your order. Limited time offer. Pay now!",
                [PAYMENT_FORM])
    assert {"payment_collection", "card_number", "cvv_collection"} <= {s.id for s in r.behavioral_signals}
    assert r.severity == "CRITICAL"
    assert r.attack_intent == "Financial Information Theft"


def test_5_many_social_signals_only():
    r = analyze("social only", "https://www.example.com/promo", "Special Promo",
                "URGENT: Security alert! Your account will be suspended. Verify your account "
                "within 24 hours. Only 3 left, limited time offer, act now! Trusted by millions, "
                "5,000 people are viewing this.")
    assert len(r.social_signals) >= 6
    assert not r.technical_signals and not r.behavioral_signals
    assert r.severity == "MEDIUM"  # one category alone never reaches HIGH
    assert r.attack_intent == "Social Engineering"


def test_6_login_plus_payment_picks_correct_primary():
    r = analyze("login+payment", "http://secure-billing-update.xyz/checkout", "Checkout",
                "Update your payment details. Verify your account. Act now.",
                [LOGIN_FORM, PAYMENT_FORM])
    assert r.attack_intent == "Financial Information Theft"
    assert "Credential Theft" in r.secondary_intents


def test_7_suspicious_tld_alone_is_not_flagged():
    r = analyze("tld only", "https://my-blog.xyz/", "My Blog", "Welcome to my personal blog about hiking.")
    assert r.severity == "LOW"
    assert any(s.id == "suspicious_tld" for s in r.technical_signals)


def test_8_input_length_limit():
    try:
        PageInput(url="https://a.com", text="x" * 20001)
    except ValidationError:
        return
    raise AssertionError("oversized text should be rejected")


# ------------------------- LLM explanation layer ---------------------------
# No network needed: the model call is replaced by a fake, or by a local HTTP
# server that imitates the API.

PHISH = dict(
    url="http://accounts-google-verify.top/login", title="Sign in - Google",
    text="Security alert: unusual sign-in detected. Verify your account within 24 hours "
         "or your account will be suspended. Act now!",
    forms=[LOGIN_FORM],
)
GOOD_REPLY = {
    "tactics": ["Fear", "Urgency", "Account threat"],
    "attack_chain": ["create fear", "CREATE URGENCY", "REQUEST VERIFICATION", "COLLECT CREDENTIALS"],
    "explanation": "The page creates fear of losing the account, adds a deadline, and uses "
                   "verification as the pretext to collect credentials.",
}


def _phish():
    return run_analysis(PageInput(**PHISH))


@contextmanager
def llm_on(fake=None, **env):
    """Enable the LLM layer for one block, then restore everything."""
    names = {"OPENROUTER_API_KEY", "OPENROUTER_API_URL", "LLM_TIMEOUT", *env}
    saved_env = {k: os.environ.get(k) for k in names}
    saved_call = ai_analysis._call_llm

    os.environ["OPENROUTER_API_KEY"] = "test-key"
    os.environ.update(env)
    if fake is not None:
        ai_analysis._call_llm = fake
    ai_analysis._LLM_CACHE.clear()
    try:
        yield
    finally:
        ai_analysis._call_llm = saved_call
        ai_analysis._LLM_CACHE.clear()
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _rule_view(result):
    return result.model_dump(exclude={"ai_analysis"})


def test_9_llm_unconfigured_still_works():
    r = _phish()
    assert r.severity == "CRITICAL" and r.attack_intent == "Credential Theft"
    assert r.ai_analysis is not None and r.ai_analysis.available is False
    assert r.ai_analysis.message == "AI analysis unavailable. Showing rule-based analysis."
    benign = analyze("benign", "https://www.python.org/about/", "About Python", "Python is a language.")
    assert benign.ai_analysis is None  # low risk: no AI section at all


def test_10_llm_never_changes_rule_results():
    baseline = _rule_view(_phish())
    with llm_on(fake=lambda system, user: json.dumps(GOOD_REPLY)):
        r = _phish()
    assert _rule_view(r) == baseline
    assert r.ai_analysis.available is True
    assert r.ai_analysis.attack_chain == ["CREATE FEAR", "CREATE URGENCY", "REQUEST VERIFICATION", "COLLECT CREDENTIALS"]
    assert r.ai_analysis.tactics and r.ai_analysis.explanation


def test_11_unevidenced_or_unknown_steps_are_dropped():
    reply = {"tactics": [], "explanation": "x y z",
             "attack_chain": ["CREATE SCARCITY", "CREATE FEAR", "COLLECT PAYMENT DATA",
                              "COLLECT CREDENTIALS", "MAKE UP A STEP"]}
    with llm_on(fake=lambda system, user: json.dumps(reply)):
        r = _phish()
    # this page has no scarcity and no payment form, so those steps must not survive
    assert r.ai_analysis.attack_chain == ["CREATE FEAR", "COLLECT CREDENTIALS"]


def test_12_llm_failures_never_break_analysis():
    baseline = _rule_view(_phish())

    def boom(system, user):
        raise RuntimeError("api down")

    bad_replies = ["not json at all", "[]", json.dumps({"attack_chain": [], "explanation": "x"}),
                   json.dumps({"attack_chain": ["CREATE FEAR", "CREATE URGENCY"], "explanation": ""})]
    for fake in [boom] + [(lambda system, user, t=t: t) for t in bad_replies]:
        with llm_on(fake=fake):
            r = _phish()
        assert _rule_view(r) == baseline
        assert r.ai_analysis.available is False and "unavailable" in r.ai_analysis.message

    fenced = "```json\n" + json.dumps(GOOD_REPLY) + "\n```"  # models often wrap JSON in fences
    with llm_on(fake=lambda system, user: fenced):
        assert _phish().ai_analysis.available is True


def test_13_llm_payload_contains_no_page_content():
    seen = []
    with llm_on(fake=lambda system, user: seen.append(user) or json.dumps(GOOD_REPLY)):
        _phish()
    assert len(seen) == 1
    payload = seen[0].lower()
    for forbidden in ("accounts-google-verify", "google", "within 24 hours", "sign in - google",
                      "http://", "evidence"):
        assert forbidden not in payload, forbidden
    assert "password_field" in payload and "fear_threat" in payload


def test_14_low_risk_pages_never_call_the_llm():
    calls = []
    with llm_on(fake=lambda system, user: calls.append(1) or json.dumps(GOOD_REPLY)):
        analyze("normal login", "https://example.com/login", "Login",
                "Sign in to your account. Enter your email and password.", [LOGIN_FORM])
        analyze("benign", "https://www.python.org/about/", "About Python", "Python is a language.")
    assert calls == []


class _FakeApi(BaseHTTPRequestHandler):
    hits = []
    delay = 0.0

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        type(self).hits.append((dict(self.headers), body))
        time.sleep(type(self).delay)
        reply = json.dumps({
    "choices": [
        {
            "message": {
                "content": json.dumps(GOOD_REPLY)
            }
        }
    ]
}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *args):
        pass


@contextmanager
def _fake_api(delay=0.0):
    handler = type("Handler", (_FakeApi,), {"hits": [], "delay": delay})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1/messages", handler
    finally:
        server.shutdown()


def test_15_real_http_path_headers_cache_and_timeout():
    with _fake_api() as (url, handler):
        with llm_on(OPENROUTER_API_URL=url):
            first, second = _phish(), _phish()
        assert first.ai_analysis.available and second.ai_analysis.available
        assert len(handler.hits) == 1, "second identical analysis should come from the cache"
        headers, body = handler.hits[0]
        headers = {k.lower(): v for k, v in headers.items()}  # urllib capitalizes header names
        assert headers.get("authorization") == "Bearer test-key"
        assert headers.get("content-type") == "application/json"
        assert headers.get("http-referer") == "http://127.0.0.1:8000"
        assert headers.get("x-title") == "DarkShield"
        assert body["model"] == "nvidia/nemotron-3-ultra-550b-a55b:free"
        assert body["messages"][0]["role"] == "system"
        assert body["messages"][0]["content"]
        assert body["messages"][1]["role"] == "user"
        assert body["messages"][1]["content"]
        assert "accounts-google-verify" not in json.dumps(body)

    with _fake_api(delay=1.5) as (url, handler):
        with llm_on(OPENROUTER_API_URL=url, LLM_TIMEOUT="0.3"):
            slow = _phish()
        assert slow.ai_analysis.available is False and slow.risk_score == first.risk_score


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failures = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"  FAIL  {name}: {exc!r}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)

def test_known_malicious_url():
    from backend.threat_intel import check_threat_intel

    signals = check_threat_intel(
        "http://secure-account-verification-login.com/verify"
    )

    assert any(
        signal["id"] == "known_malicious_url"
        for signal in signals
    )


def test_unknown_url_has_no_threat_intel_signal():
    from backend.threat_intel import check_threat_intel

    signals = check_threat_intel("https://example.com/unknown-page")

    assert not any(
        signal["id"] == "known_malicious_url"
        for signal in signals
    )


def test_benign_dataset_url_has_no_threat_signal():
    from backend.threat_intel import check_threat_intel

    signals = check_threat_intel("https://example.com/")

    assert not any(
        signal["id"] == "known_malicious_url"
        for signal in signals
    )