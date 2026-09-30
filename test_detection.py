"""
Local tests. No extra dependencies needed:

    python3 test_detection.py          # prints a summary line per test
    python3 -m pytest -s test_detection.py   # optional, if pytest is installed
"""

import sys

from pydantic import ValidationError

from main import FormInfo, PageInput, run_analysis


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