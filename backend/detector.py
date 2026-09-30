"""
detector.py — evidence extraction (NO scoring happens here).

Every detector returns a list of "signal" dicts:

    {"id": str, "label": str, "description": str, "weight": int, "evidence": [str]}

`weight` is the number of risk points the signal contributes. risk_engine.py
decides how those points are combined.

Page content (title/text/forms) is UNTRUSTED input. We only run bounded regexes
over it. Nothing is fetched, executed, rendered or submitted.
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlparse

Signal = Dict[str, Any]
Form = Dict[str, Any]


def _signal(
    signal_id: str,
    label: str,
    description: str,
    weight: int,
    evidence: Optional[List[str]] = None,
) -> Signal:
    return {
        "id": signal_id,
        "label": label,
        "description": description,
        "weight": weight,
        "evidence": evidence or [],
    }


# ---------------------------------------------------------------------------
# TECHNICAL SIGNALS (URL / domain deception)
# ---------------------------------------------------------------------------

# TLDs that are cheap/free and over-represented in abuse reports. A weak signal
# on its own: plenty of legitimate sites use them.
SUSPICIOUS_TLDS: Set[str] = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click",
    "country", "rest", "icu", "buzz", "monster", "cyou", "sbs", "cfd",
}

# Words that phishing hostnames often stack together ("secure-account-verify").
PHISHY_TOKENS: Set[str] = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "accounts", "update", "confirm", "wallet", "banking",
    "billing", "payment", "checkout", "support", "helpdesk",
}

# Frequently impersonated brands. Extend freely.
BRANDS: List[str] = [
    "paypal", "amazon", "google", "microsoft", "apple", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "paytm", "phonepe", "sbi", "hdfc",
    "icici", "flipkart",
]

REDIRECT_PARAMS: Set[str] = {
    "redirect", "redirect_uri", "redirect_url", "url", "next", "return",
    "returnurl", "return_to", "continue", "dest", "destination", "goto",
    "target", "link",
}

# Second-level labels used under country TLDs (example.co.uk -> registered
# domain is "example", not "co"). Not a full public-suffix list; good enough.
_SECOND_LEVEL_LABELS: Set[str] = {"co", "com", "org", "net", "gov", "edu", "ac"}


def _parse_url(url: str) -> Optional[Tuple[Any, str, bool]]:
    """Return (parsed_url, lowercase_host, had_scheme) or None if unparseable."""
    raw = url.strip()
    has_scheme = "://" in raw
    try:
        parsed = urlparse(raw if has_scheme else "http://" + raw)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    return parsed, host, has_scheme


def _as_ip(host: str) -> Optional[Any]:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _split_host(host: str) -> Tuple[List[str], str, str]:
    """Split a hostname into (subdomain labels, registered label, tld)."""
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return [], (labels[0] if labels else ""), ""
    tld = labels[-1]
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL_LABELS and len(tld) == 2:
        return labels[:-3], labels[-3], tld
    return labels[:-2], labels[-2], tld


def _redirect_target_host(value: str) -> str:
    try:
        return (urlparse(value).hostname or "").lower()
    except ValueError:
        return ""


def collects_sensitive_data(forms: List[Form]) -> bool:
    """True if any form asks for a password or payment details."""
    return any(
        f.get("password") or f.get("payment") or f.get("card") or f.get("cvv")
        for f in forms
    )


def _domain_signals(host: str) -> List[Signal]:
    """Checks that only make sense for a real domain name (not an IP)."""
    signals: List[Signal] = []
    subdomains, sld, tld = _split_host(host)
    tokens = [t for t in re.split(r"[.\-]", host) if t]

    if tld in SUSPICIOUS_TLDS:
        signals.append(_signal(
            "suspicious_tld", "suspicious TLD",
            "The domain uses a top-level domain often seen in abusive campaigns (weak signal on its own).",
            8, ["." + tld],
        ))

    if sld.count("-") >= 2:
        signals.append(_signal(
            "hyphenated_domain", "hyphenated domain",
            "The domain name contains several hyphens, a common pattern in lookalike domains.",
            8, [sld],
        ))

    if len(subdomains) >= 3:
        signals.append(_signal(
            "deep_subdomains", "deep subdomains",
            "The host has many subdomain levels, which can bury the real domain from the user.",
            8, [host],
        ))

    # Brand name present in the hostname, but it is not the registered domain
    # (paypal.com.evil.top, paypal-help.com). Legit brand domains don't trigger.
    for brand in BRANDS:
        if brand in tokens and sld != brand:
            signals.append(_signal(
                "brand_impersonation", "brand name in unrelated domain",
                "A well-known brand name appears in the host, but the registered domain is different: possible impersonation.",
                15, [brand + " in " + host],
            ))
            break

    # Two or more "phishing vocabulary" words inside the hostname itself.
    hits = sorted(set(tokens) & PHISHY_TOKENS)
    if len(hits) >= 2:
        signals.append(_signal(
            "phishy_keywords", "phishing-style keywords in domain",
            "The host name stacks words such as 'secure', 'verify' or 'account'.",
            10, hits,
        ))

    if any(label.startswith("xn--") for label in host.split(".")):
        signals.append(_signal(
            "punycode_domain", "punycode domain",
            "The domain uses punycode, which can be used for lookalike characters (legitimate IDNs exist too).",
            6, [host],
        ))

    return signals


def detect_technical_signals(url: str, forms: List[Form]) -> List[Signal]:
    parsed_info = _parse_url(url)
    if parsed_info is None or not parsed_info[1]:
        return [_signal(
            "unparseable_url", "malformed URL",
            "The URL could not be parsed into a valid host name.", 5, [url[:80]],
        )]

    parsed, host, has_scheme = parsed_info
    signals: List[Signal] = []

    ip = _as_ip(host)
    if ip is not None:
        # Private/loopback addresses (routers, local dev servers) are normal,
        # so they are NOT flagged. This avoids a classic false positive.
        if not (ip.is_private or ip.is_loopback):
            signals.append(_signal(
                "ip_address_host", "IP-address host",
                "The page is served from a raw IP address instead of a normal domain name.",
                20, [host],
            ))
    else:
        signals.extend(_domain_signals(host))

    # http://paypal.com@evil.top/ : the browser goes to evil.top.
    if "@" in parsed.netloc:
        signals.append(_signal(
            "at_symbol_in_url", "deceptive '@' in URL",
            "The URL contains '@', which can disguise the real destination host.",
            20, [parsed.netloc[:80]],
        ))

    # ?redirect=https://other-site : open-redirect style parameter pointing off-site.
    for key, value in parse_qsl(parsed.query):
        if key.lower() in REDIRECT_PARAMS and value.lower().startswith(("http://", "https://", "//")):
            target = _redirect_target_host(value)
            if target and target != host:
                signals.append(_signal(
                    "suspicious_redirect", "redirect parameter",
                    "A URL parameter redirects to a different site.", 10, [f"{key} -> {target}"],
                ))
                break

    if len(url.strip()) >= 150:
        signals.append(_signal(
            "long_url", "very long URL",
            "Unusually long URLs are sometimes used to hide the real destination.",
            4, [f"{len(url.strip())} characters"],
        ))

    # Plain HTTP only matters if the page actually collects sensitive data.
    if has_scheme and parsed.scheme == "http" and collects_sensitive_data(forms):
        signals.append(_signal(
            "insecure_http", "unencrypted (HTTP) page collecting data",
            "The page requests sensitive data over an unencrypted HTTP connection.",
            6, ["http://"],
        ))

    return signals


# ---------------------------------------------------------------------------
# SOCIAL-ENGINEERING SIGNALS (language analysis)
# ---------------------------------------------------------------------------

# (id, label, description, weight, [regex patterns]). Patterns run on lowercased,
# whitespace-normalised text. Each rule yields at most ONE signal, so repeating
# a phrase 50 times cannot inflate the score. All patterns are simple and
# bounded (no nested quantifiers) so hostile page text cannot cause slow matching.
_SOCIAL_RULES: List[Tuple[str, str, str, int, List[str]]] = [
    ("urgency", "artificial urgency",
     "The page uses time-pressure language to rush the user.", 10, [
         r"\burgent(?:ly)?\b", r"\bimmediately\b", r"\bright away\b",
         r"\bexpires? (?:today|soon|in \d+)", r"\bhurry\b", r"\blast chance\b",
         r"\bfinal (?:notice|warning)\b", r"\bwithin \d+ (?:hours?|minutes?)\b", r"\basap\b",
     ]),
    ("pressure_to_act", "pressure to act immediately",
     "The page pushes the user to act right now.", 10, [
         r"\bact now\b",
         r"\b(?:click|tap|respond|reply|call|pay|buy|order|claim|verify|login|log in|sign in) (?:here )?(?:now|immediately)\b",
         r"\bdon'?t (?:wait|miss|delay)\b", r"\bdo it now\b",
     ]),
    ("scarcity", "scarcity claims",
     "The page claims stock or availability is nearly gone.", 8, [
         r"\bonly \d+ (?:items? |units? |seats? |rooms? |pieces? )?(?:left|remaining|available)\b",
         r"\bonly (?:a )?few (?:items? )?(?:left|remaining)\b",
         r"\bwhile (?:supplies|stocks?) last\b", r"\balmost (?:gone|sold out)\b",
         r"\bselling (?:out )?fast\b", r"\b\d+ (?:items? )?left in stock\b",
     ]),
    ("limited_time", "limited-time offer",
     "The page advertises an offer that supposedly expires soon.", 8, [
         r"\blimited[- ]time\b", r"\boffer (?:ends|expires)\b",
         r"\bends? (?:today|tonight|soon|in \d+)", r"\bflash sale\b",
         r"\btoday only\b", r"\bcountdown\b",
     ]),
    ("fear_threat", "fear or threat language",
     "The page uses alarming or threatening wording.", 10, [
         r"\bsecurity (?:alert|warning|breach)\b",
         r"\bunauthori[sz]ed (?:access|login|activity|transaction|sign-?in)\b",
         r"\bsuspicious (?:activity|login|sign-?in)\b",
         r"\b(?:account|device|computer) (?:has been|was|is) (?:compromised|hacked|infected)\b",
         r"\blegal action\b", r"\bvirus(?:es)? (?:detected|found)\b",
     ]),
    ("account_suspension", "account-suspension pressure",
     "The page threatens to suspend, lock or close an account.", 12, [
         r"\b(?:account|access|card)s? (?:has been |will be |is |may be |was )?(?:suspended|locked|blocked|deactivated|disabled|terminated)\b",
         r"\bto avoid (?:suspension|closure|termination|being (?:suspended|locked|blocked))\b",
     ]),
    ("verification_request", "verification demand",
     "The page asks the user to verify, confirm or update account details.", 12, [
         r"\bverify your (?:account|identity|email|information|details|password|card)\b",
         r"\bconfirm your (?:account|identity|password|details|information|email)\b",
         r"\bupdate your (?:payment|billing|account|password|card)(?: details| information| info)?\b",
         r"\bre-?activate your account\b", r"\bvalidate your (?:account|identity)\b",
     ]),
    ("social_proof", "artificial social proof",
     "The page claims many other people are viewing or buying (often fabricated).", 6, [
         r"\b[\d,]{2,}\+? (?:people|customers|users|shoppers|others|buyers|visitors) (?:are |have )?(?:viewing|watching|looking|bought|purchased|ordered)\b",
         r"\bjoin [\d,]{2,} (?:people|customers|users|members)\b",
         r"\b(?:someone|\d+ people) (?:just )?(?:bought|purchased)\b",
     ]),
    ("fake_popularity", "popularity claims",
     "The page makes sweeping popularity or trust claims.", 5, [
         r"\btrusted by (?:millions|thousands|over)\b",
         r"\bmillions of (?:happy |satisfied )?(?:customers|users|people)\b",
         r"(?:#|number )1 (?:rated|choice|seller|store|shop)\b",
         r"\b(?:best[- ]?seller|going viral|trending now|everyone is (?:buying|talking))\b",
         r"\b100% (?:satisfaction|genuine|guaranteed|safe|secure)\b",
     ]),
]

_COMPILED_SOCIAL = [
    (sid, label, desc, weight, [re.compile(p) for p in patterns])
    for sid, label, desc, weight, patterns in _SOCIAL_RULES
]


def _normalize(*parts: str) -> str:
    """Join, lowercase, unify apostrophes and collapse whitespace."""
    joined = " ".join(parts).replace("\u2019", "'")
    return re.sub(r"\s+", " ", joined).lower()


def detect_social_signals(title: str, text: str) -> List[Signal]:
    haystack = _normalize(title, text)
    signals: List[Signal] = []
    for sid, label, desc, weight, patterns in _COMPILED_SOCIAL:
        matches: List[str] = []
        for pattern in patterns:
            for m in pattern.finditer(haystack):
                snippet = m.group(0)[:80]
                if snippet not in matches:
                    matches.append(snippet)
                if len(matches) >= 3:
                    break
            if len(matches) >= 3:
                break
        if matches:
            signals.append(_signal(sid, label, desc, weight, matches))
    return signals


# ---------------------------------------------------------------------------
# BEHAVIORAL SIGNALS (what the page asks the user to do / hand over)
# ---------------------------------------------------------------------------

_LOGIN_FORM_TYPES = {"login", "signin", "sign-in", "sign_in", "log-in", "log_in"}
_VERIFY_FORM_TYPES = {"verification", "verify", "account_verification", "account-verification"}

_CARD_TEXT = re.compile(r"\bcard number\b|\bexpir(?:y|ation) date\b")
_CVV_TEXT = re.compile(r"\b(?:cvv2?|cvc|security code)\b")
_SIGN_IN_TEXT = re.compile(r"\b(?:sign|log)[ -]?in\b")
# A verb asking for the data + a bounded gap + the sensitive item.
_SENSITIVE_ACTION_TEXT = re.compile(
    r"\b(?:enter|provide|send|share|submit|confirm|type|reply with)\b[^.!?]{0,40}"
    r"\b(?:otp|one[- ]time password|upi pin|atm pin|pin number|aadhaar|social security|ssn|"
    r"seed phrase|recovery phrase|private key)\b"
)


def detect_behavioral_signals(forms: List[Form], title: str, text: str) -> List[Signal]:
    haystack = _normalize(title, text)
    signals: List[Signal] = []

    form_types = {str(f.get("type", "")).strip().lower() for f in forms}
    has_password = any(f.get("password") for f in forms)
    has_email = any(f.get("email") for f in forms)
    has_payment = any(f.get("payment") for f in forms)
    has_card = any(f.get("card") for f in forms) or bool(_CARD_TEXT.search(haystack))
    has_cvv = any(f.get("cvv") for f in forms) or bool(_CVV_TEXT.search(haystack))

    if has_password:
        signals.append(_signal("password_field", "password collection",
                               "A form on this page asks for a password.", 15, ["password field"]))
    if has_email:
        signals.append(_signal("email_collection", "email/identity collection",
                               "A form on this page asks for an email address or identity.", 5, ["email field"]))
    if form_types & _LOGIN_FORM_TYPES or (has_password and _SIGN_IN_TEXT.search(haystack)):
        signals.append(_signal("login_request", "login request",
                               "The page asks the user to sign in.", 5, ["login form"]))
    if form_types & _VERIFY_FORM_TYPES:
        signals.append(_signal("account_verification", "account-verification form",
                               "The page presents an account-verification form.", 8, ["verification form"]))

    match = _SENSITIVE_ACTION_TEXT.search(haystack)
    if match:
        signals.append(_signal("sensitive_action", "request for highly sensitive data (OTP/PIN/ID)",
                               "The page asks the user to hand over an OTP, PIN, ID number or recovery phrase.",
                               12, [match.group(0)[:80]]))

    if has_payment:
        signals.append(_signal("payment_collection", "payment collection",
                               "The page collects payment details.", 15, ["payment form"]))
    if has_card:
        signals.append(_signal("card_number", "card-number collection",
                               "The page asks for a credit/debit card number.", 12, ["card number"]))
    if has_cvv:
        signals.append(_signal("cvv_collection", "CVV collection",
                               "The page asks for a card security code (CVV/CVC).", 15, ["cvv"]))

    return signals