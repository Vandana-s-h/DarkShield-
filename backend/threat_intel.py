"""
threat_intel.py — local threat-intelligence lookup.

Uses a locally downloaded malicious/phishing URL dataset.

Important:
- No network request happens during /analyze.
- Unknown URLs are treated as unknown, NOT safe.
- The dataset is loaded once and cached in memory.
"""

import csv
import os
from typing import Any, Dict, List
from urllib.parse import urlparse

Signal = Dict[str, Any]

DEFAULT_FEED_PATH = os.path.join(
    os.path.dirname(__file__),
    "data",
    "malicious_urls.csv",
)

# In-memory cache
_FEED_CACHE: Dict[str, Dict[str, str]] = {}
_LOADED_PATH = ""


def _normalise_url(url: str) -> str:
    """Normalise a URL for exact threat-feed comparison."""
    value = url.strip()

    if not value:
        return ""

    if "://" not in value:
        value = "http://" + value

    try:
        parsed = urlparse(value)
    except ValueError:
        return ""

    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")

    if not host:
        return ""

    path = parsed.path or "/"
    query = parsed.query

    normalised = f"{scheme}://{host}{path}"

    if query:
        normalised += f"?{query}"

    return normalised


def _load_feed(path: str) -> Dict[str, Dict[str, str]]:
    """Load the local dataset into memory."""
    global _FEED_CACHE, _LOADED_PATH

    if _LOADED_PATH == path and _FEED_CACHE:
        return _FEED_CACHE

    if not os.path.exists(path):
        return {}

    entries: Dict[str, Dict[str, str]] = {}

    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)

        for row in reader:
            raw_url = row.get("url", "")
            normalised = _normalise_url(raw_url)

            if normalised:
                entries[normalised] = row

    _FEED_CACHE = entries
    _LOADED_PATH = path

    return entries


def check_threat_intel(
    url: str,
    feed_path: str = DEFAULT_FEED_PATH,
) -> List[Signal]:
    """
    Check whether a URL appears in the local threat-intelligence dataset.
    """

    normalised = _normalise_url(url)

    if not normalised:
        return []

    entries = _load_feed(feed_path)
    match = entries.get(normalised)

    if not match:
        return []

    label = (match.get("label") or "").strip().lower()

    # Only malicious entries should generate a threat signal.
    if label != "malicious":
        return []

    evidence = [normalised]

    source = (match.get("source") or "").strip()
    if source:
        evidence.append(f"source: {source}")

    return [{
        "id": "known_malicious_url",
        "label": "known malicious URL",
        "description": (
            "The URL appears in the local threat-intelligence dataset."
        ),
        "weight": 25,
        "evidence": evidence,
    }]