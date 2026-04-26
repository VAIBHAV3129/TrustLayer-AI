"""
Feature extraction for TrustLayer Engine v2.

TrustLayer AI is an explainable AI-powered threat detection engine designed
for real-time trust scoring of digital interactions.

This system is designed with input validation, adversarial resistance, and
controlled execution to ensure reliability in real-world environments.

Test cases:
- Scam: "Your bank account will be blocked, click here immediately"
- Suspicious: "Check this investment opportunity"
- Safe: "Let's meet tomorrow"
"""

from __future__ import annotations

import difflib
import re
import unicodedata
from typing import Dict, Iterable, List, Set


LEETSPEAK_MAP = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }
)

FEATURE_KEYWORDS = {
    "urgency_terms": [
        "urgent",
        "immediately",
        "now",
        "act fast",
        "asap",
        "right away",
        "within today",
        "click",
    ],
    "link_presence": [
        "http",
        "https",
        "www",
        ".com",
        ".net",
        ".org",
        "bit.ly",
        "tinyurl",
        "goo.gl",
        "click here",
    ],
    "financial_terms": [
        "bank",
        "account",
        "payment",
        "transaction",
        "upi",
        "wallet",
        "credit card",
        "debit card",
        "investment",
        "refund",
        "transfer",
    ],
    "threat_language": [
        "blocked",
        "suspended",
        "penalty",
        "warning",
        "legal action",
        "security alert",
        "unauthorized",
        "verify now",
    ],
    "sensitive_requests": [
        "otp",
        "password",
        "pin",
        "cvv",
        "passcode",
        "verification code",
        "login details",
    ],
    "emotional_pressure": [
        "limited time",
        "last chance",
        "don't miss",
        "exclusive offer",
        "final notice",
        "act now",
        "expires today",
    ],
}


def normalize_for_analysis(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text or "")
    normalized = normalized.lower().translate(LEETSPEAK_MAP)
    normalized = re.sub(r"[\u200b-\u200f\u202a-\u202e]", "", normalized)
    normalized = re.sub(r"[^a-z0-9\s:/._'-]", " ", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _tokenize(text: str) -> List[str]:
    return re.findall(r"[a-z0-9]+", text)


def _count_substring_occurrences(text: str, keyword: str) -> int:
    return len(re.findall(re.escape(keyword), text))


def _best_fuzzy_match(token: str, vocabulary: Iterable[str]) -> str | None:
    for keyword in vocabulary:
        if len(keyword) < 3:
            continue
        score = difflib.SequenceMatcher(None, token, keyword).ratio()
        if score >= 0.84:
            return keyword
    return None


def _collect_feature_matches(normalized_text: str, keywords: List[str]) -> List[str]:
    matches: List[str] = []
    tokens = _tokenize(normalized_text)
    simple_keywords: Set[str] = {keyword for keyword in keywords if " " not in keyword and "." not in keyword}

    for keyword in keywords:
        if " " in keyword or "." in keyword or keyword in {"http", "https", "www"}:
            hits = _count_substring_occurrences(normalized_text, keyword)
            if hits:
                matches.extend([keyword] * hits)

    for token in tokens:
        if token in simple_keywords:
            matches.append(token)
            continue

        fuzzy_match = _best_fuzzy_match(token, simple_keywords)
        if fuzzy_match:
            matches.append(f"{token}->{fuzzy_match}")

    return matches


def extract_features(text: str) -> Dict[str, Dict[str, object]]:
    normalized_text = normalize_for_analysis(text)
    extracted: Dict[str, Dict[str, object]] = {}

    for feature_name, keywords in FEATURE_KEYWORDS.items():
        matches = _collect_feature_matches(normalized_text, keywords)
        deduped_matches = list(dict.fromkeys(matches))
        extracted[feature_name] = {
            "present": bool(matches),
            "count": len(matches),
            "matches": deduped_matches,
        }

    non_ascii_chars = sum(1 for char in text if ord(char) > 127)
    alpha_chars = sum(1 for char in normalized_text if char.isalpha())
    total_chars = len(normalized_text)
    word_count = len(normalized_text.split()) if normalized_text else 0
    total_feature_hits = sum(
        int(bool(extracted[feature_name]["present"]))
        for feature_name in FEATURE_KEYWORDS
    )

    insufficient_data = total_chars < 12 or word_count < 3
    gibberish_like = total_chars > 0 and alpha_chars < max(3, total_chars // 4) and total_feature_hits == 0
    non_english_heavy = len(text) > 0 and (non_ascii_chars / max(1, len(text))) > 0.35

    extracted["metadata"] = {
        "length": total_chars,
        "word_count": word_count,
        "normalized_text": normalized_text,
        "non_ascii_ratio": round(non_ascii_chars / max(1, len(text)), 2),
        "signal_count": total_feature_hits,
        "insufficient_data": insufficient_data,
        "gibberish_like": gibberish_like,
        "non_english_heavy": non_english_heavy,
    }
    return extracted
