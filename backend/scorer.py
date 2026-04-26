"""
Scoring module for TrustLayer Engine v2.

This system is designed with input validation, adversarial resistance, and
controlled execution to ensure reliability in real-world environments.
"""

from __future__ import annotations

from typing import Dict, Tuple


WEIGHTS = {
    "urgency_terms": 20,
    "link_presence": 15,
    "financial_terms": 25,
    "threat_language": 20,
    "sensitive_requests": 30,
    "emotional_pressure": 15,
}


def _clamp(value: int, lower: int = 0, upper: int = 100) -> int:
    return max(lower, min(upper, int(value)))


def compute_score(features: Dict[str, Dict[str, object]]) -> Tuple[int, int]:
    raw_risk_score = sum(
        weight * int(bool(features.get(feature_name, {}).get("present")))
        for feature_name, weight in WEIGHTS.items()
    )
    risk_score = _clamp(raw_risk_score)
    trust_score = _clamp(100 - risk_score)
    return trust_score, risk_score


def calculate_confidence(features: Dict[str, Dict[str, object]], risk_score: int) -> int:
    metadata = features.get("metadata", {})
    signal_count = int(metadata.get("signal_count", 0))
    confidence = max(10, min(100, risk_score))

    if signal_count <= 1:
        confidence -= 15
    if metadata.get("insufficient_data"):
        confidence -= 25
    if metadata.get("gibberish_like"):
        confidence -= 20
    if metadata.get("non_english_heavy") and signal_count == 0:
        confidence -= 10
    if risk_score >= 70 and signal_count >= 3:
        confidence += 10

    return _clamp(confidence, 5, 100)


def determine_risk_level(risk_score: int) -> str:
    if risk_score >= 70:
        return "High"
    if risk_score >= 30:
        return "Medium"
    return "Low"
