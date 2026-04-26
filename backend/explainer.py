"""
Explainability layer for TrustLayer Engine v2.
"""

from __future__ import annotations

from typing import Dict, List


REASON_MAP = {
    "urgency_terms": "Urgency language detected",
    "link_presence": "Suspicious link pattern found",
    "financial_terms": "Financially sensitive language identified",
    "threat_language": "Threat or penalty language detected",
    "sensitive_requests": "Sensitive information requested",
    "emotional_pressure": "Emotional pressure tactics detected",
}


def generate_reasons(features: Dict[str, Dict[str, object]], campaign: Dict[str, object] | None = None) -> List[str]:
    metadata = features.get("metadata", {})

    if metadata.get("insufficient_data") and not metadata.get("signal_count"):
        return ["Insufficient data for high-confidence analysis"]
    if metadata.get("gibberish_like"):
        return ["Input appears noisy or gibberish-heavy"]

    reasons = [
        reason
        for feature_name, reason in REASON_MAP.items()
        if features.get(feature_name, {}).get("present")
    ]
    if campaign and campaign.get("name"):
        reasons.append(
            f"Matched high-risk lure family: {campaign['name']} ({campaign.get('hook', 'Unknown')} hook)"
        )
    return reasons or ["No strong threat indicators detected"]
