"""
TrustLayer Engine v2 orchestration.

This module powers an explainable AI-powered threat detection engine designed
for real-time trust scoring of digital interactions.

This system is designed with input validation, adversarial resistance, and
controlled execution to ensure reliability in real-world environments.
"""

from __future__ import annotations

from typing import Dict

try:
    from .classifier import classify, detect_campaign
    from .explainer import generate_reasons
    from .features import extract_features
    from .recommender import recommend_actions
    from .scorer import calculate_confidence, compute_score, determine_risk_level
except ImportError:
    from classifier import classify, detect_campaign
    from explainer import generate_reasons
    from features import extract_features
    from recommender import recommend_actions
    from scorer import calculate_confidence, compute_score, determine_risk_level


def analyze_text(text: str) -> Dict[str, object]:
    features = extract_features(text)
    trust_score, risk_score = compute_score(features)
    campaign = detect_campaign(features)
    if campaign.get("severity") == "High":
        risk_score = max(risk_score, 75)
        trust_score = max(0, 100 - risk_score)
    category = classify(features, risk_score, campaign)
    reasons = generate_reasons(features, campaign)
    confidence = calculate_confidence(features, risk_score)
    risk_level = determine_risk_level(risk_score)
    actions = recommend_actions(category, risk_level, campaign.get("name"))

    return {
        "score": trust_score,
        "risk": risk_level,
        "category": category,
        "campaign": campaign.get("name"),
        "hook": campaign.get("hook"),
        "confidence": confidence,
        "reasons": reasons,
        "actions": actions,
        "risk_score": risk_score,
        "features": features,
    }
