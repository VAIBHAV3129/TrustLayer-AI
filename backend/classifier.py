"""
Classification rules for TrustLayer Engine v2.
"""

from __future__ import annotations

from typing import Dict


CAMPAIGN_PROFILES = {
    "Account Security & Verification": {
        "hook": "Fear",
        "severity": "High",
        "keywords": [
            "login",
            "new device",
            "account",
            "suspended",
            "sign in",
            "code",
            "verify",
            "password",
            "security check",
            "unrecognized",
            "google drive",
            "storage",
            "re authenticate",
            "password reset",
            "session",
            "lockout",
        ],
    },
    "Financial & Banking": {
        "hook": "Money",
        "severity": "High",
        "keywords": [
            "wire transfer",
            "invoice",
            "tax refund",
            "zelle",
            "credit card",
            "salary",
            "pay scale",
            "subscription",
            "renew",
            "fraud",
            "apple.com",
            "unclaimed funds",
            "crypto",
            "wallet",
            "high risk transactions",
            "bank",
        ],
    },
    "Deliveries & Logistics": {
        "hook": "Convenience",
        "severity": "High",
        "keywords": [
            "deliver",
            "parcel",
            "reschedule",
            "package",
            "warehouse",
            "address",
            "customs",
            "shipment",
            "track",
            "gift card",
            "amazon",
            "order",
        ],
    },
    "Workplace & Productivity": {
        "hook": "Authority",
        "severity": "High",
        "keywords": [
            "meeting invite",
            "emergency update",
            "join",
            "google meet",
            "fake login",
            "file shared",
            "shared",
            "drive",
            "layoff",
            "open to view",
            "it ticket",
            "patch",
            "laptop",
            "quick favor",
            "conference",
            "mandatory",
            "harassment training",
            "eod",
            "hr action",
            "holiday party",
            "hr system",
            "register",
            "confidential",
            "strategy roadmap",
        ],
    },
    "Social Media & Communication": {
        "hook": "Curiosity",
        "severity": "High",
        "keywords": [
            "friend request",
            "view profile",
            "mentioned",
            "video",
            "copyrighted",
            "deleted",
            "free products",
            "voicemail",
            "unknown number",
            "whatsapp",
            "new device",
            "enter the code",
        ],
    },
    "Emerging Tech & AI Scams": {
        "hook": "2026",
        "severity": "High",
        "keywords": [
            "scan to pay",
            "qr code",
            "voice note",
            "ai cloned",
            "researchers",
            "data link",
            "grant",
            "gmail",
            "smartcalendar ai",
            "optimize your schedule",
            "pro version",
            "limited keys",
            "oauth",
        ],
    },
    "Miscellaneous Lures": {
        "hook": "Mixed",
        "severity": "High",
        "keywords": [
            "won",
            "claim",
            "warrant",
            "arrest",
            "unpaid fines",
            "donate",
            "disaster",
            "loan forgiveness",
            "pre approved",
            "lab results",
            "patient portal",
            "free",
            "pay shipping",
        ],
    },
}


CAMPAIGN_CATEGORY_MAP = {
    "Account Security & Verification": "Phishing",
    "Financial & Banking": "Financial Fraud",
    "Deliveries & Logistics": "Phishing",
    "Workplace & Productivity": "Social Engineering",
    "Social Media & Communication": "Social Engineering",
    "Emerging Tech & AI Scams": "Phishing",
    "Miscellaneous Lures": "Social Engineering",
}


def detect_campaign(features: Dict[str, Dict[str, object]]) -> Dict[str, object]:
    normalized_text = str(features.get("metadata", {}).get("normalized_text", ""))
    best_name = None
    best_score = 0

    for campaign_name, profile in CAMPAIGN_PROFILES.items():
        score = sum(1 for keyword in profile["keywords"] if keyword in normalized_text)
        if score > best_score:
            best_name = campaign_name
            best_score = score

    if not best_name or best_score < 2:
        return {
            "name": None,
            "hook": None,
            "severity": "None",
            "score": 0,
        }

    profile = CAMPAIGN_PROFILES[best_name]
    return {
        "name": best_name,
        "hook": profile["hook"],
        "severity": profile["severity"],
        "score": best_score,
    }


def classify(features: Dict[str, Dict[str, object]], risk_score: int, campaign: Dict[str, object]) -> str:
    metadata = features.get("metadata", {})
    has_financial = bool(features.get("financial_terms", {}).get("present"))
    has_sensitive = bool(features.get("sensitive_requests", {}).get("present"))
    has_link = bool(features.get("link_presence", {}).get("present"))
    has_urgency = bool(features.get("urgency_terms", {}).get("present"))
    has_emotional = bool(features.get("emotional_pressure", {}).get("present"))
    has_threat = bool(features.get("threat_language", {}).get("present"))

    if metadata.get("insufficient_data") and risk_score == 0:
        return "Unknown"
    if has_financial and has_sensitive:
        return "Financial Fraud"
    if has_link and has_urgency:
        return "Phishing"
    if has_emotional and has_threat:
        return "Social Engineering"
    if campaign.get("name"):
        return CAMPAIGN_CATEGORY_MAP.get(str(campaign["name"]), "Phishing")
    if risk_score == 0:
        return "Safe"
    return "Unknown"
