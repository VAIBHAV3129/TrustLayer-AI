"""
Response recommendations for TrustLayer AI.

This system is designed with input validation, adversarial resistance, and
controlled execution to ensure reliability in real-world environments.
"""

from __future__ import annotations

from typing import Dict, List


PLAYBOOKS = {
    "Phishing": [
        "Do not click links or download attachments from this message.",
        "Verify the sender or service through an official channel before taking action.",
        "Report the message to your security or IT team and block the source if possible.",
    ],
    "Financial Fraud": [
        "Do not transfer funds, share banking details, or approve payment requests.",
        "Contact the bank or finance owner using a trusted phone number or official app.",
        "Escalate the message for fraud review and preserve the original content as evidence.",
    ],
    "Social Engineering": [
        "Pause the interaction and validate the request with a known contact path.",
        "Do not share internal files, credentials, or MFA codes in response to this message.",
        "Notify the appropriate security, HR, or operations contact for review.",
    ],
    "Safe": [
        "No immediate threat action is recommended.",
        "Continue normal verification habits if the message later changes or requests credentials.",
    ],
    "Unknown": [
        "Treat the message cautiously until it is independently verified.",
        "Avoid sharing sensitive data or installing anything referenced in the content.",
        "Escalate for manual review if the request affects money, access, or identity.",
    ],
}


def recommend_actions(category: str, risk: str, campaign: str | None = None) -> List[str]:
    actions = list(PLAYBOOKS.get(category, PLAYBOOKS["Unknown"]))
    if risk == "High" and campaign:
        actions.append(f"Flag this as a potential {campaign} campaign in your incident notes.")
    return actions[:4]
