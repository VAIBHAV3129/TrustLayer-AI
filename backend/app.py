"""
Flask application for TrustLayer AI.

TrustLayer AI is an explainable AI-powered threat detection engine designed
for real-time trust scoring of digital interactions.

This system is designed with input validation, adversarial resistance, and
controlled execution to ensure reliability in real-world environments.
"""

from __future__ import annotations

from collections import defaultdict, deque
import os
from pathlib import Path
import re
import time
from typing import Deque, Dict

from flask import Flask, jsonify, request, send_from_directory

try:
    from .audit import log_analysis_event
    from .engine import analyze_text
except ImportError:
    from audit import log_analysis_event
    from engine import analyze_text


BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"
MAX_INPUT_LENGTH = 1000
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_BUCKETS: Dict[str, Deque[float]] = defaultdict(deque)
FALLBACK_RESPONSE = {
    "score": 50,
    "risk": "Unknown",
    "category": "Unknown",
    "confidence": 30,
    "reasons": ["System fallback triggered"],
    "actions": ["Treat the result as unverified and retry the analysis."],
}

app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")


@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self' data:; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


def _get_client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _is_rate_limited(client_ip: str) -> bool:
    now = time.time()
    bucket = RATE_LIMIT_BUCKETS[client_ip]

    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SECONDS:
        bucket.popleft()

    if len(bucket) >= RATE_LIMIT_REQUESTS:
        return True

    bucket.append(now)
    return False


def _sanitize_input(raw_text: str) -> str:
    normalized = raw_text or ""
    normalized = re.sub(r"(?is)<script.*?>.*?</script>", " ", normalized)
    normalized = re.sub(r"(?is)<style.*?>.*?</style>", " ", normalized)
    normalized = re.sub(r"(?s)<[^>]*>", " ", normalized)
    normalized = re.sub(r"[\x00-\x1f\x7f]", " ", normalized)
    normalized = normalized.replace("<", " ").replace(">", " ")
    normalized = re.sub(r"\s+", " ", normalized).strip().lower()
    return normalized


def _format_result(result: Dict[str, object]) -> Dict[str, object]:
    return {
        "score": result["score"],
        "risk": result["risk"],
        "category": result["category"],
        "campaign": result.get("campaign"),
        "hook": result.get("hook"),
        "confidence": result["confidence"],
        "reasons": result["reasons"],
        "actions": result.get("actions", []),
    }


@app.get("/")
def serve_index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/health")
def health_check():
    return jsonify({"status": "active", "engine": "TrustLayer Engine v2"})


@app.post("/analyze")
def analyze():
    client_ip = _get_client_ip()

    if _is_rate_limited(client_ip):
        return jsonify({"error": "Rate limit exceeded"}), 429

    try:
        payload = request.get_json(silent=True) or {}
        raw_text = str(payload.get("text", ""))
        sanitized_text = _sanitize_input(raw_text)

        if not sanitized_text:
            result = {
                "score": 100,
                "risk": "Low",
                "category": "Unknown",
                "confidence": 10,
                "reasons": ["Input text is required for analysis."],
                "actions": ["Provide a message, URL, or request before running analysis."],
            }
            log_analysis_event(client_ip, raw_text, result, status="rejected_empty")
            return jsonify({"error": "Input text is required for analysis.", **result}), 400

        if len(sanitized_text) > MAX_INPUT_LENGTH:
            result = {
                "score": 100,
                "risk": "Low",
                "category": "Unknown",
                "confidence": 10,
                "reasons": [f"Input exceeds the {MAX_INPUT_LENGTH} character limit."],
                "actions": ["Shorten the message or split it into smaller items for analysis."],
            }
            log_analysis_event(client_ip, raw_text, result, status="rejected_too_long")
            return jsonify({"error": f"Input exceeds the {MAX_INPUT_LENGTH} character limit.", **result}), 400

        result = analyze_text(sanitized_text)
        response_payload = _format_result(result)
        log_analysis_event(client_ip, raw_text, response_payload, status="success")
        return jsonify(response_payload)
    except Exception:
        log_analysis_event(client_ip, "analysis_error", FALLBACK_RESPONSE, status="fallback")
        return jsonify(FALLBACK_RESPONSE), 200


@app.post("/analyze/batch")
def analyze_batch():
    client_ip = _get_client_ip()

    if _is_rate_limited(client_ip):
        return jsonify({"error": "Rate limit exceeded"}), 429

    try:
        payload = request.get_json(silent=True) or {}
        raw_items = payload.get("items", [])

        if not isinstance(raw_items, list):
            return jsonify({"error": "Batch payload must include an items array."}), 400

        sanitized_items = []
        for item in raw_items[:25]:
            sanitized = _sanitize_input(str(item))
            if sanitized:
                sanitized_items.append(sanitized)

        if not sanitized_items:
            return jsonify({"error": "At least one valid input item is required."}), 400

        results = []
        summary = {"High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        for index, sanitized_text in enumerate(sanitized_items, start=1):
            result = _format_result(analyze_text(sanitized_text))
            result["id"] = index
            result["text"] = sanitized_text
            results.append(result)
            summary[result["risk"]] = summary.get(result["risk"], 0) + 1
            log_analysis_event(client_ip, sanitized_text, result, status="batch_success")

        return jsonify(
            {
                "total": len(results),
                "summary": summary,
                "results": results,
            }
        )
    except Exception:
        log_analysis_event(client_ip, "batch_analysis_error", FALLBACK_RESPONSE, status="batch_fallback")
        return jsonify({"error": "Batch analysis failed", "results": [], "summary": {}}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug, host="0.0.0.0", port=port)
