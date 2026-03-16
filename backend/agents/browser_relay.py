"""
SentinelAI — Browser Relay
Receives URL data from the Chrome extension and pipes it to the orchestrator.
Also serves as the WebSocket bridge for extension ↔ backend real-time communication.
This module is imported by main.py — it provides utility functions for the extension flow.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone


def format_extension_payload(raw: dict) -> dict:
    """Normalise browser extension payload before analysis."""
    return {
        "url": raw.get("url", ""),
        "tab_id": raw.get("tab_id"),
        "timestamp": raw.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "source": "browser_extension",
        "user_agent": raw.get("user_agent", ""),
        "referrer": raw.get("referrer", ""),
    }


def should_warn(sentinel_score: int) -> bool:
    """Returns True if browser should inject warning overlay."""
    return sentinel_score >= 61


def build_extension_response(incident: dict) -> dict:
    """Build the response sent back to the Chrome extension."""
    return {
        "incident_id": incident.get("incident_id", ""),
        "sentinel_score": incident.get("sentinel_score", 0),
        "severity": incident.get("severity", "Clean"),
        "threat_brief": incident.get("threat_brief", ""),
        "recommended_action": incident.get("recommended_action", ""),
        "should_warn": should_warn(incident.get("sentinel_score", 0)),
        "mitre_label": incident.get("mitre_label", ""),
        "top_features": _extract_top_features_for_extension(incident),
    }


def _extract_top_features_for_extension(incident: dict) -> list[str]:
    """Extract the top 3 risk factors for compact display in extension popup."""
    evidence = incident.get("evidence", {})
    features = []

    if "url" in evidence:
        features.extend(evidence["url"].get("top_features", [])[:2])
    if "nlp" in evidence:
        features.extend(evidence["nlp"].get("top_tokens", [])[:2])

    context_mods = incident.get("context_modifiers", [])
    features.extend(context_mods[:2])

    return features[:3]
