"""
SentinelAI — Response Generator
Produces contextual mitigation recommendations based on severity and threat type.
"""

from __future__ import annotations


ACTIONS: dict[str, dict[str, str]] = {
    "phishing": {
        "Critical":         "DELETE this message immediately. Do NOT click any links or open attachments. Report to IT security via your ticketing system right now. Reset your password as a precaution.",
        "Likely Malicious": "Do not interact with this message. Move to quarantine folder. Notify IT security with a screenshot. Verify sender identity via phone if expecting a legitimate message.",
        "Suspicious":       "Treat with caution. Verify sender identity before responding. Do not click embedded links — navigate directly to the service website instead.",
        "Clean":            "No immediate action required. Stay vigilant for follow-up messages.",
    },
    "url_malicious": {
        "Critical":         "BLOCK this URL immediately. Do not navigate to it. Report to IT and add to firewall blocklist. If already visited, run endpoint AV scan immediately.",
        "Likely Malicious": "Avoid this URL. Block at web proxy. Alert the sender's domain to your security team for investigation.",
        "Suspicious":       "Exercise caution. Verify URL legitimacy via VirusTotal before proceeding. Prefer direct navigation over clicking.",
        "Clean":            "URL appears safe. Standard browsing precautions apply.",
    },
    "deepfake": {
        "Critical":         "This media is likely synthetic. DO NOT act on any requests made in this video/audio. Verify the person's identity through an independent channel (call their known number). Report to anti-fraud team.",
        "Likely Malicious": "High probability of synthetic media. Pause any decisions based on this content. Cross-verify through secure alternative channel.",
        "Suspicious":       "Treat this media as potentially manipulated. Do not share or act on it until verified.",
        "Clean":            "Media appears authentic. No action required.",
    },
    "prompt_injection": {
        "Critical":         "REJECT this input. An adversary is attempting to take control of your AI system. Sanitise and block this input immediately. Review AI system logs for prior injection attempts.",
        "Likely Malicious": "Block this prompt. Audit AI system guardrails. Review recent AI outputs for signs of manipulation.",
        "Suspicious":       "Inspect this prompt carefully before processing. Apply input sanitisation filters.",
        "Clean":            "No injection patterns detected.",
    },
    "behaviour_anomaly": {
        "Critical":         "LOCK this account immediately. Initiate incident response. Preserve auth logs for forensics. Notify the account owner through an out-of-band channel.",
        "Likely Malicious": "Temporarily suspend account access. Require MFA re-enrollment. Investigate login source IPs against known good locations.",
        "Suspicious":       "Flag account for enhanced monitoring. Request the user to verify recent activity via security portal.",
        "Clean":            "Behaviour within normal parameters. Continue monitoring.",
    },
    "ai_generated": {
        "Critical":         "Flag this content as AI-generated disinformation. Do not publish or forward. Report to platform trust and safety team. Document for legal evidence if required.",
        "Likely Malicious": "Do not distribute this content. Mark as AI-generated and escalate to content moderation.",
        "Suspicious":       "Verify authorship before acting on this content. Apply AI-content disclosure labels.",
        "Clean":            "Content appears human-authored. No action required.",
    },
    "unknown": {
        "Critical":         "Escalate to Level-2 security analyst immediately. Preserve all context for investigation.",
        "Likely Malicious": "Quarantine and escalate. Do not interact with the flagged input pending review.",
        "Suspicious":       "Treat with caution. Escalate if severity increases.",
        "Clean":            "No specific action required.",
    },
}


class ResponseGenerator:
    def recommend(self, severity: str, threat_type: str, evidence: dict) -> str:
        threat_actions = ACTIONS.get(threat_type, ACTIONS["unknown"])
        return threat_actions.get(severity, threat_actions.get("Suspicious", "Exercise caution."))
