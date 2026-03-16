"""
SentinelAI — MITRE ATT&CK Mapper
Maps detected threat types to ATT&CK tactic IDs, names, and kill-chain phases.
"""

from __future__ import annotations


MITRE_MAP: dict[str, dict] = {
    "phishing": {
        "tactic_id": "T1566",
        "tactic_name": "Phishing",
        "phase": "Initial Access",
        "description": (
            "Adversaries send malicious messages to gain access to victim systems. "
            "Phishing may use deceptive emails, links, or attachments."
        ),
        "mitigations": [
            "Enable email filtering and anti-phishing tools.",
            "Train users to recognise phishing attempts.",
            "Implement DMARC/SPF/DKIM email authentication.",
        ],
    },
    "url_malicious": {
        "tactic_id": "T1192",
        "tactic_name": "Spearphishing Link",
        "phase": "Initial Access",
        "description": (
            "Spearphishing links are malicious URLs sent to specific targets. "
            "They often lead to credential harvest pages or malware downloads."
        ),
        "mitigations": [
            "Block access to known malicious URLs via web proxy.",
            "Implement URL reputation scanning.",
            "Educate users about hovering over links before clicking.",
        ],
    },
    "deepfake": {
        "tactic_id": "T1598",
        "tactic_name": "Phishing for Information",
        "phase": "Reconnaissance",
        "description": (
            "Adversaries create synthetic media (video/audio) to impersonate trusted individuals "
            "and extract sensitive information or authorise fraudulent actions."
        ),
        "mitigations": [
            "Implement secondary authentication channels for sensitive requests.",
            "Deploy deepfake detection at media ingest points.",
            "Train staff to verify video call identities through alternative means.",
        ],
    },
    "prompt_injection": {
        "tactic_id": "T1059",
        "tactic_name": "Command and Scripting Interpreter",
        "phase": "Execution",
        "description": (
            "Adversaries inject malicious instructions into AI/LLM prompts to hijack "
            "model behaviour, bypass guardrails, or exfiltrate data."
        ),
        "mitigations": [
            "Sanitise all user-supplied input to LLM systems.",
            "Implement prompt injection guardrails.",
            "Apply least-privilege to AI agent capabilities.",
        ],
    },
    "behaviour_anomaly": {
        "tactic_id": "T1078",
        "tactic_name": "Valid Accounts",
        "phase": "Defense Evasion",
        "description": (
            "Adversaries use stolen or compromised credentials to access systems, "
            "evading detection by appearing as legitimate users."
        ),
        "mitigations": [
            "Enforce multi-factor authentication on all accounts.",
            "Monitor for impossible travel and unusual login times.",
            "Implement UEBA (User Entity Behaviour Analytics).",
        ],
    },
    "ai_generated": {
        "tactic_id": "T1585",
        "tactic_name": "Establish Accounts",
        "phase": "Resource Development",
        "description": (
            "Adversaries create AI-generated content (text, profiles, reviews) "
            "to build credibility for social engineering campaigns at scale."
        ),
        "mitigations": [
            "Deploy AI-content detectors at content ingestion points.",
            "Flag accounts with AI-generated profile content for review.",
            "Apply rate limiting to bulk content submissions.",
        ],
    },
    "unknown": {
        "tactic_id": "T0000",
        "tactic_name": "Unknown Technique",
        "phase": "Unknown",
        "description": "Threat type could not be classified into a known ATT&CK category.",
        "mitigations": ["Escalate to security analyst for manual review."],
    },
}


class MITREMapper:
    def get_mapping(self, threat_type: str) -> dict:
        return MITRE_MAP.get(threat_type, MITRE_MAP["unknown"])

    def all_tactics(self) -> list[dict]:
        return [
            {"key": k, **v}
            for k, v in MITRE_MAP.items()
            if k != "unknown"
        ]


mitre_mapper = MITREMapper()
