"""
SpectraGuard - XAI Synthesiser
Generates human-readable evidence and threat briefs.
"""
from typing import Dict, Any, List

class XAISynthesiser:
    def __init__(self):
        self.brief_templates = {
            "CRITICAL": "SpectraGuard has blocked this activity. {summary}",
            "HIGH": "High risk detected. {summary}",
            "MEDIUM": "Suspicious activity flagged. {summary}",
            "LOW": "Activity verified for normal patterns."
        }

    def extract_evidence(self, detector_name: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key features that led to the score."""
        evidence = {"score": result.get("score", 0)}
        
        if detector_name == "url":
            evidence["reason"] = f"Malicious patterns found in URL. Risk: {result.get('risk_category', 'general')}"
            evidence["features"] = result.get("top_features", [])
        elif detector_name == "nlp":
            evidence["reason"] = "Text contains phishing or malicious intent markers."
            evidence["highlights"] = result.get("top_tokens", [])
        elif detector_name == "deepfake":
            evidence["reason"] = "AI-generated artifacts detected in media content."
            evidence["details"] = result.get("findings", [])
        elif detector_name == "anomaly":
            evidence["reason"] = "User behavior inconsistent with historical baseline."
            evidence["anomalies"] = result.get("anomalous_fields", [])
            
        return evidence

    async def generate_brief(self, evidence: Dict[str, Any], score: float, severity: str) -> str:
        """Create a human-readable summary of the threat."""
        if not evidence:
            return "No immediate threats detected."

        reasons = [e.get("reason", "") for e in evidence.values() if e.get("reason")]
        summary = " ".join(reasons)
        
        template = self.brief_templates.get(severity, "{summary}")
        return template.format(summary=summary)
