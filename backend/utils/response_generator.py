"""
SentinelAI - Response Generator
Generates specific recommended actions based on score and threat type.
"""

def get_recommendation(score: int, input_type: str = "url") -> str:
    """
    Generate a specific recommended action based on score and input type.
    """
    if input_type in ("url", "url_malicious"):
        if score >= 81:
            return ("BLOCK this URL immediately. Do not navigate to it. "
                    "Report to IT and add to firewall blocklist. "
                    "If already visited, run endpoint AV scan immediately.")
        elif score >= 61:
            return ("Do NOT click this link. Mark the email or message as spam. "
                    "Be cautious of any downloads from this domain.")
        elif score >= 41:
            return ("Wait before proceeding. This URL has suspicious characteristics. "
                    "Verify the source through a separate trusted channel.")
        else:
            return "No immediate action required. Monitor for unusual activity."
    
    elif input_type in ("phishing", "nlp"):
        if score >= 81:
            return ("DO NOT respond or click any links. This is a high-confidence phishing attempt. "
                    "Delete the message and alert your security team.")
        elif score >= 61:
            return ("Possible phishing attempt. Check the sender's email address closely. "
                    "Do not provide any credentials or sensitive info.")
        else:
            return "Treat with normal caution. Be skeptical of unsolicited requests."

    elif input_type == "deepfake":
        if score >= 81:
            return ("CRITICAL: This media shows clear signs of AI manipulation. "
                    "Do not use this for identity verification. Flag as deepfake.")
        else:
            return "Potential AI-generated artifacts. Review carefully before trusting."

    elif input_type == "behaviour_anomaly":
        if score >= 81:
            return ("ACCOUNT LOCKDOWN recommended. Unusual activity detected. "
                    "Reset credentials and review recent access logs.")
        else:
            return "Minor behavioral shift detected. Monitor for further anomalies."

    return "Proceed with caution. Follow standard security protocols."

class ResponseGenerator:
    def recommend(self, severity: str, threat_type: str, evidence: dict) -> str:
        # Map severity to a base score for the helper function
        sev_map = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 50, "LOW": 20}
        score = sev_map.get(severity, 0)
        return get_recommendation(score, threat_type)
