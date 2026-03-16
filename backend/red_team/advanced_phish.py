"""
SentinelAI - Advanced Phishing Simulator
Crafts complex spear-phishing templates for red-team drills.
"""
class AdvancedPhishSimulator:
    def generate_template(self, target_brand: str, urgent: bool = True) -> str:
        urgency = "immediately" if urgent else "at your convenience"
        return f"Dear user, your {target_brand} account has been flagged. Please verify {urgency}."
