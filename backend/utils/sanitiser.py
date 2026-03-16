"""
SentinelAI - Sanitiser
Strips PII and malicious scripts from payloads before analysis.
"""
import re

class Sanitiser:
    def clean_text(self, text: str) -> str:
        if not text: return ""
        # Remove common PII patterns (simple regex for demo)
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN_REDACTED]', text)
        # Remove script tags
        text = re.sub(r'<script.*?>.*?</script>', '[SCRIPT_REMOVED]', text, flags=re.DOTALL)
        return text

    def clean_url(self, url: str) -> str:
        # Remove auth info from URL
        return re.sub(r'://.*?@', '://', url)
