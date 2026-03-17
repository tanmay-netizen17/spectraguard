"""
SpectraGuard - Audit Logger
Records all security-relevant events for compliance.
"""
import json
import os
from datetime import datetime, timezone

class AuditLogger:
    def __init__(self):
        self.log_file = "audit_log.json"

    def log_event(self, event_type: str, details: dict):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "details": details
        }
        # In a real app, this would write to a secure database or syslog
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception:
            pass
