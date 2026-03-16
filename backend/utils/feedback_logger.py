"""
SentinelAI - Feedback Logger
Collects user feedback on detection accuracy for future retraining.
"""
import json
from datetime import datetime

class FeedbackLogger:
    def __init__(self):
        self.feedback_file = "user_feedback.json"

    def log_feedback(self, incident_id: str, is_correct: bool, comments: str = ""):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "incident_id": incident_id,
            "is_correct": is_correct,
            "comments": comments
        }
        try:
            with open(self.feedback_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass
