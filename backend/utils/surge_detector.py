"""
SpectraGuard - Surge Detector
Identifies sudden spikes in threat activity across the network.
"""
from datetime import datetime, timedelta

class SurgeDetector:
    def __init__(self):
        self.history = []

    def report_threat(self, score: float):
        if score > 70:
            self.history.append(datetime.now())
        self._cleanup()

    def is_surge_active(self) -> bool:
        self._cleanup()
        # Case: More than 5 high-threat events in the last 60 seconds
        return len(self.history) > 5

    def _cleanup(self):
        cutoff = datetime.now() - timedelta(seconds=60)
        self.history = [t for t in self.history if t > cutoff]
