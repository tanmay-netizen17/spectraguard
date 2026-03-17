"""
SpectraGuard - Fusion Engine
Combines detector scores and context signals into a single sentinel_score.
"""

from typing import Dict, List, Any

class FusionEngine:
    def __init__(self):
        # Weights for each detector type
        self.weights = {
            "url": 0.5,
            "nlp": 0.4,
            "deepfake": 0.6,
            "anomaly": 0.5,
            "aigen": 0.3
        }

    def compute(self, detector_results: Dict[str, Any], context_signals: Dict[str, bool]) -> Dict[str, Any]:
        """
        Merge detector results and context signals.
        """
        scores = []
        detectors_triggered = []

        for name, result in detector_results.items():
            score = result.get("score", 0)
            if score > 0.1:
                weight = self.weights.get(name, 0.4)
                scores.append(score * weight)
                detectors_triggered.append(name)

        if not scores:
            final_score = 0
        else:
            # Weighted average of active detectors
            sum_weights = sum(self.weights.get(n, 0.4) for n in detectors_triggered)
            final_score = (sum(scores) / sum_weights) * 100 if sum_weights > 0 else 0

        # Coordination Multiplier
        multiplier = 1.0
        if len(detectors_triggered) >= 2:
            multiplier = 1.15
        if len(detectors_triggered) >= 3:
            multiplier = 1.3
        
        final_score *= multiplier

        # Context Modifiers
        modifier_total = 0
        context_modifiers = []

        if context_signals.get("domain_age_new"):
            modifier_total += 10
            context_modifiers.append("new_domain")
        
        if context_signals.get("spf_dkim_fail"):
            modifier_total += 15
            context_modifiers.append("auth_failure")

        if context_signals.get("digit_substitution"):
            modifier_total += 8
            context_modifiers.append("digit_substitution")

        if context_signals.get("after_hours"):
            modifier_total += 5
            context_modifiers.append("out_of_hours")

        final_score += modifier_total
        final_score = min(100.0, max(0.0, final_score))

        # Severity mapping
        severity = "LOW"
        if final_score >= 80:
            severity = "CRITICAL"
        elif final_score >= 60:
            severity = "HIGH"
        elif final_score >= 40:
            severity = "MEDIUM"

        return {
            "sentinel_score": round(float(final_score), 2),
            "severity": severity,
            "detectors_triggered": detectors_triggered,
            "coordination_multiplier": multiplier,
            "context_modifiers": context_modifiers,
            "context_modifier_total": modifier_total
        }
