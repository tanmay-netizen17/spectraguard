"""
SpectraGuard - NLP Detector
Handles:
  1. Phishing / spear-phishing email detection
  2. Prompt injection detection
  3. AI-generated content detection

Uses a RoBERTa-based transformer model or custom Random Forest classifier.
"""

from __future__ import annotations
import re
import math
import os
from typing import Optional

# Try to load transformer model; gracefully degrade to heuristic if unavailable
try:
    from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

# -- Suspicious token registry ──────────────────────────────────────────────────
PHISHING_TOKENS = {
    "urgent", "immediately", "suspended", "verify", "account", "password",
    "click here", "confirm", "unusual activity", "security alert", "login",
    "unauthorized", "expire", "limited time", "act now", "prize", "won",
    "congratulations", "update your", "required action", "dear customer",
    "validate", "authenticate", "credentials", "billing", "invoice overdue",
}

PROMPT_INJECTION_TOKENS = {
    "ignore previous", "ignore all", "disregard", "forget instructions",
    "new instructions", "system:", "as an ai", "pretend you are",
    "act as", "roleplay", "override", "jailbreak", "bypass", "do anything",
    "dan mode", "developer mode", "simulate", "hypothetically",
}

AI_GENERATED_MARKERS = {
    "it is important to note", "in conclusion", "furthermore", "moreover",
    "it is worth noting", "in summary", "as an ai language model",
    "as a large language model", "certainly", "absolutely, here",
    "of course, i", "i hope this helps", "feel free to ask",
    "in this essay", "to summarize", "overall, it",
}


class NLPDetector:
    """
    Multi-head NLP classifier for phishing, prompt injection, and AI-generated content.
    """

    def __init__(self):
        self.model = None
        self.email_clf = None
        self.email_vec = None
        self._try_load_model()

    def _try_load_model(self):
        """Attempt to load models."""
        # Load custom trained model
        if JOBLIB_AVAILABLE:
            try:
                model_dir = os.path.join(os.path.dirname(__file__), "..", "models")
                clf_path = os.path.join(model_dir, "email_classifier.joblib")
                vec_path = os.path.join(model_dir, "email_vectorizer.joblib")
                
                if os.path.exists(clf_path) and os.path.exists(vec_path):
                    self.email_clf = joblib.load(clf_path)
                    self.email_vec = joblib.load(vec_path)
            except Exception:
                pass

        # Load transformer as secondary/fallback
        if TRANSFORMERS_AVAILABLE:
            try:
                self.model = pipeline(
                    "text-classification",
                    model="mrm8488/bert-tiny-finetuned-sms-spam-detection",
                    truncation=True,
                    max_length=512,
                )
            except Exception:
                self.model = None

    async def analyse(self, text: str) -> dict:
        """Full phishing + prompt-injection analysis."""
        phishing_score = await self._phishing_score(text)
        prompt_injection_score = self._prompt_injection_score(text)
        top_tokens = self._extract_top_tokens(text)

        combined = max(phishing_score, prompt_injection_score)

        return {
            "score": round(float(combined), 4),
            "phishing_score": round(float(phishing_score), 4),
            "prompt_injection_score": round(float(prompt_injection_score), 4),
            "top_tokens": top_tokens,
            "model_used": "email-rf" if self.email_clf else "bert-tiny" if self.model else "heuristic",
            "char_count": len(text),
            "word_count": len(text.split()),
        }

    async def _phishing_score(self, text: str) -> float:
        heuristic = self._token_match_score(text.lower(), PHISHING_TOKENS)
        model_score = 0.0

        if self.email_clf and self.email_vec:
            try:
                X = self.email_vec.transform([text])
                model_score = float(self.email_clf.predict_proba(X)[0][1])
            except Exception:
                pass
        elif self.model:
            try:
                result = self.model(text[:512])[0]
                model_score = result["score"] if result["label"].upper() in ("SPAM", "LABEL_1") else 1 - result["score"]
            except Exception:
                pass

        if self.email_clf or self.model:
            return 0.7 * model_score + 0.3 * heuristic
        return heuristic

    def _prompt_injection_score(self, text: str) -> float:
        return self._token_match_score(text.lower(), PROMPT_INJECTION_TOKENS)

    async def detect_ai_generated(self, text: str) -> dict:
        score = self._ai_generated_score(text)
        return {
            "score": round(score, 4),
            "perplexity_estimate": round(self._estimate_perplexity(text), 2),
            "ai_markers_found": self._find_ai_markers(text),
            "model_used": "heuristic-stylometric",
        }

    def _ai_generated_score(self, text: str) -> float:
        marker_score = self._token_match_score(text.lower(), AI_GENERATED_MARKERS)
        style_score = self._stylometric_score(text)
        return min(1.0, 0.6 * marker_score + 0.4 * style_score)

    @staticmethod
    def _token_match_score(text: str, token_set: set) -> float:
        hits = sum(1 for token in token_set if token in text)
        return min(1.0, hits / 5.0)

    @staticmethod
    def _extract_top_tokens(text: str) -> list[str]:
        lower = text.lower()
        found = [t for t in PHISHING_TOKENS if t in lower]
        found += [t for t in PROMPT_INJECTION_TOKENS if t in lower]
        return found[:5]

    @staticmethod
    def _stylometric_score(text: str) -> float:
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if len(s.strip()) > 5]
        if len(sentences) < 3: return 0.0
        lengths = [len(s.split()) for s in sentences]
        mean = sum(lengths) / len(lengths)
        variance = sum((l - mean)**2 for l in lengths) / len(lengths)
        uniformity_score = 1.0 / (1.0 + math.sqrt(variance + 1))
        words = text.lower().split()
        if not words: return 0.0
        unique_ratio = len(set(words)) / len(words)
        ttr_score = max(0.0, 0.6 - unique_ratio) / 0.6
        return min(1.0, (uniformity_score + ttr_score) / 2)

    @staticmethod
    def _estimate_perplexity(text: str) -> float:
        from collections import Counter
        chars = list(text.lower())
        if len(chars) < 10: return 0.0
        freq = Counter(chars)
        n = len(chars)
        entropy = -sum((c / n) * math.log2(c / n) for c in freq.values())
        return round(entropy, 3)

    @staticmethod
    def _find_ai_markers(text: str) -> list[str]:
        lower = text.lower()
        return [m for m in AI_GENERATED_MARKERS if m in lower][:5]
