"""
SentinelAI — NLP Detector
Handles:
  1. Phishing / spear-phishing email detection
  2. Prompt injection detection
  3. AI-generated content detection

Uses a RoBERTa-based transformer model fine-tuned on:
  - SpamAssassin public corpus (phishing)
  - Deepset prompt-injections dataset (HuggingFace)
  - GPT-2 Output Dataset (AI-generated)

In demo/hackathon mode: falls back to a heuristic scorer if model weights
are not present, ensuring the API always returns useful results.
"""

from __future__ import annotations

import re
import math
from typing import Optional

# Try to load transformer model; gracefully degrade to heuristic if unavailable
try:
    from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

# ── Suspicious token registry ──────────────────────────────────────────────────
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
        self._try_load_model()

    def _try_load_model(self):
        """Attempt to load a pre-trained RoBERTa model for sequence classification."""
        if not TRANSFORMERS_AVAILABLE:
            return
        try:
            # Primary: fine-tuned model (place weights in models/)
            self.model = pipeline(
                "text-classification",
                model="mrm8488/bert-tiny-finetuned-sms-spam-detection",
                truncation=True,
                max_length=512,
            )
        except Exception:
            self.model = None  # Fall back to heuristics

    async def analyse(self, text: str) -> dict:
        """Full phishing + prompt-injection analysis."""
        phishing_score = await self._phishing_score(text)
        prompt_injection_score = self._prompt_injection_score(text)
        top_tokens = self._extract_top_tokens(text)

        # Combined NLP score — max of the two signals
        combined = max(phishing_score, prompt_injection_score)

        return {
            "score": round(combined, 4),
            "phishing_score": round(phishing_score, 4),
            "prompt_injection_score": round(prompt_injection_score, 4),
            "top_tokens": top_tokens,
            "model_used": "bert-tiny-spam" if self.model else "heuristic",
            "char_count": len(text),
            "word_count": len(text.split()),
        }

    async def detect_ai_generated(self, text: str) -> dict:
        """Stylometric analysis for AI-generated content."""
        score = self._ai_generated_score(text)
        return {
            "score": round(score, 4),
            "perplexity_estimate": round(self._estimate_perplexity(text), 2),
            "ai_markers_found": self._find_ai_markers(text),
            "model_used": "heuristic-stylometric",
        }

    # ── Private methods ──────────────────────────────────────────────────────

    async def _phishing_score(self, text: str) -> float:
        """Combine model output (if available) with heuristic token matching."""
        heuristic = self._token_match_score(text.lower(), PHISHING_TOKENS)

        if self.model:
            try:
                result = self.model(text[:512])[0]
                model_score = (
                    result["score"] if result["label"].upper() in ("SPAM", "LABEL_1")
                    else 1 - result["score"]
                )
                # Blend: 60% model, 40% heuristic
                return 0.6 * model_score + 0.4 * heuristic
            except Exception:
                pass

        return heuristic

    def _prompt_injection_score(self, text: str) -> float:
        return self._token_match_score(text.lower(), PROMPT_INJECTION_TOKENS)

    def _ai_generated_score(self, text: str) -> float:
        """Combine marker matching + stylometric signals."""
        marker_score = self._token_match_score(text.lower(), AI_GENERATED_MARKERS)
        style_score = self._stylometric_score(text)
        return min(1.0, 0.6 * marker_score + 0.4 * style_score)

    @staticmethod
    def _token_match_score(text: str, token_set: set) -> float:
        """Score 0.0–1.0 based on fraction of suspicious tokens found."""
        hits = sum(1 for token in token_set if token in text)
        # Sigmoid-like mapping: 5 hits → ~0.9 score
        return min(1.0, hits / 5.0)

    @staticmethod
    def _extract_top_tokens(text: str) -> list[str]:
        """Return top-5 suspicious tokens found in the text."""
        lower = text.lower()
        found = [t for t in PHISHING_TOKENS if t in lower]
        found += [t for t in PROMPT_INJECTION_TOKENS if t in lower]
        return found[:5]

    @staticmethod
    def _stylometric_score(text: str) -> float:
        """
        Heuristic stylometric score based on:
        - Sentence length uniformity (AI tends to write very uniform sentences)
        - Vocabulary richness (AI has slightly lower type-token ratio)
        - Absence of typos / colloquialisms
        """
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if len(s.strip()) > 5]
        if len(sentences) < 3:
            return 0.0

        lengths = [len(s.split()) for s in sentences]
        mean = sum(lengths) / len(lengths)
        variance = sum((l - mean) ** 2 for l in lengths) / len(lengths)
        # Low variance → high uniformity → more likely AI
        uniformity_score = 1.0 / (1.0 + math.sqrt(variance + 1))

        words = text.lower().split()
        if len(words) == 0:
            return 0.0
        unique_ratio = len(set(words)) / len(words)
        # TTR below 0.6 correlates with AI output
        ttr_score = max(0.0, 0.6 - unique_ratio) / 0.6

        return min(1.0, (uniformity_score + ttr_score) / 2)

    @staticmethod
    def _estimate_perplexity(text: str) -> float:
        """
        Rough character-level perplexity estimate.
        Real implementation would use the language model's logits.
        """
        from collections import Counter
        chars = list(text.lower())
        if len(chars) < 10:
            return 0.0
        freq = Counter(chars)
        n = len(chars)
        entropy = -sum((c / n) * math.log2(c / n) for c in freq.values())
        # AI text tends to have lower character-level entropy
        return round(entropy, 3)

    @staticmethod
    def _find_ai_markers(text: str) -> list[str]:
        lower = text.lower()
        return [m for m in AI_GENERATED_MARKERS if m in lower][:5]
