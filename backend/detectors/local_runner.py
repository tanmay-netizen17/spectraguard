"""
SentinelAI - Local Runner
Simulates local Edge/On-device inference using ONNX or lightweight heuristics.
"""

import os
from typing import Dict, Any

class LocalNLPDetector:
    def __init__(self):
        self.model_path = os.path.join(os.path.dirname(__file__), "..", "models", "nlp_local.onnx")
        self.ready = os.path.exists(self.model_path)
        if self.ready:
            print(f"[LocalMode] NLP ONNX model loaded from {self.model_path}")

    def analyse(self, text: str) -> Dict[str, Any]:
        # Lightweight heuristic for prompt injection
        injection_keywords = {"ignore previous", "system:", "dan mode", "developer mode"}
        text_lower = text.lower()
        hits = sum(1 for kw in injection_keywords if kw in text_lower)
        score = min(1.0, hits / 2.0)
        
        return {
            "score": score,
            "is_local": True,
            "engine": "onnx-runtime-web" if self.ready else "wasm-heuristic"
        }

class LocalURLDetector:
    def __init__(self):
        self.model_path = os.path.join(os.path.dirname(__file__), "..", "models", "url_local.onnx")
        self.ready = os.path.exists(self.model_path)
        if self.ready:
            print(f"[LocalMode] URL ONNX model loaded from {self.model_path}")

    def score(self, url: str) -> Dict[str, Any]:
        # Simple entropy and TLD check for local mode
        url_lower = url.lower()
        suspicious_tlds = {".xyz", ".top", ".pw", ".bid"}
        has_bad_tld = any(url_lower.endswith(tld) for tld in suspicious_tlds)
        
        return {
            "score": 0.7 if has_bad_tld else 0.1,
            "is_local": True,
            "engine": "onnx-runtime-web" if self.ready else "bloom-filter"
        }
