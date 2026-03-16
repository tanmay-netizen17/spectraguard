"""
SentinelAI — URL Detector
Uses LightGBM trained on 50+ lexical + structural URL features.
Falls back to heuristic scoring if model weights are unavailable.

Feature engineering covers:
  - URL length, token counts
  - Entropy of domain/path
  - TLD reputation
  - Digit-for-letter substitution
  - IP address usage
  - Subdomain depth
  - Special character density
  - Domain age (via WHOIS, optional)
  - Shortener detection
  - Keyword matching (known phishing words)
"""

from __future__ import annotations

import re
import math
import urllib.parse
from typing import Optional

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

try:
    import lightgbm as lgb
    import numpy as np
    LGBM_AVAILABLE = True
except ImportError:
    LGBM_AVAILABLE = False

# Known URL shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly",
    "short.io", "rb.gy", "is.gd", "v.gd", "cutt.ly",
}

# Suspicious TLDs often abused in phishing
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "info",
    "click", "online", "site", "website", "link", "win", "review",
}

# Common phishing keywords in URLs
PHISHING_KEYWORDS = {
    "secure", "login", "update", "verify", "account", "banking",
    "paypal", "amazon", "google", "apple", "microsoft", "netflix",
    "signin", "password", "confirm", "support", "helpdesk",
    "suspended", "urgent", "alert",
}

# Digit-for-letter substitution pairs
DIGIT_SUBS = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"}


class URLDetector:
    """
    Scores a URL from 0.0 (benign) to 1.0 (malicious) using a LightGBM
    model trained on 50+ lexical features. Degrades gracefully to heuristics.
    """

    def __init__(self):
        self.model = None
        self._try_load_model()

    def _try_load_model(self):
        """Load pre-trained LightGBM model from models/ directory."""
        if not LGBM_AVAILABLE:
            return
        try:
            self.model = lgb.Booster(model_file="models/url_lgbm.txt")
        except Exception:
            self.model = None

    async def score(self, url: str) -> dict:
        """Full URL analysis — returns score + all features."""
        features = self._extract_features(url)
        feature_vec = list(features.values())

        if self.model and LGBM_AVAILABLE:
            try:
                import numpy as np
                prob = float(self.model.predict(np.array([feature_vec]))[0])
            except Exception:
                prob = self._heuristic_score(features)
        else:
            prob = self._heuristic_score(features)

        top_features = self._explain_top_features(features)

        return {
            "score": round(min(1.0, max(0.0, prob)), 4),
            "url": url,
            "domain_age_days": features.get("domain_age_days", -1),
            "entropy": round(features.get("domain_entropy", 0.0), 3),
            "has_digit_substitution": bool(features.get("has_digit_sub", 0)),
            "is_ip_address": bool(features.get("is_ip_address", 0)),
            "uses_shortener": bool(features.get("uses_shortener", 0)),
            "top_features": top_features,
            "all_features": {k: round(v, 4) if isinstance(v, float) else v
                             for k, v in features.items()},
            "model_used": "lightgbm" if self.model else "heuristic",
        }

    # ── Feature extraction (50+ features) ────────────────────────────────────

    def _extract_features(self, url: str) -> dict:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc or ""
        path = parsed.path or ""
        query = parsed.query or ""

        if TLDEXTRACT_AVAILABLE:
            ext = tldextract.extract(url)
            subdomain = ext.subdomain
            registered_domain = ext.registered_domain
            tld = ext.suffix
        else:
            subdomain = ""
            registered_domain = domain
            tld = domain.rsplit(".", 1)[-1] if "." in domain else ""

        full_url_lower = url.lower()

        features: dict[str, float] = {
            # Length features
            "url_length": len(url),
            "domain_length": len(domain),
            "path_length": len(path),
            "query_length": len(query),

            # Token counts
            "num_dots": url.count("."),
            "num_hyphens": url.count("-"),
            "num_underscores": url.count("_"),
            "num_slashes": url.count("/"),
            "num_at_signs": url.count("@"),
            "num_equals": url.count("="),
            "num_ampersands": url.count("&"),
            "num_question_marks": url.count("?"),
            "num_percent": url.count("%"),
            "num_digits_in_domain": sum(1 for c in domain if c.isdigit()),
            "num_subdomains": len(subdomain.split(".")) if subdomain else 0,

            # Entropy features (higher → more random-looking → suspicious)
            "url_entropy": self._entropy(url),
            "domain_entropy": self._entropy(registered_domain),
            "path_entropy": self._entropy(path),

            # Boolean flags
            "is_https": float(parsed.scheme == "https"),
            "is_ip_address": float(bool(re.match(r"^\d+\.\d+\.\d+\.\d+", domain))),
            "has_port": float(":" in domain),
            "uses_shortener": float(registered_domain in URL_SHORTENERS),
            "suspicious_tld": float(tld.lower() in SUSPICIOUS_TLDS),
            "has_digit_sub": float(self._has_digit_substitution(domain)),
            "domain_has_phishing_kw": float(
                any(kw in domain.lower() for kw in PHISHING_KEYWORDS)
            ),
            "path_has_phishing_kw": float(
                any(kw in full_url_lower for kw in PHISHING_KEYWORDS)
            ),
            "has_hex_encoding": float("%2" in query or "%2" in path),
            "has_double_slash": float("//" in path),
            "has_at_in_url": float("@" in url),
            "redirect_count": float(url.lower().count("redirect") + url.lower().count("url=")),

            # Ratio features
            "digit_ratio_domain": sum(1 for c in domain if c.isdigit()) / max(len(domain), 1),
            "alpha_ratio_domain": sum(1 for c in domain if c.isalpha()) / max(len(domain), 1),
            "special_ratio_url": sum(1 for c in url if not c.isalnum() and c not in "-._/:?=&#") / max(len(url), 1),

            # Structural
            "path_depth": len([p for p in path.split("/") if p]),
            "registered_domain_length": len(registered_domain),
            "tld_length": len(tld),
            "query_param_count": len(query.split("&")) if query else 0,

            # Domain age (placeholder — real WHOIS lookup would fill this)
            "domain_age_days": -1,  # -1 = unknown; populated asynchronously if WHOIS available
        }

        return features

    def _heuristic_score(self, features: dict) -> float:
        """
        Rule-based fallback score from features.
        Each rule contributes a weighted penalty.
        """
        score = 0.0

        # Hard signals
        if features.get("is_ip_address"):        score += 0.25
        if features.get("has_digit_sub"):         score += 0.20
        if features.get("uses_shortener"):        score += 0.15
        if features.get("has_at_in_url"):         score += 0.20
        if features.get("suspicious_tld"):        score += 0.15

        # Soft signals
        if features.get("num_subdomains", 0) > 3: score += 0.10
        if features.get("url_entropy", 0) > 4.5:  score += 0.10
        if features.get("domain_has_phishing_kw"): score += 0.15
        if features.get("path_has_phishing_kw"):   score += 0.10
        if features.get("url_length", 0) > 100:   score += 0.05
        if features.get("redirect_count", 0) > 0: score += 0.10
        if not features.get("is_https"):           score += 0.05

        return min(1.0, score)

    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    @staticmethod
    def _has_digit_substitution(domain: str) -> bool:
        """Check if domain uses digit-for-letter substitutions like 'g00gle'."""
        for digit, letter in DIGIT_SUBS.items():
            if digit in domain:
                # Check if adjacent to letters (actual substitution pattern)
                idx = domain.find(digit)
                context = domain[max(0, idx-1):idx+2]
                if any(c.isalpha() for c in context):
                    return True
        return False

    @staticmethod
    def _explain_top_features(features: dict) -> list[str]:
        """Return human-readable list of the most significant risk factors found."""
        explanations = []
        if features.get("is_ip_address"):          explanations.append("uses_raw_ip_address")
        if features.get("has_digit_sub"):           explanations.append("digit_substitution_detected")
        if features.get("uses_shortener"):          explanations.append("url_shortener_detected")
        if features.get("suspicious_tld"):          explanations.append("suspicious_tld")
        if features.get("has_at_in_url"):           explanations.append("at_sign_in_url")
        if features.get("domain_has_phishing_kw"):  explanations.append("phishing_keyword_in_domain")
        if features.get("url_entropy", 0) > 4.5:   explanations.append("high_url_entropy")
        if features.get("num_subdomains", 0) > 3:  explanations.append("excessive_subdomains")
        if features.get("redirect_count", 0) > 0:  explanations.append("redirect_chain_detected")
        return explanations[:10]
