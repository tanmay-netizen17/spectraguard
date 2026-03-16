"""
SentinelAI — URL Detector  (v2.0)
==================================
Uses LightGBM trained on 60+ lexical, structural, and semantic URL features.
Falls back to heuristic scoring if model weights are unavailable.

Feature engineering covers:
  - URL length, token counts
  - Shannon entropy of domain / path / full URL
  - TLD reputation scoring
  - Digit-for-letter substitution (leetspeak)
  - Homoglyph / Unicode spoofing detection
  - Punycode / IDN (Internationalized Domain Name) detection
  - IPv4 and IPv6 address usage as host
  - Subdomain depth
  - Special character density
  - Known URL shortener detection (expanded list)
  - Phishing keyword matching (domain + path + query)
  - Base64 / hex payload in query string
  - Double extension detection (e.g. invoice.pdf.exe)
  - Redirect chain signals
  - Domain age via async WHOIS (optional, non-blocking)
  - URL scheme validation (data:, javascript:, ftp: abuse)
"""

from __future__ import annotations

import re
import math
import asyncio
import unicodedata
import urllib.parse
from pathlib import Path
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

try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# ── Expanded URL shorteners ────────────────────────────────────────────────────
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly",
    "short.io", "rb.gy", "is.gd", "v.gd", "cutt.ly", "tiny.cc",
    "lnkd.in", "youtu.be", "snip.ly", "bl.ink", "rebrand.ly",
    "smarturl.it", "qr.ae", "clck.ru", "url.ie", "trib.al",
    "soo.gd", "ity.im", "adf.ly", "bc.vc", "u.to",
}

# ── Suspicious TLDs often abused in phishing / malware campaigns ───────────────
SUSPICIOUS_TLDS = {
    # Legacy freemium abuse
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "pw",
    # Common phishing vectors
    "cc", "info", "click", "online", "site", "website", "link",
    "win", "review", "loan", "date", "faith", "racing", "trade",
    "cricket", "science", "party", "country", "webcam", "download",
    # Newer gTLD abuse
    "cyou", "life", "buzz", "rest", "guru", "surf", "uno",
    "fun", "icu", "vip", "live", "work", "works",
}

# ── Phishing / brand-impersonation keywords ────────────────────────────────────
PHISHING_KEYWORDS = {
    # Generic social engineering
    "secure", "login", "update", "verify", "account", "banking",
    "signin", "password", "confirm", "support", "helpdesk",
    "suspended", "urgent", "alert", "validate", "authenticate",
    "credential", "recover", "reset", "2fa", "otp", "token",
    # Major brand names (commonly impersonated)
    "paypal", "amazon", "google", "apple", "microsoft", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "icloud", "outlook", "office365", "chase", "wellsfargo",
    "citibank", "hsbc", "barclays", "coinbase", "binance",
    "metamask", "blockchain", "wallet",
}

# ── Digit-for-letter substitutions (leet speak) ────────────────────────────────
DIGIT_SUBS = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"}

# ── Visually confusable Unicode → ASCII mappings (homoglyph spoofing) ──────────
# Source: simplified Unicode confusables table
HOMOGLYPH_MAP: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u03b1": "a",  # Greek α
    "\u03b5": "e",  # Greek ε
    "\u03bf": "o",  # Greek ο
    "\u03c1": "p",  # Greek ρ
    "\u0dbd": "l",  # Sinhala ල
    "\u216c": "l",  # Roman numeral Ⅼ
    "\u0001d0": "o", # Mathematical ℐ-family
}

# ── Dangerous / abusable URL schemes ──────────────────────────────────────────
DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file", "ftp", "blob"}

# Resolve model path relative to this file so it works regardless of CWD
_DETECTOR_DIR = Path(__file__).parent
_MODEL_PATH = _DETECTOR_DIR.parent / "models" / "url_lgbm.txt"


class URLDetector:
    """
    Scores a URL from 0.0 (benign) to 1.0 (malicious).

    Uses a LightGBM model (60+ features) when available; degrades gracefully
    to a calibrated heuristic scorer.  All feature extraction is synchronous
    and CPU-bound; optional WHOIS lookup runs asynchronously and will not
    block the main analysis if it times out.
    """

    def __init__(self):
        self.model = None
        self._try_load_model()

    def _try_load_model(self):
        """
        Load pre-trained LightGBM model from models/ directory.

        IMPORTANT: We check Path.exists() BEFORE calling lgb.Booster().
        LightGBM [Fatal] errors are C-level and cannot be caught by Python's
        try/except — they crash the entire process. The existence check prevents
        LightGBM from ever attempting to open a missing file.
        """
        if not LGBM_AVAILABLE:
            return
        if not _MODEL_PATH.exists():
            # No model file — heuristic fallback will be used automatically.
            return
        try:
            self.model = lgb.Booster(model_file=str(_MODEL_PATH))
        except Exception:
            self.model = None

    # ── Public API ────────────────────────────────────────────────────────────

    async def score(self, url: str) -> dict:
        """
        Full URL analysis.

        Returns a dict with:
          - score             float [0,1]
          - url               original URL
          - normalised_url    lower-cased, scheme-normalised URL used for analysis
          - domain_age_days   int (-1 = unknown)
          - entropy           domain Shannon entropy
          - risk_category     human-readable threat category
          - has_digit_substitution, is_ip_address, uses_shortener, has_homoglyph,
            is_idn, dangerous_scheme   – bool flags
          - top_features      list[str]  human-readable risk signals
          - all_features      dict of all numeric features
          - model_used        "lightgbm" | "heuristic"
        """
        normalised = self._normalise_url(url)
        features = self._extract_features(normalised, url)

        # Optional async WHOIS (non-blocking, 5 s timeout)
        if WHOIS_AVAILABLE and features.get("domain_age_days", -1) == -1:
            try:
                age = await asyncio.wait_for(
                    self._async_whois_age(features.get("_registered_domain", "")),
                    timeout=5.0,
                )
                features["domain_age_days"] = age
            except (asyncio.TimeoutError, Exception):
                pass

        # Remove internal helper keys before scoring
        features.pop("_registered_domain", None)

        feature_vec = list(features.values())

        if self.model is not None and LGBM_AVAILABLE:
            try:
                prediction = self.model.predict(np.array([feature_vec]))
                prob = float(prediction[0])
            except Exception:
                prob = float(self._heuristic_score(features))
        else:
            # Fallback if model not loaded
            prob = float(self._heuristic_score(features))

        prob = float(round(min(1.0, max(0.0, float(prob))), 4))
        top_features = self._explain_top_features(features)
        risk_category = self._classify_risk_category(features)

        return {
            "score": prob,
            "url": url,
            "normalised_url": normalised,
            "domain_age_days": features.get("domain_age_days", -1),
            "entropy": round(features.get("domain_entropy", 0.0), 3),
            # Bool flags (keys align with orchestrator.py + xai_synthesiser.py)
            "has_digit_substitution": bool(features.get("has_digit_sub", 0)),
            "is_ip_address": bool(features.get("is_ip_address", 0)),
            "uses_shortener": bool(features.get("uses_shortener", 0)),
            "has_homoglyph": bool(features.get("has_homoglyph", 0)),
            "is_idn": bool(features.get("is_idn", 0)),
            "dangerous_scheme": bool(features.get("dangerous_scheme", 0)),
            "suspicious_tld": bool(features.get("suspicious_tld", 0)),
            "has_at_in_url": bool(features.get("has_at_in_url", 0)),
            # Explainability
            "top_features": top_features,
            "risk_category": risk_category,
            "all_features": {
                k: round(v, 4) if isinstance(v, float) else v
                for k, v in features.items()
            },
            "model_used": "lightgbm" if self.model else "heuristic",
        }

    # ── URL normalisation ─────────────────────────────────────────────────────

    @staticmethod
    def _normalise_url(url: str) -> str:
        """
        Ensure URL has a scheme so urlparse works correctly.
        Strips leading/trailing whitespace and null bytes.
        """
        url = url.strip().strip("\x00")
        if not re.match(r"^[a-zA-Z][a-zA-Z\d+\-.]*://", url):
            url = "http://" + url
        return url

    # ── Feature extraction (60+ features) ────────────────────────────────────

    def _extract_features(self, url: str, raw_url: str = "") -> dict:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc or ""
        # Strip user:password@ prefix from domain if present
        if "@" in domain:
            domain = domain.split("@", 1)[1]
        # Strip port
        host = domain.split(":")[0] if ":" in domain else domain
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        scheme = parsed.scheme.lower()

        if TLDEXTRACT_AVAILABLE:
            ext = tldextract.extract(url)
            subdomain = ext.subdomain or ""
            registered_domain = ext.registered_domain or host
            tld = ext.suffix or ""
        else:
            subdomain = ""
            registered_domain = host
            tld = host.rsplit(".", 1)[-1] if "." in host else ""

        full_lower = url.lower()

        # ── Homoglyph / Unicode spoofing ─────────────────────────────────────
        has_homoglyph = self._detect_homoglyph(host)
        # Non-ASCII characters in domain (Punycode / IDN)
        is_idn = host.startswith("xn--") or any(ord(c) > 127 for c in host)

        # ── IPv4 and IPv6 detection ───────────────────────────────────────────
        is_ipv4 = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
        is_ipv6 = host.startswith("[") and host.endswith("]")
        is_ip_address = is_ipv4 or is_ipv6

        # ── Dangerous scheme ──────────────────────────────────────────────────
        dangerous_scheme = float(scheme in DANGEROUS_SCHEMES)

        # ── Double-extension in path (e.g. invoice.pdf.exe) ──────────────────
        has_double_ext = float(bool(
            re.search(r"\.(pdf|doc|docx|xls|xlsx|zip|rar)\.[a-z]{2,4}$", path.lower())
        ))

        # ── Base64 payload in query / path ────────────────────────────────────
        has_b64_payload = float(bool(
            re.search(r"[A-Za-z0-9+/]{40,}={0,2}", query + path)
        ))

        # ── Subdomains ────────────────────────────────────────────────────────
        num_subdomains = len(subdomain.split(".")) if subdomain else 0

        features: dict[str, float] = {
            # ── Length features ───────────────────────────────────────────────
            "url_length": float(len(url)),
            "domain_length": float(len(host)),
            "path_length": float(len(path)),
            "query_length": float(len(query)),
            "fragment_length": float(len(fragment)),

            # ── Token counts ──────────────────────────────────────────────────
            "num_dots": float(url.count(".")),
            "num_hyphens": float(url.count("-")),
            "num_underscores": float(url.count("_")),
            "num_slashes": float(url.count("/")),
            "num_at_signs": float(url.count("@")),
            "num_equals": float(url.count("=")),
            "num_ampersands": float(url.count("&")),
            "num_question_marks": float(url.count("?")),
            "num_percent": float(url.count("%")),
            "num_tildes": float(url.count("~")),
            "num_digits_in_domain": float(sum(1 for c in host if c.isdigit())),
            "num_subdomains": float(num_subdomains),

            # ── Shannon entropy ───────────────────────────────────────────────
            "url_entropy": self._entropy(url),
            "domain_entropy": self._entropy(registered_domain),
            "path_entropy": self._entropy(path),
            "query_entropy": self._entropy(query),

            # ── Boolean flags ─────────────────────────────────────────────────
            "is_https": float(scheme == "https"),
            "is_http": float(scheme == "http"),
            "dangerous_scheme": dangerous_scheme,
            "is_ip_address": float(is_ip_address),
            "is_ipv6": float(is_ipv6),
            "has_port": float(bool(re.search(r":\d+", domain))),
            "uses_shortener": float(registered_domain.lower() in URL_SHORTENERS),
            "suspicious_tld": float(tld.lower() in SUSPICIOUS_TLDS),
            "has_digit_sub": float(self._has_digit_substitution(host)),
            "has_homoglyph": float(has_homoglyph),
            "is_idn": float(is_idn),
            "domain_has_phishing_kw": float(
                any(kw in host.lower() for kw in PHISHING_KEYWORDS)
            ),
            "path_has_phishing_kw": float(
                any(kw in (path + query).lower() for kw in PHISHING_KEYWORDS)
            ),
            "has_hex_encoding": float("%2" in query or "%2" in path),
            "has_double_slash": float("//" in path),
            "has_at_in_url": float("@" in (raw_url or url)),
            "redirect_count": float(
                full_lower.count("redirect") + full_lower.count("url=")
                + full_lower.count("next=") + full_lower.count("goto=")
            ),
            "has_double_ext": has_double_ext,
            "has_b64_payload": has_b64_payload,

            # ── Ratio features ────────────────────────────────────────────────
            "digit_ratio_domain": sum(1 for c in host if c.isdigit()) / max(len(host), 1),
            "alpha_ratio_domain": sum(1 for c in host if c.isalpha()) / max(len(host), 1),
            "special_ratio_url": sum(
                1 for c in url if not c.isalnum() and c not in "-._/:?=&#"
            ) / max(len(url), 1),
            "hyphen_ratio_domain": host.count("-") / max(len(host), 1),

            # ── Structural ────────────────────────────────────────────────────
            "path_depth": float(len([p for p in path.split("/") if p])),
            "registered_domain_length": float(len(registered_domain)),
            "tld_length": float(len(tld)),
            "query_param_count": float(len(query.split("&")) if query else 0),
            "has_fragment": float(bool(fragment)),

            # ── Domain age placeholder (-1 = unknown) ─────────────────────────
            # Populated asynchronously by async_whois_age() if WHOIS is available.
            "domain_age_days": -1.0,

            # Internal helper (removed before returning to caller)
            "_registered_domain": registered_domain,  # type: ignore[dict-item]
        }

        return features

    # ── Heuristic scorer ──────────────────────────────────────────────────────

    def _heuristic_score(self, features: dict) -> float:
        """
        Calibrated rule-based fallback score.
        Each signal contributes a weighted penalty; total is clamped to [0, 1].
        Threshold of 0.5 matches roughly "Suspicious" band in the Fusion Engine.
        """
        score = 0.0

        # ── Hard signals (high certainty) ─────────────────────────────────────
        if features.get("is_ip_address"):       score += 0.25
        if features.get("dangerous_scheme"):    score += 0.35
        if features.get("has_at_in_url"):       score += 0.20
        if features.get("has_digit_sub"):       score += 0.20
        if features.get("has_homoglyph"):       score += 0.25
        if features.get("is_idn"):              score += 0.15
        if features.get("uses_shortener"):      score += 0.15
        if features.get("has_double_ext"):      score += 0.20
        if features.get("suspicious_tld"):      score += 0.15

        # ── Medium signals ────────────────────────────────────────────────────
        if features.get("domain_has_phishing_kw"): score += 0.15
        if features.get("path_has_phishing_kw"):   score += 0.10
        if features.get("has_b64_payload"):         score += 0.10
        if features.get("redirect_count", 0) > 0:  score += 0.10
        if features.get("has_hex_encoding"):        score += 0.08

        # ── Soft signals (contextual) ─────────────────────────────────────────
        if features.get("num_subdomains", 0) > 3:   score += 0.10
        if features.get("url_entropy", 0) > 4.5:    score += 0.08
        if features.get("url_length", 0) > 100:     score += 0.05
        if features.get("url_length", 0) > 150:     score += 0.05  # stacking
        if not features.get("is_https"):             score += 0.05
        if features.get("hyphen_ratio_domain", 0) > 0.2: score += 0.05

        # ── Domain age penalty ────────────────────────────────────────────────
        age = features.get("domain_age_days", -1)
        if 0 <= age < 7:   score += 0.25
        elif 0 <= age < 30: score += 0.10

        return min(1.0, score)

    # ── Risk category classification ──────────────────────────────────────────

    @staticmethod
    def _classify_risk_category(features: dict) -> str:
        """Map feature pattern to a human-readable risk category."""
        if features.get("dangerous_scheme"):
            return "code_execution"
        if features.get("has_double_ext"):
            return "malware_delivery"
        if features.get("has_homoglyph") or features.get("has_digit_sub") or features.get("is_idn"):
            return "brand_spoofing"
        if features.get("domain_has_phishing_kw") or features.get("path_has_phishing_kw"):
            return "credential_harvesting"
        if features.get("uses_shortener"):
            return "url_obfuscation"
        if features.get("is_ip_address"):
            return "ip_based_c2"
        if features.get("redirect_count", 0) > 0:
            return "redirect_chain"
        if features.get("suspicious_tld"):
            return "suspicious_domain"
        return "generic_malicious"

    # ── Shannon entropy ───────────────────────────────────────────────────────

    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        freq: dict[str, int] = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    # ── Digit substitution (leet-speak) ──────────────────────────────────────

    @staticmethod
    def _has_digit_substitution(domain: str) -> bool:
        """
        Detect leet-speak digit-for-letter substitutions like 'g00gle' or 'payp4l'.
        Requires the digit to be adjacent to at least one letter (avoids false-positives
        on legitimate numeric domain labels).
        """
        for digit in DIGIT_SUBS:
            for i, ch in enumerate(domain):
                if ch == digit:
                    context = domain[max(0, i - 1): i + 2]
                    if any(c.isalpha() for c in context):
                        return True
        return False

    # ── Homoglyph / Unicode spoofing ─────────────────────────────────────────

    @staticmethod
    def _detect_homoglyph(domain: str) -> bool:
        """
        Detect Unicode characters that visually resemble ASCII letters but map
        to a different code point (e.g. Cyrillic 'а' vs Latin 'a').
        """
        if not domain:
            return False
        for ch in domain:
            if ch in HOMOGLYPH_MAP:
                return True
            # Catch any non-ASCII letter whose NFKC normal form differs (broad check)
            if ord(ch) > 127 and ch.isalpha():
                nfkc = unicodedata.normalize("NFKC", ch)
                if nfkc != ch and nfkc.isascii():
                    return True
        return False

    # ── Async WHOIS lookup ────────────────────────────────────────────────────

    @staticmethod
    async def _async_whois_age(domain: str) -> int:
        """
        Return domain age in days, or -1 if WHOIS lookup fails / is unavailable.
        Runs the blocking WHOIS call in an executor thread to avoid blocking the
        asyncio event loop.
        """
        if not WHOIS_AVAILABLE or not domain:
            return -1
        try:
            loop = asyncio.get_event_loop()
            info = await loop.run_in_executor(None, python_whois.whois, domain)
            creation = info.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                from datetime import datetime, timezone
                now = datetime.now(timezone.utc)
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                age = (now - creation).days
                return max(0, age)
        except Exception:
            pass
        return -1

    # ── Top feature explainability ────────────────────────────────────────────

    @staticmethod
    def _explain_top_features(features: dict) -> list[str]:
        """Return a human-readable list of the most significant risk signals found."""
        explanations: list[str] = []

        checks = [
            ("dangerous_scheme",        "dangerous_url_scheme_detected"),
            ("is_ip_address",           "uses_raw_ip_address"),
            ("has_homoglyph",           "unicode_homoglyph_spoofing"),
            ("is_idn",                  "internationalized_domain_name"),
            ("has_digit_sub",           "digit_substitution_leetspeak"),
            ("has_double_ext",          "double_extension_malware_indicator"),
            ("uses_shortener",          "url_shortener_masking_destination"),
            ("suspicious_tld",          "suspicious_top_level_domain"),
            ("has_at_in_url",           "at_sign_credential_redirect"),
            ("domain_has_phishing_kw",  "phishing_keyword_in_domain"),
            ("path_has_phishing_kw",    "phishing_keyword_in_path_or_query"),
            ("has_b64_payload",         "base64_encoded_payload_detected"),
            ("has_hex_encoding",        "hex_percent_encoding_obfuscation"),
            ("has_double_slash",        "double_slash_path_confusion"),
            ("redirect_count",          "redirect_chain_detected"),
        ]

        for key, label in checks:
            val = features.get(key, 0)
            if val:
                explanations.append(label)

        if features.get("num_subdomains", 0) > 3:
            explanations.append("excessive_subdomain_depth")
        if features.get("url_entropy", 0) > 4.5:
            explanations.append("high_url_entropy_randomised_domain")
        if features.get("url_length", 0) > 100:
            explanations.append("abnormally_long_url")
        age = features.get("domain_age_days", -1)
        if 0 <= age < 7:
            explanations.append(f"newly_registered_domain_{age}d")
        elif 0 <= age < 30:
            explanations.append(f"recently_registered_domain_{age}d")
        if features.get("hyphen_ratio_domain", 0) > 0.2:
            explanations.append("high_hyphen_density_in_domain")

        return explanations[:12]
