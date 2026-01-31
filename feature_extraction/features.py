"""
Feature engineering for DLP detection.

This module is deliberately security-first:
- Strong regex + keyword detectors catch known sensitive patterns
- Entropy helps flag secrets that don't match known formats
- Lightweight NLP token stats support ML as a secondary signal
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple


# ----------------------------
# Keywords (security heuristics)
# ----------------------------
KEYWORDS_HIGH = {
    "password",
    "passcode",
    "otp",
    "one-time password",
    "secret",
    "private key",
    "ssh private key",
    "api key",
    "access key",
    "bearer",
    "token",
    "client_secret",
}

KEYWORDS_MEDIUM = {
    "ssn",
    "social security",
    "credit card",
    "card number",
    "account number",
    "routing",
    "bank",
    "invoice",
    "customer",
    "address",
    "phone",
    "email",
    "database",
    "db",
    "host",
    "internal",
}


# ----------------------------
# Regex patterns (security)
# ----------------------------
# SSN (US)
RE_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Credit card (very common patterns; plus optional spaces/hyphens)
RE_CC_GENERIC = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

# Emails
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# AWS Access Key ID (AKIA... or ASIA... for temp)
RE_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")

# GitHub tokens (classic patterns)
RE_GH_TOKEN = re.compile(r"\bghp_[A-Za-z0-9]{20,}\b|\bgho_[A-Za-z0-9]{20,}\b")

# Slack tokens (common)
RE_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")

# JWT (3 base64url segments)
RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

# OpenSSH key markers
RE_SSH_KEY = re.compile(r"-----BEGIN (?:OPENSSH|RSA|DSA|EC) PRIVATE KEY-----")

# Generic "key=value" secret-ish
RE_KEY_VALUE_SECRET = re.compile(
    r"\b(?:api[_-]?key|secret|token|password|pass|client_secret)\s*[:=]\s*([^\s,;]{6,})",
    re.IGNORECASE,
)

# IP addresses (often sensitive in internal context)
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# ----------------------------
# Validation Functions
# ----------------------------
def luhn_check(card_number: str) -> bool:
    """
    Validate a credit card number using the Luhn algorithm.
    Reduces false positives by verifying checksum.
    
    Args:
        card_number: String of digits (spaces/hyphens will be removed)
    
    Returns:
        True if valid according to Luhn algorithm, False otherwise
    """
    # Remove spaces and hyphens
    digits = re.sub(r"[^0-9]", "", card_number)
    
    if not digits or len(digits) < 13 or len(digits) > 19:
        return False
    
    # Luhn algorithm
    def luhn_digit(d: str) -> int:
        return int(d)
    
    total = 0
    reverse_digits = digits[::-1]
    
    for i, digit in enumerate(reverse_digits):
        n = luhn_digit(digit)
        if i % 2 == 1:  # Every second digit from the right
            n *= 2
            if n > 9:
                n -= 9
        total += n
    
    return total % 10 == 0


def validate_ssn(ssn: str) -> bool:
    """
    Validate SSN format more strictly.
    
    Args:
        ssn: SSN string in format XXX-XX-XXXX
    
    Returns:
        True if valid SSN format, False otherwise
    """
    match = RE_SSN.match(ssn)
    if not match:
        return False
    
    parts = ssn.split("-")
    area = int(parts[0])
    group = int(parts[1])
    serial = int(parts[2])
    
    # Basic validation rules
    # Area number cannot be 000, 666, or 900-999
    if area == 0 or area == 666 or area >= 900:
        return False
    
    # Group number cannot be 00
    if group == 0:
        return False
    
    # Serial number cannot be 0000
    if serial == 0:
        return False
    
    return True


def shannon_entropy(s: str) -> float:
    """
    Shannon entropy estimate for a string.
    Higher entropy often indicates secrets/tokens (not always).
    """
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent


def basic_token_stats(text: str) -> Dict[str, float]:
    """
    Lightweight NLP token analysis (not heavy NLP libraries).
    """
    tokens = [t for t in re.split(r"[^\w@.-]+", text) if t]
    token_lens = [len(t) for t in tokens] or [0]
    longest = max(token_lens)
    avg_len = sum(token_lens) / max(1, len(token_lens))
    digit_tokens = sum(1 for t in tokens if any(c.isdigit() for c in t))
    upper_tokens = sum(1 for t in tokens if any(c.isupper() for c in t))
    return {
        "num_tokens": float(len(tokens)),
        "avg_token_len": float(avg_len),
        "max_token_len": float(longest),
        "digit_token_ratio": float(digit_tokens) / max(1.0, float(len(tokens))),
        "upper_token_ratio": float(upper_tokens) / max(1.0, float(len(tokens))),
    }


def keyword_hits(text_lower: str) -> Tuple[int, int, List[str]]:
    """
    Count keyword hits (medium/high) and return matched keywords for explainability.
    """
    hits_high: List[str] = [k for k in KEYWORDS_HIGH if k in text_lower]
    hits_med: List[str] = [k for k in KEYWORDS_MEDIUM if k in text_lower]
    return len(hits_med), len(hits_high), sorted(set(hits_med + hits_high))


def regex_hits(text: str) -> Dict[str, int]:
    """
    Regex detections with validation; counts are used for risk scoring and as ML features.
    Now includes Luhn validation for credit cards and stricter SSN validation.
    """
    # Credit card detection with Luhn validation
    cc_match = RE_CC_GENERIC.search(text)
    has_valid_cc = 0
    if cc_match:
        # Extract all potential CC numbers and validate
        potential_ccs = RE_CC_GENERIC.findall(text)
        for cc in potential_ccs:
            if luhn_check(cc):
                has_valid_cc = 1
                break
    
    # SSN detection with validation
    ssn_match = RE_SSN.search(text)
    has_valid_ssn = 0
    if ssn_match:
        potential_ssns = RE_SSN.findall(text)
        for ssn in potential_ssns:
            if validate_ssn(ssn):
                has_valid_ssn = 1
                break
    
    return {
        "has_ssn": has_valid_ssn,
        "has_cc_like": has_valid_cc,
        "has_email": int(bool(RE_EMAIL.search(text))),
        "has_aws_access_key": int(bool(RE_AWS_ACCESS_KEY.search(text))),
        "has_github_token": int(bool(RE_GH_TOKEN.search(text))),
        "has_slack_token": int(bool(RE_SLACK_TOKEN.search(text))),
        "has_jwt": int(bool(RE_JWT.search(text))),
        "has_ssh_private_key": int(bool(RE_SSH_KEY.search(text))),
        "has_key_value_secret": int(bool(RE_KEY_VALUE_SECRET.search(text))),
        "has_ipv4": int(bool(RE_IPV4.search(text))),
    }



def extract_numeric_features(text: str) -> Dict[str, float]:
    """
    Hand-crafted numeric features used by ML as supporting signals.
    """
    text = text or ""
    text_lower = text.lower()

    med_k, high_k, _matched = keyword_hits(text_lower)
    rh = regex_hits(text)

    # Entropy on "likely secret chunks": long, non-space spans
    chunks = re.findall(r"[A-Za-z0-9_./+=-]{12,}", text)
    entropies = [shannon_entropy(c) for c in chunks] or [0.0]
    max_ent = max(entropies)
    avg_ent = sum(entropies) / max(1, len(entropies))

    stats = basic_token_stats(text)

    digits = sum(1 for c in text if c.isdigit())
    uppers = sum(1 for c in text if c.isupper())
    lowers = sum(1 for c in text if c.islower())
    specials = sum(1 for c in text if not c.isalnum() and not c.isspace())
    length = len(text)

    feats: Dict[str, float] = {
        "text_len": float(length),
        "digit_ratio": float(digits) / max(1.0, float(length)),
        "upper_ratio": float(uppers) / max(1.0, float(length)),
        "lower_ratio": float(lowers) / max(1.0, float(length)),
        "special_ratio": float(specials) / max(1.0, float(length)),
        "keyword_med_count": float(med_k),
        "keyword_high_count": float(high_k),
        "max_chunk_entropy": float(max_ent),
        "avg_chunk_entropy": float(avg_ent),
    }

    for k, v in rh.items():
        feats[k] = float(v)

    feats.update(stats)
    return feats


def numeric_feature_frame(texts) -> "object":
    """
    Build a pandas DataFrame of numeric security features from an array-like of texts.

    This exists in a stable, importable module so ML pipelines can be safely
    serialized/deserialized (joblib/pickle).
    """
    # Local import to keep this module lightweight for non-ML use
    import pandas as pd  # type: ignore

    if hasattr(texts, "tolist"):
        texts_list = texts.tolist()
    else:
        texts_list = list(texts)

    # If a transformer passes shape (n, 1), flatten it.
    if texts_list and isinstance(texts_list[0], (list, tuple)) and len(texts_list[0]) == 1:
        texts_list = [t[0] for t in texts_list]

    rows = [extract_numeric_features(t) for t in texts_list]
    return pd.DataFrame(rows).fillna(0.0)


@dataclass
class RuleDecision:
    classification: str  # SAFE | SENSITIVE | HIGHLY CONFIDENTIAL
    risk_level: str      # LOW | MEDIUM | HIGH
    action: str          # ALLOW | LOG | BLOCK
    reasons: List[str]
    risk_score: int


def rule_based_assessment(text: str) -> RuleDecision:
    """
    Security-first DLP decisioning. ML should only adjust confidence, not override
    high-certainty security detections.
    """
    reasons: List[str] = []
    score = 0
    text = text or ""
    tl = text.lower()

    med_k, high_k, matched_kw = keyword_hits(tl)
    if high_k:
        score += 35 + 10 * high_k
        reasons.append(f"High-risk keyword(s): {', '.join(matched_kw)}")
    elif med_k:
        score += 15 + 5 * med_k
        reasons.append(f"Sensitive keyword(s): {', '.join(matched_kw)}")

    rh = regex_hits(text)
    if rh["has_ssh_private_key"]:
        score += 80
        reasons.append("SSH private key marker detected")
    if rh["has_aws_access_key"]:
        score += 70
        reasons.append("AWS access key format detected")
    if rh["has_github_token"] or rh["has_slack_token"] or rh["has_jwt"] or rh["has_key_value_secret"]:
        score += 55
        reasons.append("Token/secret pattern detected")
    if rh["has_ssn"]:
        score += 60
        reasons.append("SSN pattern detected")
    if rh["has_cc_like"]:
        # Add some protection against random long numbers: require keyword OR Luhn-like formatting is out of scope.
        score += 45
        reasons.append("Card-like number pattern detected")
    if rh["has_email"]:
        score += 10
        reasons.append("Email address detected")

    # Contextual signal: internal IPs with internal wording
    if rh["has_ipv4"] and any(w in tl for w in ("internal", "database", "db", "host", "server")):
        score += 20
        reasons.append("Internal infrastructure info (IP + context) detected")

    # Entropy-based suspicion for secrets without known signatures
    feats = extract_numeric_features(text)
    if feats["max_chunk_entropy"] >= 4.2 and feats["max_token_len"] >= 20:
        score += 25
        reasons.append("High-entropy long token detected (possible secret)")

    # Basic length heuristic
    if feats["text_len"] >= 250:
        score += 5
        reasons.append("Long message (higher exfil surface)")

    # Clamp
    score = max(0, min(100, int(score)))

    # Map score -> risk/action
    if score >= 70:
        risk_level, action, classification = "HIGH", "BLOCKED", "HIGHLY CONFIDENTIAL"
    elif score >= 30:
        risk_level, action, classification = "MEDIUM", "LOGGED", "SENSITIVE"
    else:
        risk_level, action, classification = "LOW", "ALLOWED", "SAFE"

    if not reasons:
        reasons.append("No sensitive patterns detected")

    return RuleDecision(
        classification=classification,
        risk_level=risk_level,
        action=action,
        reasons=reasons,
        risk_score=score,
    )


