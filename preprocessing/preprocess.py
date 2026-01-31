"""
Preprocessing utilities for the AI-based DLP system.

Security note:
We intentionally keep preprocessing minimal to preserve potentially-sensitive patterns
for detection (e.g., tokens, key prefixes, card-like number spacing).
"""

from __future__ import annotations

import re


_WHITESPACE_RE = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """
    Normalize input text while retaining key security-relevant structure.
    - Trims leading/trailing whitespace
    - Collapses repeated whitespace to single spaces
    - Keeps original casing impact minimal by lowercasing (rules may also use raw text)
    """
    if text is None:
        return ""
    text = str(text).strip()
    text = _WHITESPACE_RE.sub(" ", text)
    return text


def normalize_for_ml(text: str) -> str:
    """
    ML-oriented normalization:
    - Lowercase
    - Keep punctuation (TF-IDF can benefit from token prefixes like 'sk-', 'AKIA')
    """
    return normalize_text(text).lower()


