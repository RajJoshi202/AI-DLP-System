"""
Data redaction and masking engine for AI-DLP System.
Provides multiple redaction modes for sensitive data handling.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from typing import Dict, List, Tuple

from feature_extraction.features import (
    RE_AWS_ACCESS_KEY,
    RE_CC_GENERIC,
    RE_EMAIL,
    RE_GH_TOKEN,
    RE_IPV4,
    RE_JWT,
    RE_SLACK_TOKEN,
    RE_SSH_KEY,
    RE_SSN,
)


class RedactionEngine:
    """Engine for redacting sensitive data from text."""
    
    # Token storage for reversible redaction
    _token_map: Dict[str, str] = {}
    
    @staticmethod
    def full_redact(text: str, placeholder: str = "[REDACTED]") -> str:
        """
        Full redaction: Replace all sensitive data with placeholder.
        
        Args:
            text: Input text
            placeholder: Replacement text (default: [REDACTED])
        
        Returns:
            Redacted text
        """
        result = text
        
        # Redact SSN
        result = RE_SSN.sub(placeholder, result)
        
        # Redact credit cards
        result = RE_CC_GENERIC.sub(placeholder, result)
        
        # Redact emails
        result = RE_EMAIL.sub(placeholder, result)
        
        # Redact AWS keys
        result = RE_AWS_ACCESS_KEY.sub(placeholder, result)
        
        # Redact GitHub tokens
        result = RE_GH_TOKEN.sub(placeholder, result)
        
        # Redact Slack tokens
        result = RE_SLACK_TOKEN.sub(placeholder, result)
        
        # Redact JWTs
        result = RE_JWT.sub(placeholder, result)
        
        # Redact SSH keys
        result = RE_SSH_KEY.sub(placeholder, result)
        
        # Redact IP addresses
        result = RE_IPV4.sub(placeholder, result)
        
        return result
    
    @staticmethod
    def partial_mask(text: str, show_last: int = 4) -> str:
        """
        Partial masking: Show last N characters, mask the rest.
        
        Args:
            text: Input text
            show_last: Number of characters to show at the end
        
        Returns:
            Partially masked text
        """
        result = text
        
        # Mask SSN (show last 4)
        def mask_ssn(match):
            ssn = match.group(0)
            return f"***-**-{ssn[-4:]}"
        result = RE_SSN.sub(mask_ssn, result)
        
        # Mask credit cards (show last 4)
        def mask_cc(match):
            cc = match.group(0)
            digits = re.sub(r"[^0-9]", "", cc)
            if len(digits) >= show_last:
                return "*" * (len(digits) - show_last) + digits[-show_last:]
            return "*" * len(digits)
        result = RE_CC_GENERIC.sub(mask_cc, result)
        
        # Mask emails (show domain)
        def mask_email(match):
            email = match.group(0)
            parts = email.split("@")
            if len(parts) == 2:
                return f"***@{parts[1]}"
            return "***"
        result = RE_EMAIL.sub(mask_email, result)
        
        # Mask AWS keys (show last 4)
        def mask_aws(match):
            key = match.group(0)
            return f"{key[:4]}{'*' * (len(key) - 8)}{key[-4:]}"
        result = RE_AWS_ACCESS_KEY.sub(mask_aws, result)
        
        # Mask tokens (show last 4)
        def mask_token(match):
            token = match.group(0)
            if len(token) > show_last:
                return "*" * (len(token) - show_last) + token[-show_last:]
            return "*" * len(token)
        result = RE_GH_TOKEN.sub(mask_token, result)
        result = RE_SLACK_TOKEN.sub(mask_token, result)
        result = RE_JWT.sub(mask_token, result)
        
        # Mask IP addresses (show last octet)
        def mask_ip(match):
            ip = match.group(0)
            parts = ip.split(".")
            if len(parts) == 4:
                return f"***.***.***.{parts[3]}"
            return "***"
        result = RE_IPV4.sub(mask_ip, result)
        
        return result
    
    @classmethod
    def tokenize(cls, text: str) -> Tuple[str, Dict[str, str]]:
        """
        Tokenization: Replace sensitive data with reversible tokens.
        
        Args:
            text: Input text
        
        Returns:
            Tuple of (tokenized text, token map)
        """
        result = text
        token_map = {}
        
        patterns = [
            ("SSN", RE_SSN),
            ("CC", RE_CC_GENERIC),
            ("EMAIL", RE_EMAIL),
            ("AWS_KEY", RE_AWS_ACCESS_KEY),
            ("GH_TOKEN", RE_GH_TOKEN),
            ("SLACK_TOKEN", RE_SLACK_TOKEN),
            ("JWT", RE_JWT),
            ("IP", RE_IPV4),
        ]
        
        for pattern_name, pattern in patterns:
            matches = pattern.findall(result)
            for match in matches:
                # Generate unique token
                token = f"[{pattern_name}_{secrets.token_hex(8).upper()}]"
                token_map[token] = match
                cls._token_map[token] = match
                result = result.replace(match, token, 1)
        
        return result, token_map
    
    @classmethod
    def detokenize(cls, text: str, token_map: Dict[str, str] = None) -> str:
        """
        Reverse tokenization: Replace tokens with original values.
        
        Args:
            text: Tokenized text
            token_map: Optional token map (uses class storage if not provided)
        
        Returns:
            Original text
        """
        result = text
        map_to_use = token_map if token_map is not None else cls._token_map
        
        for token, original in map_to_use.items():
            result = result.replace(token, original)
        
        return result
    
    @staticmethod
    def hash_redact(text: str) -> str:
        """
        Hash-based redaction: One-way hashing for anonymization.
        
        Args:
            text: Input text
        
        Returns:
            Text with hashed sensitive data
        """
        result = text
        
        patterns = [
            RE_SSN,
            RE_CC_GENERIC,
            RE_EMAIL,
            RE_AWS_ACCESS_KEY,
            RE_GH_TOKEN,
            RE_SLACK_TOKEN,
            RE_JWT,
            RE_IPV4,
        ]
        
        def hash_match(match):
            value = match.group(0)
            hashed = hashlib.sha256(value.encode()).hexdigest()[:16]
            return f"[HASH:{hashed}]"
        
        for pattern in patterns:
            result = pattern.sub(hash_match, result)
        
        return result
    
    @classmethod
    def redact(cls, text: str, mode: str = "full", **kwargs) -> Dict[str, any]:
        """
        Main redaction method with mode selection.
        
        Args:
            text: Input text
            mode: Redaction mode (full, partial, tokenize, hash)
            **kwargs: Additional arguments for specific modes
        
        Returns:
            Dictionary with redacted text and metadata
        """
        if mode == "full":
            placeholder = kwargs.get("placeholder", "[REDACTED]")
            redacted = cls.full_redact(text, placeholder)
            return {"redacted_text": redacted, "mode": mode}
        
        elif mode == "partial":
            show_last = kwargs.get("show_last", 4)
            redacted = cls.partial_mask(text, show_last)
            return {"redacted_text": redacted, "mode": mode}
        
        elif mode == "tokenize":
            redacted, token_map = cls.tokenize(text)
            return {
                "redacted_text": redacted,
                "mode": mode,
                "token_map": token_map,
                "reversible": True,
            }
        
        elif mode == "hash":
            redacted = cls.hash_redact(text)
            return {"redacted_text": redacted, "mode": mode, "reversible": False}
        
        else:
            raise ValueError(f"Unknown redaction mode: {mode}")
    
    @classmethod
    def get_available_modes(cls) -> List[Dict[str, str]]:
        """Get list of available redaction modes."""
        return [
            {
                "mode": "full",
                "description": "Replace all sensitive data with [REDACTED]",
                "reversible": False,
            },
            {
                "mode": "partial",
                "description": "Show last N characters, mask the rest",
                "reversible": False,
            },
            {
                "mode": "tokenize",
                "description": "Replace with reversible tokens",
                "reversible": True,
            },
            {
                "mode": "hash",
                "description": "One-way hashing for anonymization",
                "reversible": False,
            },
        ]
