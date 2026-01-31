"""
Policy management system for AI-DLP System.
Provides compliance templates and custom policy evaluation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class PolicyManager:
    """Manager for DLP policies and compliance templates."""
    
    # Pre-built compliance templates
    COMPLIANCE_TEMPLATES = {
        "GDPR": {
            "name": "GDPR Compliance",
            "description": "General Data Protection Regulation - Focus on PII detection",
            "priority": 10,
            "rules": {
                "keywords": ["personal", "gdpr", "consent", "data subject"],
                "patterns": ["email", "ssn", "phone"],
                "risk_adjustment": 15,
                "block_threshold": 60,
            },
        },
        "HIPAA": {
            "name": "HIPAA Compliance",
            "description": "Health Insurance Portability and Accountability Act - Healthcare data protection",
            "priority": 10,
            "rules": {
                "keywords": ["patient", "medical", "health", "diagnosis", "treatment", "phi"],
                "patterns": ["ssn", "email", "phone"],
                "risk_adjustment": 20,
                "block_threshold": 55,
            },
        },
        "PCI_DSS": {
            "name": "PCI-DSS Compliance",
            "description": "Payment Card Industry Data Security Standard - Payment card data protection",
            "priority": 10,
            "rules": {
                "keywords": ["card", "payment", "cvv", "cardholder"],
                "patterns": ["cc_like", "credit card"],
                "risk_adjustment": 25,
                "block_threshold": 50,
            },
        },
        "SOC2": {
            "name": "SOC2 Compliance",
            "description": "Service Organization Control 2 - Security controls",
            "priority": 8,
            "rules": {
                "keywords": ["confidential", "internal", "proprietary", "security"],
                "patterns": ["aws_access_key", "github_token", "slack_token", "jwt", "ssh_private_key"],
                "risk_adjustment": 15,
                "block_threshold": 65,
            },
        },
    }
    
    @classmethod
    def get_templates(cls) -> Dict[str, Dict[str, Any]]:
        """Get all compliance templates."""
        return cls.COMPLIANCE_TEMPLATES
    
    @classmethod
    def get_template(cls, template_name: str) -> Optional[Dict[str, Any]]:
        """Get a specific compliance template."""
        return cls.COMPLIANCE_TEMPLATES.get(template_name)
    
    @staticmethod
    def evaluate_policy(policy: Dict[str, Any], detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate a policy against a detection result.
        
        Args:
            policy: Policy configuration
            detection_result: DLP detection result
        
        Returns:
            Modified detection result with policy adjustments
        """
        result = detection_result.copy()
        rules = policy.get("rules", {})
        
        # Apply risk adjustment
        risk_adjustment = rules.get("risk_adjustment", 0)
        if risk_adjustment:
            result["risk_score"] = min(100, result.get("risk_score", 0) + risk_adjustment)
            result["reasons"].append(f"Policy '{policy['name']}': +{risk_adjustment} risk adjustment")
        
        # Apply block threshold
        block_threshold = rules.get("block_threshold")
        if block_threshold and result.get("risk_score", 0) >= block_threshold:
            result["risk_level"] = "HIGH"
            result["action"] = "BLOCKED"
            result["classification"] = "HIGHLY CONFIDENTIAL"
            result["reasons"].append(f"Policy '{policy['name']}': Block threshold ({block_threshold}) exceeded")
        
        # Check for keyword matches
        keywords = rules.get("keywords", [])
        input_text = result.get("input", "").lower()
        matched_keywords = [kw for kw in keywords if kw.lower() in input_text]
        if matched_keywords:
            result["reasons"].append(f"Policy '{policy['name']}': Matched keywords: {', '.join(matched_keywords)}")
        
        return result
    
    @staticmethod
    def apply_policies(policies: List[Dict[str, Any]], detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply multiple policies to a detection result.
        Policies are applied in priority order (highest first).
        
        Args:
            policies: List of policy configurations
            detection_result: DLP detection result
        
        Returns:
            Modified detection result with all policy adjustments
        """
        # Sort by priority (descending)
        sorted_policies = sorted(policies, key=lambda p: p.get("priority", 0), reverse=True)
        
        result = detection_result.copy()
        for policy in sorted_policies:
            if policy.get("enabled", True):
                result = PolicyManager.evaluate_policy(policy, result)
        
        return result
    
    @staticmethod
    def create_custom_policy(
        name: str,
        description: str = "",
        keywords: List[str] = None,
        patterns: List[str] = None,
        risk_adjustment: int = 0,
        block_threshold: int = 70,
        priority: int = 5,
    ) -> Dict[str, Any]:
        """
        Create a custom policy configuration.
        
        Args:
            name: Policy name
            description: Policy description
            keywords: List of keywords to match
            patterns: List of pattern types to match
            risk_adjustment: Risk score adjustment
            block_threshold: Threshold for blocking
            priority: Policy priority
        
        Returns:
            Policy configuration dictionary
        """
        return {
            "name": name,
            "description": description,
            "enabled": True,
            "priority": priority,
            "rules": {
                "keywords": keywords or [],
                "patterns": patterns or [],
                "risk_adjustment": risk_adjustment,
                "block_threshold": block_threshold,
            },
        }
    
    @staticmethod
    def validate_policy(policy: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """
        Validate a policy configuration.
        
        Args:
            policy: Policy configuration
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not policy.get("name"):
            return False, "Policy name is required"
        
        if "rules" not in policy:
            return False, "Policy rules are required"
        
        rules = policy["rules"]
        
        # Validate risk adjustment
        risk_adj = rules.get("risk_adjustment", 0)
        if not isinstance(risk_adj, int) or risk_adj < -100 or risk_adj > 100:
            return False, "Risk adjustment must be an integer between -100 and 100"
        
        # Validate block threshold
        block_thresh = rules.get("block_threshold")
        if block_thresh is not None:
            if not isinstance(block_thresh, int) or block_thresh < 0 or block_thresh > 100:
                return False, "Block threshold must be an integer between 0 and 100"
        
        # Validate priority
        priority = policy.get("priority", 0)
        if not isinstance(priority, int):
            return False, "Priority must be an integer"
        
        return True, None
