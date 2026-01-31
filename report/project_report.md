## Project Report: AI-Based Data Loss Prevention (DLP) System

### Introduction
Data Loss Prevention (DLP) systems reduce the risk of sensitive data leaving an organization through email, chat, documents, tickets, or insider misuse. In modern environments, manual review is not scalable, so organizations combine **deterministic security controls** (policies + pattern detection) with **AI assistance** to triage and reduce false positives.

### Problem Statement
Organizations face data leakage via:
- Accidental exposure (sharing passwords/tokens in chat)
- Insider threat activity (intentional exfiltration)
- Misconfigurations (secrets hardcoded in text, tickets, or docs)

Traditional keyword-only approaches are noisy, while AI-only approaches can be unreliable and hard to explain.

### Objectives
- Detect sensitive patterns (credentials, tokens, payment data, SSN-like data)
- Classify text into: **SAFE**, **SENSITIVE**, **HIGHLY CONFIDENTIAL**
- Apply policy-based enforcement: **Allow / Log / Block + Alert**
- Provide explainable reasons and security logging
- Use a lightweight ML model only as a supporting signal

### System Architecture
Pipeline:
- **Preprocessing**: normalize text (keep security-relevant structure)
- **Security-first feature engineering**:
  - Keyword detection (password/otp/secret/token/api key)
  - Regex detection (SSN, credit-card-like, AWS keys, GitHub/Slack tokens, JWT, SSH key marker)
  - Entropy estimation for unknown secrets
  - Lightweight token statistics (NLP-ish without heavy libraries)
- **Risk scoring**: combine detections into an interpretable score (0–100)
- **Policy engine**: map risk → allow/log/block
- **ML assist (secondary)**: TF-IDF + numeric security features → Logistic Regression
- **Logging and alerting**: write medium/high events to `logs/alerts.log`

### Feature Engineering
Implemented in `feature_extraction/features.py`:
- **Keyword detection**:
  - High-risk keywords increase risk score strongly
  - Medium-risk keywords add moderate risk
- **Regex detection**:
  - Strong signals like private keys, tokens, SSNs, or access keys trigger high scores
- **Entropy detection**:
  - High entropy long tokens may be secrets even if they don’t match known formats
- **Text metrics**:
  - length, digit ratio, special char ratio, token statistics

### ML Model Explanation (Supporting Role)
Model: **Logistic Regression**
- Input features:
  - TF-IDF token features (unigrams + bigrams)
  - Numeric security features (keyword counts, regex flags, entropy, token stats)
- Split:
  - 80/20 train-test split
- Output:
  - 3-class label prediction: 0 Safe, 1 Sensitive, 2 Highly Confidential

How ML is used:
- ML may **escalate** LOW→MEDIUM or MEDIUM→HIGH when confidence is strong.
- ML **never downgrades** a HIGH rule-based block.
- This preserves security correctness and reduces unsafe “AI-only” behavior.

### Results
The training script prints:
- Accuracy
- Classification report

Operationally, the DLP engine produces:
- Classification + risk level + action
- Human-readable reasons
- Audit log entries for medium/high events

### Conclusion
This project demonstrates a realistic DLP approach:
- **Deterministic security controls** for strong enforcement
- **AI assistance** for triage and false-positive reduction
- **Explainable** outcomes suitable for SOC workflows and incident response

### Future Scope
- Luhn validation for credit card numbers
- Configurable policy packs (PCI/HIPAA/SOC2)
- Data redaction instead of blocking (mask secrets)
- File and network egress simulation (email/web proxy)
- Larger dataset and evaluation on real-world-like corpora


