## AI-Based Data Loss Prevention (DLP) System (Security-First + ML-Assisted)

An enterprise-grade **Data Loss Prevention (DLP) system** combining deterministic security controls with ML-assisted classification to detect and prevent sensitive data leakage across your organization.

This project is a **production-style, cybersecurity-first Data Loss Prevention (DLP) system** built in Python.

- **80% cybersecurity**: sensitive data identification, policy enforcement, risk scoring, logging/alerting, insider-threat style controls
- **20% ML**: a lightweight text classifier to assist decisions and reduce false positives (never overrides high-certainty security blocks)

### Overview

Modern organizations face critical data security challenges:
- **Accidental exposure**: passwords/tokens accidentally shared in chat or documents
- **Insider threats**: intentional or negligent data exfiltration
- **Misconfigurations**: hardcoded secrets in code, tickets, or logs

This system solves these problems through a two-stage pipeline:
1. **Security-First Rules**: deterministic detection of credentials, tokens, PII, and payment data
2. **ML Assistance**: Logistic Regression model fine-tunes LOW/MEDIUM decisions and reduces false positives

---

## Architecture (Text Diagram)

```
User Text
  |
  v
Preprocessing (normalize)
  |
  v
Security Detection (PRIMARY)
- Keyword rules
- Regex detectors (CC/SSN/tokens/keys)
- Entropy + token stats
- Risk scoring + policy decision
  |
  +----> ML Assist (SECONDARY)
  |        - TF-IDF + numeric security features
  |        - Logistic Regression
  |        - Used to adjust LOW/MEDIUM only
  |
  v
Decision Output
- SAFE / SENSITIVE / HIGHLY CONFIDENTIAL
- LOW / MEDIUM / HIGH risk
- ALLOWED / LOGGED / BLOCKED action
  |
  v
Logging + Alerts (logs/alerts.log)
```

---

## Key Features (Cybersecurity-Focused)

- **Data classification**: `SAFE`, `SENSITIVE`, `HIGHLY CONFIDENTIAL`
- **Sensitive data identification**:
  - Keyword detection (password, otp, secret, token, api key)
  - Regex detection (credit-card-like numbers, SSN, AWS key, GitHub token, Slack token, JWT, SSH key marker, email)
  - **Entropy detection** for unknown secrets/tokens
- **Policy-based enforcement**:
  - Low → Allow
  - Medium → Log
  - High → Block + Alert
- **Explainability**: every decision returns a list of reasons
- **Audit logging**: medium/high events are written to `logs/alerts.log`
- **Real-time file monitoring**: watch directories for sensitive content
- **RESTful API**: FastAPI backend for integration with other security tools
- **User-friendly dashboard**: React + Vite frontend for alerts and policy management
- **ML-assisted triage**: Logistic Regression reduces false positives without compromising security

---

## Use Cases

- **Email/Chat DLP**: Prevent credential leakage in workplace communications
- **Code Repository Protection**: Detect hardcoded secrets before they're committed
- **Document Security**: Classify and protect sensitive files and records
- **Insider Threat Detection**: Monitor for suspicious data movement patterns
- **Compliance**: Support PCI-DSS, HIPAA, SOC2, and GDPR requirements
- **Incident Response**: Provide detailed audit logs for forensic analysis

---

## Technology Stack

### Backend & Core ML
- **FastAPI**: RESTful API framework for high-performance service
- **SQLAlchemy**: SQL database ORM with async support
- **scikit-learn**: Machine learning (Logistic Regression, TF-IDF vectorizer)
- **watchdog**: Real-time file system monitoring
- **PyPDF2, python-docx**: Document parsing support

### Frontend
- **React + Vite**: Modern, fast UI for dashboard and alerts
- **WebSockets**: Real-time alert notifications

### Infrastructure
- **SQLite** with async drivers for lightweight deployment
- **joblib**: Model persistence and serialization
- **python-dotenv**: Environment configuration management

---

## Folder Structure

```
AI-DLP-System/
├── app/                          # Core DLP engine
│   └── dlp_engine.py
├── backend/                      # API and monitoring services
│   ├── api_server.py             # FastAPI REST endpoints
│   ├── file_monitor.py           # Real-time file system watcher
│   ├── policy_manager.py         # Policy enforcement logic
│   ├── database.py               # Database models and queries
│   └── redaction_engine.py       # Data redaction utilities
├── frontend/                     # React dashboard
│   ├── src/
│   │   ├── components/           # UI components (Navbar, RiskBadge, etc.)
│   │   ├── pages/                # Dashboard, Alerts, Policies pages
│   │   └── services/             # API communication
│   └── package.json
├── model/                        # ML training pipeline
│   ├── train_model.py
│   └── dlp_model.pkl             # Trained model (generated)
├── feature_extraction/           # Feature engineering module
│   └── features.py
├── preprocessing/                # Data preprocessing
│   └── preprocess.py
├── dataset/
│   └── dlp_dataset.csv
├── data/                         # Sample data files
│   └── demo_files/
├── logs/                         # Audit and alert logs
│   └── alerts.log
├── monitored_files/              # Files under monitoring
├── uploads/                      # Uploaded documents for analysis
├── report/
│   └── project_report.md         # Detailed project documentation
├── requirements.txt              # Python dependencies
└── README.md
```

---

## Quick Start

### Prerequisites
- Python 3.8+
- pip or conda

### Installation & Setup

```bash
# Clone and navigate to project
cd AI-DLP-System

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Train the ML model (optional but recommended)
python -m model.train_model

# Run the DLP engine
python -m app.dlp_engine

# Or start the FastAPI backend server
python backend/api_server.py
```

### Frontend (Optional)

```bash
cd frontend
npm install
npm run dev
```

---

## Sample Output

Input:

`My password is admin123`

Example output:

- **Classification**: Highly Confidential
- **Risk Level**: HIGH
- **Action**: BLOCKED
- **Reason**: Credential detected (keyword + secret pattern)

---

## Tools Used

- Python 3
- pandas, numpy
- scikit-learn (Logistic Regression, TF-IDF)
- joblib (model persistence)

---

## Future Enhancements

- Add **Luhn check** for credit card validation (reduce false positives)
- Add configurable policy packs (PCI, HIPAA, SOC2)
- Streaming file/email “egress” simulation (proxy-style DLP)
- Entity redaction mode (mask tokens instead of blocking)
- More labeled data + evaluation dashboard- Docker containerization for easy deployment
- Integration with SIEM platforms (Splunk, ELK)
- Advanced analytics and threat intelligence feeds
- Multi-language support for pattern detection

---

## Contributing

Contributions are welcome! Please follow these guidelines:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -m 'Add YourFeature'`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Open a Pull Request

---

## Security & Disclaimer

⚠️ **This is a security-focused educational project.** For production use:
- Conduct security audits
- Test thoroughly with real-world data patterns
- Implement proper access controls and encryption
- Follow your organization's security policies
- Consider working with security professionals

---

## License

This project is provided as-is for educational and research purposes.

---

## Support & Questions

For questions or issues:
- Check the [project report](report/project_report.md) for detailed documentation
- Review the sample output section below
- Open an issue in the repository

