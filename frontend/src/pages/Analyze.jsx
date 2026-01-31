import { useState } from 'react';
import RiskBadge from '../components/RiskBadge';
import { analyzeText, redactText } from '../services/api';
import './Analyze.css';

function Analyze() {
    const [inputText, setInputText] = useState('');
    const [result, setResult] = useState(null);
    const [redactedText, setRedactedText] = useState('');
    const [loading, setLoading] = useState(false);
    const [redacting, setRedacting] = useState(false);
    const [redactionMode, setRedactionMode] = useState('full');

    const handleAnalyze = async () => {
        if (!inputText.trim()) {
            alert('Please enter some text to analyze');
            return;
        }

        try {
            setLoading(true);
            const data = await analyzeText(inputText);
            setResult(data);
            setRedactedText('');
        } catch (error) {
            console.error('Error analyzing text:', error);
            alert('Failed to analyze text. Make sure the backend server is running.');
        } finally {
            setLoading(false);
        }
    };

    const handleRedact = async () => {
        if (!inputText.trim()) {
            alert('Please enter some text to redact');
            return;
        }

        try {
            setRedacting(true);
            const data = await redactText(inputText, redactionMode);
            setRedactedText(data.redacted_text);
        } catch (error) {
            console.error('Error redacting text:', error);
            alert('Failed to redact text');
        } finally {
            setRedacting(false);
        }
    };

    const handleClear = () => {
        setInputText('');
        setResult(null);
        setRedactedText('');
    };

    const exampleTexts = [
        'My password is admin123 and my email is john@example.com',
        'Credit card: 4532-1488-0343-6467, SSN: 123-45-6789',
        'AWS Key: AKIAIOSFODNN7EXAMPLE, Database host: 192.168.1.100',
    ];

    return (
        <div className="page-container fade-in">
            <div className="page-header">
                <div>
                    <h1>Analyze Text</h1>
                    <p className="text-muted">Scan text for sensitive data and security risks</p>
                </div>
            </div>

            <div className="analyze-layout">
                <div className="analyze-input glass-card">
                    <div className="input-header">
                        <h2>Input Text</h2>
                        <div className="input-actions">
                            <button className="btn btn-secondary" onClick={handleClear}>
                                Clear
                            </button>
                        </div>
                    </div>

                    <textarea
                        className="analyze-textarea"
                        placeholder="Enter or paste text to analyze for sensitive data..."
                        value={inputText}
                        onChange={(e) => setInputText(e.target.value)}
                    />

                    <div className="example-section">
                        <p className="text-sm text-muted">Try these examples:</p>
                        <div className="example-buttons">
                            {exampleTexts.map((text, index) => (
                                <button
                                    key={index}
                                    className="btn btn-secondary text-sm"
                                    onClick={() => setInputText(text)}
                                >
                                    Example {index + 1}
                                </button>
                            ))}
                        </div>
                    </div>

                    <div className="action-buttons">
                        <button
                            className="btn btn-primary"
                            onClick={handleAnalyze}
                            disabled={loading || !inputText.trim()}
                        >
                            {loading ? (
                                <>
                                    <div className="loading"></div>
                                    Analyzing...
                                </>
                            ) : (
                                <>
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <circle cx="11" cy="11" r="8"></circle>
                                        <path d="m21 21-4.35-4.35"></path>
                                    </svg>
                                    Analyze Text
                                </>
                            )}
                        </button>

                        <div className="redaction-controls">
                            <select
                                className="redaction-select"
                                value={redactionMode}
                                onChange={(e) => setRedactionMode(e.target.value)}
                            >
                                <option value="full">Full Redaction</option>
                                <option value="partial">Partial Masking</option>
                                <option value="tokenize">Tokenize</option>
                                <option value="hash">Hash</option>
                            </select>
                            <button
                                className="btn btn-secondary"
                                onClick={handleRedact}
                                disabled={redacting || !inputText.trim()}
                            >
                                {redacting ? (
                                    <>
                                        <div className="loading"></div>
                                        Redacting...
                                    </>
                                ) : (
                                    'Redact'
                                )}
                            </button>
                        </div>
                    </div>
                </div>

                {result && (
                    <div className="analyze-result glass-card slide-in">
                        <div className="result-header">
                            <h2>Analysis Result</h2>
                            <RiskBadge level={result.risk_level} />
                        </div>

                        <div className="result-summary">
                            <div className="summary-item">
                                <span className="summary-label">Classification:</span>
                                <span className="summary-value">{result.classification}</span>
                            </div>
                            <div className="summary-item">
                                <span className="summary-label">Action:</span>
                                <span className={`summary-value action-${result.action?.toLowerCase()}`}>
                                    {result.action}
                                </span>
                            </div>
                            <div className="summary-item">
                                <span className="summary-label">Risk Score:</span>
                                <span className="summary-value">{result.risk_score}/100</span>
                            </div>
                        </div>

                        <div className="risk-bar">
                            <div
                                className={`risk-fill risk-${result.risk_level?.toLowerCase()}`}
                                style={{ width: `${result.risk_score}%` }}
                            ></div>
                        </div>

                        <div className="result-reasons">
                            <h3>Detection Reasons:</h3>
                            <ul>
                                {result.reasons?.map((reason, index) => (
                                    <li key={index}>{reason}</li>
                                ))}
                            </ul>
                        </div>

                        {result.ml_assist && (
                            <div className="ml-assist">
                                <h3>ML Confidence:</h3>
                                <p>
                                    {(result.ml_assist.confidence * 100).toFixed(1)}% confidence
                                    {result.ml_assist.pred_label === 0 && ' (SAFE)'}
                                    {result.ml_assist.pred_label === 1 && ' (SENSITIVE)'}
                                    {result.ml_assist.pred_label === 2 && ' (HIGHLY CONFIDENTIAL)'}
                                </p>
                            </div>
                        )}
                    </div>
                )}

                {redactedText && (
                    <div className="redacted-result glass-card slide-in">
                        <div className="result-header">
                            <h2>Redacted Text</h2>
                            <span className="badge">{redactionMode} mode</span>
                        </div>
                        <div className="redacted-content">
                            <pre>{redactedText}</pre>
                        </div>
                        <button
                            className="btn btn-secondary"
                            onClick={() => {
                                navigator.clipboard.writeText(redactedText);
                                alert('Copied to clipboard!');
                            }}
                        >
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                            </svg>
                            Copy to Clipboard
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
}

export default Analyze;
