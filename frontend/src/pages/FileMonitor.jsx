import { useState, useEffect } from 'react';
import { startMonitoring, stopMonitoring, getMonitorStatus, getFileResults } from '../services/api';
import RiskBadge from '../components/RiskBadge';
import './FileMonitor.css';

function FileMonitor() {
    const [directory, setDirectory] = useState('');
    const [status, setStatus] = useState(null);
    const [results, setResults] = useState([]);
    const [loading, setLoading] = useState(false);
    const [showDetailsModal, setShowDetailsModal] = useState(false);
    const [selectedResult, setSelectedResult] = useState(null);

    useEffect(() => {
        loadStatus();
        loadResults();
    }, []);

    const loadStatus = async () => {
        try {
            const data = await getMonitorStatus();
            setStatus(data);
        } catch (error) {
            console.error('Error loading status:', error);
        }
    };

    const loadResults = async () => {
        try {
            const data = await getFileResults(0, 50);
            setResults(data.scans || []);
        } catch (error) {
            console.error('Error loading results:', error);
        }
    };

    const handleStart = async () => {
        if (!directory.trim()) {
            alert('Please enter a directory path');
            return;
        }

        try {
            setLoading(true);
            await startMonitoring(directory, true, true);
            await loadStatus();
            alert('Monitoring started successfully!');
        } catch (error) {
            console.error('Error starting monitoring:', error);
            alert('Failed to start monitoring');
        } finally {
            setLoading(false);
        }
    };

    const handleStop = async () => {
        try {
            setLoading(true);
            await stopMonitoring();
            await loadStatus();
            alert('Monitoring stopped');
        } catch (error) {
            console.error('Error stopping monitoring:', error);
            alert('Failed to stop monitoring');
        } finally {
            setLoading(false);
        }
    };

    const handleFileUpload = async (event) => {
        const file = event.target.files[0];
        if (!file) return;

        try {
            setLoading(true);

            const formData = new FormData();
            formData.append('file', file);

            const response = await fetch('http://localhost:8000/api/files/upload', {
                method: 'POST',
                body: formData,
            });

            if (!response.ok) {
                throw new Error('Upload failed');
            }

            const data = await response.json();
            console.log('File scanned:', data);

            // Show detailed results in modal
            setSelectedResult({
                filename: file.name,
                ...data.result,
                scan: data.scan,
            });
            setShowDetailsModal(true);

            // Reload results to show the new scan
            await loadResults();

            // Reset file input
            event.target.value = '';
        } catch (error) {
            console.error('Error uploading file:', error);
            alert('Failed to upload and scan file: ' + error.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="page-container fade-in">
            <div className="page-header">
                <div>
                    <h1>File Monitor</h1>
                    <p className="text-muted">Monitor directories for sensitive data in files</p>
                </div>
                <button className="btn btn-secondary" onClick={loadResults}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="23 4 23 10 17 10"></polyline>
                        <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
                    </svg>
                    Refresh
                </button>
            </div>

            <div className="upload-section glass-card">
                <div className="section-header">
                    <h2>Upload & Scan File</h2>
                    <span className="badge badge-low">Quick Scan</span>
                </div>
                <div className="upload-area">
                    <div className="upload-icon">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="17 8 12 3 7 8"></polyline>
                            <line x1="12" y1="3" x2="12" y2="15"></line>
                        </svg>
                    </div>
                    <h3>Upload a file to scan</h3>
                    <p className="text-muted">Supports: TXT, PDF, DOCX, CSV, LOG, MD</p>
                    <label htmlFor="file-upload" className="btn btn-primary">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="17 8 12 3 7 8"></polyline>
                            <line x1="12" y1="3" x2="12" y2="15"></line>
                        </svg>
                        Choose File
                    </label>
                    <input
                        id="file-upload"
                        type="file"
                        accept=".txt,.pdf,.docx,.csv,.log,.md"
                        onChange={handleFileUpload}
                        style={{ display: 'none' }}
                        disabled={loading}
                    />
                    <p className="text-sm text-muted mt-sm">File will be scanned immediately after upload</p>
                </div>
            </div>

            <div className="monitor-controls glass-card">
                <div className="control-header">
                    <h2>Monitoring Controls</h2>
                    {status && (
                        <span className={`status-badge ${status.is_running ? 'active' : 'inactive'}`}>
                            {status.is_running ? 'Active' : 'Inactive'}
                        </span>
                    )}
                </div>

                <div className="control-form">
                    <div className="form-group">
                        <label>Directory Path</label>
                        <input
                            type="text"
                            placeholder="e.g., ./monitored_files or C:\Documents"
                            value={directory}
                            onChange={(e) => setDirectory(e.target.value)}
                            disabled={status?.is_running}
                        />
                        <p className="text-sm text-muted">Enter the absolute or relative path to monitor</p>
                    </div>

                    <div className="control-buttons">
                        <button
                            className="btn btn-primary"
                            onClick={handleStart}
                            disabled={loading || status?.is_running}
                        >
                            {loading ? <div className="loading"></div> : 'Start Monitoring'}
                        </button>
                        <button
                            className="btn btn-danger"
                            onClick={handleStop}
                            disabled={loading || !status?.is_running}
                        >
                            Stop Monitoring
                        </button>
                    </div>

                    {status?.monitored_paths && status.monitored_paths.length > 0 && (
                        <div className="monitored-paths">
                            <p className="text-sm font-semibold">Currently Monitoring:</p>
                            <ul>
                                {status.monitored_paths.map((path, index) => (
                                    <li key={index}>{path}</li>
                                ))}
                            </ul>
                        </div>
                    )}
                </div>
            </div>

            <div className="scan-results glass-card">
                <div className="section-header">
                    <h2>Scan Results</h2>
                    <span className="badge">{results.length} Files</span>
                </div>

                {results.length === 0 ? (
                    <div className="empty-state">
                        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                            <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                            <polyline points="13 2 13 9 20 9"></polyline>
                        </svg>
                        <h3>No Scans Yet</h3>
                        <p>Start monitoring a directory to see file scan results</p>
                    </div>
                ) : (
                    <div className="results-table">
                        <table>
                            <thead>
                                <tr>
                                    <th>File Path</th>
                                    <th>Scan Time</th>
                                    <th>Size</th>
                                    <th>Findings</th>
                                    <th>Risk</th>
                                </tr>
                            </thead>
                            <tbody>
                                {results.map((scan) => (
                                    <tr key={scan.id}>
                                        <td className="file-path">{scan.file_path}</td>
                                        <td>{new Date(scan.scan_time).toLocaleString()}</td>
                                        <td>{(scan.file_size / 1024).toFixed(2)} KB</td>
                                        <td>{scan.findings_count}</td>
                                        <td>
                                            <RiskBadge level={scan.highest_risk} />
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {showDetailsModal && selectedResult && (
                <div className="modal-overlay" onClick={() => setShowDetailsModal(false)}>
                    <div className="modal-content glass-card details-modal" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h2>Scan Results: {selectedResult.filename}</h2>
                            <button className="modal-close" onClick={() => setShowDetailsModal(false)}>
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <line x1="18" y1="6" x2="6" y2="18"></line>
                                    <line x1="6" y1="6" x2="18" y2="18"></line>
                                </svg>
                            </button>
                        </div>

                        <div className="details-content">
                            <div className="details-summary">
                                <div className="summary-row">
                                    <span className="label">Risk Level:</span>
                                    <RiskBadge level={selectedResult.risk_level} />
                                </div>
                                <div className="summary-row">
                                    <span className="label">Classification:</span>
                                    <span className="value">{selectedResult.classification}</span>
                                </div>
                                <div className="summary-row">
                                    <span className="label">Action:</span>
                                    <span className={`value action-${selectedResult.action?.toLowerCase()}`}>
                                        {selectedResult.action}
                                    </span>
                                </div>
                                <div className="summary-row">
                                    <span className="label">Risk Score:</span>
                                    <span className="value">{selectedResult.risk_score}/100</span>
                                </div>
                            </div>

                            <div className="risk-bar">
                                <div
                                    className={`risk-fill risk-${selectedResult.risk_level?.toLowerCase()}`}
                                    style={{ width: `${selectedResult.risk_score}%` }}
                                ></div>
                            </div>

                            <div className="details-section">
                                <h3>🔍 What Was Detected</h3>
                                <div className="detection-reasons">
                                    {selectedResult.reasons && selectedResult.reasons.length > 0 ? (
                                        <ul>
                                            {selectedResult.reasons.map((reason, idx) => (
                                                <li key={idx} className="reason-item">
                                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                        <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                                                    </svg>
                                                    {reason}
                                                </li>
                                            ))}
                                        </ul>
                                    ) : (
                                        <p className="text-muted">No specific threats detected</p>
                                    )}
                                </div>
                            </div>

                            {selectedResult.patterns_found && Object.keys(selectedResult.patterns_found).length > 0 && (
                                <div className="details-section">
                                    <h3>🎯 Sensitive Patterns Found</h3>
                                    <div className="patterns-grid">
                                        {Object.entries(selectedResult.patterns_found).map(([pattern, count]) => (
                                            <div key={pattern} className="pattern-card">
                                                <div className="pattern-name">{pattern.replace(/_/g, ' ').toUpperCase()}</div>
                                                <div className="pattern-count">{count} occurrence{count > 1 ? 's' : ''}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {selectedResult.ml_assist && (
                                <div className="details-section">
                                    <h3>🤖 ML Analysis</h3>
                                    <div className="ml-details">
                                        <div className="ml-row">
                                            <span className="label">Confidence:</span>
                                            <span className="value">{(selectedResult.ml_assist.confidence * 100).toFixed(1)}%</span>
                                        </div>
                                        <div className="ml-row">
                                            <span className="label">Prediction:</span>
                                            <span className="value">
                                                {selectedResult.ml_assist.pred_label === 0 && 'SAFE'}
                                                {selectedResult.ml_assist.pred_label === 1 && 'SENSITIVE'}
                                                {selectedResult.ml_assist.pred_label === 2 && 'HIGHLY CONFIDENTIAL'}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            )}

                            <div className="details-section">
                                <h3>📋 Input Preview</h3>
                                <div className="input-preview">
                                    <pre>{selectedResult.input_text?.substring(0, 500)}{selectedResult.input_text?.length > 500 ? '...' : ''}</pre>
                                </div>
                            </div>

                            <div className="modal-actions">
                                <button className="btn btn-secondary" onClick={() => setShowDetailsModal(false)}>
                                    Close
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

export default FileMonitor;
