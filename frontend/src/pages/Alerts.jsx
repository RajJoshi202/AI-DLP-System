import { useState, useEffect } from 'react';
import { getAnalysisHistory } from '../services/api';
import RiskBadge from '../components/RiskBadge';
import './Alerts.css';

function Alerts() {
    const [alerts, setAlerts] = useState([]);
    const [filter, setFilter] = useState('all');
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadAlerts();
    }, [filter]);

    const loadAlerts = async () => {
        try {
            setLoading(true);
            const riskLevel = filter === 'all' ? null : filter.toUpperCase();
            const data = await getAnalysisHistory(0, 100, riskLevel);
            setAlerts(data.alerts || []);
        } catch (error) {
            console.error('Error loading alerts:', error);
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return (
            <div className="page-container">
                <div className="loading-container">
                    <div className="loading"></div>
                    <p>Loading alerts...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="page-container fade-in">
            <div className="page-header">
                <div>
                    <h1>Alerts</h1>
                    <p className="text-muted">View and manage DLP detection alerts</p>
                </div>
                <button className="btn btn-secondary" onClick={loadAlerts}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="23 4 23 10 17 10"></polyline>
                        <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
                    </svg>
                    Refresh
                </button>
            </div>

            <div className="alerts-filters glass-card">
                <div className="filter-buttons">
                    <button
                        className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
                        onClick={() => setFilter('all')}
                    >
                        All Alerts
                    </button>
                    <button
                        className={`filter-btn ${filter === 'high' ? 'active' : ''}`}
                        onClick={() => setFilter('high')}
                    >
                        High Risk
                    </button>
                    <button
                        className={`filter-btn ${filter === 'medium' ? 'active' : ''}`}
                        onClick={() => setFilter('medium')}
                    >
                        Medium Risk
                    </button>
                    <button
                        className={`filter-btn ${filter === 'low' ? 'active' : ''}`}
                        onClick={() => setFilter('low')}
                    >
                        Low Risk
                    </button>
                </div>
            </div>

            <div className="alerts-list">
                {alerts.length === 0 ? (
                    <div className="empty-state glass-card">
                        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
                            <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
                        </svg>
                        <h3>No Alerts Found</h3>
                        <p>No alerts match your current filter</p>
                    </div>
                ) : (
                    alerts.map((alert) => (
                        <div key={alert.id} className="alert-card glass-card">
                            <div className="alert-header">
                                <div className="alert-info">
                                    <RiskBadge level={alert.risk_level} />
                                    <span className="alert-time">
                                        {new Date(alert.timestamp).toLocaleString()}
                                    </span>
                                </div>
                                <span className={`action-badge action-${alert.action?.toLowerCase()}`}>
                                    {alert.action}
                                </span>
                            </div>

                            <div className="alert-content">
                                <h3 className="alert-classification">{alert.classification}</h3>
                                <div className="alert-text">
                                    <p className="text-sm text-muted">Input:</p>
                                    <p className="input-preview">{alert.input_text}</p>
                                </div>

                                <div className="alert-reasons">
                                    <p className="text-sm font-semibold">Reasons:</p>
                                    <ul>
                                        {alert.reasons?.map((reason, idx) => (
                                            <li key={idx}>{reason}</li>
                                        ))}
                                    </ul>
                                </div>

                                <div className="alert-meta">
                                    <span className="meta-item">
                                        <strong>Score:</strong> {alert.risk_score}/100
                                    </span>
                                    <span className="meta-item">
                                        <strong>Source:</strong> {alert.source}
                                    </span>
                                </div>
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}

export default Alerts;
