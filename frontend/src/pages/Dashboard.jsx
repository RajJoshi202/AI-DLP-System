import { useState, useEffect } from 'react';
import StatsCard from '../components/StatsCard';
import RiskBadge from '../components/RiskBadge';
import { getStats, getTimeline } from '../services/api';
import './Dashboard.css';

function Dashboard() {
    const [stats, setStats] = useState(null);
    const [timeline, setTimeline] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadDashboardData();
    }, []);

    const loadDashboardData = async () => {
        try {
            setLoading(true);
            const [statsData, timelineData] = await Promise.all([
                getStats(),
                getTimeline(10),
            ]);
            setStats(statsData);
            setTimeline(timelineData.timeline || []);
        } catch (error) {
            console.error('Error loading dashboard data:', error);
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return (
            <div className="page-container">
                <div className="loading-container">
                    <div className="loading"></div>
                    <p>Loading dashboard...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="page-container fade-in">
            <div className="page-header">
                <div>
                    <h1>Dashboard</h1>
                    <p className="text-muted">Overview of your DLP system activity</p>
                </div>
                <button className="btn btn-primary" onClick={loadDashboardData}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="23 4 23 10 17 10"></polyline>
                        <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
                    </svg>
                    Refresh
                </button>
            </div>

            <div className="stats-grid grid grid-4">
                <StatsCard
                    title="Total Alerts"
                    value={stats?.total_alerts || 0}
                    color="primary"
                    icon={
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
                            <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
                        </svg>
                    }
                />
                <StatsCard
                    title="High Risk"
                    value={stats?.high_risk_alerts || 0}
                    color="danger"
                    icon={
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path>
                            <line x1="12" y1="9" x2="12" y2="13"></line>
                            <line x1="12" y1="17" x2="12.01" y2="17"></line>
                        </svg>
                    }
                />
                <StatsCard
                    title="Medium Risk"
                    value={stats?.medium_risk_alerts || 0}
                    color="warning"
                    icon={
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="12" y1="8" x2="12" y2="12"></line>
                            <line x1="12" y1="16" x2="12.01" y2="16"></line>
                        </svg>
                    }
                />
                <StatsCard
                    title="File Scans"
                    value={stats?.total_file_scans || 0}
                    color="success"
                    icon={
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                            <polyline points="13 2 13 9 20 9"></polyline>
                        </svg>
                    }
                />
            </div>

            <div className="dashboard-content">
                <div className="dashboard-section glass-card">
                    <div className="section-header">
                        <h2>Recent Activity</h2>
                        <span className="badge">{timeline.length} Events</span>
                    </div>
                    <div className="timeline-container">
                        {timeline.length === 0 ? (
                            <div className="empty-state">
                                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                                    <circle cx="12" cy="12" r="10"></circle>
                                    <line x1="12" y1="8" x2="12" y2="12"></line>
                                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                                </svg>
                                <h3>No Activity Yet</h3>
                                <p>Start analyzing text or monitoring files to see activity here</p>
                            </div>
                        ) : (
                            <div className="timeline-list">
                                {timeline.map((event, index) => (
                                    <div key={index} className="timeline-item">
                                        <div className="timeline-marker">
                                            <div className={`marker-dot ${event.risk_level?.toLowerCase()}`}></div>
                                        </div>
                                        <div className="timeline-content">
                                            <div className="timeline-header">
                                                <RiskBadge level={event.risk_level} />
                                                <span className="timeline-time">
                                                    {new Date(event.timestamp).toLocaleString()}
                                                </span>
                                            </div>
                                            <p className="timeline-classification">{event.classification}</p>
                                            <p className="timeline-source text-muted">{event.source}</p>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>

                <div className="dashboard-section glass-card">
                    <div className="section-header">
                        <h2>Quick Actions</h2>
                    </div>
                    <div className="quick-actions">
                        <a href="/analyze" className="action-card">
                            <div className="action-icon">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <circle cx="11" cy="11" r="8"></circle>
                                    <path d="m21 21-4.35-4.35"></path>
                                </svg>
                            </div>
                            <div className="action-content">
                                <h3>Analyze Text</h3>
                                <p>Scan text for sensitive data</p>
                            </div>
                        </a>
                        <a href="/monitor" className="action-card">
                            <div className="action-icon">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                                    <polyline points="13 2 13 9 20 9"></polyline>
                                </svg>
                            </div>
                            <div className="action-content">
                                <h3>Monitor Files</h3>
                                <p>Watch directories for changes</p>
                            </div>
                        </a>
                        <a href="/policies" className="action-card">
                            <div className="action-icon">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                                </svg>
                            </div>
                            <div className="action-content">
                                <h3>Manage Policies</h3>
                                <p>Configure DLP policies</p>
                            </div>
                        </a>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Dashboard;
