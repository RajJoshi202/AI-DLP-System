import './StatsCard.css';

function StatsCard({ title, value, icon, trend, color = 'primary' }) {
    return (
        <div className={`stats-card glass-card ${color}`}>
            <div className="stats-header">
                <div className="stats-icon-wrapper">
                    <div className="stats-icon">{icon}</div>
                </div>
                {trend && (
                    <div className={`stats-trend ${trend.direction}`}>
                        <span className="trend-value">{trend.value}</span>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            {trend.direction === 'up' ? (
                                <polyline points="18 15 12 9 6 15"></polyline>
                            ) : (
                                <polyline points="6 9 12 15 18 9"></polyline>
                            )}
                        </svg>
                    </div>
                )}
            </div>
            <div className="stats-content">
                <h3 className="stats-value">{value}</h3>
                <p className="stats-title">{title}</p>
            </div>
        </div>
    );
}

export default StatsCard;
