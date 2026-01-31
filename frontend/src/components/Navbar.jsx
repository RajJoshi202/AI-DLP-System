import './Navbar.css';

function Navbar({ onMenuClick }) {
    return (
        <nav className="navbar">
            <div className="navbar-content">
                <div className="navbar-left">
                    <button className="menu-btn" onClick={onMenuClick} aria-label="Toggle menu">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <line x1="3" y1="12" x2="21" y2="12"></line>
                            <line x1="3" y1="6" x2="21" y2="6"></line>
                            <line x1="3" y1="18" x2="21" y2="18"></line>
                        </svg>
                    </button>
                    <div className="navbar-brand">
                        <div className="brand-icon">
                            <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
                                <rect width="32" height="32" rx="8" fill="url(#gradient)" />
                                <path d="M16 8L22 12V20L16 24L10 20V12L16 8Z" stroke="white" strokeWidth="2" fill="none" />
                                <defs>
                                    <linearGradient id="gradient" x1="0" y1="0" x2="32" y2="32">
                                        <stop offset="0%" stopColor="#6366f1" />
                                        <stop offset="100%" stopColor="#8b5cf6" />
                                    </linearGradient>
                                </defs>
                            </svg>
                        </div>
                        <div className="brand-text">
                            <h1 className="brand-title">AI-DLP System</h1>
                            <p className="brand-subtitle">Data Loss Prevention</p>
                        </div>
                    </div>
                </div>
                <div className="navbar-right">
                    <div className="status-indicator">
                        <span className="status-dot"></span>
                        <span className="status-text">Backend Active</span>
                    </div>
                </div>
            </div>
        </nav>
    );
}

export default Navbar;
