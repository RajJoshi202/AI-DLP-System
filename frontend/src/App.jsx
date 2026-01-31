import { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Analyze from './pages/Analyze';
import FileMonitor from './pages/FileMonitor';
import Policies from './pages/Policies';
import Alerts from './pages/Alerts';
import './App.css';

function App() {
    const [sidebarOpen, setSidebarOpen] = useState(true);

    return (
        <Router>
            <div className="app">
                <Navbar onMenuClick={() => setSidebarOpen(!sidebarOpen)} />
                <div className="app-container">
                    <Sidebar isOpen={sidebarOpen} />
                    <main className={`app-main ${sidebarOpen ? 'sidebar-open' : 'sidebar-closed'}`}>
                        <Routes>
                            <Route path="/" element={<Navigate to="/dashboard" replace />} />
                            <Route path="/dashboard" element={<Dashboard />} />
                            <Route path="/analyze" element={<Analyze />} />
                            <Route path="/monitor" element={<FileMonitor />} />
                            <Route path="/policies" element={<Policies />} />
                            <Route path="/alerts" element={<Alerts />} />
                        </Routes>
                    </main>
                </div>
            </div>
        </Router>
    );
}

export default App;
