import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link, useLocation } from 'react-router-dom';
import { Shield, Activity, History, LogOut } from 'lucide-react';
import Auth from './pages/Auth';
import Dashboard from './pages/Dashboard';
import ScanHistory from './pages/History';

function Sidebar({ onLogout }) {
  const location = useLocation();
  
  return (
    <div className="sidebar glass-panel" style={{ borderTopLeftRadius: 0, borderBottomLeftRadius: 0, border: 'none', borderRight: '1px solid rgba(255,255,255,0.05)' }}>
      <div className="flex items-center gap-4 mb-8 px-4">
        <Shield size={32} className="text-neon-blue" />
        <h1 className="text-xl font-bold">API Scanner</h1>
      </div>
      
      <div style={{ flex: 1 }}>
        <Link to="/" className={`sidebar-link ${location.pathname === '/' ? 'active' : ''}`}>
          <Activity size={20} /> New Scan
        </Link>
        <Link to="/history" className={`sidebar-link ${location.pathname === '/history' ? 'active' : ''}`}>
          <History size={20} /> History
        </Link>
      </div>
      
      <button onClick={onLogout} className="sidebar-link btn-secondary" style={{ border: 'none', background: 'transparent', textAlign: 'left' }}>
        <LogOut size={20} /> Disconnect
      </button>
    </div>
  );
}

function Layout({ onLogout }) {
  return (
    <div className="layout">
      <Sidebar onLogout={onLogout} />
      <div className="main-content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/history" element={<ScanHistory />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </div>
  );
}

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));

  useEffect(() => {
    const handleStorageChange = () => {
      setToken(localStorage.getItem('token'));
    };
    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
  };

  return (
    <BrowserRouter>
      {token ? (
        <Layout onLogout={handleLogout} />
      ) : (
        <Auth setToken={setToken} />
      )}
    </BrowserRouter>
  );
}
