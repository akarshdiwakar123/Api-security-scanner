import { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { Shield } from 'lucide-react';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export default function Auth({ setToken }) {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [username, setUsername] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    try {
      const endpoint = isLogin ? '/auth/login' : '/auth/register';
      const payload = isLogin ? { email, password } : { email, username, password };
      
      const res = await axios.post(`${API_URL}${endpoint}`, payload);
      const token = res.data.access_token;
      
      localStorage.setItem('token', token);
      setToken(token);
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.detail || 'Authentication failed');
    }
  };

  return (
    <div className="auth-container">
      <div className="glass-panel p-8 text-center" style={{ maxWidth: '400px', width: '100%' }}>
        <Shield size={48} className="text-neon-blue mx-auto mb-4" />
        <h2 className="text-2xl font-bold mb-6">API Security Scanner</h2>
        
        {error && <div className="mb-4 p-3 rounded" style={{ background: 'rgba(239, 68, 68, 0.2)', border: '1px solid rgba(239, 68, 68, 0.5)', color: 'var(--neon-red)' }}>{error}</div>}
        
        <form onSubmit={handleSubmit} style={{ textAlign: 'left' }}>
          {!isLogin && (
            <div>
              <label>Username</label>
              <input 
                type="text" 
                className="input-field" 
                value={username} onChange={e => setUsername(e.target.value)} required 
              />
            </div>
          )}
          <div>
            <label>Email Address</label>
            <input 
              type="email" 
              className="input-field" 
              value={email} onChange={e => setEmail(e.target.value)} required 
            />
          </div>
          <div>
            <label>Security Key (Password)</label>
            <input 
              type="password" 
              className="input-field" 
              value={password} onChange={e => setPassword(e.target.value)} required minLength={8}
            />
          </div>
          
          <button type="submit" className="btn w-full mt-4">
            {isLogin ? 'CONNECT TO SECURE RELAY' : 'INITIALIZE SYSTEM ACCOUNT'}
          </button>
        </form>
        
        <p className="mt-6 text-sm text-secondary">
          {isLogin ? 'No active clearance?' : 'Already initialized?'} 
          <span 
            className="text-neon-blue cursor-pointer ml-2" 
            style={{ fontWeight: '600' }}
            onClick={() => setIsLogin(!isLogin)}
          >
            {isLogin ? 'Request Access' : 'Sign In'}
          </span>
        </p>
      </div>
    </div>
  );
}
