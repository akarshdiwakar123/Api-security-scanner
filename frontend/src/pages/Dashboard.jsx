import { useState, useEffect } from 'react';
import axios from 'axios';
import { Pie } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Terminal } from 'lucide-react';

ChartJS.register(ArcElement, Tooltip, Legend);

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

function ScanForm({ onScanStart }) {
  const [url, setUrl] = useState('');
  const [endpoint, setEndpoint] = useState('');
  const [token, setToken] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    try {
      const hdrs = { Authorization: `Bearer ${localStorage.getItem('token')}` };
      const res = await axios.post(`${API_URL}/scan`, {
        url, endpoint, token, persist: true
      }, { headers: hdrs });
      
      onScanStart(res.data.scan_id, res.data.task_id);
    } catch (err) {
      if (err.response?.status === 402) {
        // Redirect to billing or show billing error
        try {
          const checkoutRes = await axios.post(`${API_URL}/billing/checkout`, {}, {
            headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
          });
          window.location.href = checkoutRes.data.checkout_url;
        } catch (e) {
          setError("Billing error: Cannot process upgrade right now.");
        }
      } else {
        setError(err.response?.data?.detail || "Failed to start scan");
      }
    }
  };

  return (
    <div className="glass-panel p-8 mb-6">
      <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
        <Terminal size={24} className="text-neon-blue" />
        Configure Scan Target
      </h2>
      
      {error && <div className="mb-4 p-3 rounded" style={{ background: 'rgba(239, 68, 68, 0.2)', border: '1px solid rgba(239, 68, 68, 0.5)', color: 'var(--neon-red)' }}>{error}</div>}
      
      <form onSubmit={handleSubmit} className="grid-2">
        <div>
          <label>Target Base URL</label>
          <input type="text" className="input-field" placeholder="https://api.example.com" value={url} onChange={e => setUrl(e.target.value)} required />
        </div>
        <div>
          <label>Target Endpoint</label>
          <input type="text" className="input-field" placeholder="/v1/users/1" value={endpoint} onChange={e => setEndpoint(e.target.value)} required />
        </div>
        <div style={{ gridColumn: 'span 2' }}>
          <label>Bearer Token (Optional)</label>
          <input type="password" className="input-field" placeholder="ey..." value={token} onChange={e => setToken(e.target.value)} />
        </div>
        <div style={{ gridColumn: 'span 2' }}>
          <button type="submit" className="btn w-full">INITIATE SECURITY SCAN</button>
        </div>
      </form>
    </div>
  );
}

function ScanResults({ statusData, findings }) {
  const data = {
    labels: ['HIGH', 'MEDIUM', 'LOW'],
    datasets: [{
      data: [statusData.high, statusData.medium, statusData.low],
      backgroundColor: ['#ef4444', '#eab308', '#10b981'],
      borderColor: '#0f172a',
      borderWidth: 2,
    }]
  };
  
  const hdrs = { Authorization: `Bearer ${localStorage.getItem('token')}` };

  const downloadPDF = async () => {
    try {
      const res = await axios.get(`${API_URL}/scans/${statusData.scan_id}/report.pdf`, {
        headers: hdrs, responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `Security_Report_${statusData.scan_id}.pdf`);
      document.body.appendChild(link);
      link.click();
    } catch(e) {
      alert("Failed to download PDF");
    }
  };

  return (
    <div className="glass-panel p-8">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-xl font-bold">Scan Complete (ID: {statusData.scan_id})</h2>
        <button className="btn btn-secondary" onClick={downloadPDF}>Download PDF Report</button>
      </div>

      <div className="grid-4 mb-8">
        <div className="metric-card m-total glass-panel">
          <div className="text-sm font-semibold text-secondary">TOTAL THREATS</div>
          <div className="metric-value">{statusData.total}</div>
        </div>
        <div className="metric-card m-high glass-panel">
          <div className="text-sm font-semibold text-secondary">HIGH RISK</div>
          <div className="metric-value text-neon-red">{statusData.high}</div>
        </div>
        <div className="metric-card m-medium glass-panel">
          <div className="text-sm font-semibold text-secondary">MEDIUM RISK</div>
          <div className="metric-value text-neon-warn">{statusData.medium}</div>
        </div>
        <div className="metric-card m-low glass-panel">
          <div className="text-sm font-semibold text-secondary">LOW RISK</div>
          <div className="metric-value text-neon-green">{statusData.low}</div>
        </div>
      </div>

      {statusData.total > 0 && (
        <div className="grid-2 mb-8">
          <div className="glass-panel p-4 flex justify-center items-center">
            <div style={{ width: '250px' }}>
              <Pie data={data} options={{ plugins: { legend: { labels: { color: '#fff' } } } }} />
            </div>
          </div>
          <div className="glass-panel p-4" style={{ maxHeight: '300px', overflowY: 'auto' }}>
            <h3 className="font-bold mb-4 border-b border-white/10 pb-2">Detected Vulnerabilities</h3>
            {findings.map((f, i) => (
              <div key={i} className="mb-4">
                <div className="flex gap-2 items-center mb-1">
                  <span className={`badge ${f.severity}`}>{f.severity}</span>
                  <span className="font-semibold">{f.title}</span>
                </div>
                <div className="text-sm text-secondary mb-1">Endpoint: {f.endpoint}</div>
                <div className="text-sm">{f.description}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      
      {statusData.total === 0 && (
        <div className="p-4 text-center rounded bg-green-500/10 text-neon-green border border-green-500/20">
          No vulnerabilities were detected on the target endpoint.
        </div>
      )}
    </div>
  );
}

export default function Dashboard() {
  const [scanId, setScanId] = useState(null);
  const [status, setStatus] = useState('idle'); // idle, polling, completed, failed
  const [statusData, setStatusData] = useState(null);
  const [findings, setFindings] = useState([]);
  
  const hdrs = { Authorization: `Bearer ${localStorage.getItem('token')}` };

  const startPolling = (sid) => {
    setScanId(sid);
    setStatus('polling');
  };

  useEffect(() => {
    let interval;
    if (status === 'polling' && scanId) {
      interval = setInterval(async () => {
        try {
          const res = await axios.get(`${API_URL}/scan/status/${scanId}`, { headers: hdrs });
          if (res.data.status === 'completed') {
            setStatusData(res.data);
            
            // Fetch findings
            const vRes = await axios.get(`${API_URL}/scans/${scanId}`, { headers: hdrs });
            setFindings(vRes.data);
            setStatus('completed');
            clearInterval(interval);
          } else if (res.data.status === 'failed') {
            setStatus('failed');
            clearInterval(interval);
          }
        } catch(e) {
          console.error(e);
        }
      }, 2000);
    }
    return () => clearInterval(interval);
  }, [status, scanId]);

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Target Overview</h1>
      <ScanForm onScanStart={startPolling} />
      
      {status === 'polling' && (
        <div className="glass-panel p-8 text-center">
          <div className="text-xl mb-4 text-neon-blue">Scan queued in background workers...</div>
          <div className="text-sm text-secondary">Awaiting completion of Scan #{scanId}</div>
        </div>
      )}
      
      {status === 'failed' && (
        <div className="glass-panel p-8 text-center" style={{ borderColor: 'var(--neon-red)' }}>
          <div className="text-xl text-neon-red">Scan Failed</div>
        </div>
      )}
      
      {status === 'completed' && statusData && (
        <ScanResults statusData={statusData} findings={findings} />
      )}
    </div>
  );
}
