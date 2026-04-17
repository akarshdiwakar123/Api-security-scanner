import { useState, useEffect } from 'react';
import axios from 'axios';
import { History as HistoryIcon, Trash2, Download } from 'lucide-react';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export default function History() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  const hdrs = { Authorization: `Bearer ${localStorage.getItem('token')}` };

  const fetchScans = async () => {
    try {
      const res = await axios.get(`${API_URL}/scans`, { headers: hdrs });
      setScans(res.data);
    } catch(e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const handleDelete = async (id) => {
    if(!window.confirm('Delete this scan record?')) return;
    try {
      await axios.delete(`${API_URL}/scans/${id}`, { headers: hdrs });
      setScans(scans.filter(s => s.id !== id));
    } catch(e) {
      alert('Failed to delete scan.');
    }
  };

  const downloadPDF = async (id) => {
    try {
      const res = await axios.get(`${API_URL}/scans/${id}/report.pdf`, {
        headers: hdrs, responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `Security_Report_${id}.pdf`);
      document.body.appendChild(link);
      link.click();
    } catch(e) {
      alert("Failed to download PDF");
    }
  };

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6 flex items-center gap-2">
        <HistoryIcon className="text-neon-blue" />
        Scan History
      </h1>

      <div className="glass-panel" style={{ overflow: 'hidden' }}>
        {loading ? (
          <div className="p-8 text-center text-secondary">Loading history...</div>
        ) : scans.length === 0 ? (
          <div className="p-8 text-center text-secondary">No previous scans found.</div>
        ) : (
          <table className="w-full text-left" style={{ borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: 'rgba(0,0,0,0.2)' }}>
                <th className="p-4 border-b border-white/10">ID</th>
                <th className="p-4 border-b border-white/10">Target</th>
                <th className="p-4 border-b border-white/10">Date</th>
                <th className="p-4 border-b border-white/10">Threats Found</th>
                <th className="p-4 border-b border-white/10 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map(s => (
                <tr key={s.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)', transition: 'background 0.2s' }} className="hover:bg-white/5">
                  <td className="p-4 font-semibold text-secondary">#{s.id}</td>
                  <td className="p-4">
                    <div>{s.target}</div>
                    <div className="text-sm text-secondary">{s.endpoint}</div>
                  </td>
                  <td className="p-4 text-sm text-secondary">{new Date(s.scanned_at).toLocaleString()}</td>
                  <td className="p-4">
                    <div className="flex gap-2 text-sm">
                      <span className="text-neon-red px-2 py-1 rounded bg-red-500/10">H: {s.high}</span>
                      <span className="text-neon-warn px-2 py-1 rounded bg-yellow-500/10">M: {s.medium}</span>
                      <span className="text-neon-green px-2 py-1 rounded bg-green-500/10">L: {s.low}</span>
                    </div>
                  </td>
                  <td className="p-4 text-right flex justify-end gap-2">
                    <button className="p-2 rounded bg-blue-500/10 text-neon-blue hover:bg-blue-500/20" title="Download Report" onClick={() => downloadPDF(s.id)}>
                      <Download size={16} />
                    </button>
                    <button className="p-2 rounded bg-red-500/10 text-neon-red hover:bg-red-500/20" title="Delete Scan" onClick={() => handleDelete(s.id)}>
                      <Trash2 size={16} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
