import React, { useState, useEffect } from 'react';
import { Flame, Search, Globe, Shield, AlertTriangle, CheckCircle, Lock, ExternalLink } from 'lucide-react';
import { api } from '../services/api';
import { ASMAsset } from '../types';

export const ASMView: React.FC = () => {
  const [assets, setAssets] = useState<ASMAsset[]>([]);
  const [scanTarget, setScanTarget] = useState('localhost');
  const [scopeConfirmed, setScopeConfirmed] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanFeedback, setScanFeedback] = useState<any | null>(null);

  useEffect(() => {
    loadAssets();
  }, []);

  const loadAssets = async () => {
    try {
      const data = await api.getASMAssets();
      setAssets(data);
    } catch (e) {
      console.error(e);
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scanTarget.trim()) return;
    setScanning(true);
    setScanFeedback(null);
    try {
      const res = await api.runASMScan(scanTarget);
      setScanFeedback(res.discovery);
      await loadAssets();
    } catch (err: any) {
      setScanFeedback({ error: err.message });
    } finally {
      setScanning(false);
    }
  };

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div>
        <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc' }}>
          Attack Surface Management (ASM)
        </h1>
        <p style={{ fontSize: '0.8rem', color: '#64748b' }}>
          Authorized discovery of domains, exposed services, and SSL certificate posture (Strict scope enforcement)
        </p>
      </div>

      {/* Authorized Scan Trigger Bar */}
      <div className="soc-card" style={{ padding: '20px' }}>
        <h2 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', marginBottom: '8px' }}>
          Run Scoped Attack Surface Exposure Discovery
        </h2>
        <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '14px' }}>
          Performs non-intrusive DNS resolution, port checks (80, 443, 22, 3389, 8080), and SSL certificate validity verification.
        </div>

        <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', gap: '12px' }}>
            <input
              type="text"
              value={scanTarget}
              onChange={(e) => setScanTarget(e.target.value)}
              placeholder="e.g. corp.internal or 127.0.0.1"
              style={{
                flex: 1,
                background: '#060910',
                border: '1px solid #232f4c',
                color: '#fff',
                padding: '8px 12px',
                borderRadius: '6px',
                fontSize: '0.85rem',
                fontFamily: 'var(--font-mono)',
                outline: 'none'
              }}
            />
            <button
              type="submit"
              className="btn-primary"
              disabled={scanning || !scopeConfirmed}
              style={{ padding: '0 24px' }}
            >
              <Search size={14} /> {scanning ? 'Scanning Target...' : 'Inspect Exposure'}
            </button>
          </div>

          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.78rem', color: '#cbd5e1', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={scopeConfirmed}
              onChange={(e) => setScopeConfirmed(e.target.checked)}
            />
            I confirm that this target is within the authorized enterprise audit scope. (Mandatory Policy Gate)
          </label>
        </form>

        {/* Scan Result Output */}
        {scanFeedback && (
          <div style={{
            marginTop: '16px',
            padding: '16px',
            borderRadius: '6px',
            background: 'rgba(12, 16, 29, 0.9)',
            border: '1px solid #232f4c'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div style={{ fontWeight: 700, fontSize: '0.9rem', color: '#fff' }}>
                Exposure Profile: {scanFeedback.target}
              </div>
              <span className={`badge ${scanFeedback.risk_score > 40 ? 'badge-high' : 'badge-low'}`}>
                RISK SCORE: {scanFeedback.risk_score}/100
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', fontSize: '0.76rem', color: '#cbd5e1' }}>
              <div>Resolved IP: <strong style={{ color: '#38bdf8' }}>{scanFeedback.resolved_ip || 'None'}</strong></div>
              <div>Open Ports: <strong style={{ color: '#10b981' }}>{scanFeedback.open_ports?.join(', ') || 'None detected'}</strong></div>
              <div>SSL Expiry: <strong style={{ color: '#fbbf24' }}>{scanFeedback.ssl_info?.notAfter || 'No SSL'}</strong></div>
            </div>
          </div>
        )}
      </div>

      {/* Discovered Assets Table */}
      <div className="soc-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a233a', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f8fafc' }}>
            Discovered Surface Assets ({assets.length})
          </h2>
          <div className="badge badge-info">AUTHORIZED SCOPE ACTIVE</div>
        </div>

        <table className="soc-table">
          <thead>
            <tr>
              <th>TARGET</th>
              <th>TYPE</th>
              <th>RESOLVED IP</th>
              <th>OPEN PORTS</th>
              <th>SSL CERT ISSUER</th>
              <th>EXPOSURE RISK</th>
              <th>LAST AUDITED</th>
            </tr>
          </thead>
          <tbody>
            {assets.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '36px', color: '#64748b' }}>
                  No attack surface assets recorded yet. Use the scanner above to audit authorized domains.
                </td>
              </tr>
            ) : (
              assets.map((a) => (
                <tr key={a.id}>
                  <td className="code-font" style={{ color: '#38bdf8', fontWeight: 600 }}>{a.target}</td>
                  <td>
                    <span className="badge badge-info">{a.type}</span>
                  </td>
                  <td className="code-font">{a.resolved_ip || '-'}</td>
                  <td className="code-font" style={{ color: '#10b981' }}>
                    {a.open_ports.length > 0 ? a.open_ports.join(', ') : 'None'}
                  </td>
                  <td style={{ fontSize: '0.72rem', maxWidth: '220px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {a.ssl_cert_issuer || 'None'}
                  </td>
                  <td>
                    <span className={`badge ${a.risk_score >= 40 ? 'badge-high' : 'badge-low'}`}>
                      {a.risk_score}/100
                    </span>
                  </td>
                  <td className="code-font" style={{ fontSize: '0.7rem', color: '#64748b' }}>
                    {new Date(a.last_scanned * 1000).toLocaleTimeString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
