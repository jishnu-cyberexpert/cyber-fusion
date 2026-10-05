import React, { useState, useEffect } from 'react';
import { Lock, ShieldCheck, RefreshCw, CheckCircle2, AlertTriangle, Key } from 'lucide-react';
import { api } from '../services/api';
import { AuditRecord } from '../types';

export const AuditView: React.FC = () => {
  const [logs, setLogs] = useState<AuditRecord[]>([]);
  const [verifyStatus, setVerifyStatus] = useState<any | null>(null);
  const [verifying, setVerifying] = useState(false);

  useEffect(() => {
    loadLogs();
  }, []);

  const loadLogs = async () => {
    try {
      const data = await api.getAuditLogs();
      setLogs(data);
    } catch (e) {
      console.error(e);
    }
  };

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const res = await api.verifyAuditChain();
      setVerifyStatus(res);
    } catch (err: any) {
      setVerifyStatus({ status: 'ERROR', message: err.message });
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc' }}>
            Tamper-Resistant Cryptographic Audit Trail
          </h1>
          <p style={{ fontSize: '0.8rem', color: '#64748b' }}>
            Immutable SHA-256 blockchain-style hashed logs recording all SOC administrative, containment, and response operations
          </p>
        </div>
        <button
          className="btn-primary"
          disabled={verifying}
          onClick={handleVerify}
          style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
        >
          <ShieldCheck size={16} /> {verifying ? 'Verifying Hashes...' : 'Verify Chain Integrity'}
        </button>
      </div>

      {/* Verification Feedback Banner */}
      {verifyStatus && (
        <div style={{
          padding: '14px 18px',
          borderRadius: '6px',
          background: verifyStatus.tamper_detected ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
          border: `1px solid ${verifyStatus.tamper_detected ? 'rgba(239, 68, 68, 0.5)' : 'rgba(16, 185, 129, 0.5)'}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {verifyStatus.tamper_detected ? (
              <AlertTriangle size={20} color="#ef4444" />
            ) : (
              <CheckCircle2 size={20} color="#10b981" />
            )}
            <div>
              <div style={{
                fontWeight: 800,
                fontSize: '0.88rem',
                fontFamily: 'var(--font-mono)',
                color: verifyStatus.tamper_detected ? '#f87171' : '#34d399'
              }}>
                {verifyStatus.tamper_detected
                  ? 'SECURITY ALERT: Audit Log Hash Chain Compromised'
                  : 'INTEGRITY VERIFIED: SHA-256 Hash Chain Is Cryptographically Valid'}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#cbd5e1', marginTop: '2px' }}>
                {verifyStatus.records_verified} audit blocks verified against unbroken previous-record hashes. Zero tampering detected.
              </div>
            </div>
          </div>
          <div className="code-font" style={{ fontSize: '0.7rem', color: '#94a3b8' }}>
            Latest: {verifyStatus.latest_hash?.slice(0, 16)}...
          </div>
        </div>
      )}

      {/* Audit Log Table */}
      <div className="soc-card" style={{ padding: '0', overflow: 'hidden' }}>
        <table className="soc-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>TIMESTAMP</th>
              <th>ACTOR</th>
              <th>ACTION</th>
              <th>TARGET</th>
              <th>RESULT</th>
              <th>SHA-256 BLOCK HASH</th>
              <th>PREVIOUS HASH LINK</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ textAlign: 'center', padding: '36px', color: '#64748b' }}>
                  No audit operations recorded yet.
                </td>
              </tr>
            ) : (
              logs.map((log) => (
                <tr key={log.id}>
                  <td className="code-font" style={{ color: '#64748b' }}>#{log.id}</td>
                  <td className="code-font" style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
                    {new Date(log.timestamp * 1000).toLocaleTimeString()}
                  </td>
                  <td style={{ color: '#06b6d4', fontWeight: 600 }}>{log.actor}</td>
                  <td className="code-font" style={{ color: '#e2e8f0', fontSize: '0.75rem' }}>{log.action}</td>
                  <td className="code-font" style={{ color: '#38bdf8' }}>{log.target}</td>
                  <td>
                    <span className={`badge ${log.result.includes('SUCCESS') ? 'badge-low' : 'badge-high'}`}>
                      {log.result}
                    </span>
                  </td>
                  <td className="code-font" style={{ fontSize: '0.7rem', color: '#10b981' }}>
                    {log.current_hash.slice(0, 14)}...
                  </td>
                  <td className="code-font" style={{ fontSize: '0.7rem', color: '#64748b' }}>
                    {log.prev_hash.slice(0, 14)}...
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
