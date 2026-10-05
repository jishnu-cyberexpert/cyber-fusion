import React, { useState } from 'react';
import {
  Laptop,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  HardDrive,
  RefreshCw,
  Terminal,
  AlertTriangle,
  Play,
  CheckCircle2,
  XCircle
} from 'lucide-react';
import { Endpoint } from '../types';
import { api } from '../services/api';

interface EDRViewProps {
  endpoints: Endpoint[];
  onRefresh: () => void;
}

export const EDRView: React.FC<EDRViewProps> = ({ endpoints, onRefresh }) => {
  const [selectedAgent, setSelectedAgent] = useState<Endpoint | null>(endpoints[0] || null);
  const [actionLoading, setActionLoading] = useState(false);
  const [feedbackMessage, setFeedbackMessage] = useState<string | null>(null);

  const handleIsolate = async (agent: Endpoint, isolate: boolean) => {
    setActionLoading(true);
    setFeedbackMessage(null);
    try {
      const action = isolate ? 'ISOLATE_ENDPOINT' : 'DEISOLATE_ENDPOINT';
      const res = await api.dispatchEndpointTask(agent.agent_id, action, {
        hostname: agent.hostname,
        policy: 'soc_quarantine_enforcement'
      });
      setFeedbackMessage(
        isolate
          ? `Host ${agent.hostname} isolated. Network lockdown command dispatched to live agent.`
          : `Host ${agent.hostname} de-isolated. Normal communications restored.`
      );
      onRefresh();
    } catch (err: any) {
      setFeedbackMessage(`Error dispatching action: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc' }}>
            Endpoint Detection & Response (EDR) Fleet
          </h1>
          <p style={{ fontSize: '0.8rem', color: '#64748b' }}>
            Real-time enrolled host monitoring, active telemetry ingestion, and authorized containment
          </p>
        </div>
        <button className="btn-secondary" onClick={onRefresh} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <RefreshCw size={14} /> Refresh Fleet
        </button>
      </div>

      {feedbackMessage && (
        <div style={{
          background: 'rgba(6, 182, 212, 0.12)',
          border: '1px solid rgba(6, 182, 212, 0.4)',
          borderRadius: '6px',
          padding: '10px 16px',
          color: '#38bdf8',
          fontSize: '0.82rem',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <CheckCircle2 size={16} />
          {feedbackMessage}
        </div>
      )}

      {/* Endpoint Fleet Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: '16px' }}>
        {endpoints.map((ep) => {
          const isSelected = selectedAgent?.agent_id === ep.agent_id;
          const isOnline = ep.status === 'ONLINE' || ep.status === 'ISOLATED';
          const isIsolated = ep.isolation_status || ep.status === 'ISOLATED';

          return (
            <div
              key={ep.agent_id}
              className="soc-card"
              style={{
                padding: '20px',
                border: isSelected ? '1px solid #06b6d4' : isIsolated ? '1px solid #ef4444' : '1px solid #1a233a',
                display: 'flex',
                flexDirection: 'column',
                gap: '14px',
                cursor: 'pointer'
              }}
              onClick={() => setSelectedAgent(ep)}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{
                    width: '42px',
                    height: '42px',
                    borderRadius: '8px',
                    background: isIsolated ? 'rgba(239, 68, 68, 0.15)' : 'rgba(6, 182, 212, 0.15)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <Laptop size={22} color={isIsolated ? '#ef4444' : '#06b6d4'} />
                  </div>
                  <div>
                    <div style={{ fontWeight: 800, fontSize: '0.98rem', color: '#f8fafc' }}>
                      {ep.hostname}
                    </div>
                    <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                      {ep.ip_address} • {ep.os_type}
                    </div>
                  </div>
                </div>

                <span className={`badge ${isIsolated ? 'badge-critical' : isOnline ? 'badge-low' : 'badge-info'}`}>
                  {isIsolated ? 'ISOLATED' : ep.status}
                </span>
              </div>

              {/* Hardware & Agent Info */}
              <div style={{
                background: 'rgba(12, 16, 29, 0.6)',
                borderRadius: '6px',
                padding: '10px 14px',
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: '8px',
                fontSize: '0.73rem',
                fontFamily: 'var(--font-mono)'
              }}>
                <div>
                  <span style={{ color: '#64748b' }}>Agent ID:</span>
                  <div style={{ color: '#cbd5e1', fontWeight: 600 }}>{ep.agent_id}</div>
                </div>
                <div>
                  <span style={{ color: '#64748b' }}>Agent Ver:</span>
                  <div style={{ color: '#cbd5e1', fontWeight: 600 }}>{ep.agent_version}</div>
                </div>
                <div>
                  <span style={{ color: '#64748b' }}>CPU Usage:</span>
                  <div style={{ color: '#10b981', fontWeight: 600 }}>{ep.cpu_percent}%</div>
                </div>
                <div>
                  <span style={{ color: '#64748b' }}>Last Heartbeat:</span>
                  <div style={{ color: '#38bdf8', fontWeight: 600 }}>{ep.last_seen_seconds_ago}s ago</div>
                </div>
              </div>

              {/* Interactive Response Controls */}
              <div style={{ display: 'flex', gap: '10px', marginTop: '4px' }}>
                {isIsolated ? (
                  <button
                    className="btn-secondary"
                    disabled={actionLoading}
                    onClick={(e) => {
                      e.stopPropagation();
                      handleIsolate(ep, false);
                    }}
                    style={{ flex: 1, justifyContent: 'center' }}
                  >
                    <ShieldCheck size={14} color="#10b981" /> Restore Network Access
                  </button>
                ) : (
                  <button
                    className="btn-danger"
                    disabled={actionLoading}
                    onClick={(e) => {
                      e.stopPropagation();
                      handleIsolate(ep, true);
                    }}
                    style={{ flex: 1, justifyContent: 'center' }}
                  >
                    <ShieldAlert size={14} /> Isolate Endpoint
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Selected Endpoint Deep Dive Panel */}
      {selectedAgent && (
        <div className="soc-card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f8fafc' }}>
                Live Forensic Inspection: {selectedAgent.hostname}
              </h3>
              <p style={{ fontSize: '0.75rem', color: '#64748b' }}>
                Streaming telemetry collected by CyberFusion Agent on {selectedAgent.os_type} ({selectedAgent.os_version})
              </p>
            </div>
            <div className="badge badge-info">
              MAC: {selectedAgent.mac_address}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '16px' }}>
            <div style={{ background: '#0c101d', padding: '14px', borderRadius: '6px', border: '1px solid #1a233a' }}>
              <div style={{ color: '#64748b', fontSize: '0.75rem', marginBottom: '4px' }}>PROCESS MONITORING</div>
              <div style={{ color: '#10b981', fontWeight: 700, fontSize: '0.9rem' }}>ACTIVE (HOOKED)</div>
              <div style={{ color: '#94a3b8', fontSize: '0.7rem', marginTop: '4px' }}>Captures process create, ppid, cmdline</div>
            </div>
            <div style={{ background: '#0c101d', padding: '14px', borderRadius: '6px', border: '1px solid #1a233a' }}>
              <div style={{ color: '#64748b', fontSize: '0.75rem', marginBottom: '4px' }}>SOCKET MONITORING</div>
              <div style={{ color: '#10b981', fontWeight: 700, fontSize: '0.9rem' }}>ACTIVE (TCP/UDP)</div>
              <div style={{ color: '#94a3b8', fontSize: '0.7rem', marginTop: '4px' }}>Inspects outbound connections & DNS</div>
            </div>
            <div style={{ background: '#0c101d', padding: '14px', borderRadius: '6px', border: '1px solid #1a233a' }}>
              <div style={{ color: '#64748b', fontSize: '0.75rem', marginBottom: '4px' }}>CONTAINMENT ENFORCEMENT</div>
              <div style={{ color: selectedAgent.isolation_status ? '#ef4444' : '#06b6d4', fontWeight: 700, fontSize: '0.9rem' }}>
                {selectedAgent.isolation_status ? 'ISOLATION ACTIVE' : 'READY FOR DISPATCH'}
              </div>
              <div style={{ color: '#94a3b8', fontSize: '0.7rem', marginTop: '4px' }}>Mutual TLS token authentication</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
