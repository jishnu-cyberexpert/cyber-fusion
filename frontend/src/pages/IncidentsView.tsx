import React, { useState, useEffect } from 'react';
import {
  AlertOctagon,
  ShieldCheck,
  ShieldAlert,
  Clock,
  User,
  Laptop,
  Network,
  FileCode,
  MessageSquare,
  ChevronRight,
  CheckCircle,
  Hash
} from 'lucide-react';
import { Incident } from '../types';
import { api } from '../services/api';

interface IncidentsViewProps {
  incidents: Incident[];
  onRefresh: () => void;
}

export const IncidentsView: React.FC<IncidentsViewProps> = ({ incidents, onRefresh }) => {
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(incidents[0]?.incident_id || null);
  const [detail, setDetail] = useState<any | null>(null);
  const [newNote, setNewNote] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (selectedIncidentId) {
      loadDetail(selectedIncidentId);
    }
  }, [selectedIncidentId]);

  const loadDetail = async (id: string) => {
    try {
      const data = await api.getIncidentDetail(id);
      setDetail(data);
    } catch (err) {
      console.error(err);
    }
  };

  const handleStatusChange = async (status: string) => {
    if (!selectedIncidentId) return;
    setLoading(true);
    try {
      await api.updateIncidentStatus(selectedIncidentId, status);
      await loadDetail(selectedIncidentId);
      onRefresh();
    } finally {
      setLoading(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim() || !selectedIncidentId) return;
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/v1/incidents/${selectedIncidentId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: newNote })
      });
      if (res.ok) {
        setNewNote('');
        loadDetail(selectedIncidentId);
      }
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div>
        <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc' }}>
          Incident Response & Digital Forensics Case Management
        </h1>
        <p style={{ fontSize: '0.8rem', color: '#64748b' }}>
          Enterprise lifecycle: Detection → Triage → Investigation → Containment → Eradication → Closure
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.8fr', gap: '20px', minHeight: '680px' }}>
        {/* Left: Incident Queue */}
        <div className="soc-card" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#94a3b8', letterSpacing: '0.5px', fontFamily: 'var(--font-mono)' }}>
            CORRELATED CASE QUEUE ({incidents.length})
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', overflowY: 'auto', maxHeight: '680px' }}>
            {incidents.length === 0 ? (
              <div style={{ padding: '40px 20px', textAlign: 'center', color: '#64748b', fontSize: '0.82rem' }}>
                No active security incidents in this environment mode.
              </div>
            ) : (
              incidents.map((inc) => {
                const isSelected = inc.incident_id === selectedIncidentId;
                return (
                  <div
                    key={inc.incident_id}
                    onClick={() => setSelectedIncidentId(inc.incident_id)}
                    style={{
                      padding: '12px 14px',
                      background: isSelected ? 'rgba(6, 182, 212, 0.12)' : 'rgba(12, 16, 29, 0.6)',
                      border: isSelected ? '1px solid #06b6d4' : '1px solid #1a233a',
                      borderRadius: '6px',
                      cursor: 'pointer',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span className={`badge badge-${inc.severity.toLowerCase()}`}>
                        {inc.severity}
                      </span>
                      <span className="code-font" style={{ fontSize: '0.72rem', color: '#38bdf8' }}>
                        {inc.status}
                      </span>
                    </div>

                    <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f1f5f9' }}>
                      {inc.title}
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                      <span>{inc.incident_id}</span>
                      <span>{new Date(inc.created_at * 1000).toLocaleTimeString()}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right: Detailed Case File */}
        {detail ? (
          <div className="soc-card" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {/* Header & Status Actions */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid #1a233a', paddingBottom: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                  <span className={`badge badge-${detail.severity.toLowerCase()}`}>
                    {detail.severity}
                  </span>
                  <span className="code-font" style={{ color: '#64748b', fontSize: '0.8rem' }}>
                    {detail.incident_id}
                  </span>
                </div>
                <h2 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#fff' }}>
                  {detail.title}
                </h2>
                <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '4px' }}>
                  {detail.description}
                </p>
              </div>

              {/* Status transition dropdown / buttons */}
              <div style={{ display: 'flex', gap: '8px' }}>
                {detail.status !== 'CONTAINED' && detail.status !== 'CLOSED' && (
                  <button
                    className="btn-danger"
                    disabled={loading}
                    onClick={() => handleStatusChange('CONTAINED')}
                    style={{ fontSize: '0.75rem', padding: '6px 12px' }}
                  >
                    Contain Incident
                  </button>
                )}
                {detail.status !== 'CLOSED' ? (
                  <button
                    className="btn-primary"
                    disabled={loading}
                    onClick={() => handleStatusChange('CLOSED')}
                    style={{ fontSize: '0.75rem', padding: '6px 12px' }}
                  >
                    Close Case
                  </button>
                ) : (
                  <button
                    className="btn-secondary"
                    disabled={loading}
                    onClick={() => handleStatusChange('INVESTIGATING')}
                    style={{ fontSize: '0.75rem', padding: '6px 12px' }}
                  >
                    Reopen Case
                  </button>
                )}
              </div>
            </div>

            {/* Entity Graph Context */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
              <div style={{ background: '#0c101d', border: '1px solid #1a233a', borderRadius: '6px', padding: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#64748b', fontSize: '0.72rem', marginBottom: '4px' }}>
                  <Laptop size={14} /> HOSTS
                </div>
                <div className="code-font" style={{ color: '#38bdf8', fontSize: '0.82rem', fontWeight: 600 }}>
                  {detail.entities?.hosts?.join(', ') || 'None identified'}
                </div>
              </div>

              <div style={{ background: '#0c101d', border: '1px solid #1a233a', borderRadius: '6px', padding: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#64748b', fontSize: '0.72rem', marginBottom: '4px' }}>
                  <User size={14} /> IDENTITIES
                </div>
                <div className="code-font" style={{ color: '#a78bfa', fontSize: '0.82rem', fontWeight: 600 }}>
                  {detail.entities?.users?.join(', ') || 'None identified'}
                </div>
              </div>

              <div style={{ background: '#0c101d', border: '1px solid #1a233a', borderRadius: '6px', padding: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#64748b', fontSize: '0.72rem', marginBottom: '4px' }}>
                  <Network size={14} /> NETWORK / IPS
                </div>
                <div className="code-font" style={{ color: '#34d399', fontSize: '0.82rem', fontWeight: 600 }}>
                  {detail.entities?.ips?.join(', ') || 'None identified'}
                </div>
              </div>
            </div>

            {/* Correlated Detections Timeline */}
            <div>
              <h3 style={{ fontSize: '0.88rem', fontWeight: 700, color: '#f8fafc', marginBottom: '10px' }}>
                Correlated Telemetry Detections ({detail.alerts?.length || 0})
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {detail.alerts?.map((alt: any) => (
                  <div
                    key={alt.alert_id}
                    style={{
                      background: 'rgba(12, 16, 29, 0.5)',
                      border: '1px solid #1a233a',
                      padding: '10px 14px',
                      borderRadius: '6px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center'
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.82rem', color: '#e2e8f0' }}>{alt.title}</div>
                      <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>{alt.mitre_tactic} • {alt.mitre_technique}</div>
                    </div>
                    <span className={`badge badge-${alt.severity.toLowerCase()}`}>
                      {alt.severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Analyst Case Notes Thread */}
            <div style={{ marginTop: 'auto' }}>
              <h3 style={{ fontSize: '0.88rem', fontWeight: 700, color: '#f8fafc', marginBottom: '10px' }}>
                Analyst Collaboration Notes ({detail.notes?.length || 0})
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '160px', overflowY: 'auto', marginBottom: '10px' }}>
                {detail.notes?.map((n: any) => (
                  <div key={n.id} style={{ background: '#060910', padding: '8px 12px', borderRadius: '4px', border: '1px solid #1a233a' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: '#64748b' }}>
                      <strong style={{ color: '#06b6d4' }}>{n.author}</strong>
                      <span>{new Date(n.timestamp * 1000).toLocaleTimeString()}</span>
                    </div>
                    <div style={{ color: '#cbd5e1', fontSize: '0.78rem', marginTop: '3px' }}>{n.note}</div>
                  </div>
                ))}
              </div>

              <form onSubmit={handleAddNote} style={{ display: 'flex', gap: '8px' }}>
                <input
                  type="text"
                  placeholder="Add case investigation note..."
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  style={{
                    flex: 1,
                    background: '#060910',
                    border: '1px solid #232f4c',
                    color: '#f8fafc',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    fontSize: '0.8rem',
                    outline: 'none'
                  }}
                />
                <button type="submit" className="btn-primary" style={{ padding: '8px 16px' }}>
                  Post Note
                </button>
              </form>
            </div>
          </div>
        ) : (
          <div className="soc-card" style={{ padding: '40px', textAlign: 'center', color: '#64748b' }}>
            Select an incident from the queue to view full forensics, entity graphs, and containment actions.
          </div>
        )}
      </div>
    </div>
  );
};
