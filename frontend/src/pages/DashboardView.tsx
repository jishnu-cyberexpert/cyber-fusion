import React from 'react';
import {
  ShieldAlert,
  Laptop,
  Activity,
  Layers,
  Clock,
  ArrowUpRight,
  ExternalLink,
  Flame,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import { Incident, Alert, SecurityEvent, SystemHealth, EnvironmentMode } from '../types';

interface DashboardViewProps {
  mode: EnvironmentMode;
  health: SystemHealth | null;
  incidents: Incident[];
  alerts: Alert[];
  recentEvents: SecurityEvent[];
  endpointsCount: number;
  onNavigate: (tab: any) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  mode,
  health,
  incidents,
  alerts,
  recentEvents,
  endpointsCount,
  onNavigate
}) => {
  const criticalIncidents = incidents.filter(i => i.severity === 'CRITICAL');
  const openIncidents = incidents.filter(i => i.status !== 'CLOSED');

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner Notice regarding Mode & Real Data */}
      <div style={{
        background: mode === 'LIVE' ? 'rgba(16, 185, 129, 0.08)' : 'rgba(245, 158, 11, 0.08)',
        border: `1px solid ${mode === 'LIVE' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`,
        borderRadius: '8px',
        padding: '12px 18px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className={mode === 'LIVE' ? 'pulse-green' : 'pulse-red'} />
          <div>
            <span style={{
              fontWeight: 800,
              fontSize: '0.85rem',
              color: mode === 'LIVE' ? '#34d399' : '#fbbf24',
              fontFamily: 'var(--font-mono)'
            }}>
              DATA PLANE MODE: {mode}
            </span>
            <span style={{ color: '#94a3b8', fontSize: '0.8rem', marginLeft: '10px' }}>
              {mode === 'LIVE'
                ? 'Consuming strictly real telemetry from enrolled host infrastructure and active network collectors.'
                : 'Isolated laboratory simulation mode. LAB events are segregated from production metrics.'}
            </span>
          </div>
        </div>
        <div style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
          NO FAKE METRICS ENFORCED
        </div>
      </div>

      {/* Primary KPI Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        {/* Card 1: Real EPS */}
        <div className="soc-card" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ color: '#94a3b8', fontSize: '0.78rem', fontWeight: 600 }}>LIVE INGESTION RATE</span>
            <Activity size={18} color="#06b6d4" />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
            <span style={{ fontSize: '2rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
              {health?.pipeline.measured_eps ?? '0.0'}
            </span>
            <span style={{ fontSize: '0.8rem', color: '#06b6d4', fontWeight: 700 }}>EPS</span>
          </div>
          <div style={{ marginTop: '8px', fontSize: '0.72rem', color: '#64748b' }}>
            Total Ingested: <strong style={{ color: '#e2e8f0' }}>{health?.pipeline.total_ingested ?? 0}</strong> events
          </div>
        </div>

        {/* Card 2: Active Endpoints */}
        <div className="soc-card" style={{ padding: '18px', cursor: 'pointer' }} onClick={() => onNavigate('edr')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ color: '#94a3b8', fontSize: '0.78rem', fontWeight: 600 }}>FLEET ENDPOINTS</span>
            <Laptop size={18} color="#10b981" />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
            <span style={{ fontSize: '2rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
              {endpointsCount}
            </span>
            <span style={{ fontSize: '0.8rem', color: '#10b981', fontWeight: 700 }}>ONLINE</span>
          </div>
          <div style={{ marginTop: '8px', fontSize: '0.72rem', color: '#64748b' }}>
            Host Telemetry Streaming Active
          </div>
        </div>

        {/* Card 3: Active Incidents */}
        <div className="soc-card" style={{ padding: '18px', cursor: 'pointer' }} onClick={() => onNavigate('incidents')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ color: '#94a3b8', fontSize: '0.78rem', fontWeight: 600 }}>ACTIVE INCIDENTS</span>
            <ShieldAlert size={18} color={criticalIncidents.length > 0 ? '#ef4444' : '#f59e0b'} />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
            <span style={{ fontSize: '2rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
              {openIncidents.length}
            </span>
            {criticalIncidents.length > 0 && (
              <span className="badge badge-critical" style={{ fontSize: '0.7rem' }}>
                {criticalIncidents.length} CRITICAL
              </span>
            )}
          </div>
          <div style={{ marginTop: '8px', fontSize: '0.72rem', color: '#64748b' }}>
            Correlated across multi-domain telemetry
          </div>
        </div>

        {/* Card 4: Detection Pipeline Latency */}
        <div className="soc-card" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ color: '#94a3b8', fontSize: '0.78rem', fontWeight: 600 }}>PROCESSING LATENCY</span>
            <Clock size={18} color="#a78bfa" />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
            <span style={{ fontSize: '2rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
              {health?.pipeline.avg_latency_ms ?? '0.0'}
            </span>
            <span style={{ fontSize: '0.8rem', color: '#a78bfa', fontWeight: 700 }}>ms</span>
          </div>
          <div style={{ marginTop: '8px', fontSize: '0.72rem', color: '#64748b' }}>
            Queue Depth: <strong style={{ color: '#e2e8f0' }}>{health?.pipeline.queue_depth ?? 0}</strong>
          </div>
        </div>
      </div>

      {/* Main Grid: Live Incidents & Live Alert Stream */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '20px' }}>
        {/* Left: Correlated Security Incidents */}
        <div className="soc-card" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div>
              <h2 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc' }}>
                Correlated Security Incidents
              </h2>
              <p style={{ fontSize: '0.75rem', color: '#64748b' }}>
                Cross-domain incidents linked by entity graph analysis (EDR, NDR, IAM, WAF)
              </p>
            </div>
            <button className="btn-secondary" onClick={() => onNavigate('incidents')}>
              View All Cases
            </button>
          </div>

          {incidents.length === 0 ? (
            <div style={{ padding: '40px 20px', textAlign: 'center', color: '#64748b' }}>
              <CheckCircle2 size={36} color="#10b981" style={{ margin: '0 auto 12px auto' }} />
              <div style={{ fontWeight: 600, color: '#e2e8f0', marginBottom: '4px' }}>No Active Incidents in {mode} Mode</div>
              <div style={{ fontSize: '0.8rem' }}>All telemetry is nominal and below alert thresholds.</div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {incidents.slice(0, 5).map((inc) => (
                <div
                  key={inc.incident_id}
                  onClick={() => onNavigate('incidents')}
                  style={{
                    background: 'rgba(12, 16, 29, 0.7)',
                    border: '1px solid #1a233a',
                    borderRadius: '6px',
                    padding: '14px',
                    cursor: 'pointer',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    transition: 'all 0.15s ease'
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.borderColor = '#2d3b5e')}
                  onMouseLeave={(e) => (e.currentTarget.style.borderColor = '#1a233a')}
                >
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className={`badge badge-${inc.severity.toLowerCase()}`}>
                        {inc.severity}
                      </span>
                      <span style={{ fontWeight: 700, fontSize: '0.88rem', color: '#f1f5f9' }}>
                        {inc.title}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                      {inc.description}
                    </div>
                    <div style={{ display: 'flex', gap: '12px', fontSize: '0.72rem', color: '#64748b', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                      <span>ID: {inc.incident_id}</span>
                      <span>Assignee: {inc.assignee}</span>
                      <span>Status: <strong style={{ color: '#38bdf8' }}>{inc.status}</strong></span>
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {inc.mitre_tactics && inc.mitre_tactics.length > 0 && (
                      <span className="badge badge-medium">
                        {inc.mitre_tactics[0]}
                      </span>
                    )}
                    <ExternalLink size={16} color="#64748b" />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Live Triggered Alerts Feed */}
        <div className="soc-card" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div>
              <h2 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc' }}>
                Detection Engine Alerts
              </h2>
              <p style={{ fontSize: '0.75rem', color: '#64748b' }}>
                Sigma & IOC rule matches in real-time
              </p>
            </div>
            <span style={{ fontSize: '0.72rem', color: '#06b6d4', fontFamily: 'var(--font-mono)' }}>
              LIVE STREAM
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', overflowY: 'auto', maxHeight: '420px' }}>
            {alerts.length === 0 ? (
              <div style={{ padding: '30px', textAlign: 'center', color: '#64748b', fontSize: '0.82rem' }}>
                Awaiting real-time detection events...
              </div>
            ) : (
              alerts.slice(0, 8).map((alt) => (
                <div
                  key={alt.alert_id}
                  style={{
                    padding: '10px 12px',
                    background: 'rgba(12, 16, 29, 0.5)',
                    borderLeft: `3px solid ${
                      alt.severity === 'CRITICAL' ? '#ef4444' : alt.severity === 'HIGH' ? '#f59e0b' : '#06b6d4'
                    }`,
                    borderRadius: '0 6px 6px 0',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#e2e8f0' }}>
                      {alt.title}
                    </span>
                    <span className={`badge badge-${alt.severity.toLowerCase()}`}>
                      {alt.severity}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.73rem', color: '#94a3b8' }}>
                    {alt.description}
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.68rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                    <span>Target: {alt.affected_host || alt.source_ip || 'Internal'}</span>
                    <span>{alt.mitre_technique}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Bottom: Live Telemetry Stream Inspector (OCSF/ECS Unified Data Plane) */}
      <div className="soc-card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <div>
            <h2 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc' }}>
              Real-Time Security Data Plane Feed
            </h2>
            <p style={{ fontSize: '0.75rem', color: '#64748b' }}>
              Normalized ECS/OCSF telemetry streaming directly from live host agents & collectors
            </p>
          </div>
          <button className="btn-secondary" onClick={() => onNavigate('siem')}>
            Open SIEM Console
          </button>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>SOURCE</th>
                <th>CATEGORY</th>
                <th>HOST</th>
                <th>PROCESS / ENTITY</th>
                <th>NETWORK CONNS</th>
                <th>STATUS</th>
              </tr>
            </thead>
            <tbody>
              {recentEvents.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '24px', color: '#64748b' }}>
                    Connecting to live telemetry data plane stream...
                  </td>
                </tr>
              ) : (
                recentEvents.slice(0, 8).map((ev, idx) => (
                  <tr key={ev.event_uuid || idx}>
                    <td className="code-font" style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
                      {new Date(ev.timestamp * 1000).toLocaleTimeString()}
                    </td>
                    <td>
                      <span className="badge badge-info">{ev.data_source}</span>
                    </td>
                    <td style={{ color: '#cbd5e1', fontWeight: 500 }}>{ev.category}</td>
                    <td className="code-font" style={{ color: '#38bdf8' }}>{ev.hostname || 'Localhost'}</td>
                    <td className="code-font" style={{ maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {ev.process ? `${ev.process} (PID:${ev.pid})` : ev.user || '-'}
                    </td>
                    <td className="code-font" style={{ fontSize: '0.72rem' }}>
                      {ev.source_ip ? `${ev.source_ip} -> ${ev.dest_ip || 'local'}` : '-'}
                    </td>
                    <td>
                      {ev.is_alert ? (
                        <span className="badge badge-high">ALERT</span>
                      ) : (
                        <span style={{ color: '#10b981', fontSize: '0.72rem', fontWeight: 600 }}>NORMALIZED</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
