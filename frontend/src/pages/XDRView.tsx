import React from 'react';
import { Layers, Network, Laptop, User, ShieldAlert, ArrowRight, Share2, Workflow } from 'lucide-react';
import { Incident } from '../types';

interface XDRViewProps {
  incidents: Incident[];
}

export const XDRView: React.FC<XDRViewProps> = ({ incidents }) => {
  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div>
        <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc' }}>
          Cross-Domain XDR Correlation Engine
        </h1>
        <p style={{ fontSize: '0.8rem', color: '#64748b' }}>
          Correlates signals across EDR + NDR + Identity + Cloud + WAF + DLP into unified incidents using entity graph relationships
        </p>
      </div>

      {/* Cross-Domain Pipeline Visualizer */}
      <div className="soc-card" style={{ padding: '24px' }}>
        <h2 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', marginBottom: '16px' }}>
          Multi-Domain Correlation Pipeline Architecture
        </h2>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(5, 1fr)',
          gap: '12px',
          alignItems: 'center'
        }}>
          <div style={{ background: '#0c101d', border: '1px solid #1a233a', padding: '14px', borderRadius: '6px', textAlign: 'center' }}>
            <Laptop size={20} color="#06b6d4" style={{ margin: '0 auto 6px auto' }} />
            <div style={{ fontWeight: 700, fontSize: '0.82rem', color: '#fff' }}>1. EDR Signal</div>
            <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Process spawn / LSASS access on Host</div>
          </div>

          <div style={{ background: '#0c101d', border: '1px solid #1a233a', padding: '14px', borderRadius: '6px', textAlign: 'center' }}>
            <Network size={20} color="#10b981" style={{ margin: '0 auto 6px auto' }} />
            <div style={{ fontWeight: 700, fontSize: '0.82rem', color: '#fff' }}>2. NDR Telemetry</div>
            <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Outbound C2 connection on TCP 443</div>
          </div>

          <div style={{ background: '#0c101d', border: '1px solid #1a233a', padding: '14px', borderRadius: '6px', textAlign: 'center' }}>
            <User size={20} color="#a78bfa" style={{ margin: '0 auto 6px auto' }} />
            <div style={{ fontWeight: 700, fontSize: '0.82rem', color: '#fff' }}>3. Identity / IAM</div>
            <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Failed login burst or impossible travel</div>
          </div>

          <div style={{ background: '#0c101d', border: '1px solid #1a233a', padding: '14px', borderRadius: '6px', textAlign: 'center' }}>
            <Share2 size={20} color="#f59e0b" style={{ margin: '0 auto 6px auto' }} />
            <div style={{ fontWeight: 700, fontSize: '0.82rem', color: '#fff' }}>4. Entity Intersect</div>
            <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Graph matching on Host + User + IP</div>
          </div>

          <div style={{ background: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.4)', padding: '14px', borderRadius: '6px', textAlign: 'center' }}>
            <ShieldAlert size={20} color="#ef4444" style={{ margin: '0 auto 6px auto' }} />
            <div style={{ fontWeight: 700, fontSize: '0.82rem', color: '#f87171' }}>5. Unified Incident</div>
            <div style={{ fontSize: '0.7rem', color: '#fca5a5' }}>Contextual risk & automated playbooks</div>
          </div>
        </div>
      </div>

      {/* Active Correlated Incidents Graph Cards */}
      <div>
        <h2 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc', marginBottom: '14px' }}>
          Active Correlated Incidents ({incidents.length})
        </h2>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {incidents.length === 0 ? (
            <div className="soc-card" style={{ padding: '36px', textAlign: 'center', color: '#64748b' }}>
              No multi-domain incidents currently active. As detections occur across hosts, network, and identities, the XDR graph engine links them here.
            </div>
          ) : (
            incidents.map((inc) => (
              <div key={inc.incident_id} className="soc-card" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span className={`badge badge-${inc.severity.toLowerCase()}`}>
                      {inc.severity}
                    </span>
                    <span style={{ fontWeight: 800, fontSize: '0.95rem', color: '#fff' }}>
                      {inc.title}
                    </span>
                  </div>
                  <span className="code-font" style={{ fontSize: '0.75rem', color: '#38bdf8' }}>
                    {inc.incident_id}
                  </span>
                </div>

                <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '14px' }}>
                  {inc.description}
                </div>

                {/* Correlated Entities Pill Graph */}
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: 600 }}>GRAPH ENTITIES:</span>
                  {inc.entities.hosts?.map((h) => (
                    <span key={h} className="badge badge-low" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Laptop size={12} /> Host: {h}
                    </span>
                  ))}
                  {inc.entities.users?.map((u) => (
                    <span key={u} className="badge badge-medium" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <User size={12} /> Identity: {u}
                    </span>
                  ))}
                  {inc.entities.ips?.map((ip) => (
                    <span key={ip} className="badge badge-high" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Network size={12} /> IP: {ip}
                    </span>
                  ))}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
