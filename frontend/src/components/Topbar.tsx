import React from 'react';
import { Shield, Activity, Radio, Database, Building2, AlertTriangle, Cpu, Terminal } from 'lucide-react';
import { EnvironmentMode, SystemHealth } from '../types';

interface TopbarProps {
  mode: EnvironmentMode;
  onModeChange: (mode: EnvironmentMode) => void;
  tenantId: string;
  onTenantChange: (tenant: string) => void;
  health: SystemHealth | null;
  wsConnected: boolean;
}

export const Topbar: React.FC<TopbarProps> = ({
  mode,
  onModeChange,
  tenantId,
  onTenantChange,
  health,
  wsConnected
}) => {
  return (
    <header style={{
      height: '64px',
      background: 'rgba(12, 16, 29, 0.95)',
      backdropFilter: 'blur(16px)',
      borderBottom: '1px solid #1a233a',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 24px',
      position: 'sticky',
      top: 0,
      zIndex: 50
    }}>
      {/* Brand & Platform Identifier */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{
          width: '38px',
          height: '38px',
          borderRadius: '8px',
          background: 'linear-gradient(135deg, #06b6d4, #3b82f6)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 16px rgba(6, 182, 212, 0.4)'
        }}>
          <Shield size={22} color="#fff" />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontWeight: 800, fontSize: '1.05rem', letterSpacing: '0.8px', color: '#fff' }}>
              CYBERFUSION
            </span>
            <span style={{
              background: 'rgba(6, 182, 212, 0.15)',
              border: '1px solid rgba(6, 182, 212, 0.5)',
              color: '#38bdf8',
              fontSize: '0.65rem',
              fontWeight: 700,
              padding: '1px 6px',
              borderRadius: '4px',
              letterSpacing: '0.5px'
            }}>
              XDR ENTERPRISE
            </span>
            <span style={{ color: '#64748b', fontSize: '0.75rem', fontFamily: 'monospace' }}>
              v3.4.0
            </span>
          </div>
          <div style={{ fontSize: '0.72rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>Unified Security Data Plane</span>
            <span style={{ color: '#334155' }}>•</span>
            <span style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <span className="pulse-green" style={{ width: '6px', height: '6px' }} />
              Telemetry Pipeline Active
            </span>
          </div>
        </div>
      </div>

      {/* Center: Environment Mode Switcher (LIVE / LAB / DEMO) */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div style={{
          background: '#060910',
          border: '1px solid #1e293b',
          borderRadius: '24px',
          padding: '3px',
          display: 'flex',
          alignItems: 'center',
          gap: '2px'
        }}>
          {(['LIVE', 'LAB', 'DEMO'] as EnvironmentMode[]).map((m) => {
            const isActive = mode === m;
            let activeColor = '#10b981'; // Green for LIVE
            if (m === 'LAB') activeColor = '#f59e0b'; // Amber for LAB
            if (m === 'DEMO') activeColor = '#8b5cf6'; // Purple for DEMO

            return (
              <button
                key={m}
                onClick={() => onModeChange(m)}
                style={{
                  background: isActive ? (m === 'LIVE' ? 'rgba(16, 185, 129, 0.18)' : m === 'LAB' ? 'rgba(245, 158, 11, 0.18)' : 'rgba(139, 92, 246, 0.18)') : 'transparent',
                  border: isActive ? `1px solid ${activeColor}` : '1px solid transparent',
                  color: isActive ? '#fff' : '#64748b',
                  padding: '4px 14px',
                  borderRadius: '18px',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  fontFamily: 'monospace',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  transition: 'all 0.15s ease'
                }}
              >
                {isActive && (
                  <span style={{
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    background: activeColor,
                    boxShadow: `0 0 8px ${activeColor}`
                  }} />
                )}
                {m}
                {m === 'LIVE' && <span style={{ fontSize: '0.65rem', opacity: 0.8 }}>(REAL DATA)</span>}
                {m === 'LAB' && <span style={{ fontSize: '0.65rem', opacity: 0.8 }}>(SANDBOX)</span>}
              </button>
            );
          })}
        </div>
      </div>

      {/* Right Controls: Real EPS, Latency, Tenant Switcher */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
        {/* Real EPS & Measured Latency */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          background: 'rgba(18, 24, 41, 0.6)',
          border: '1px solid #1a233a',
          padding: '6px 14px',
          borderRadius: '6px',
          fontFamily: 'var(--font-mono)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Activity size={14} color="#06b6d4" />
            <span style={{ color: '#94a3b8', fontSize: '0.72rem' }}>EPS:</span>
            <span style={{ color: '#38bdf8', fontWeight: 700, fontSize: '0.85rem' }}>
              {health?.pipeline.measured_eps ?? '0.0'}
            </span>
          </div>
          <span style={{ color: '#334155' }}>|</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ color: '#94a3b8', fontSize: '0.72rem' }}>LATENCY:</span>
            <span style={{ color: '#10b981', fontWeight: 700, fontSize: '0.85rem' }}>
              {health?.pipeline.avg_latency_ms ?? '0.0'} ms
            </span>
          </div>
          <span style={{ color: '#334155' }}>|</span>
          <div title={wsConnected ? 'Live WebSocket Streaming Active' : 'Connecting to Security Stream...'} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span className={wsConnected ? "pulse-green" : "pulse-red"} />
            <span style={{ fontSize: '0.7rem', color: wsConnected ? '#10b981' : '#ef4444' }}>
              {wsConnected ? 'STREAM' : 'RECONNECT'}
            </span>
          </div>
        </div>

        {/* Multi-Tenant Switcher */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Building2 size={16} color="#94a3b8" />
          <select
            value={tenantId}
            onChange={(e) => onTenantChange(e.target.value)}
            style={{
              background: '#0c101d',
              border: '1px solid #232f4c',
              color: '#e2e8f0',
              padding: '6px 10px',
              borderRadius: '6px',
              fontSize: '0.78rem',
              fontFamily: 'var(--font-mono)',
              cursor: 'pointer',
              outline: 'none'
            }}
          >
            <option value="tenant-enterprise-secops">CyberFusion Global Enterprise SecOps</option>
            <option value="tenant-finance-corp">Apex Financial Services (MDR Customer)</option>
          </select>
        </div>
      </div>
    </header>
  );
};
