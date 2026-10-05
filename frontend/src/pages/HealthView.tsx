import React from 'react';
import { Activity, Cpu, HardDrive, Database, Radio, CheckCircle, RefreshCw, AlertTriangle } from 'lucide-react';
import { SystemHealth } from '../types';

interface HealthViewProps {
  health: SystemHealth | null;
  onRefresh: () => void;
}

export const HealthView: React.FC<HealthViewProps> = ({ health, onRefresh }) => {
  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc' }}>
            Infrastructure Health & Observability Metrics
          </h1>
          <p style={{ fontSize: '0.8rem', color: '#64748b' }}>
            Real measured CPU, memory, event bus queues, and pipeline processing performance
          </p>
        </div>
        <button className="btn-secondary" onClick={onRefresh}>
          <RefreshCw size={14} /> Refresh Metrics
        </button>
      </div>

      {/* Hardware Gauge Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        <div className="soc-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
            <span style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 600 }}>HOST CPU USAGE</span>
            <Cpu size={18} color="#06b6d4" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
            {health?.system.cpu_percent ?? 0}%
          </div>
          <div style={{ height: '6px', background: '#1e293b', borderRadius: '3px', marginTop: '10px', overflow: 'hidden' }}>
            <div style={{
              height: '100%',
              width: `${health?.system.cpu_percent ?? 0}%`,
              background: 'linear-gradient(90deg, #06b6d4, #3b82f6)'
            }} />
          </div>
        </div>

        <div className="soc-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
            <span style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 600 }}>MEMORY UTILIZATION</span>
            <HardDrive size={18} color="#10b981" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
            {health?.system.memory_percent ?? 0}%
          </div>
          <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '4px' }}>
            {health?.system.memory_used_mb ?? 0} MB consumed
          </div>
        </div>

        <div className="soc-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
            <span style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 600 }}>STORAGE VOLUME</span>
            <Database size={18} color="#a78bfa" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
            {health?.system.disk_percent ?? 0}%
          </div>
          <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '4px' }}>
            {health?.system.disk_free_gb ?? 0} GB available
          </div>
        </div>

        <div className="soc-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
            <span style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 600 }}>SYSTEM UPTIME</span>
            <Activity size={18} color="#f59e0b" />
          </div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
            {Math.round((health?.uptime_seconds ?? 0) / 60)} min
          </div>
          <div style={{ fontSize: '0.72rem', color: '#10b981', marginTop: '6px' }}>
            High-Availability Daemon Online
          </div>
        </div>
      </div>

      {/* Real-time Pipeline Performance Metrics */}
      <div className="soc-card" style={{ padding: '24px' }}>
        <h2 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc', marginBottom: '16px' }}>
          Real-Time Streaming Bus Performance (Measured Telemetry)
        </h2>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
          <div style={{ background: '#0c101d', border: '1px solid #1a233a', padding: '16px', borderRadius: '6px' }}>
            <div style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: '4px' }}>MEASURED EPS</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#06b6d4', fontFamily: 'var(--font-mono)' }}>
              {health?.pipeline.measured_eps ?? 0}
            </div>
            <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Real-time window calculation</div>
          </div>

          <div style={{ background: '#0c101d', border: '1px solid #1a233a', padding: '16px', borderRadius: '6px' }}>
            <div style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: '4px' }}>QUEUE DEPTH</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#10b981', fontFamily: 'var(--font-mono)' }}>
              {health?.pipeline.queue_depth ?? 0}
            </div>
            <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Max limit: {health?.pipeline.max_queue_size}</div>
          </div>

          <div style={{ background: '#0c101d', border: '1px solid #1a233a', padding: '16px', borderRadius: '6px' }}>
            <div style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: '4px' }}>AVG PROCESSING LATENCY</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>
              {health?.pipeline.avg_latency_ms ?? 0} ms
            </div>
            <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Ingest to Alert dispatch</div>
          </div>

          <div style={{ background: '#0c101d', border: '1px solid #1a233a', padding: '16px', borderRadius: '6px' }}>
            <div style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: '4px' }}>DEAD LETTER QUEUE (DLQ)</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 800, color: (health?.pipeline.dlq_depth ?? 0) > 0 ? '#ef4444' : '#64748b', fontFamily: 'var(--font-mono)' }}>
              {health?.pipeline.dlq_depth ?? 0}
            </div>
            <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Failed / malformed events</div>
          </div>
        </div>
      </div>
    </div>
  );
};
