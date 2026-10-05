import React, { useState, useEffect } from 'react';
import { TestTube2, Play, AlertOctagon, CheckCircle2, ShieldAlert, AlertTriangle } from 'lucide-react';
import { api } from '../services/api';
import { EnvironmentMode } from '../types';

interface LABViewProps {
  currentMode: EnvironmentMode;
  onSwitchToLab: () => void;
}

export const LABView: React.FC<LABViewProps> = ({ currentMode, onSwitchToLab }) => {
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<any | null>(null);

  useEffect(() => {
    loadScenarios();
  }, []);

  const loadScenarios = async () => {
    try {
      const data = await api.getLabScenarios();
      setScenarios(data);
    } catch (e) {
      console.error(e);
    }
  };

  const runSimulation = async (id: string) => {
    setRunning(id);
    setFeedback(null);
    try {
      const res = await api.runLabSimulation(id);
      setFeedback(res);
      if (currentMode !== 'LAB') {
        onSwitchToLab();
      }
    } catch (err: any) {
      setFeedback({ error: err.message });
    } finally {
      setRunning(null);
    }
  };

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Warning Banner */}
      <div style={{
        background: 'rgba(245, 158, 11, 0.1)',
        border: '1px solid rgba(245, 158, 11, 0.4)',
        borderRadius: '8px',
        padding: '16px 20px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <TestTube2 size={24} color="#f59e0b" />
          <div>
            <div style={{ fontWeight: 800, fontSize: '0.92rem', color: '#fbbf24', fontFamily: 'var(--font-mono)' }}>
              LABORATORY TESTING ENVIRONMENT — STRICT ISOLATION ENFORCED
            </div>
            <div style={{ fontSize: '0.78rem', color: '#cbd5e1', marginTop: '2px' }}>
              All simulated attacks, synthetic telemetry, and test events executed here are strictly tagged with <strong>mode: "LAB"</strong>.
              They are completely segregated and will NEVER appear in LIVE production SOC dashboards.
            </div>
          </div>
        </div>
      </div>

      {feedback && (
        <div style={{
          background: 'rgba(16, 185, 129, 0.12)',
          border: '1px solid rgba(16, 185, 129, 0.4)',
          borderRadius: '6px',
          padding: '12px 18px',
          color: '#34d399',
          fontSize: '0.84rem',
          display: 'flex',
          alignItems: 'center',
          gap: '10px'
        }}>
          <CheckCircle2 size={18} />
          <span>
            {feedback.scenario} simulation successfully executed into the LAB data plane ({feedback.events_dispatched} events dispatched).
          </span>
        </div>
      )}

      {/* Scenarios Grid */}
      <div>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#f8fafc', marginBottom: '14px' }}>
          Available Synthetic Attack Scenarios
        </h2>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
          {scenarios.map((sc) => (
            <div
              key={sc.id}
              className="soc-card"
              style={{
                padding: '20px',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px',
                border: '1px solid rgba(245, 158, 11, 0.3)'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="badge badge-high">LAB SCENARIO</span>
                <span className="code-font" style={{ fontSize: '0.7rem', color: '#94a3b8' }}>
                  {sc.event_count} Events
                </span>
              </div>

              <div style={{ fontWeight: 800, fontSize: '0.95rem', color: '#fff' }}>
                {sc.name}
              </div>

              <div style={{ fontSize: '0.78rem', color: '#94a3b8', lineHeight: '1.4' }}>
                {sc.description}
              </div>

              <button
                className="btn-primary"
                disabled={running === sc.id}
                onClick={() => runSimulation(sc.id)}
                style={{
                  marginTop: 'auto',
                  justifyContent: 'center',
                  background: 'linear-gradient(135deg, #d97706, #b45309)',
                  borderColor: 'rgba(245, 158, 11, 0.5)'
                }}
              >
                <Play size={14} /> {running === sc.id ? 'Simulating Attack...' : 'Launch Lab Simulation'}
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
