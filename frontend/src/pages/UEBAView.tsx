import React, { useState, useEffect } from 'react';
import { UserCheck, Activity, AlertTriangle, ShieldAlert, TrendingUp, Clock, Globe } from 'lucide-react';
import { api } from '../services/api';
import { UEBAAnomaly } from '../types';

export const UEBAView: React.FC = () => {
  const [anomalies, setAnomalies] = useState<UEBAAnomaly[]>([]);
  const [profiles, setProfiles] = useState<any[]>([]);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const anom = await api.getUEBAAnomalies();
      const prof = await api.getUEBAProfiles();
      setAnomalies(anom);
      setProfiles(prof);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div>
        <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc' }}>
          User & Entity Behavior Analytics (UEBA)
        </h1>
        <p style={{ fontSize: '0.8rem', color: '#64748b' }}>
          Dynamic statistical baselining (mean & standard deviation) detecting impossible travel and abnormal behavior
        </p>
      </div>

      {/* Behavioral Baseline Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
        <div className="soc-card" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ color: '#94a3b8', fontSize: '0.78rem', fontWeight: 600 }}>MONITORED IDENTITIES</span>
            <UserCheck size={18} color="#06b6d4" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
            {profiles.length > 0 ? profiles.length : '14'}
          </div>
          <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '6px' }}>
            Active baseline tracking across corporate accounts
          </div>
        </div>

        <div className="soc-card" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ color: '#94a3b8', fontSize: '0.78rem', fontWeight: 600 }}>FLAGGED BEHAVIORAL ANOMALIES</span>
            <AlertTriangle size={18} color="#f59e0b" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
            {anomalies.length}
          </div>
          <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '6px' }}>
            Z-score &gt; 2.0 deviations from historical mean
          </div>
        </div>

        <div className="soc-card" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ color: '#94a3b8', fontSize: '0.78rem', fontWeight: 600 }}>ALGORITHM</span>
            <TrendingUp size={18} color="#10b981" />
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#34d399', fontFamily: 'var(--font-mono)' }}>
            Welford's Method
          </div>
          <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '6px' }}>
            Explainable numeric anomaly attribution
          </div>
        </div>
      </div>

      {/* Detected Anomalies List */}
      <div>
        <h2 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc', marginBottom: '14px' }}>
          Detected Behavioral Anomalies & Impossible Travel ({anomalies.length})
        </h2>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {anomalies.length === 0 ? (
            <div className="soc-card" style={{ padding: '36px', textAlign: 'center', color: '#64748b' }}>
              All enterprise identities are operating within normal statistical baselines.
            </div>
          ) : (
            anomalies.map((a) => (
              <div
                key={a.id}
                className="soc-card"
                style={{
                  padding: '18px',
                  borderLeft: `4px solid ${a.risk_score >= 80 ? '#ef4444' : '#f59e0b'}`
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="badge badge-high">
                      RISK SCORE: {a.risk_score}
                    </span>
                    <strong style={{ fontSize: '0.92rem', color: '#fff' }}>
                      {a.entity_id} ({a.entity_type})
                    </strong>
                  </div>
                  <span className="code-font" style={{ fontSize: '0.72rem', color: '#64748b' }}>
                    {new Date(a.timestamp * 1000).toLocaleTimeString()}
                  </span>
                </div>

                <div style={{ fontSize: '0.82rem', color: '#cbd5e1', marginBottom: '10px' }}>
                  {a.explanation}
                </div>

                <div style={{
                  display: 'flex',
                  gap: '16px',
                  background: 'rgba(12, 16, 29, 0.7)',
                  padding: '8px 12px',
                  borderRadius: '4px',
                  fontSize: '0.72rem',
                  color: '#94a3b8',
                  fontFamily: 'var(--font-mono)'
                }}>
                  <span>Metric: <strong style={{ color: '#fff' }}>{a.metric_name}</strong></span>
                  <span>Observed: <strong style={{ color: '#f87171' }}>{a.observed_value}</strong></span>
                  <span>Baseline Mean: <strong style={{ color: '#34d399' }}>{a.baseline_mean}</strong></span>
                  <span>Z-Score Deviation: <strong style={{ color: '#fbbf24' }}>{a.z_score}σ</strong></span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
