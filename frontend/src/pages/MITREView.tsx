import React, { useState, useEffect } from 'react';
import { ShieldCheck, Layers, Eye, CheckCircle2, AlertOctagon } from 'lucide-react';
import { api } from '../services/api';
import { EnvironmentMode } from '../types';

interface MITREViewProps {
  mode: EnvironmentMode;
}

export const MITREView: React.FC<MITREViewProps> = ({ mode }) => {
  const [matrixData, setMatrixData] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadCoverage();
  }, [mode]);

  const loadCoverage = async () => {
    setLoading(true);
    try {
      const data = await api.getMitreCoverage(mode);
      setMatrixData(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const tacticsList = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact'
  ];

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc' }}>
            MITRE ATT&CK Enterprise Matrix Coverage
          </h1>
          <p style={{ fontSize: '0.8rem', color: '#64748b' }}>
            Interactive heatmap reflecting only verified production detection rules and real observed events ({mode} Mode)
          </p>
        </div>
        <div className="badge badge-low">
          ATT&CK v14.1 ALIGNED
        </div>
      </div>

      {/* Heatmap Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(6, 1fr)',
        gap: '12px',
        overflowX: 'auto'
      }}>
        {tacticsList.map((tactic) => {
          const rulesInTactic = matrixData?.matrix?.[tactic] || [];
          const hasDetections = rulesInTactic.some((r: any) => r.detections_count > 0);

          return (
            <div
              key={tactic}
              style={{
                background: '#0c101d',
                border: '1px solid #1a233a',
                borderRadius: '6px',
                display: 'flex',
                flexDirection: 'column',
                minHeight: '400px'
              }}
            >
              <div style={{
                background: hasDetections ? 'rgba(239, 68, 68, 0.2)' : 'rgba(18, 24, 41, 0.95)',
                borderBottom: '1px solid #1a233a',
                padding: '10px',
                borderTopLeftRadius: '6px',
                borderTopRightRadius: '6px'
              }}>
                <div style={{
                  fontSize: '0.75rem',
                  fontWeight: 800,
                  color: hasDetections ? '#f87171' : '#cbd5e1',
                  textAlign: 'center',
                  fontFamily: 'var(--font-mono)'
                }}>
                  {tactic}
                </div>
                <div style={{ textAlign: 'center', fontSize: '0.65rem', color: '#64748b', marginTop: '2px' }}>
                  {rulesInTactic.length} Rules Active
                </div>
              </div>

              <div style={{ padding: '8px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {rulesInTactic.length === 0 ? (
                  <div style={{ padding: '20px 6px', textAlign: 'center', color: '#475569', fontSize: '0.7rem' }}>
                    No deployed rules
                  </div>
                ) : (
                  rulesInTactic.map((tech: any) => (
                    <div
                      key={tech.technique_id}
                      style={{
                        padding: '8px',
                        borderRadius: '4px',
                        background: tech.detections_count > 0 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(26, 35, 58, 0.4)',
                        border: `1px solid ${tech.detections_count > 0 ? '#ef4444' : '#1e293b'}`,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '2px'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className="code-font" style={{ fontSize: '0.7rem', color: '#06b6d4', fontWeight: 700 }}>
                          {tech.technique_id}
                        </span>
                        {tech.detections_count > 0 && (
                          <span className="badge badge-critical" style={{ padding: '1px 4px', fontSize: '0.62rem' }}>
                            {tech.detections_count} HITS
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: '#e2e8f0', fontWeight: 500, lineHeight: '1.2' }}>
                        {tech.name}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
