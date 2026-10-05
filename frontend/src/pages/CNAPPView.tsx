import React, { useState, useEffect } from 'react';
import { Cloud, ShieldAlert, CheckCircle, Terminal, ExternalLink } from 'lucide-react';
import { api } from '../services/api';
import { CNAPPFinding } from '../types';

export const CNAPPView: React.FC = () => {
  const [findings, setFindings] = useState<CNAPPFinding[]>([]);

  useEffect(() => {
    loadFindings();
  }, []);

  const loadFindings = async () => {
    try {
      const data = await api.getCNAPPFindings();
      setFindings(data);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div>
        <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc' }}>
          CNAPP Cloud Security Posture Management
        </h1>
        <p style={{ fontSize: '0.8rem', color: '#64748b' }}>
          Real-time cloud asset posture audit across AWS, Microsoft Azure, and Google Cloud Platform
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
        <div className="soc-card" style={{ padding: '18px' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '4px' }}>AWS CLOUDTRAIL / S3</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f59e0b', fontFamily: 'var(--font-mono)' }}>
            1 Finding
          </div>
          <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '4px' }}>CIS AWS Benchmark 2.1.5</div>
        </div>

        <div className="soc-card" style={{ padding: '18px' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '4px' }}>AZURE NSG & DEFENDER</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#ef4444', fontFamily: 'var(--font-mono)' }}>
            1 Finding
          </div>
          <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '4px' }}>CIS Azure Benchmark 6.1</div>
        </div>

        <div className="soc-card" style={{ padding: '18px' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '4px' }}>GCP IAM AUDIT</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#06b6d4', fontFamily: 'var(--font-mono)' }}>
            1 Finding
          </div>
          <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '4px' }}>CIS GCP Benchmark 1.4</div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="soc-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a233a' }}>
          <h2 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f8fafc' }}>
            Cloud Security Findings ({findings.length})
          </h2>
        </div>

        <table className="soc-table">
          <thead>
            <tr>
              <th>PROVIDER</th>
              <th>ACCOUNT / RESOURCE</th>
              <th>FINDING TITLE</th>
              <th>SEVERITY</th>
              <th>COMPLIANCE FRAMEWORK</th>
              <th>REMEDIATION CLI</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f, idx) => (
              <tr key={idx}>
                <td>
                  <span className="badge badge-info">{f.cloud_provider}</span>
                </td>
                <td className="code-font" style={{ fontSize: '0.72rem', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {f.resource_id}
                </td>
                <td style={{ color: '#fff', fontWeight: 600 }}>{f.finding_title}</td>
                <td>
                  <span className={`badge badge-${f.severity.toLowerCase()}`}>
                    {f.severity}
                  </span>
                </td>
                <td className="code-font" style={{ fontSize: '0.72rem', color: '#38bdf8' }}>
                  {f.compliance_framework}
                </td>
                <td className="code-font" style={{ fontSize: '0.7rem', color: '#34d399', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {f.remediation_command}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
