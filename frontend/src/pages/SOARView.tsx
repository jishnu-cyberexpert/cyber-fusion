import React, { useState, useEffect } from 'react';
import {
  Bot,
  Play,
  CheckCircle,
  AlertTriangle,
  ShieldAlert,
  Clock,
  UserCheck,
  RefreshCw,
  Terminal,
  ShieldCheck,
  XCircle
} from 'lucide-react';
import { api } from '../services/api';
import { SOARPlaybook, SOARActionExecution } from '../types';

export const SOARView: React.FC = () => {
  const [playbooks, setPlaybooks] = useState<SOARPlaybook[]>([]);
  const [executions, setExecutions] = useState<SOARActionExecution[]>([]);
  const [targetEntity, setTargetEntity] = useState('185.220.101.5');
  const [selectedAction, setSelectedAction] = useState('BLOCK_IP_FIREWALL');
  const [actionResult, setActionResult] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const pb = await api.getPlaybooks();
      const ex = await api.getSOARExecutions();
      setPlaybooks(pb);
      setExecutions(ex);
    } catch (err) {
      console.error(err);
    }
  };

  const handleExecute = async () => {
    setLoading(true);
    setActionResult(null);
    try {
      const res = await api.executeSOARAction(selectedAction, targetEntity, undefined, {
        reason: 'Automated SOC Response Trigger'
      });
      setActionResult(res);
      await loadData();
    } catch (err: any) {
      setActionResult({ status: 'FAILED', output: err.message });
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (execId: string, approved: boolean) => {
    try {
      await api.approveSOARAction(execId, approved);
      await loadData();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div>
        <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc' }}>
          SOAR Response Orchestration & Mitigation Engine
        </h1>
        <p style={{ fontSize: '0.8rem', color: '#64748b' }}>
          Autonomous and human-in-the-loop playbooks enforcing strict integration verification and zero false claims
        </p>
      </div>

      {/* Manual Action Dispatch Console */}
      <div className="soc-card" style={{ padding: '20px' }}>
        <h2 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', marginBottom: '14px' }}>
          Dispatch Response Mitigation Action
        </h2>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: '12px' }}>
          <div>
            <label style={{ fontSize: '0.72rem', color: '#94a3b8', display: 'block', marginBottom: '4px' }}>
              RESPONSE ACTION TYPE:
            </label>
            <select
              value={selectedAction}
              onChange={(e) => setSelectedAction(e.target.value)}
              style={{
                width: '100%',
                background: '#060910',
                border: '1px solid #232f4c',
                color: '#fff',
                padding: '8px 12px',
                borderRadius: '6px',
                fontSize: '0.8rem',
                fontFamily: 'var(--font-mono)',
                outline: 'none'
              }}
            >
              <option value="BLOCK_IP_FIREWALL">BLOCK_IP_FIREWALL (Perimeter Firewall API)</option>
              <option value="ISOLATE_ENDPOINT">ISOLATE_ENDPOINT (EDR Host Quarantine)</option>
              <option value="KILL_PROCESS">KILL_PROCESS (Live Agent Process Terminate)</option>
              <option value="REVOKE_IAM_SESSION">REVOKE_IAM_SESSION (Entra ID / Okta SSO Token Evict)</option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: '0.72rem', color: '#94a3b8', display: 'block', marginBottom: '4px' }}>
              TARGET ENTITY (IP / Hostname / PID / Identity):
            </label>
            <input
              type="text"
              value={targetEntity}
              onChange={(e) => setTargetEntity(e.target.value)}
              placeholder="e.g. 185.220.101.5 or JISHNUPRASAD"
              style={{
                width: '100%',
                background: '#060910',
                border: '1px solid #232f4c',
                color: '#fff',
                padding: '8px 12px',
                borderRadius: '6px',
                fontSize: '0.8rem',
                fontFamily: 'var(--font-mono)',
                outline: 'none'
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'flex-end' }}>
            <button
              className="btn-primary"
              disabled={loading}
              onClick={handleExecute}
              style={{ height: '38px', padding: '0 20px' }}
            >
              <Play size={14} /> Execute Action
            </button>
          </div>
        </div>

        {/* Action Result Card with STRICT NO FALSE CLAIMS */}
        {actionResult && (
          <div style={{
            marginTop: '16px',
            padding: '14px 18px',
            borderRadius: '6px',
            background: actionResult.status === 'SUCCESS' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
            border: `1px solid ${actionResult.status === 'SUCCESS' ? 'rgba(16, 185, 129, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`,
            display: 'flex',
            flexDirection: 'column',
            gap: '6px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {actionResult.status === 'SUCCESS' ? (
                  <CheckCircle size={18} color="#10b981" />
                ) : (
                  <AlertTriangle size={18} color="#ef4444" />
                )}
                <strong style={{
                  fontSize: '0.88rem',
                  fontFamily: 'var(--font-mono)',
                  color: actionResult.status === 'SUCCESS' ? '#34d399' : '#f87171'
                }}>
                  {actionResult.status}
                </strong>
              </div>
              <span className="code-font" style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
                ID: {actionResult.execution_id}
              </span>
            </div>
            <div style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
              {actionResult.output}
            </div>
          </div>
        )}
      </div>

      {/* Pre-Built Enterprise Response Playbooks */}
      <div>
        <h2 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc', marginBottom: '12px' }}>
          Configured Enterprise SOAR Playbooks
        </h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
          {playbooks.map((pb) => (
            <div key={pb.playbook_id} className="soc-card" style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="badge badge-low">{pb.playbook_id}</span>
                {pb.requires_approval && (
                  <span className="badge badge-high">APPROVAL GATE</span>
                )}
              </div>
              <div style={{ fontWeight: 700, fontSize: '0.92rem', color: '#f1f5f9' }}>
                {pb.name}
              </div>
              <div style={{ fontSize: '0.76rem', color: '#94a3b8' }}>
                {pb.description}
              </div>
              <div style={{ marginTop: 'auto', paddingTop: '8px', borderTop: '1px solid #1a233a', fontSize: '0.7rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                Trigger: {pb.trigger_condition}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Recent Action Executions Table */}
      <div className="soc-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a233a', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ fontSize: '0.9rem', fontWeight: 700, color: '#f8fafc' }}>
            Response Execution Audit Log & Approvals
          </h3>
          <button className="btn-secondary" onClick={loadData} style={{ padding: '4px 10px', fontSize: '0.72rem' }}>
            <RefreshCw size={12} /> Refresh
          </button>
        </div>

        <table className="soc-table">
          <thead>
            <tr>
              <th>EXECUTION ID</th>
              <th>ACTION TYPE</th>
              <th>TARGET ENTITY</th>
              <th>STATUS</th>
              <th>OUTPUT / AUDIT TRAIL</th>
              <th>APPROVAL GATE</th>
            </tr>
          </thead>
          <tbody>
            {executions.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: '24px', color: '#64748b' }}>
                  No response actions executed yet.
                </td>
              </tr>
            ) : (
              executions.map((ex) => (
                <tr key={ex.execution_id}>
                  <td className="code-font" style={{ fontSize: '0.72rem' }}>{ex.execution_id}</td>
                  <td className="code-font" style={{ color: '#06b6d4', fontWeight: 600 }}>{ex.action_type}</td>
                  <td className="code-font" style={{ color: '#38bdf8' }}>{ex.target_entity}</td>
                  <td>
                    <span className={`badge ${
                      ex.status === 'SUCCESS' ? 'badge-low' :
                      ex.status.includes('NOT CONFIGURED') ? 'badge-critical' : 'badge-high'
                    }`}>
                      {ex.status}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.75rem', maxWidth: '320px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {ex.execution_output}
                  </td>
                  <td>
                    {ex.status === 'PENDING_APPROVAL' ? (
                      <div style={{ display: 'flex', gap: '6px' }}>
                        <button
                          className="btn-primary"
                          onClick={() => handleApprove(ex.execution_id, true)}
                          style={{ padding: '3px 8px', fontSize: '0.7rem' }}
                        >
                          Approve
                        </button>
                        <button
                          className="btn-danger"
                          onClick={() => handleApprove(ex.execution_id, false)}
                          style={{ padding: '3px 8px', fontSize: '0.7rem' }}
                        >
                          Reject
                        </button>
                      </div>
                    ) : (
                      <span className="code-font" style={{ fontSize: '0.7rem', color: '#64748b' }}>
                        {ex.approval_status}
                      </span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
