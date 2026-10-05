import React, { useState, useEffect } from 'react';
import { Search, Terminal, Bookmark, Play, Filter, Clock, CheckCircle } from 'lucide-react';
import { api } from '../services/api';
import { EnvironmentMode } from '../types';

interface HuntingViewProps {
  mode: EnvironmentMode;
}

export const HuntingView: React.FC<HuntingViewProps> = ({ mode }) => {
  const [queryString, setQueryString] = useState('process_name = powershell.exe');
  const [savedHunts, setSavedHunts] = useState<any[]>([]);
  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [timeWindow, setTimeWindow] = useState(120);

  useEffect(() => {
    loadSaved();
    runQuery('process_name = powershell.exe');
  }, []);

  const loadSaved = async () => {
    try {
      const data = await api.getSavedHunts();
      setSavedHunts(data);
    } catch (e) {
      console.error(e);
    }
  };

  const runQuery = async (queryToRun: string) => {
    setLoading(true);
    try {
      const data = await api.executeHunt(queryToRun, mode, timeWindow);
      setResults(data.results || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div>
        <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc' }}>
          Live Threat Hunting & Query Engine
        </h1>
        <p style={{ fontSize: '0.8rem', color: '#64748b' }}>
          Execute structured security queries across real normalized telemetry ({mode} data plane)
        </p>
      </div>

      {/* Query Search Bar */}
      <div className="soc-card" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
        <div style={{ display: 'flex', gap: '10px' }}>
          <div style={{
            flex: 1,
            background: '#060910',
            border: '1px solid #232f4c',
            borderRadius: '6px',
            display: 'flex',
            alignItems: 'center',
            padding: '0 12px'
          }}>
            <Search size={16} color="#06b6d4" />
            <input
              type="text"
              value={queryString}
              onChange={(e) => setQueryString(e.target.value)}
              placeholder="e.g. process_name = powershell.exe OR command_line LIKE %bypass% OR dest_port = 443"
              style={{
                flex: 1,
                background: 'transparent',
                border: 'none',
                color: '#fff',
                padding: '10px',
                fontSize: '0.85rem',
                fontFamily: 'var(--font-mono)',
                outline: 'none'
              }}
            />
          </div>

          <button
            className="btn-primary"
            disabled={loading}
            onClick={() => runQuery(queryString)}
            style={{ padding: '0 20px' }}
          >
            <Play size={14} /> Run Hunt
          </button>
        </div>

        {/* Saved Hunt Presets */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: 600 }}>SAVED HUNTS:</span>
          {savedHunts.map((hunt) => (
            <button
              key={hunt.id}
              onClick={() => {
                setQueryString(hunt.query);
                runQuery(hunt.query);
              }}
              style={{
                background: 'rgba(12, 16, 29, 0.8)',
                border: '1px solid #1a233a',
                color: '#cbd5e1',
                padding: '3px 8px',
                borderRadius: '4px',
                fontSize: '0.72rem',
                fontFamily: 'var(--font-mono)',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '4px'
              }}
            >
              <Bookmark size={10} color="#06b6d4" />
              {hunt.name}
            </button>
          ))}
        </div>
      </div>

      {/* Query Results Table */}
      <div className="soc-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a233a', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontWeight: 700, fontSize: '0.85rem', color: '#f8fafc' }}>
            Matching Telemetry ({results.length} records)
          </div>
          <div style={{ fontSize: '0.72rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
            TIME WINDOW: Last {timeWindow} minutes
          </div>
        </div>

        <table className="soc-table">
          <thead>
            <tr>
              <th>TIMESTAMP</th>
              <th>DATA SOURCE</th>
              <th>HOST</th>
              <th>PROCESS / ENTITY</th>
              <th>COMMAND LINE / DETAILS</th>
              <th>NETWORK</th>
              <th>ALERT STATUS</th>
            </tr>
          </thead>
          <tbody>
            {results.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '36px', color: '#64748b' }}>
                  No matching telemetry observed in this time window.
                </td>
              </tr>
            ) : (
              results.map((r, idx) => (
                <tr key={idx}>
                  <td className="code-font" style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
                    {new Date(r.timestamp * 1000).toLocaleTimeString()}
                  </td>
                  <td>
                    <span className="badge badge-info">{r.data_source}</span>
                  </td>
                  <td className="code-font" style={{ color: '#38bdf8' }}>{r.hostname}</td>
                  <td className="code-font" style={{ fontWeight: 600 }}>{r.process || r.user || '-'}</td>
                  <td className="code-font" style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {r.command_line || '-'}
                  </td>
                  <td className="code-font" style={{ fontSize: '0.72rem' }}>
                    {r.source_ip ? `${r.source_ip} -> ${r.dest_ip}:${r.dest_port || ''}` : '-'}
                  </td>
                  <td>
                    {r.is_alert ? (
                      <span className="badge badge-critical">TRIGGERED ALERT</span>
                    ) : (
                      <span style={{ color: '#64748b', fontSize: '0.72rem' }}>Normal Event</span>
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
