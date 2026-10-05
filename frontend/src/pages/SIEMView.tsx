import React, { useState, useEffect } from 'react';
import { Database, Filter, Search, Eye, Code2, RefreshCw, UploadCloud, CheckCircle2, AlertCircle, HardDrive } from 'lucide-react';
import { SecurityEvent } from '../types';
import { api } from '../services/api';

interface SIEMViewProps {
  events: SecurityEvent[];
  mode?: string;
  onEventsUpdate?: (events: SecurityEvent[]) => void;
}

export const SIEMView: React.FC<SIEMViewProps> = ({ events = [], mode = 'LIVE', onEventsUpdate }) => {
  const [selectedSource, setSelectedSource] = useState<string>('ALL');
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [inspectEvent, setInspectEvent] = useState<SecurityEvent | null>(null);

  // MongoDB & Pipeline States
  const [mongoStatus, setMongoStatus] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [syncing, setSyncing] = useState<boolean>(false);
  const [syncMessage, setSyncMessage] = useState<string | null>(null);
  const [localEvents, setLocalEvents] = useState<SecurityEvent[]>(events);

  const sources = ['ALL', 'EDR', 'NDR', 'IAM', 'WAF', 'DLP', 'SYSLOG'];

  // Load status and initial events
  useEffect(() => {
    fetchSiemData();
  }, [mode, selectedSource]);

  // Keep localEvents updated when parent events update
  useEffect(() => {
    if (events && events.length > 0) {
      setLocalEvents((prev) => {
        const existingUuids = new Set(prev.map(e => e.event_uuid || e.uuid));
        const newOnes = events.filter(e => !existingUuids.has(e.event_uuid || e.uuid));
        if (newOnes.length === 0) return prev;
        return [...newOnes, ...prev].slice(0, 100);
      });
    }
  }, [events]);

  const fetchSiemData = async () => {
    setLoading(true);
    try {
      const [statusRes, eventsRes] = await Promise.all([
        api.getSiemStatus().catch(() => null),
        api.getSiemEvents(mode, 100, selectedSource === 'ALL' ? undefined : selectedSource, searchFilter).catch(() => ({ events: [] }))
      ]);

      if (statusRes) {
        setMongoStatus(statusRes);
      }

      if (eventsRes && Array.isArray(eventsRes.events)) {
        setLocalEvents(eventsRes.events);
        if (onEventsUpdate) {
          onEventsUpdate(eventsRes.events);
        }
      }
    } catch (err) {
      console.error('Failed to load SIEM telemetry:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSyncToMongoDB = async () => {
    setSyncing(true);
    setSyncMessage(null);
    try {
      const res = await api.syncSiemMongoDB(1000);
      setSyncMessage(res.message || 'Synced successfully to MongoDB Atlas');
      await fetchSiemData();
    } catch (err: any) {
      setSyncMessage(`Sync error: ${err.message || 'Failed to sync'}`);
    } finally {
      setSyncing(false);
      setTimeout(() => setSyncMessage(null), 5000);
    }
  };

  const safeEvents = Array.isArray(localEvents) ? localEvents : [];

  const filtered = safeEvents.filter((ev) => {
    if (!ev) return false;
    const matchSource = selectedSource === 'ALL' || ev.data_source === selectedSource;
    const s = searchFilter.toLowerCase();
    const matchSearch =
      !s ||
      (ev.process && ev.process.toLowerCase().includes(s)) ||
      (ev.process_name && ev.process_name.toLowerCase().includes(s)) ||
      (ev.hostname && ev.hostname.toLowerCase().includes(s)) ||
      (ev.category && ev.category.toLowerCase().includes(s)) ||
      (ev.action && ev.action.toLowerCase().includes(s)) ||
      (ev.user && ev.user.toLowerCase().includes(s)) ||
      (ev.user_identity && ev.user_identity.toLowerCase().includes(s)) ||
      (ev.source_ip && ev.source_ip.toLowerCase().includes(s)) ||
      (ev.dest_ip && ev.dest_ip.toLowerCase().includes(s));
    return matchSource && matchSearch;
  });

  const isMongoConnected = mongoStatus?.mongodb_atlas?.connected ?? false;
  const mongoCount = mongoStatus?.mongodb_atlas?.total_logs ?? 0;
  const mongoPing = mongoStatus?.mongodb_atlas?.ping_ms;

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header & Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc', margin: 0 }}>
              SIEM Telemetry & Log Normalization Plane
            </h1>
            <span style={{
              background: 'rgba(6, 182, 212, 0.15)',
              color: '#06b6d4',
              padding: '3px 8px',
              borderRadius: '6px',
              fontSize: '0.72rem',
              fontWeight: 700,
              fontFamily: 'var(--font-mono)'
            }}>
              LIVE STREAM
            </span>
          </div>
          <p style={{ fontSize: '0.8rem', color: '#64748b', marginTop: '4px', marginBottom: 0 }}>
            Continuous real-time ingestion, OCSF / ECS normalization, and persistent injection into MongoDB Atlas
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            onClick={fetchSiemData}
            disabled={loading}
            className="btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '6px 12px', fontSize: '0.75rem', cursor: 'pointer' }}
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>

          <button
            onClick={handleSyncToMongoDB}
            disabled={syncing}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 14px',
              background: syncing ? '#047857' : '#10b981',
              color: '#fff',
              border: 'none',
              borderRadius: '6px',
              fontSize: '0.75rem',
              fontWeight: 700,
              cursor: syncing ? 'not-allowed' : 'pointer',
              transition: 'background 0.15s ease'
            }}
          >
            <UploadCloud size={15} />
            <span>{syncing ? 'Injecting to Atlas...' : 'Inject Logs to MongoDB Atlas'}</span>
          </button>
        </div>
      </div>

      {/* MongoDB Atlas Integration Banner */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '12px'
      }}>
        {/* Card 1: Atlas Connection */}
        <div style={{
          background: '#0c101d',
          border: isMongoConnected ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: '8px',
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px'
        }}>
          <div style={{
            width: '36px',
            height: '36px',
            borderRadius: '8px',
            background: isMongoConnected ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            {isMongoConnected ? (
              <CheckCircle2 size={20} color="#10b981" />
            ) : (
              <AlertCircle size={20} color="#ef4444" />
            )}
          </div>
          <div>
            <div style={{ fontSize: '0.68rem', color: '#64748b', fontWeight: 600, textTransform: 'uppercase' }}>
              MongoDB Atlas Ingestion
            </div>
            <div style={{ fontSize: '0.9rem', fontWeight: 700, color: isMongoConnected ? '#34d399' : '#f87171' }}>
              {isMongoConnected ? 'Atlas Live Connected' : 'Disconnected'}
            </div>
            <div style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              {mongoPing !== null && mongoPing !== undefined ? `Ping: ${mongoPing}ms` : 'Connecting...'}
            </div>
          </div>
        </div>

        {/* Card 2: MongoDB Logs Stored */}
        <div style={{
          background: '#0c101d',
          border: '1px solid #1a233a',
          borderRadius: '8px',
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px'
        }}>
          <div style={{
            width: '36px',
            height: '36px',
            borderRadius: '8px',
            background: 'rgba(6, 182, 212, 0.15)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Database size={18} color="#06b6d4" />
          </div>
          <div>
            <div style={{ fontSize: '0.68rem', color: '#64748b', fontWeight: 600, textTransform: 'uppercase' }}>
              Atlas Stored Documents
            </div>
            <div style={{ fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
              {mongoCount.toLocaleString()}
            </div>
            <div style={{ fontSize: '0.7rem', color: '#06b6d4' }}>
              cyberfusion_xdr.security_logs
            </div>
          </div>
        </div>

        {/* Card 3: SQLite Backlog / Archive */}
        <div style={{
          background: '#0c101d',
          border: '1px solid #1a233a',
          borderRadius: '8px',
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px'
        }}>
          <div style={{
            width: '36px',
            height: '36px',
            borderRadius: '8px',
            background: 'rgba(168, 85, 247, 0.15)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <HardDrive size={18} color="#a855f7" />
          </div>
          <div>
            <div style={{ fontSize: '0.68rem', color: '#64748b', fontWeight: 600, textTransform: 'uppercase' }}>
              Local Relational Store
            </div>
            <div style={{ fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
              {(mongoStatus?.sqlite_events_stored ?? 0).toLocaleString()}
            </div>
            <div style={{ fontSize: '0.7rem', color: '#a855f7' }}>
              Dual-Storage Redundancy
            </div>
          </div>
        </div>
      </div>

      {/* Sync Status Banner */}
      {syncMessage && (
        <div style={{
          padding: '10px 16px',
          background: syncMessage.includes('error') ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
          border: syncMessage.includes('error') ? '1px solid #ef4444' : '1px solid #10b981',
          borderRadius: '6px',
          color: syncMessage.includes('error') ? '#fca5a5' : '#6ee7b7',
          fontSize: '0.8rem',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          {syncMessage.includes('error') ? <AlertCircle size={16} /> : <CheckCircle2 size={16} />}
          <span>{syncMessage}</span>
        </div>
      )}

      {/* Filter Bar */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        background: '#0c101d',
        border: '1px solid #1a233a',
        padding: '12px 18px',
        borderRadius: '8px',
        flexWrap: 'wrap',
        gap: '10px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <Filter size={16} color="#64748b" />
          <span style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600 }}>SOURCE:</span>
          {sources.map((s) => (
            <button
              key={s}
              onClick={() => setSelectedSource(s)}
              style={{
                background: selectedSource === s ? 'rgba(6, 182, 212, 0.2)' : 'transparent',
                border: selectedSource === s ? '1px solid #06b6d4' : '1px solid #1e293b',
                color: selectedSource === s ? '#38bdf8' : '#94a3b8',
                padding: '4px 10px',
                borderRadius: '4px',
                fontSize: '0.72rem',
                fontWeight: 600,
                fontFamily: 'var(--font-mono)',
                cursor: 'pointer'
              }}
            >
              {s}
            </button>
          ))}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', width: '320px' }}>
          <Search size={16} color="#64748b" />
          <input
            type="text"
            placeholder="Filter by process, host, user, IP..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            style={{
              width: '100%',
              background: '#060910',
              border: '1px solid #232f4c',
              color: '#f8fafc',
              padding: '6px 12px',
              borderRadius: '6px',
              fontSize: '0.78rem',
              outline: 'none',
              fontFamily: 'var(--font-mono)'
            }}
          />
        </div>
      </div>

      {/* Telemetry Stream Table */}
      <div className="soc-card" style={{ padding: '0', overflow: 'hidden' }}>
        <table className="soc-table">
          <thead>
            <tr>
              <th>EVENT UUID</th>
              <th>TIMESTAMP</th>
              <th>DATA SOURCE</th>
              <th>CATEGORY</th>
              <th>ACTION</th>
              <th>HOST / ENTITY</th>
              <th>DETAILS</th>
              <th>STORAGE</th>
              <th>ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={9} style={{ textAlign: 'center', padding: '36px', color: '#64748b' }}>
                  {loading ? 'Fetching security telemetry stream...' : 'No matching telemetry found. Streaming live collectors or click "Inject Logs to MongoDB Atlas".'}
                </td>
              </tr>
            ) : (
              filtered.slice(0, 50).map((ev, idx) => {
                const uuidStr = String(ev.event_uuid || ev.uuid || `ev-${idx}`);
                const shortUuid = uuidStr.length >= 8 ? uuidStr.slice(0, 8) : uuidStr;
                const timeStr = ev.timestamp ? new Date(ev.timestamp * 1000).toLocaleTimeString() : 'N/A';
                const actionStr = ev.action || 'activity';
                const hostStr = ev.hostname || 'Internal';
                const procStr = ev.process || ev.process_name;
                const userStr = ev.user || ev.user_identity;
                const storageBadge = ev.storage_backend === 'MONGODB_ATLAS' || isMongoConnected ? 'MongoDB Atlas' : 'Local Data Plane';

                return (
                  <tr key={uuidStr + idx}>
                    <td className="code-font" style={{ fontSize: '0.7rem', color: '#64748b' }}>
                      {shortUuid}...
                    </td>
                    <td className="code-font" style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
                      {timeStr}
                    </td>
                    <td>
                      <span className="badge badge-info">{ev.data_source || 'EDR'}</span>
                    </td>
                    <td style={{ color: '#e2e8f0', fontWeight: 600 }}>{ev.category || 'telemetry'}</td>
                    <td className="code-font" style={{ color: '#06b6d4', fontSize: '0.75rem' }}>{actionStr}</td>
                    <td className="code-font" style={{ color: '#38bdf8' }}>{hostStr}</td>
                    <td className="code-font" style={{ maxWidth: '260px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {procStr
                        ? `${procStr} ${userStr ? `(${userStr})` : ''}`
                        : ev.source_ip
                        ? `${ev.source_ip} -> ${ev.dest_ip || 'Internal'}`
                        : '-'}
                    </td>
                    <td>
                      <span style={{
                        fontSize: '0.66rem',
                        fontWeight: 700,
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: storageBadge === 'MongoDB Atlas' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(148, 163, 184, 0.1)',
                        color: storageBadge === 'MongoDB Atlas' ? '#34d399' : '#94a3b8',
                        fontFamily: 'var(--font-mono)'
                      }}>
                        {storageBadge}
                      </span>
                    </td>
                    <td>
                      <button
                        className="btn-secondary"
                        onClick={() => setInspectEvent(ev)}
                        style={{ padding: '4px 8px', fontSize: '0.7rem' }}
                      >
                        <Eye size={12} /> Inspect JSON
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* JSON Inspector Modal */}
      {inspectEvent && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100
        }}>
          <div className="soc-card" style={{ width: '680px', maxHeight: '80vh', display: 'flex', flexDirection: 'column', padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Code2 size={18} color="#06b6d4" />
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#fff', margin: 0 }}>
                  Normalized OCSF / ECS Telemetry Record
                </h3>
              </div>
              <button className="btn-secondary" onClick={() => setInspectEvent(null)} style={{ padding: '4px 10px' }}>
                Close
              </button>
            </div>
            <div style={{
              background: '#0c101d',
              border: '1px solid #1e293b',
              borderRadius: '6px',
              padding: '8px 12px',
              marginBottom: '10px',
              fontSize: '0.74rem',
              display: 'flex',
              gap: '16px',
              color: '#94a3b8'
            }}>
              <span>Storage: <b style={{ color: '#34d399' }}>MongoDB Atlas ({inspectEvent.storage_backend || 'security_logs'})</b></span>
              <span>Source: <b style={{ color: '#38bdf8' }}>{inspectEvent.data_source}</b></span>
              <span>Action: <b style={{ color: '#06b6d4' }}>{inspectEvent.action}</b></span>
            </div>
            <pre style={{
              background: '#060910',
              padding: '16px',
              borderRadius: '6px',
              overflowY: 'auto',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.76rem',
              color: '#34d399',
              border: '1px solid #1e293b',
              flex: 1
            }}>
              {JSON.stringify(inspectEvent, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
