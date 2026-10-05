import React, { useState, useEffect } from 'react';
import { 
  Globe2, Search, ShieldAlert, CheckCircle, Database, Tag, 
  ExternalLink, RefreshCw, Zap, ShieldCheck, AlertTriangle, 
  Clock, Activity, Lock
} from 'lucide-react';
import { api } from '../services/api';
import { ThreatIntelIOC } from '../types';

interface VirusTotalStatus {
  configured: boolean;
  masked_key: string;
  tier: string;
  quotas: {
    max_requests_per_minute: number;
    max_requests_per_day: number;
    max_requests_per_month: number;
  };
  usage: {
    requests_used_today: number;
    requests_remaining_today: number;
    requests_in_current_minute: number;
    rate_limit_state: string;
    seconds_until_next_slot: number;
    cached_indicators_count: number;
    cache_ttl_hours: number;
  };
}

export const TIPView: React.FC = () => {
  const [iocs, setIocs] = useState<ThreatIntelIOC[]>([]);
  const [correlatedThreats, setCorrelatedThreats] = useState<any[]>([]);
  const [searchVal, setSearchVal] = useState('185.220.101.5');
  const [searchType, setSearchType] = useState('ip');
  const [lookupResult, setLookupResult] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [vtStatus, setVtStatus] = useState<VirusTotalStatus | null>(null);
  const [refreshingVT, setRefreshingVT] = useState(false);

  useEffect(() => {
    loadIOCs();
    loadVTStatus();
    loadCorrelated();
  }, []);

  const loadCorrelated = async () => {
    try {
      const data = await api.getCorrelatedThreats();
      setCorrelatedThreats(data);
    } catch (e) {
      console.error(e);
    }
  };

  const loadIOCs = async () => {
    try {
      const data = await api.getThreatIOCs();
      setIocs(data);
    } catch (e) {
      console.error(e);
    }
  };

  const loadVTStatus = async () => {
    setRefreshingVT(true);
    try {
      const data = await api.getVirusTotalStatus();
      setVtStatus(data);
    } catch (e) {
      console.error("Failed to load VirusTotal status", e);
    } finally {
      setRefreshingVT(false);
    }
  };

  const handleLookup = async () => {
    if (!searchVal.trim()) return;
    setLoading(true);
    setLookupResult(null);
    try {
      const res = await api.lookupIOC(searchType, searchVal.trim());
      setLookupResult(res);
      // Automatically refresh quota & cache status after lookup
      loadVTStatus();
    } catch (err: any) {
      setLookupResult({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const dailyUsed = vtStatus?.usage?.requests_used_today || 0;
  const dailyMax = vtStatus?.quotas?.max_requests_per_day || 500;
  const dailyPercent = Math.min(100, Math.round((dailyUsed / dailyMax) * 100));

  const vtData = lookupResult?.virustotal;

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Globe2 size={24} style={{ color: '#38bdf8' }} />
            Threat Intelligence Platform (TIP / CTI)
          </h1>
          <p style={{ fontSize: '0.8rem', color: '#64748b' }}>
            Multi-source threat feeds, live VirusTotal v3 enrichment, and STIX/TAXII indicator store
          </p>
        </div>

        {/* Live VirusTotal Badge */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button 
            onClick={loadVTStatus} 
            disabled={refreshingVT}
            style={{
              background: '#0d1527',
              border: '1px solid #1e293b',
              color: '#94a3b8',
              borderRadius: '6px',
              padding: '6px 10px',
              fontSize: '0.75rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <RefreshCw size={13} className={refreshingVT ? 'spin' : ''} />
            Refresh Quota
          </button>
        </div>
      </div>

      {/* VirusTotal Free Tier Quota & Rate Limit Control Panel */}
      <div className="soc-card" style={{ padding: '18px 20px', background: 'linear-gradient(135deg, #090f1e 0%, #0d172e 100%)', border: '1px solid #1e293b' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              width: '10px',
              height: '10px',
              borderRadius: '50%',
              background: vtStatus?.configured ? '#10b981' : '#f59e0b',
              boxShadow: vtStatus?.configured ? '0 0 8px #10b981' : 'none'
            }} />
            <span style={{ fontSize: '0.9rem', fontWeight: 700, color: '#f8fafc' }}>
              VirusTotal API v3 — Free Public Tier Integration
            </span>
            <span style={{
              fontSize: '0.7rem',
              padding: '2px 8px',
              borderRadius: '4px',
              background: 'rgba(56, 189, 248, 0.15)',
              color: '#38bdf8',
              border: '1px solid rgba(56, 189, 248, 0.3)',
              fontFamily: 'var(--font-mono)'
            }}>
              STANDARD FREE END-USER
            </span>
          </div>

          <div style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
            API Key: <span style={{ color: '#94a3b8' }}>{vtStatus?.masked_key || 'Not Detected'}</span>
          </div>
        </div>

        {/* Quota & Rate Limit Metrics Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '16px' }}>
          {/* Rate Limiting */}
          <div style={{ background: '#060a14', padding: '12px 14px', borderRadius: '8px', border: '1px solid #162036' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: 600 }}>RATE LIMIT (SLIDING 60s)</span>
              <Zap size={14} style={{ color: '#38bdf8' }} />
            </div>
            <div style={{ fontSize: '1.15rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
              {vtStatus?.usage?.requests_in_current_minute || 0} / {vtStatus?.quotas?.max_requests_per_minute || 4} <span style={{ fontSize: '0.75rem', fontWeight: 500, color: '#64748b' }}>req/min</span>
            </div>
            <div style={{ fontSize: '0.7rem', marginTop: '4px', color: vtStatus?.usage?.rate_limit_state === 'READY' ? '#10b981' : '#f59e0b' }}>
              Status: {vtStatus?.usage?.rate_limit_state || 'READY'}
              {vtStatus?.usage?.seconds_until_next_slot ? ` (delay ${vtStatus.usage.seconds_until_next_slot}s)` : ' (Next slot open)'}
            </div>
          </div>

          {/* Daily Quota */}
          <div style={{ background: '#060a14', padding: '12px 14px', borderRadius: '8px', border: '1px solid #162036' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: 600 }}>DAILY QUOTA (UTC)</span>
              <Clock size={14} style={{ color: '#10b981' }} />
            </div>
            <div style={{ fontSize: '1.15rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
              {dailyUsed} / {dailyMax} <span style={{ fontSize: '0.75rem', fontWeight: 500, color: '#64748b' }}>used</span>
            </div>
            {/* Progress Bar */}
            <div style={{ width: '100%', height: '5px', background: '#1e293b', borderRadius: '3px', marginTop: '8px', overflow: 'hidden' }}>
              <div style={{
                width: `${dailyPercent}%`,
                height: '100%',
                background: dailyPercent > 80 ? '#ef4444' : dailyPercent > 50 ? '#f59e0b' : '#10b981',
                transition: 'width 0.3s ease'
              }} />
            </div>
            <div style={{ fontSize: '0.68rem', marginTop: '4px', color: '#64748b' }}>
              {vtStatus?.usage?.requests_remaining_today ?? 500} queries remaining today
            </div>
          </div>

          {/* Intelligent 24-Hour Cache */}
          <div style={{ background: '#060a14', padding: '12px 14px', borderRadius: '8px', border: '1px solid #162036' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: 600 }}>ZERO-QUOTA CACHE (24h)</span>
              <Database size={14} style={{ color: '#818cf8' }} />
            </div>
            <div style={{ fontSize: '1.15rem', fontWeight: 800, color: '#818cf8', fontFamily: 'var(--font-mono)' }}>
              {vtStatus?.usage?.cached_indicators_count || 0} <span style={{ fontSize: '0.75rem', fontWeight: 500, color: '#64748b' }}>cached IOCs</span>
            </div>
            <div style={{ fontSize: '0.7rem', marginTop: '4px', color: '#10b981' }}>
              Zero API calls consumed for repeat lookups
            </div>
          </div>

          {/* Monthly Cap Allowance */}
          <div style={{ background: '#060a14', padding: '12px 14px', borderRadius: '8px', border: '1px solid #162036' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: 600 }}>MONTHLY ALLOWANCE</span>
              <ShieldCheck size={14} style={{ color: '#f59e0b' }} />
            </div>
            <div style={{ fontSize: '1.15rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
              15,500 <span style={{ fontSize: '0.75rem', fontWeight: 500, color: '#64748b' }}>lookups/mo</span>
            </div>
            <div style={{ fontSize: '0.7rem', marginTop: '4px', color: '#64748b' }}>
              Private IP suppression enabled
            </div>
          </div>
        </div>
      </div>

      {/* Real-time Indicator Lookup Bar */}
      <div className="soc-card" style={{ padding: '20px' }}>
        <h2 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', marginBottom: '4px' }}>
          Threat Reputation & Multi-Source Lookup
        </h2>
        <p style={{ fontSize: '0.78rem', color: '#64748b', marginBottom: '14px' }}>
          Simultaneously checks internal CTI databases and VirusTotal v3 with automatic rate-limit throttling and 24-hr TTL caching.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: '170px 1fr auto', gap: '12px' }}>
          <select
            value={searchType}
            onChange={(e) => setSearchType(e.target.value)}
            style={{
              background: '#060910',
              border: '1px solid #232f4c',
              color: '#fff',
              padding: '10px 12px',
              borderRadius: '6px',
              fontSize: '0.85rem',
              fontFamily: 'var(--font-mono)',
              outline: 'none'
            }}
          >
            <option value="ip">IP Address</option>
            <option value="domain">Domain Name</option>
            <option value="sha256">SHA-256 Hash</option>
          </select>

          <input
            type="text"
            value={searchVal}
            onChange={(e) => setSearchVal(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
            placeholder="e.g. 185.220.101.5, badsite.com, or file hash..."
            style={{
              background: '#060910',
              border: '1px solid #232f4c',
              color: '#fff',
              padding: '10px 14px',
              borderRadius: '6px',
              fontSize: '0.85rem',
              fontFamily: 'var(--font-mono)',
              outline: 'none'
            }}
          />

          <button
            className="btn-primary"
            disabled={loading}
            onClick={handleLookup}
            style={{ padding: '0 24px', display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}
          >
            {loading ? (
              <>
                <RefreshCw size={14} className="spin" /> Querying...
              </>
            ) : (
              <>
                <Search size={14} /> Query Intel
              </>
            )}
          </button>
        </div>

        {/* Lookup Results Display */}
        {lookupResult && (
          <div style={{ marginTop: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {/* Overall Verdict Bar */}
            <div style={{
              padding: '14px 18px',
              borderRadius: '8px',
              background: lookupResult.found ? 'rgba(239, 68, 68, 0.12)' : 'rgba(16, 185, 129, 0.12)',
              border: `1px solid ${lookupResult.found ? 'rgba(239, 68, 68, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`,
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '10px'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                {lookupResult.found ? (
                  <ShieldAlert size={20} style={{ color: '#ef4444' }} />
                ) : (
                  <CheckCircle size={20} style={{ color: '#10b981' }} />
                )}
                <div>
                  <strong style={{
                    fontFamily: 'var(--font-mono)',
                    color: lookupResult.found ? '#f87171' : '#34d399',
                    fontSize: '0.95rem'
                  }}>
                    {lookupResult.found ? 'CONFIRMED THREAT / MALICIOUS ATTRIBUTION' : 'CLEAN / BENIGN REPUTATION'}
                  </strong>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                    Queried: <code style={{ color: '#fff' }}>{lookupResult.query?.value}</code> ({lookupResult.query?.type?.toUpperCase()})
                  </div>
                </div>
              </div>

              {lookupResult.indicator && (
                <span className="badge badge-critical" style={{ fontSize: '0.75rem' }}>
                  CTI CONFIDENCE: {Math.round(lookupResult.indicator.confidence * 100)}%
                </span>
              )}
            </div>

            {/* VirusTotal Live Intelligence Report Card */}
            {vtData && !vtData.error && !vtData.rate_limited && (
              <div style={{
                background: '#070c17',
                border: '1px solid #1a2744',
                borderRadius: '8px',
                padding: '18px 20px',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontWeight: 700, color: '#f8fafc', fontSize: '0.95rem' }}>
                      VirusTotal v3 Intelligence Analysis
                    </span>
                    {vtData.from_cache ? (
                      <span style={{ fontSize: '0.68rem', padding: '2px 7px', background: 'rgba(16, 185, 129, 0.15)', color: '#34d399', borderRadius: '4px', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                        Cached 24h (0 Quota)
                      </span>
                    ) : (
                      <span style={{ fontSize: '0.68rem', padding: '2px 7px', background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', borderRadius: '4px', border: '1px solid rgba(56, 189, 248, 0.3)' }}>
                        Live API Lookup
                      </span>
                    )}
                  </div>

                  {vtData.permalink && (
                    <a
                      href={vtData.permalink}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        fontSize: '0.75rem',
                        color: '#38bdf8',
                        textDecoration: 'none'
                      }}
                    >
                      View on VirusTotal GUI <ExternalLink size={13} />
                    </a>
                  )}
                </div>

                {/* Score and Stats breakdown */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '10px' }}>
                  {/* Verdict & Detection Ratio */}
                  <div style={{ background: '#0b1324', padding: '10px', borderRadius: '6px' }}>
                    <div style={{ fontSize: '0.7rem', color: '#64748b' }}>SECURITY VENDORS</div>
                    <div style={{
                      fontSize: '1.1rem',
                      fontWeight: 700,
                      color: vtData.is_malicious ? '#ef4444' : vtData.verdict === 'SUSPICIOUS' ? '#f59e0b' : '#10b981',
                      fontFamily: 'var(--font-mono)'
                    }}>
                      {vtData.detection_ratio || '0/90'}
                    </div>
                    <div style={{ fontSize: '0.68rem', color: vtData.is_malicious ? '#f87171' : '#94a3b8' }}>
                      {vtData.is_malicious ? 'Flagged Malicious' : 'No Engines Flagged'}
                    </div>
                  </div>

                  {/* Threat Score */}
                  <div style={{ background: '#0b1324', padding: '10px', borderRadius: '6px' }}>
                    <div style={{ fontSize: '0.7rem', color: '#64748b' }}>THREAT SCORE</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
                      {vtData.threat_score ?? 0} / 100
                    </div>
                    <div style={{ fontSize: '0.68rem', color: '#64748b' }}>
                      VT Community Risk
                    </div>
                  </div>

                  {/* Harmless Count */}
                  <div style={{ background: '#0b1324', padding: '10px', borderRadius: '6px' }}>
                    <div style={{ fontSize: '0.7rem', color: '#64748b' }}>HARMLESS ENGINES</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#10b981', fontFamily: 'var(--font-mono)' }}>
                      {vtData.stats?.harmless ?? 0}
                    </div>
                    <div style={{ fontSize: '0.68rem', color: '#64748b' }}>Verified Clean</div>
                  </div>

                  {/* Autonomous System / ISP */}
                  <div style={{ background: '#0b1324', padding: '10px', borderRadius: '6px' }}>
                    <div style={{ fontSize: '0.7rem', color: '#64748b' }}>AS OWNER / LOCATION</div>
                    <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {vtData.as_owner || 'N/A'}
                    </div>
                    <div style={{ fontSize: '0.68rem', color: '#64748b' }}>
                      Country: {vtData.country || 'Global'} {vtData.network ? `(${vtData.network})` : ''}
                    </div>
                  </div>
                </div>

                {/* Tags */}
                {vtData.tags && vtData.tags.length > 0 && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap', marginTop: '4px' }}>
                    <span style={{ fontSize: '0.7rem', color: '#64748b' }}>Threat Tags:</span>
                    {vtData.tags.map((t: string, idx: number) => (
                      <span key={idx} style={{
                        fontSize: '0.68rem',
                        padding: '2px 8px',
                        background: '#131e36',
                        color: '#93c5fd',
                        borderRadius: '4px',
                        border: '1px solid #1e293b'
                      }}>
                        #{t}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Rate limited or Error Notification */}
            {vtData?.rate_limited && (
              <div style={{
                background: 'rgba(245, 158, 11, 0.1)',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                padding: '12px 16px',
                borderRadius: '6px',
                color: '#f59e0b',
                fontSize: '0.82rem',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}>
                <AlertTriangle size={16} />
                <span><strong>VirusTotal Free Rate Limit Enforced:</strong> {vtData.message || '4 lookups/min limit reached. Please wait a few seconds before querying.'}</span>
              </div>
            )}

            {/* Internal CTI Match Details */}
            {lookupResult.indicator && (
              <div style={{
                background: '#070c17',
                border: '1px solid #1a2744',
                borderRadius: '8px',
                padding: '14px 18px',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px'
              }}>
                <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#f8fafc' }}>
                  Internal STIX/TAXII Threat Intelligence Match
                </div>
                <div style={{ fontSize: '0.82rem', color: '#cbd5e1' }}>
                  Actor: <strong style={{ color: '#fff' }}>{lookupResult.indicator.threat_actor}</strong> |
                  Campaign: <strong>{lookupResult.indicator.campaign}</strong> |
                  Malware: <strong>{lookupResult.indicator.malware_family}</strong> |
                  Feed: <em>{lookupResult.indicator.source}</em>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Correlated Threats Table */}
      <div className="soc-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a233a', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f8fafc' }}>
            Zero-False-Positive Correlated Threats (Logs + CTI)
          </h2>
          <div className="badge badge-critical">HIGH CONFIDENCE (≥95%)</div>
        </div>

        <table className="soc-table">
          <thead>
            <tr>
              <th>INDICATOR (IOC)</th>
              <th>THREAT ACTOR</th>
              <th>CAMPAIGN / MALWARE</th>
              <th>SEVERITY</th>
              <th>CONFIDENCE</th>
              <th>ASSOCIATED EVENTS</th>
              <th>DETECTED ON</th>
            </tr>
          </thead>
          <tbody>
            {correlatedThreats.map((threat, idx) => (
              <tr key={idx}>
                <td className="code-font" style={{ color: '#ef4444', fontWeight: 600 }}>
                  <span className="badge badge-info" style={{marginRight: '6px'}}>{threat.indicator_type}</span>
                  {threat.indicator_value}
                </td>
                <td style={{ color: '#fff', fontWeight: 600 }}>{threat.threat_actor || '-'}</td>
                <td style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>
                  {threat.campaign ? `${threat.campaign} (${threat.malware_family || ''})` : '-'}
                </td>
                <td>
                  <span className={`badge badge-${threat.severity?.toLowerCase()}`}>
                    {threat.severity}
                  </span>
                </td>
                <td className="code-font" style={{ color: '#10b981' }}>
                  {Math.round(threat.confidence * 100)}%
                </td>
                <td className="code-font" style={{ color: '#93c5fd' }}>
                  {threat.associated_events_count} Event(s)
                </td>
                <td style={{ color: '#64748b', fontSize: '0.75rem' }}>
                  {new Date(threat.created_at * 1000).toLocaleString()}
                </td>
              </tr>
            ))}
            {correlatedThreats.length === 0 && (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '20px', color: '#64748b' }}>
                  No correlated threats detected yet. Waiting for live events...
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Active Indicator Registry Table */}
      <div className="soc-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a233a', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f8fafc' }}>
            Verified Threat Intelligence Indicators ({iocs.length})
          </h2>
          <div className="badge badge-low">TAXII 2.1 / STIX 2.1 COMPLIANT</div>
        </div>

        <table className="soc-table">
          <thead>
            <tr>
              <th>TYPE</th>
              <th>INDICATOR VALUE</th>
              <th>THREAT ACTOR</th>
              <th>CAMPAIGN / MALWARE</th>
              <th>SEVERITY</th>
              <th>CONFIDENCE</th>
              <th>FEED SOURCE</th>
            </tr>
          </thead>
          <tbody>
            {iocs.map((ioc, idx) => (
              <tr key={idx}>
                <td>
                  <span className="badge badge-info">{ioc.ioc_type}</span>
                </td>
                <td className="code-font" style={{ color: '#38bdf8', fontWeight: 600 }}>{ioc.value}</td>
                <td style={{ color: '#fff', fontWeight: 600 }}>{ioc.threat_actor || '-'}</td>
                <td style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>
                  {ioc.campaign ? `${ioc.campaign} (${ioc.malware_family || ''})` : '-'}
                </td>
                <td>
                  <span className={`badge badge-${ioc.severity.toLowerCase()}`}>
                    {ioc.severity}
                  </span>
                </td>
                <td className="code-font" style={{ color: '#10b981' }}>
                  {Math.round(ioc.confidence * 100)}%
                </td>
                <td style={{ color: '#64748b', fontSize: '0.75rem' }}>{ioc.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
