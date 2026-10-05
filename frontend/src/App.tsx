import React, { useState, useEffect } from 'react';
import { Topbar } from './components/Topbar';
import { Sidebar, NavItem } from './components/Sidebar';
import { DashboardView } from './pages/DashboardView';
import { EDRView } from './pages/EDRView';
import { SIEMView } from './pages/SIEMView';
import { IncidentsView } from './pages/IncidentsView';
import { HuntingView } from './pages/HuntingView';
import { SOARView } from './pages/SOARView';
import { XDRView } from './pages/XDRView';
import { UEBAView } from './pages/UEBAView';
import { TIPView } from './pages/TIPView';
import { ASMView } from './pages/ASMView';
import { MITREView } from './pages/MITREView';
import { AuditView } from './pages/AuditView';
import { HealthView } from './pages/HealthView';
import { LABView } from './pages/LABView';
import { CNAPPView } from './pages/CNAPPView';

import { api } from './services/api';
import { EnvironmentMode, SystemHealth, Endpoint, Incident, Alert, SecurityEvent } from './types';

export const App: React.FC = () => {
  const [mode, setMode] = useState<EnvironmentMode>('LIVE');
  const [tenantId, setTenantId] = useState<string>('tenant-enterprise-secops');
  const [currentTab, setCurrentTab] = useState<NavItem>('dashboard');

  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [recentEvents, setRecentEvents] = useState<SecurityEvent[]>([]);
  const [wsConnected, setWsConnected] = useState(false);

  // Initial Data Load & Periodic Polling
  useEffect(() => {
    fetchCoreData();
    const interval = setInterval(fetchCoreData, 3500);
    return () => clearInterval(interval);
  }, [mode, tenantId]);

  // WebSocket Live Stream
  useEffect(() => {
    const ws = api.createWebSocket((msg) => {
      if (msg.type === 'TELEMETRY_INGESTED') {
        const ev = msg.event;
        // Filter by mode
        if (!ev.mode || ev.mode === mode) {
          const normalizedEv = {
            ...ev,
            event_uuid: ev.event_uuid || ev.uuid || `ev-${Date.now()}`
          };
          setRecentEvents((prev) => [
            normalizedEv,
            ...prev.filter(p => (p.event_uuid || p.uuid) !== normalizedEv.event_uuid).slice(0, 99)
          ]);
          if (msg.alerts && msg.alerts.length > 0) {
            setAlerts((prev) => [...msg.alerts, ...prev.slice(0, 49)]);
            // Refresh incidents to reflect newly correlated incidents
            api.getIncidents(mode, tenantId).then(setIncidents).catch(console.error);
          }
        }
      }
    });

    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onerror = () => setWsConnected(false);

    return () => {
      ws.close();
    };
  }, [mode, tenantId]);

  const fetchCoreData = async () => {
    try {
      const [h, ep, inc, alt, siemRes] = await Promise.all([
        api.getHealth(),
        api.getEndpoints(tenantId),
        api.getIncidents(mode, tenantId),
        api.getAlerts(mode, tenantId),
        api.getSiemEvents(mode, 50).catch(() => ({ events: [] }))
      ]);
      setHealth(h);
      setEndpoints(ep);
      setIncidents(inc);
      setAlerts(alt);
      if (siemRes && Array.isArray(siemRes.events) && siemRes.events.length > 0) {
        setRecentEvents((prev) => (prev.length === 0 ? siemRes.events : prev));
      }
    } catch (err) {
      console.error("Data sync error:", err);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', width: '100vw', background: 'var(--bg-primary)' }}>
      <Topbar
        mode={mode}
        onModeChange={(m) => setMode(m)}
        tenantId={tenantId}
        onTenantChange={(t) => setTenantId(t)}
        health={health}
        wsConnected={wsConnected}
      />

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <Sidebar
          currentTab={currentTab}
          onTabChange={(tab) => setCurrentTab(tab)}
          incidentsCount={incidents.filter((i) => i.status !== 'CLOSED').length}
          endpointsCount={endpoints.filter((e) => e.status === 'ONLINE' || e.status === 'ISOLATED').length}
        />

        <main style={{ flex: 1, overflowY: 'auto', background: '#070a12' }}>
          {currentTab === 'dashboard' && (
            <DashboardView
              mode={mode}
              health={health}
              incidents={incidents}
              alerts={alerts}
              recentEvents={recentEvents}
              endpointsCount={endpoints.filter((e) => e.status === 'ONLINE' || e.status === 'ISOLATED').length}
              onNavigate={(tab) => setCurrentTab(tab)}
            />
          )}

          {currentTab === 'edr' && (
            <EDRView endpoints={endpoints} onRefresh={fetchCoreData} />
          )}

          {currentTab === 'siem' && (
            <SIEMView
              events={recentEvents}
              mode={mode}
              onEventsUpdate={(events) => setRecentEvents(events)}
            />
          )}

          {currentTab === 'incidents' && (
            <IncidentsView incidents={incidents} onRefresh={fetchCoreData} />
          )}

          {currentTab === 'hunting' && (
            <HuntingView mode={mode} />
          )}

          {currentTab === 'xdr' && (
            <XDRView incidents={incidents} />
          )}

          {currentTab === 'soar' && (
            <SOARView />
          )}

          {currentTab === 'ueba' && (
            <UEBAView />
          )}

          {currentTab === 'tip' && (
            <TIPView />
          )}

          {currentTab === 'asm' && (
            <ASMView />
          )}

          {currentTab === 'cnapp' && (
            <CNAPPView />
          )}

          {currentTab === 'mitre' && (
            <MITREView mode={mode} />
          )}

          {currentTab === 'health' && (
            <HealthView health={health} onRefresh={fetchCoreData} />
          )}

          {currentTab === 'audit' && (
            <AuditView />
          )}

          {currentTab === 'lab' && (
            <LABView
              currentMode={mode}
              onSwitchToLab={() => setMode('LAB')}
            />
          )}
        </main>
      </div>
    </div>
  );
};

export default App;
