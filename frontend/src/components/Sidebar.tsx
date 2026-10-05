import React from 'react';
import {
  LayoutDashboard,
  AlertOctagon,
  Search,
  Laptop,
  Database,
  Network,
  Cpu,
  Bot,
  UserCheck,
  Globe2,
  Cloud,
  FileCheck2,
  Flame,
  Activity,
  ShieldCheck,
  TestTube2,
  Lock,
  Layers
} from 'lucide-react';

export type NavItem =
  | 'dashboard'
  | 'incidents'
  | 'hunting'
  | 'edr'
  | 'siem'
  | 'xdr'
  | 'ndr'
  | 'soar'
  | 'ueba'
  | 'tip'
  | 'asm'
  | 'cnapp'
  | 'mitre'
  | 'health'
  | 'audit'
  | 'lab';

interface SidebarProps {
  currentTab: NavItem;
  onTabChange: (tab: NavItem) => void;
  incidentsCount: number;
  endpointsCount: number;
}

interface SidebarItem {
  id: NavItem;
  label: string;
  icon: React.ComponentType<{ size?: number; color?: string }>;
  badge?: number;
  highlight?: boolean;
}

interface SidebarSection {
  title: string;
  items: SidebarItem[];
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onTabChange,
  incidentsCount,
  endpointsCount
}) => {
  const sections: SidebarSection[] = [
    {
      title: 'OPERATIONS',
      items: [
        { id: 'dashboard', label: 'SOC Overview', icon: LayoutDashboard },
        { id: 'incidents', label: 'Incidents & Cases', icon: AlertOctagon, badge: incidentsCount },
        { id: 'hunting', label: 'Threat Hunting', icon: Search }
      ]
    },
    {
      title: 'TELEMETRY PLANE',
      items: [
        { id: 'edr', label: 'EDR Endpoints', icon: Laptop, badge: endpointsCount },
        { id: 'siem', label: 'SIEM Log Stream', icon: Database },
        { id: 'xdr', label: 'XDR Correlation', icon: Layers },
        { id: 'ndr', label: 'NDR Telemetry', icon: Network },
        { id: 'cnapp', label: 'CNAPP Cloud Posture', icon: Cloud }
      ]
    },
    {
      title: 'INTELLIGENCE & AI',
      items: [
        { id: 'tip', label: 'Threat Intel / TIP', icon: Globe2 },
        { id: 'ueba', label: 'UEBA Analytics', icon: UserCheck },
        { id: 'asm', label: 'Attack Surface (ASM)', icon: Flame },
        { id: 'mitre', label: 'MITRE ATT&CK', icon: ShieldCheck }
      ]
    },
    {
      title: 'AUTOMATION & AUDIT',
      items: [
        { id: 'soar', label: 'SOAR Orchestration', icon: Bot },
        { id: 'audit', label: 'Crypto Audit Trail', icon: Lock },
        { id: 'health', label: 'System Health & EPS', icon: Activity },
        { id: 'lab', label: 'LAB Mode Simulator', icon: TestTube2, highlight: true }
      ]
    }
  ];

  return (
    <aside style={{
      width: '240px',
      background: '#080c16',
      borderRight: '1px solid #1a233a',
      height: 'calc(100vh - 64px)',
      overflowY: 'auto',
      display: 'flex',
      flexDirection: 'column',
      padding: '16px 0'
    }}>
      {sections.map((sec, secIdx) => (
        <div key={sec.title} style={{ marginBottom: '18px' }}>
          <div style={{
            fontSize: '0.66rem',
            fontWeight: 800,
            letterSpacing: '1px',
            color: '#475569',
            padding: '0 20px 8px 20px',
            fontFamily: 'var(--font-mono)'
          }}>
            {sec.title}
          </div>
          <div>
            {sec.items.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onTabChange(item.id as NavItem)}
                  style={{
                    width: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 20px',
                    background: isActive
                      ? 'linear-gradient(90deg, rgba(6, 182, 212, 0.15) 0%, rgba(6, 182, 212, 0.02) 100%)'
                      : 'transparent',
                    border: 'none',
                    borderLeft: isActive ? '3px solid #06b6d4' : '3px solid transparent',
                    color: isActive ? '#fff' : item.highlight ? '#fbbf24' : '#94a3b8',
                    cursor: 'pointer',
                    fontSize: '0.82rem',
                    fontWeight: isActive ? 600 : 500,
                    textAlign: 'left',
                    transition: 'all 0.12s ease'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <Icon size={16} color={isActive ? '#06b6d4' : item.highlight ? '#f59e0b' : '#64748b'} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span style={{
                      background: item.id === 'incidents' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(6, 182, 212, 0.2)',
                      color: item.id === 'incidents' ? '#f87171' : '#38bdf8',
                      fontSize: '0.68rem',
                      fontWeight: 700,
                      padding: '1px 6px',
                      borderRadius: '10px',
                      fontFamily: 'var(--font-mono)'
                    }}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </aside>
  );
};
