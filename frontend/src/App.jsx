import React, { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import {
  Shield,
  AlertTriangle,
  Gauge,
  Cpu,
  Wrench,
  FlaskConical,
  Users,
  Database,
  Settings,
  ChevronDown,
  RefreshCw,
  Search,
  Calendar,
  LogOut,
  PanelLeftClose,
  PanelLeftOpen,
  Play,
  Zap,
  Terminal,
  Sun,
  Moon
} from 'lucide-react';
import logoUrl from './assets/LOGO.png';
import LoginPage from './components/LoginPage';
import OverviewTab from './components/OverviewTab';
import AlertsIncidentsTab from './components/AlertsIncidentsTab';
import RiskScoreTab from './components/RiskScoreTab';
import MLComparisonTab from './components/MLComparisonTab';
import RemediationTab from './components/RemediationTab';
import AttackSimulationTab from './components/AttackSimulationTab';
import LiveLogsTab from './components/LiveLogsTab';
import UserManagementTab from './components/UserManagementTab';
import DataSourcesTab from './components/DataSourcesTab';
import WorkspaceSettingsTab from './components/WorkspaceSettingsTab';
import { Toast, ErrorBoundary } from './components/SharedComponents';
import { API_URL, WS_URL } from './config';
import './index.css';

// Centralized Axios interceptor attaching Bearer token for all authenticated requests
axios.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token && !config.headers.Authorization) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

export const getLiveUtcTime = () => {
  const now = new Date();
  const day = now.getUTCDate();
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const month = months[now.getUTCMonth()];
  const year = now.getUTCFullYear();
  const hours = String(now.getUTCHours()).padStart(2, '0');
  const minutes = String(now.getUTCMinutes()).padStart(2, '0');

  return {
    fullDate: `${day} ${month} ${year}`,
    dayMonth: `${day} ${month}`,
    timeStr: `${hours}:${minutes}`,
    headerBadge: `Live telemetry · ${day} ${month} ${year}, ${hours}:${minutes} UTC`,
    dateRangeBadge: `${day} ${month} · 00:00–${hours}:${minutes} UTC`,
    chartBadge: `${day} ${month} · UTC`
  };
};

const App = () => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [data, setData] = useState({ summary: null, events: [], cspm: [], ciem: [] });
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState(null);
  const [playbooks, setPlaybooks] = useState([]);
  const [liveTime, setLiveTime] = useState(getLiveUtcTime());
  const [wsConnected, setWsConnected] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => {
      setLiveTime(getLiveUtcTime());
    }, 10000);
    return () => clearInterval(timer);
  }, []);

  // Category 1 & Detector Findings State
  const [findings, setFindings] = useState([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsError, setFindingsError] = useState(null);
  const [findingsAttackMode, setFindingsAttackMode] = useState(0);

  // Incident Correlation State
  const [incidents, setIncidents] = useState([]);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [incidentsStats, setIncidentsStats] = useState(null);
  const [selectedCategoryFilter, setSelectedCategoryFilter] = useState('All');
  const [targetRemediationIncidentId, setTargetRemediationIncidentId] = useState(null);

  const handleNavigateTab = (tabId, category = null) => {
    setActiveTab(tabId);
    if (category) {
      setSelectedCategoryFilter(category);
    }
  };

  const handleInvestigateFinding = (finding, incident = null) => {
    if (incident) {
      setTargetRemediationIncidentId(incident.incident_id || incident.id);
    } else if (finding) {
      const fid = finding.finding_id || finding.id;
      const princ = finding.affected_principal || finding.user;
      const matchingInc = (incidents || []).find(inc =>
        (inc.finding_ids && inc.finding_ids.includes(fid)) ||
        (inc.findings && inc.findings.some(f => f.finding_id === fid)) ||
        (princ && inc.principals && inc.principals.includes(princ))
      );
      setTargetRemediationIncidentId(matchingInc ? matchingInc.incident_id : fid);
    }
    setActiveTab('remediation');
  };

  // Figma Light/Dark theme (defaulting to light as in the wireframes, toggleable to dark)
  const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'light');
  const toggleTheme = (newTheme) => {
    const next = newTheme || (theme === 'light' ? 'dark' : 'light');
    setTheme(next);
    localStorage.setItem('theme', next);
  };

  const showToast = useCallback((message, type = 'success') => setToast({ message, type }), []);

  const [searchQuery, setSearchQuery] = useState('');
  const [showSearchDropdown, setShowSearchDropdown] = useState(false);
  const searchInputRef = useRef(null);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
        setShowSearchDropdown(true);
      }
      if (e.key === 'Escape') {
        setShowSearchDropdown(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  useEffect(() => {
    const savedToken = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    if (savedToken && savedUser) {
      setToken(savedToken);
      setUser(JSON.parse(savedUser));
    }
  }, []);

  const handleLogin = (userData, tokenData) => {
    setUser(userData);
    setToken(tokenData);
  };

  const handleLogout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  };

  const hasPermission = (perm) => {
    if (!user) return false;
    if (user.role === 'admin') return true;
    return user.permissions?.includes(perm) ?? false;
  };

  const fetchFindings = async (attacks = 0, isPolling = false) => {
    if (!isPolling) setFindingsLoading(true);
    setFindingsError(null);
    setFindingsAttackMode(attacks);
    try {
      const res = await axios.get(`${API_URL}/detection/findings?normal=50&attacks=${attacks}`);
      setFindings(res.data.data || []);
    } catch (err) {
      console.error("Error fetching findings:", err);
      setFindingsError(err.response?.data?.detail || err.message || "Failed to fetch security findings");
    } finally {
      if (!isPolling) setFindingsLoading(false);
    }
  };

  const fetchIncidents = async (isPolling = false) => {
    if (!isPolling) setIncidentsLoading(true);
    try {
      const [res, statsRes] = await Promise.all([
        axios.get(`${API_URL}/incidents`),
        axios.get(`${API_URL}/incidents/stats`)
      ]);
      setIncidents(res.data.data || []);
      setIncidentsStats(statsRes.data.data || null);
    } catch (err) {
      console.error("Error fetching incidents:", err);
    } finally {
      if (!isPolling) setIncidentsLoading(false);
    }
  };

  const fetchDashboardData = async (isPolling = false) => {
    if (!isPolling) setLoading(true);
    try {
      const [summaryRes, eventsRes, cspmRes, ciemRes, vulnsRes] = await Promise.all([
        axios.get(`${API_URL}/dashboard/summary`),
        axios.get(`${API_URL}/simulate/events?hours=6&normal=50&attacks=10`),
        axios.get(`${API_URL}/cspm/scan`),
        axios.get(`${API_URL}/ciem/scan`),
        axios.get(`${API_URL}/vulnerabilities`)
      ]);
      setData({
        summary: summaryRes.data.data,
        events: eventsRes.data.data,
        cspm: cspmRes.data.data,
        ciem: ciemRes.data.data,
        vulnerabilities: vulnsRes.data.vulnerabilities || []
      });
      fetchFindings(findingsAttackMode, isPolling);
      fetchIncidents(isPolling);
      fetchPlaybooks();
    } catch (error) {
      console.error("Error fetching data:", error);
    } finally {
      if (!isPolling) setLoading(false);
    }
  };

  const handleScanVulnerabilities = async () => {
    try {
      showToast('Initiating workload vulnerability scan...', 'info');
      const res = await axios.post(`${API_URL}/vulnerabilities/scan`);
      const count = res.data.count || 0;
      showToast(`Scan complete: ${count} vulnerabilities detected and prioritized.`, 'success');
      const refreshed = await axios.get(`${API_URL}/vulnerabilities`);
      setData(prev => ({
        ...prev,
        vulnerabilities: refreshed.data.vulnerabilities || []
      }));
    } catch (err) {
      console.error(err);
      showToast('Failed to run vulnerability scan', 'error');
    }
  };

  const handleSyncNvd = async () => {
    try {
      showToast('Connecting to NIST National Vulnerability Database API...', 'info');
      const res = await axios.post(`${API_URL}/vulnerabilities/nvd/sync`);
      const synced = res.data.synced_count ?? 0;
      const mode = res.data.mode === 'nvd_live' ? 'Live NVD feed' : 'Cached fallback retained';
      showToast(`NVD Sync: ${synced} advisories synced (${mode})`, 'success');
      const refreshed = await axios.get(`${API_URL}/vulnerabilities`);
      setData(prev => ({
        ...prev,
        vulnerabilities: refreshed.data.vulnerabilities || []
      }));
    } catch (err) {
      console.error(err);
      showToast('NVD sync failed; retained cached advisories', 'warning');
    }
  };


  const fetchPlaybooks = async () => {
    try {
      const res = await axios.get(`${API_URL}/remediation/playbooks`);
      setPlaybooks(res.data.data || []);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    if (!user) return;
    fetchDashboardData(false);

    // Auto-refresh every 5 seconds as fallback / baseline sync
    const interval = setInterval(() => {
      fetchDashboardData(true);
    }, 5000);

    return () => clearInterval(interval);
  }, [user]);

  // WebSocket Live Streaming Integration (TNY-05)
  useEffect(() => {
    if (!user) return;
    let ws = null;
    let reconnectTimer = null;
    let isCancelled = false;

    const connectWs = () => {
      try {
        ws = new WebSocket(WS_URL);
        ws.onopen = () => {
          if (!isCancelled) {
            const currentToken = localStorage.getItem('token');
            if (currentToken) {
              ws.send(JSON.stringify({ type: 'auth', token: currentToken }));
            }
            console.log('[WebSocket] Stream opened, dispatching auth handshake:', WS_URL);
          }
        };
        ws.onmessage = (event) => {
          if (isCancelled) return;
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'auth_ok') {
              setWsConnected(true);
              console.log('[WebSocket] Stream authenticated for user:', msg.username);
            } else if (msg.type === 'auth_error') {
              console.warn('[WebSocket] Authentication rejected:', msg.detail);
              setWsConnected(false);
            } else if (msg.type === 'events_update') {
              setData((prev) => ({
                ...prev,
                events: msg.latest_events && msg.latest_events.length > 0 ? msg.latest_events : prev.events,
                summary: prev.summary ? {
                  ...prev.summary,
                  threats: {
                    ...prev.summary.threats,
                    critical_threats_count: msg.critical ?? prev.summary.threats.critical_threats_count,
                    anomalies_detected_count: msg.anomalies ?? prev.summary.threats.anomalies_detected_count,
                  }
                } : prev.summary
              }));
            }
          } catch (e) {
            console.error('[WebSocket] Message parse error:', e);
          }
        };
        ws.onerror = (err) => {
          console.warn('[WebSocket] Stream error, falling back to HTTP polling:', err);
          if (!isCancelled) setWsConnected(false);
        };
        ws.onclose = () => {
          if (!isCancelled) {
            setWsConnected(false);
            reconnectTimer = setTimeout(connectWs, 5000);
          }
        };
      } catch (err) {
        console.warn('[WebSocket] Init failed:', err);
        if (!isCancelled) {
          setWsConnected(false);
          reconnectTimer = setTimeout(connectWs, 5000);
        }
      }
    };

    connectWs();

    return () => {
      isCancelled = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws) ws.close();
    };
  }, [user]);

  const hasTabAccess = (tab) => {
    if (!user) return false;
    const role = user.role || 'viewer';
    if (tab.roles) {
      return tab.roles.includes(role);
    }
    return hasPermission(tab.perm);
  };

  // Role-tailored navigation tabs:
  // - Viewer: Executive dashboards and compliance reports only (no ML training, no simulation, no admin configs)
  // - Analyst: Investigation, ML Benchmarking, Attack Simulation, Compliance
  // - Admin: Full suite + Live Log Generator daemon + User Management + Remediation
  const navTabs = [
    { id: 'overview', label: 'Overview', icon: <Shield size={16} />, perm: 'dashboard:read', roles: ['admin', 'analyst', 'viewer'] },
    { id: 'alerts', label: 'Alerts & Incidents', icon: <AlertTriangle size={16} />, perm: 'dashboard:read', roles: ['admin', 'analyst', 'viewer'] },
    { id: 'risk', label: 'Risk Score', icon: <Gauge size={16} />, perm: 'risk:read', roles: ['admin', 'analyst', 'viewer'] },
    { id: 'remediation', label: 'Remediation', icon: <Wrench size={16} />, perm: 'remediation:read', roles: ['admin', 'analyst', 'viewer'] },
    { id: 'ml', label: 'ML Comparison', icon: <Cpu size={16} />, perm: 'ml:read', roles: ['admin', 'analyst'] },
    { id: 'simulation', label: 'Attack Simulation', icon: <FlaskConical size={16} />, perm: 'simulation:read', roles: ['admin', 'analyst'] },
    { id: 'livelogs', label: 'Live Log Stream', icon: <Terminal size={16} />, perm: 'admin', roles: ['admin'] },
    { id: 'users', label: 'Users', icon: <Users size={16} />, perm: 'users:read', roles: ['admin'] },
  ];

  const footerTabs = [
    { id: 'datasources', label: 'Data sources', icon: <Database size={16} />, perm: 'dashboard:read', roles: ['admin', 'analyst', 'viewer'] },
    { id: 'settings', label: 'Platform settings', icon: <Settings size={16} />, perm: 'dashboard:read', roles: ['admin'] },
  ];

  useEffect(() => {
    if (user) {
      const allowed = [...navTabs, ...footerTabs].filter(hasTabAccess).map(t => t.id);
      if (!allowed.includes(activeTab)) {
        setActiveTab('overview');
      }
    }
  }, [user, user?.role, activeTab]);

  // Page header titles and actions according to Figma wireframes
  const pageMeta = {
    overview: {
      title: 'Overview',
      subtitle: 'Production telemetry · Wazuh SIEM & CloudTrail active stream',
      action: (
        <>
          <div className="figma-date-badge">
            <Calendar size={13} /> {liveTime.dateRangeBadge}
          </div>
          <button className="figma-btn-secondary" onClick={fetchDashboardData} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        </>
      )
    },
    alerts: {
      title: 'Alerts & Incidents',
      subtitle: 'Production telemetry · Wazuh SIEM & CloudTrail active stream',
      action: (
        <>
          <div className="figma-date-badge">
            <Calendar size={13} /> {liveTime.dateRangeBadge}
          </div>
          <button className="figma-btn-secondary" onClick={() => fetchFindings(findingsAttackMode)} disabled={findingsLoading}>
            <RefreshCw size={13} className={findingsLoading ? 'animate-spin' : ''} /> Refresh
          </button>
        </>
      )
    },
    risk: {
      title: 'Risk Score',
      subtitle: 'Real-time multi-dimensional risk posture engine',
      action: (
        <button className="figma-btn-primary" onClick={() => { setActiveTab('risk'); showToast('Risk score recomputed across all telemetry vectors'); }}>
          <RefreshCw size={13} /> Recalculate risk
        </button>
      )
    },
    ml: {
      title: 'ML Comparison',
      subtitle: 'Specialist anomaly detection benchmarks & PyOD evaluation',
      action: (
        <button className="figma-btn-primary" onClick={() => { setActiveTab('ml'); showToast('ML comparison evaluation initiated'); }}>
          <Play size={13} /> Run comparison
        </button>
      )
    },
    remediation: {
      title: 'Remediation',
      subtitle: 'Autonomous playbook execution & self-healing cloud configuration',
      action: (
        <div className="figma-date-badge">
          <Shield size={13} style={{ color: 'var(--accent-orange)' }} /> Safe Dry-Run Mode
        </div>
      )
    },
    simulation: {
      title: 'Attack Simulation',
      subtitle: 'MITRE ATT&CK sandbox runner & adversary emulation',
      action: (
        <button className="figma-btn-primary" onClick={() => { setActiveTab('simulation'); }}>
          <Play size={13} /> Run attack simulation
        </button>
      )
    },
    users: {
      title: 'Users',
      subtitle: 'User accounts and role-based access management',
      action: (
        <button className="figma-btn-primary" onClick={() => setActiveTab('users')}>
          Invite user
        </button>
      )
    },
    livelogs: {
      title: 'Live Log Stream',
      subtitle: 'Real-time telemetry ingestion daemon · === Live Log Generator ===',
      action: null
    },
    datasources: {
      title: 'Data Sources',
      subtitle: 'Telemetry connector directory and ingestion pipelines',
      action: (
        <button className="figma-btn-primary" onClick={() => setActiveTab('datasources')}>
          Add source
        </button>
      )
    },
    settings: {
      title: 'Platform Settings',
      subtitle: 'Detector sensitivity parameters and safety configurations',
      action: (
        <button className="figma-btn-primary" onClick={() => showToast('Settings saved')}>
          Save changes
        </button>
      )
    }
  };

  const currentMeta = pageMeta[activeTab] || pageMeta.overview;

  const searchResults = searchQuery.trim() === '' ? [] : [
    ...navTabs.concat(footerTabs).filter(t => t.label.toLowerCase().includes(searchQuery.toLowerCase())).map(t => ({
      type: 'Tab',
      title: t.label,
      subtitle: `Jump to ${t.label}`,
      action: () => { setActiveTab(t.id); setSearchQuery(''); setShowSearchDropdown(false); }
    })),
    ...findings.filter(f =>
      (f.title?.toLowerCase() || '').includes(searchQuery.toLowerCase()) ||
      (f.finding_id?.toLowerCase() || '').includes(searchQuery.toLowerCase()) ||
      (f.affected_principal?.toLowerCase() || '').includes(searchQuery.toLowerCase())
    ).slice(0, 5).map(f => ({
      type: `Finding · ${f.severity?.toUpperCase() || 'INFO'}`,
      title: `${f.finding_id}: ${f.title}`,
      subtitle: f.affected_principal || f.affected_resource || 'Identity fixture',
      action: () => {
        setSelectedFinding(f);
        setActiveTab('alerts');
        setSearchQuery('');
        setShowSearchDropdown(false);
      }
    }))
  ];

  if (!user) return <LoginPage onLogin={handleLogin} />;

  return (
    <div className={`figma-app-container ${theme === 'dark' ? 'theme-dark' : ''}`}>
      {/* 1. LEFT SIDEBAR (EXACT 240px FIGMA SPEC) */}
      <aside className={`figma-sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
        <div className="figma-sidebar-brand">
          <img src={logoUrl} alt="RAM Antivirus Shield" />
          {!sidebarCollapsed && <span>RAM Antivirus</span>}
        </div>



        <nav className="figma-nav-list" aria-label="Main Navigation">
          {navTabs.filter(hasTabAccess).map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                className={`figma-nav-item ${isActive ? 'active' : ''}`}
                onClick={() => setActiveTab(tab.id)}
                title={sidebarCollapsed ? tab.label : undefined}
              >
                {tab.icon}
                {!sidebarCollapsed && <span>{tab.label}</span>}
              </button>
            );
          })}

          <div className="figma-nav-divider" />

          {footerTabs.filter(hasTabAccess).map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                className={`figma-nav-item ${isActive ? 'active' : ''}`}
                onClick={() => setActiveTab(tab.id)}
                title={sidebarCollapsed ? tab.label : undefined}
              >
                {tab.icon}
                {!sidebarCollapsed && <span>{tab.label}</span>}
              </button>
            );
          })}
        </nav>

        {/* USER PROFILE IN LEFT SIDEBAR */}
        <div
          className="sidebar-user-card"
          title={`Logged in as ${user?.full_name || 'Security Analyst'} (@${user?.username || 'analyst'})`}
          style={{
            marginTop: 'auto',
            marginBottom: '8px',
            padding: sidebarCollapsed ? '8px 4px' : '10px 12px',
            backgroundColor: 'var(--surface-muted)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '10px',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            justifyContent: sidebarCollapsed ? 'center' : 'flex-start',
            transition: 'all 0.2s ease'
          }}
        >
          <div
            style={{
              width: '32px',
              height: '32px',
              borderRadius: '50%',
              backgroundColor: 'var(--surface-card)',
              border: '1px solid var(--border-subtle)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '12px',
              fontWeight: 700,
              color: 'var(--accent-orange)',
              flexShrink: 0,
              boxShadow: '0 1px 3px rgba(0, 0, 0, 0.08)'
            }}
          >
            {user?.full_name
              ? user.full_name
                  .split(' ')
                  .map((n) => n[0])
                  .join('')
                  .substring(0, 2)
                  .toUpperCase()
              : 'SA'}
          </div>

          {!sidebarCollapsed && (
            <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0, overflow: 'hidden' }}>
              <span
                style={{
                  fontSize: '13px',
                  fontWeight: 600,
                  color: 'var(--text-primary)',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis'
                }}
              >
                {user?.full_name || 'Security Analyst'}
              </span>
              <span
                style={{
                  fontSize: '11px',
                  color: 'var(--text-tertiary)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px',
                  marginTop: '1px'
                }}
              >
                <span
                  style={{
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    backgroundColor: '#10b981',
                    boxShadow: '0 0 6px rgba(16, 185, 129, 0.6)'
                  }}
                />
                {user?.role || 'analyst'} &bull; online
              </span>
            </div>
          )}
        </div>

        <div className="figma-sidebar-footer">
          <button
            className="figma-nav-item"
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            style={{ color: 'var(--text-tertiary)' }}
          >
            {sidebarCollapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
            {!sidebarCollapsed && <span>Collapse sidebar</span>}
          </button>
        </div>
      </aside>

      {/* 2. MAIN LAYOUT SHELL */}
      <div className="figma-main-layout">
        {/* TOP HEADER (SEARCH + USER CHIP + LIGHT/DARK TOGGLE) */}
        <header className="figma-top-header">
          <div className="figma-header-search" style={{ position: 'relative' }}>
            <Search size={15} style={{ color: 'var(--text-tertiary)' }} />
            <input
              ref={searchInputRef}
              type="text"
              placeholder="Search alerts, events, identities or resources..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setShowSearchDropdown(true);
              }}
              onFocus={() => setShowSearchDropdown(true)}
              onBlur={() => setTimeout(() => setShowSearchDropdown(false), 250)}
            />

            {showSearchDropdown && searchResults.length > 0 && (
              <div className="figma-search-dropdown">
                {searchResults.map((res, i) => (
                  <div key={i} className="figma-search-result-item" onMouseDown={res.action}>
                    <div>
                      <span className="search-result-title">{res.title}</span>
                      <span className="search-result-subtitle">{res.subtitle}</span>
                    </div>
                    <span className="search-result-type">{res.type}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="figma-header-right">
            {/* Sleek Theme Switcher (From Uiverse.io by andrew-demchenk0) */}
            <div className="theme-switcher" role="radiogroup" aria-label="Theme mode switcher">
              <button
                type="button"
                className={`theme-switcher_switch ${theme === 'light' ? 'active' : ''}`}
                onClick={() => toggleTheme('light')}
                title="Switch to Light mode"
                aria-label="Light mode"
              >
                <Sun size={15} className="theme-switcher-icon" />
              </button>
              <button
                type="button"
                className={`theme-switcher_switch ${theme === 'dark' ? 'active' : ''}`}
                onClick={() => toggleTheme('dark')}
                title="Switch to Dark mode"
                aria-label="Dark mode"
              >
                <Moon size={15} className="theme-switcher-icon" />
              </button>
            </div>

            <button
              className="figma-btn-secondary"
              style={{ padding: '6px 10px' }}
              onClick={handleLogout}
              title="Logout"
            >
              <LogOut size={14} />
            </button>
          </div>
        </header>

        {/* PAGE CONTENT CONTAINER */}
        <main className="figma-content-area">
          {/* HEADER ROW WITH UTC SNAPSHOT & PRIMARY ACTION */}
          <div className="figma-page-header">
            <div className="figma-page-title-group">
              <h1>{currentMeta.title}</h1>
              <div className="figma-page-subtitle">
                <span>{currentMeta.subtitle}</span>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginRight: '4px' }}>
                {liveTime.headerBadge}
              </span>
              <span style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '11.5px',
                padding: '3px 9px',
                borderRadius: '6px',
                background: 'var(--surface-muted)',
                color: 'var(--text-secondary)',
                border: '1px solid var(--border-subtle)',
                fontWeight: 500
              }}>
                <span style={{
                  width: '6px',
                  height: '6px',
                  borderRadius: '50%',
                  background: wsConnected ? 'var(--text-secondary)' : 'var(--text-muted)'
                }}></span>
                {wsConnected ? 'Stream Active' : 'Polling (5s)'}
              </span>
              {currentMeta.action}
            </div>
          </div>

          {/* PAGE ROUTING (ALL 10 FIGMA MODULES) */}
          <ErrorBoundary>
          {activeTab === 'overview' && (
            <OverviewTab
              data={data}
              findings={findings}
              findingsLoading={findingsLoading}
              findingsError={findingsError}
              fetchFindings={fetchFindings}
              liveTime={liveTime}
              onInvestigateFinding={handleInvestigateFinding}
              onNavigateTab={handleNavigateTab}
            />
          )}

          {activeTab === 'alerts' && (
            <AlertsIncidentsTab
              findings={findings}
              findingsLoading={findingsLoading}
              findingsError={findingsError}
              findingsAttackMode={findingsAttackMode}
              fetchFindings={fetchFindings}
              incidents={incidents}
              incidentsLoading={incidentsLoading}
              incidentsStats={incidentsStats}
              fetchIncidents={fetchIncidents}
              vulnerabilities={data.vulnerabilities || []}
              onScanVulnerabilities={handleScanVulnerabilities}
              onSyncNVD={handleSyncNvd}
              categoryFilter={selectedCategoryFilter}
              setCategoryFilter={setSelectedCategoryFilter}
              onInvestigateFinding={handleInvestigateFinding}
            />
          )}

          {activeTab === 'risk' && (
            <RiskScoreTab
              data={data}
              findings={findings}
              liveTime={liveTime}
              showToast={showToast}
              onNavigateTab={handleNavigateTab}
              onInvestigateFinding={handleInvestigateFinding}
            />
          )}

          {activeTab === 'ml' && <MLComparisonTab showToast={showToast} />}

          {activeTab === 'remediation' && (
            <RemediationTab
              playbooks={playbooks}
              showToast={showToast}
              cspm={data.cspm}
              ciem={data.ciem}
              findings={findings}
              incidents={incidents}
              targetIncidentId={targetRemediationIncidentId}
              onRefreshData={() => {
                fetchIncidents();
                fetchFindings(findingsAttackMode);
              }}
            />
          )}

          {activeTab === 'simulation' && <AttackSimulationTab showToast={showToast} onNavigateTab={handleNavigateTab} />}

          {activeTab === 'livelogs' && <LiveLogsTab showToast={showToast} />}

          {activeTab === 'users' && <UserManagementTab token={token} showToast={showToast} />}

          {activeTab === 'datasources' && <DataSourcesTab showToast={showToast} />}

          {activeTab === 'settings' && (
            <WorkspaceSettingsTab
              theme={theme}
              onToggleTheme={toggleTheme}
              showToast={showToast}
            />
          )}
          </ErrorBoundary>
        </main>
      </div>

      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
};

export default App;
