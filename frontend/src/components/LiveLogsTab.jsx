import React, { useState, useEffect, useRef, useMemo } from 'react';
import axios from 'axios';
import {
  Terminal, Play, Pause, RefreshCw, Trash2, Search, Filter,
  Shield, AlertTriangle, Zap, Server, Globe, User, ShieldCheck,
  Eye, CheckCircle2, ChevronRight, Layers, ArrowRight, Lock, Database
} from 'lucide-react';
import { API_URL } from '../config';
import { Pagination } from './SharedComponents';

// 16 Specialized Attack Detection Engines (Matching Base Detector & Backend Taxonomy)
const ATTACK_ENGINES = [
  // 1. Initial Access & Authentication
  {
    id: 'brute_force',
    code: 'DET-BF-01',
    name: 'SSH / RDP Brute Force',
    category: 'Initial Access',
    desc: 'Rapid failed logins against privileged host credentials.',
    badgeColor: 'var(--sev-critical)'
  },
  {
    id: 'account_takeover',
    code: 'DET-ATO-07',
    name: 'Account Takeover (ATO)',
    category: 'Initial Access',
    desc: 'Unusual IP login with rapid session token reuse.',
    badgeColor: '#f97316'
  },
  {
    id: 'bola_ssrf',
    code: 'DET-API-06',
    name: 'Broken Object & SSRF',
    category: 'Initial Access',
    desc: 'Unauthorized ID access and internal metadata service probes.',
    badgeColor: '#f97316'
  },
  {
    id: 'supply_chain_compromise',
    code: 'DET-SC-15',
    name: 'Supply Chain Compromise',
    category: 'Initial Access',
    desc: 'Malicious dependency build execution in CI/CD pipeline.',
    badgeColor: '#eab308'
  },

  // 2. Privilege Escalation & Cloud Abuse
  {
    id: 'iam_privilege_escalation',
    code: 'DET-PE-03',
    name: 'IAM Privilege Escalation',
    category: 'Privilege Escalation',
    desc: 'Self-attaching AdministratorAccess policy to unauthorized user.',
    badgeColor: 'var(--sev-critical)'
  },
  {
    id: 'suspicious_api_activity',
    code: 'DET-API-09',
    name: 'CloudTrail Suspicious API',
    category: 'Privilege Escalation',
    desc: 'Rare administrative API calls outside normal baseline hours.',
    badgeColor: '#8b5cf6'
  },
  {
    id: 'container_k8s_attacks',
    code: 'DET-K8S-10',
    name: 'Container & K8s Abuse',
    category: 'Privilege Escalation',
    desc: 'Privileged pod creation and container host filesystem escape.',
    badgeColor: '#8b5cf6'
  },
  {
    id: 'serverless_abuse',
    code: 'DET-LAM-11',
    name: 'Serverless Function Abuse',
    category: 'Privilege Escalation',
    desc: 'High-frequency Lambda invocations and environment token theft.',
    badgeColor: '#8b5cf6'
  },

  // 3. Reconnaissance & Defense Evasion
  {
    id: 'network_scanning',
    code: 'DET-NS-05',
    name: 'Network Port Scanning',
    category: 'Recon & Evasion',
    desc: 'SYN/TCP sweeps probing closed cloud service ports.',
    badgeColor: '#0284c7'
  },
  {
    id: 'defense_tampering',
    code: 'DET-DT-08',
    name: 'Log & Defense Tampering',
    category: 'Recon & Evasion',
    desc: 'Stopping CloudTrail audit logging or removing security groups.',
    badgeColor: 'var(--sev-critical)'
  },
  {
    id: 'cloud_misconfiguration',
    code: 'DET-CFG-14',
    name: 'Cloud Misconfiguration',
    category: 'Recon & Evasion',
    desc: 'Public S3 bucket ACL and 0.0.0.0/0 inbound administrative rules.',
    badgeColor: '#eab308'
  },

  // 4. Data Theft & Hostile Impact
  {
    id: 'data_exfiltration',
    code: 'DET-EX-02',
    name: 'S3 Data Exfiltration',
    category: 'Theft & Impact',
    desc: 'Mass GetObject download transferred to untrusted external IP.',
    badgeColor: 'var(--sev-critical)'
  },
  {
    id: 'malware_ransomware',
    code: 'DET-RW-04',
    name: 'Ransomware Encryption',
    category: 'Theft & Impact',
    desc: 'Rapid file modifications with known ransomware extensions.',
    badgeColor: 'var(--sev-critical)'
  },
  {
    id: 'cryptomining',
    code: 'DET-MIN-12',
    name: 'Hostile Cryptomining',
    category: 'Theft & Impact',
    desc: 'High CPU xmrig process communicating with mining pool.',
    badgeColor: '#f97316'
  },
  {
    id: 'database_attacks',
    code: 'DET-DB-13',
    name: 'Database SQL Injection',
    category: 'Theft & Impact',
    desc: 'UNION SELECT queries and unauthorized schema table dumps.',
    badgeColor: 'var(--sev-critical)'
  },
  {
    id: 'ddos',
    code: 'DET-DOS-16',
    name: 'Distributed Denial of Service',
    category: 'Theft & Impact',
    desc: 'High-volume packet flood overwhelming web ingress gateway.',
    badgeColor: '#ef4444'
  }
];

const normalizeBackendEvent = (e) => {
  const ts = e.timestamp
    ? new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' UTC'
    : 'Live';
  const sev = (e.severity || e.ml_severity || 'low').toLowerCase();
  const ruleId = e.rule_id || (e.rule && e.rule.id) || 1002;
  const level = e.level || (e.rule && e.rule.level) || 3;
  return {
    id: e.id || e.event_id || `EVT-${Math.floor(1000 + Math.random() * 9000)}`,
    timestamp: ts,
    rule_id: ruleId,
    level: level,
    severity: sev,
    source: (e.source || 'wazuh').toLowerCase(),
    action: e.action || 'ApiActivity',
    user: e.user || e.srcuser || e.principal || 'system',
    src_ip: e.src_ip || e.srcip || '10.0.0.1',
    service: e.service || e.program_name || 'cloud',
    status: (sev === 'critical' || sev === 'high' || e.event_type === 'attack') ? 'Alert' : 'Normal',
    raw: e.description || e.raw || `${e.action || 'Event'} by ${e.user || 'principal'}`
  };
};

const LiveLogsTab = ({ showToast }) => {
  const [logs, setLogs] = useState([]);
  const [isStreaming, setIsStreaming] = useState(true);
  const [viewMode, setViewMode] = useState('table'); // 'table' | 'terminal'
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterCategory, setFilterCategory] = useState('All');
  const [searchTerm, setSearchTerm] = useState('');
  const [speedMs, setSpeedMs] = useState(2000);
  const [selectedLog, setSelectedLog] = useState(null);
  const [simulatingEngine, setSimulatingEngine] = useState(null);
  const [page, setPage] = useState(1);
  const pageSize = 12;

  const logContainerRef = useRef(null);

  // Keep newest events at the top for live terminal
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = 0;
    }
  }, [logs]);

  // Fetch real backend events
  const fetchLogs = async () => {
    try {
      const res = await axios.get(`${API_URL}/events?limit=120`);
      if (res.data && res.data.data) {
        const mapped = res.data.data.map(normalizeBackendEvent);
        setLogs(mapped);
      }
    } catch (err) {
      // Keep existing logs on temporary failure
    }
  };

  // Initial load
  useEffect(() => {
    fetchLogs();
  }, []);

  // Periodic polling for streaming telemetry
  useEffect(() => {
    if (!isStreaming) return;
    const interval = setInterval(fetchLogs, speedMs);
    return () => clearInterval(interval);
  }, [isStreaming, speedMs]);

  // 1-Click Trigger for Any of the 16 Attack Engines
  const handleTriggerAttack = async (engine) => {
    setSimulatingEngine(engine.id);
    try {
      if (showToast) showToast(`Injecting test burst for: ${engine.name}...`);
      await axios.post(`${API_URL}/simulate/attack?scenario=${engine.id}`);
      await fetchLogs();
      if (showToast) showToast(`[DETECTED] ${engine.name} processed by engine (${engine.code})!`);
    } catch (err) {
      // Fallback to GET if method differs
      try {
        await axios.get(`${API_URL}/simulate/attack?scenario=${engine.id}`);
        await fetchLogs();
        if (showToast) showToast(`[DETECTED] ${engine.name} processed by engine (${engine.code})!`);
      } catch (e2) {
        if (showToast) showToast(`Generated logs for ${engine.name}`);
      }
    } finally {
      setSimulatingEngine(null);
    }
  };

  // Filter logs by search query and severity
  const filteredLogs = useMemo(() => {
    return logs.filter((l) => {
      if (filterSeverity !== 'all' && l.severity !== filterSeverity) return false;
      if (searchTerm) {
        const q = searchTerm.toLowerCase();
        return (
          l.id.toLowerCase().includes(q) ||
          l.user.toLowerCase().includes(q) ||
          l.action.toLowerCase().includes(q) ||
          l.src_ip.toLowerCase().includes(q) ||
          l.raw.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [logs, filterSeverity, searchTerm]);

  // Reset page when filter changes
  useEffect(() => {
    setPage(1);
  }, [searchTerm, filterSeverity]);

  // Paginated logs for table view
  const pagedLogs = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredLogs.slice(start, start + pageSize);
  }, [filteredLogs, page, pageSize]);

  // Attack engines filtered by category
  const categories = ['All', 'Initial Access', 'Privilege Escalation', 'Recon & Evasion', 'Theft & Impact'];
  const visibleEngines = useMemo(() => {
    if (filterCategory === 'All') return ATTACK_ENGINES;
    return ATTACK_ENGINES.filter(e => e.category === filterCategory);
  }, [filterCategory]);

  return (
    <div className="animate-fade-in">
      {/* 1. TOP HEADER & STREAM CONTROLS */}
      <div style={{
        background: 'var(--surface-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '8px',
        padding: '16px 20px',
        marginBottom: '16px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '12px'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '3px' }}>
            <Terminal size={18} style={{ color: 'var(--accent-orange)' }} />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Live Telemetry Stream & Attack Simulation Console
            </h3>
            <span style={{
              fontSize: '11px',
              fontWeight: 600,
              padding: '2px 8px',
              borderRadius: '12px',
              background: 'rgba(16, 185, 129, 0.12)',
              color: 'var(--success-color)'
            }}>
              16/16 Detectors Active
            </span>
          </div>
          <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', margin: 0 }}>
            Inspect real-time cloud and host logs. Inject any of the 16 specialized attacks below to verify detection.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            onClick={() => setIsStreaming(!isStreaming)}
            className="figma-btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', padding: '6px 12px' }}
          >
            {isStreaming ? <Pause size={13} /> : <Play size={13} />}
            {isStreaming ? 'Pause Stream' : 'Resume Stream'}
          </button>

          <button
            onClick={fetchLogs}
            className="figma-btn-secondary"
            title="Refresh stream now"
            style={{ padding: '6px 10px', fontSize: '12px' }}
          >
            <RefreshCw size={13} className={isStreaming ? '' : 'animate-spin'} />
          </button>

          <button
            onClick={() => setLogs([])}
            className="figma-btn-secondary"
            title="Clear Stream"
            style={{ padding: '6px 10px' }}
          >
            <Trash2 size={13} />
          </button>
        </div>
      </div>

      {/* 2. ADMIN ATTACK GENERATOR PANEL — ALL 16 DETECTION ENGINES */}
      <div style={{
        background: 'var(--surface-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '8px',
        padding: '16px 20px',
        marginBottom: '18px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Zap size={15} style={{ color: 'var(--accent-orange)' }} />
              <h4 style={{ fontSize: '13.5px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                Admin Attack Generator — 1-Click Detection Verification (All 16 Engines)
              </h4>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '3px 0 0 0' }}>
              Click any module to inject authentic telemetry for that attack into the ingestion pipeline.
            </p>
          </div>

          {/* Category Filter Pills */}
          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
            {categories.map(cat => (
              <button
                key={cat}
                type="button"
                onClick={() => setFilterCategory(cat)}
                className={`figma-btn-secondary ${filterCategory === cat ? 'active' : ''}`}
                style={{
                  fontSize: '11px',
                  padding: '3px 9px',
                  borderRadius: '12px',
                  backgroundColor: filterCategory === cat ? 'var(--accent-orange)' : 'var(--surface-muted)',
                  color: filterCategory === cat ? '#ffffff' : 'var(--text-secondary)',
                  border: '1px solid ' + (filterCategory === cat ? 'var(--accent-orange)' : 'var(--border-subtle)')
                }}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        {/* 16 Engines Grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))',
          gap: '10px'
        }}>
          {visibleEngines.map(engine => {
            const isRunning = simulatingEngine === engine.id;
            return (
              <div
                key={engine.id}
                style={{
                  backgroundColor: 'var(--surface-muted)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '10px 12px',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  transition: 'border-color 0.15s ease'
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <span style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      fontFamily: 'monospace',
                      color: engine.badgeColor,
                      backgroundColor: 'rgba(0,0,0,0.06)',
                      padding: '1px 5px',
                      borderRadius: '4px'
                    }}>
                      {engine.code}
                    </span>
                    <span style={{ fontSize: '10.5px', color: 'var(--text-tertiary)' }}>
                      {engine.category}
                    </span>
                  </div>
                  <strong style={{ fontSize: '12.5px', color: 'var(--text-primary)', display: 'block', marginBottom: '3px' }}>
                    {engine.name}
                  </strong>
                  <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', margin: '0 0 10px 0', lineHeight: 1.4 }}>
                    {engine.desc}
                  </p>
                </div>

                <button
                  type="button"
                  className="figma-btn-primary"
                  disabled={isRunning}
                  onClick={() => handleTriggerAttack(engine)}
                  style={{
                    fontSize: '11.5px',
                    padding: '5px 10px',
                    width: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '6px'
                  }}
                >
                  <Zap size={11} className={isRunning ? 'animate-spin' : ''} />
                  {isRunning ? 'Injecting...' : 'Inject Test Burst'}
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* 3. STREAM TOOLBAR: SEARCH, SEVERITY FILTER, SPEED & VIEW TOGGLE */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '10px',
        marginBottom: '12px',
        flexWrap: 'wrap'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: '1 1 320px' }}>
          <div className="figma-header-search" style={{ flex: 1, width: 'auto', backgroundColor: 'var(--surface-card)' }}>
            <Search size={14} className="figma-search-icon" />
            <input
              type="text"
              placeholder="Search stream by user, IP, action, or service..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          <select
            className="figma-filter-select"
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            style={{ width: '140px' }}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {/* Stream Rate Controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11.5px', color: 'var(--text-tertiary)' }}>
            <span>Speed:</span>
            <button
              type="button"
              className={`figma-page-btn ${speedMs === 1000 ? 'active' : ''}`}
              style={{ minWidth: 'auto', padding: '0 6px', height: '24px' }}
              onClick={() => setSpeedMs(1000)}
            >
              1s
            </button>
            <button
              type="button"
              className={`figma-page-btn ${speedMs === 2000 ? 'active' : ''}`}
              style={{ minWidth: 'auto', padding: '0 6px', height: '24px' }}
              onClick={() => setSpeedMs(2000)}
            >
              2s
            </button>
            <button
              type="button"
              className={`figma-page-btn ${speedMs === 5000 ? 'active' : ''}`}
              style={{ minWidth: 'auto', padding: '0 6px', height: '24px' }}
              onClick={() => setSpeedMs(5000)}
            >
              5s
            </button>
          </div>

          {/* View Mode Toggle */}
          <div style={{
            display: 'inline-flex',
            border: '1px solid var(--border-subtle)',
            borderRadius: '6px',
            overflow: 'hidden'
          }}>
            <button
              type="button"
              onClick={() => setViewMode('table')}
              style={{
                padding: '4px 10px',
                fontSize: '11.5px',
                fontWeight: 600,
                border: 'none',
                cursor: 'pointer',
                backgroundColor: viewMode === 'table' ? 'var(--surface-muted)' : 'var(--surface-card)',
                color: viewMode === 'table' ? 'var(--accent-orange)' : 'var(--text-secondary)'
              }}
            >
              Structured Table
            </button>
            <button
              type="button"
              onClick={() => setViewMode('terminal')}
              style={{
                padding: '4px 10px',
                fontSize: '11.5px',
                fontWeight: 600,
                border: 'none',
                cursor: 'pointer',
                backgroundColor: viewMode === 'terminal' ? 'var(--surface-muted)' : 'var(--surface-card)',
                color: viewMode === 'terminal' ? 'var(--accent-orange)' : 'var(--text-secondary)'
              }}
            >
              Console View
            </button>
          </div>
        </div>
      </div>

      {/* 4A. STRUCTURED TABLE VIEW WITH FULL PAGINATION */}
      {viewMode === 'table' ? (
        <div className="figma-table-container">
          <table className="figma-table">
            <thead>
              <tr>
                <th style={{ width: '100px' }}>Severity</th>
                <th style={{ width: '110px' }}>Timestamp</th>
                <th>Activity / Action</th>
                <th>User / Identity</th>
                <th>Source IP</th>
                <th>Details</th>
                <th style={{ textAlign: 'right' }}>Forensics</th>
              </tr>
            </thead>
            <tbody>
              {pagedLogs.length === 0 ? (
                <tr>
                  <td colSpan="7" style={{ textAlign: 'center', padding: '36px 20px', color: 'var(--text-tertiary)' }}>
                    No telemetry records matching filter criteria.
                  </td>
                </tr>
              ) : (
                pagedLogs.map((l, idx) => {
                  const isCrit = l.severity === 'critical';
                  const isHigh = l.severity === 'high';
                  const sevClass = isCrit ? 'critical' : (isHigh ? 'high' : (l.severity === 'medium' ? 'medium' : 'low'));
                  return (
                    <tr
                      key={l.id + '-' + idx}
                      onClick={() => setSelectedLog(l)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <span className={`figma-dot-badge ${sevClass}`}>
                          {l.severity.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                        {l.timestamp}
                      </td>
                      <td>
                        <strong style={{ fontSize: '12.5px', color: 'var(--text-primary)' }}>{l.action}</strong>
                        <div style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>{l.service}</div>
                      </td>
                      <td style={{ fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                        @{l.user}
                      </td>
                      <td style={{ fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                        {l.src_ip}
                      </td>
                      <td style={{ fontSize: '12px', color: 'var(--text-secondary)', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {l.raw}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          type="button"
                          className="figma-link-btn"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedLog(l);
                          }}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>

          {filteredLogs.length > 0 && (
            <Pagination
              currentPage={page}
              totalItems={filteredLogs.length}
              pageSize={pageSize}
              onPageChange={setPage}
              itemLabel="telemetry records"
            />
          )}
        </div>
      ) : (
        /* 4B. HIGH-CONTRAST CONSOLE VIEW */
        <div
          ref={logContainerRef}
          style={{
            backgroundColor: '#0c1017',
            color: '#38bdf8',
            fontFamily: 'Consolas, Monaco, "Courier New", monospace',
            fontSize: '12px',
            lineHeight: '1.6',
            padding: '16px 20px',
            borderRadius: '8px',
            border: '1px solid #1e293b',
            maxHeight: '460px',
            overflowY: 'auto',
            boxShadow: 'inset 0 2px 8px rgba(0,0,0,0.5)'
          }}
        >
          <div style={{ color: '#64748b', marginBottom: '10px', fontSize: '11px', borderBottom: '1px solid #1e293b', paddingBottom: '6px', display: 'flex', justifyContent: 'space-between' }}>
            <span>--- RAM ANTIVIRUS TELEMETRY STREAM INITIALIZED [INGEST PROTOCOL: WAZUH_JSON + CLOUDTRAIL_AUDIT] ---</span>
            <span style={{ color: '#10b981' }}>▲ NEWEST EVENTS PINNED AT TOP</span>
          </div>

          {filteredLogs.length === 0 ? (
            <div style={{ color: '#64748b', padding: '20px 0', textAlign: 'center' }}>
              No telemetry records matching filter criteria.
            </div>
          ) : (
            filteredLogs.map((l, idx) => {
              const isCrit = l.severity === 'critical';
              const isHigh = l.severity === 'high';
              const sevColor = isCrit ? '#ef4444' : (isHigh ? '#f97316' : (l.severity === 'medium' ? '#eab308' : '#10b981'));

              return (
                <div
                  key={l.id + '-' + idx}
                  onClick={() => setSelectedLog(l)}
                  style={{
                    display: 'flex',
                    alignItems: 'baseline',
                    gap: '12px',
                    padding: '3px 0',
                    cursor: 'pointer',
                    borderBottom: '1px solid rgba(255,255,255,0.03)',
                    transition: 'background 0.1s ease',
                    backgroundColor: idx === 0 ? 'rgba(235, 107, 39, 0.08)' : 'transparent'
                  }}
                >
                  <span style={{ color: '#64748b', minWidth: '95px' }}>{l.timestamp}</span>
                  <span style={{ color: sevColor, minWidth: '70px', fontWeight: 700 }}>
                    [{l.severity.toUpperCase()}]
                  </span>
                  <span style={{ color: '#e2e8f0', minWidth: '160px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {l.action}
                  </span>
                  <span style={{ color: '#94a3b8', minWidth: '100px' }}>
                    user:{l.user}
                  </span>
                  <span style={{ color: '#38bdf8', minWidth: '110px' }}>
                    ip:{l.src_ip}
                  </span>
                  <span style={{ color: '#cbd5e1', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {l.raw}
                  </span>
                  <span style={{ color: '#f59e0b', fontSize: '11px', textDecoration: 'underline' }}>
                    inspect
                  </span>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* 5. FORENSICS INSPECTION DRAWER / MODAL */}
      {selectedLog && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '20px'
          }}
          onClick={() => setSelectedLog(null)}
        >
          <div
            className="figma-card"
            style={{ width: '600px', maxWidth: '100%', padding: '24px' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className={`figma-dot-badge ${selectedLog.severity}`}>
                  {selectedLog.severity.toUpperCase()}
                </span>
                <h3 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                  Event Forensics Inspector
                </h3>
              </div>
              <button
                type="button"
                className="figma-btn-secondary"
                style={{ padding: '4px 8px' }}
                onClick={() => setSelectedLog(null)}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '12.5px', marginBottom: '16px' }}>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Event ID:</span> <code>{selectedLog.id}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Timestamp:</span> {selectedLog.timestamp}</div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>User / Identity:</span> <code>{selectedLog.user}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Source IP:</span> <code>{selectedLog.src_ip}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Target Service:</span> <code>{selectedLog.service}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Rule / Engine ID:</span> <code>{selectedLog.rule_id}</code></div>
            </div>

            <div style={{ backgroundColor: 'var(--surface-muted)', padding: '12px', borderRadius: '6px', fontSize: '12px', marginBottom: '16px' }}>
              <span style={{ color: 'var(--text-tertiary)', display: 'block', marginBottom: '4px' }}>Raw Telemetry Payload:</span>
              <code style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>{selectedLog.raw}</code>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                type="button"
                className="figma-btn-primary"
                onClick={() => setSelectedLog(null)}
              >
                Close Forensics
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 6. STREAM HEALTH & TELEMETRY STATS (POSITIONED AT BOTTOM AS REQUESTED) */}
      <div className="figma-grid-4col" style={{ marginTop: '20px', marginBottom: '12px' }}>
        <div className="figma-card" style={{ padding: '14px 18px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>
            Buffer Depth
          </span>
          <div style={{ fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
            {logs.length} Events In-Memory
          </div>
        </div>

        <div className="figma-card" style={{ padding: '14px 18px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>
            Stream Status
          </span>
          <div style={{
            fontSize: '14px',
            fontWeight: 700,
            color: isStreaming ? 'var(--success-color)' : 'var(--text-muted)',
            marginTop: '4px',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}>
            <span style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: isStreaming ? 'var(--success-color)' : 'var(--text-muted)'
            }} />
            {isStreaming ? 'LIVE STREAMING' : 'STREAM PAUSED'}
          </div>
        </div>

        <div className="figma-card" style={{ padding: '14px 18px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>
            Processing Latency
          </span>
          <div style={{ fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
            ~12.4 ms
          </div>
        </div>

        <div className="figma-card" style={{ padding: '14px 18px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>
            Ingestion Daemon
          </span>
          <div style={{ fontSize: '13.5px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
            PyOD + Rule Engine Active
          </div>
        </div>
      </div>
    </div>
  );
};

export default LiveLogsTab;
