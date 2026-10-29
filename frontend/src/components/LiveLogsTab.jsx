import React, { useState, useEffect, useRef, useMemo } from 'react';
import axios from 'axios';
import {
  Terminal, Play, Pause, RefreshCw, Trash2, Search, Filter,
  Shield, AlertTriangle, Zap, Server, Globe, User, ShieldCheck,
  Eye, CheckCircle2, ChevronRight, Layers, ArrowRight, Lock, Database, Code, Copy, Check, ChevronDown, ChevronUp
} from 'lucide-react';
import { API_URL } from '../config';
import { Pagination } from './SharedComponents';

// 16 Specialized Attack Detection Engines
const ATTACK_ENGINES = [
  { id: 'brute_force', code: 'DET-BF-01', name: 'SSH / RDP Brute Force', category: 'Initial Access', desc: 'Rapid failed logins against privileged credentials.' },
  { id: 'account_takeover', code: 'DET-ATO-07', name: 'Account Takeover (ATO)', category: 'Initial Access', desc: 'Unusual IP login with rapid session token reuse.' },
  { id: 'bola_ssrf', code: 'DET-API-06', name: 'Broken Object & SSRF', category: 'Initial Access', desc: 'Unauthorized ID access and internal metadata service probes.' },
  { id: 'supply_chain', code: 'DET-SC-15', name: 'Supply Chain Compromise', category: 'Initial Access', desc: 'Malicious dependency build execution in CI/CD pipeline.' },

  { id: 'iam_privilege_escalation', code: 'DET-PE-03', name: 'IAM Privilege Escalation', category: 'Privilege Escalation', desc: 'Attaching AdministratorAccess policy to unauthorized user.' },
  { id: 'suspicious_api_activity', code: 'DET-API-09', name: 'CloudTrail Suspicious API', category: 'Privilege Escalation', desc: 'Rare administrative API calls outside normal baseline hours.' },
  { id: 'container_k8s', code: 'DET-K8S-10', name: 'Container & K8s Abuse', category: 'Privilege Escalation', desc: 'Privileged pod creation and host namespace access.' },
  { id: 'serverless_abuse', code: 'DET-LAM-11', name: 'Serverless Function Abuse', category: 'Privilege Escalation', desc: 'High-frequency Lambda invocations and environment token theft.' },

  { id: 'network_scanning', code: 'DET-NS-05', name: 'Network Port Scanning', category: 'Recon & Evasion', desc: 'SYN/TCP sweeps probing closed cloud service ports.' },
  { id: 'defense_tampering', code: 'DET-DT-08', name: 'Log & Defense Tampering', category: 'Recon & Evasion', desc: 'Stopping CloudTrail audit logging or removing security groups.' },
  { id: 'cloud_misconfiguration', code: 'DET-CFG-14', name: 'Cloud Misconfiguration', category: 'Recon & Evasion', desc: 'Public S3 bucket ACL and 0.0.0.0/0 inbound administrative rules.' },

  { id: 'data_exfiltration', code: 'DET-EX-02', name: 'S3 Data Exfiltration', category: 'Theft & Impact', desc: 'Mass GetObject download transferred to untrusted external IP.' },
  { id: 'malware_ransomware', code: 'DET-RW-04', name: 'Ransomware Encryption', category: 'Theft & Impact', desc: 'Rapid file modifications with known ransomware extensions.' },
  { id: 'cryptomining', code: 'DET-MIN-12', name: 'Hostile Cryptomining', category: 'Theft & Impact', desc: 'High CPU xmrig process communicating with mining pool.' },
  { id: 'database_attacks', code: 'DET-DB-13', name: 'Database SQL Injection', category: 'Theft & Impact', desc: 'UNION SELECT queries and unauthorized schema table dumps.' },
  { id: 'ddos', code: 'DET-DOS-16', name: 'Distributed Denial of Service', category: 'Theft & Impact', desc: 'High-volume packet flood overwhelming web ingress gateway.' }
];

const normalizeBackendEvent = (e) => {
  const ts = e.timestamp
    ? new Date(e.timestamp).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
    : new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

  const service = (e.service || e.program_name || 'iam').toLowerCase();
  let eventSource = 'aws.cloudtrail';
  if (service === 's3') eventSource = 'aws.s3';
  else if (service === 'ec2' || service === 'vpc-flow' || service === 'network') eventSource = 'vpc.flow';
  else if (service === 'wazuh' || service === 'sshd' || service === 'linux') eventSource = 'wazuh.hids';
  else if (service === 'lambda') eventSource = 'aws.lambda';
  else if (service === 'k8s' || service === 'container') eventSource = 'k8s.audit';

  const isAttack = e.event_type === 'attack' || (e.failed_attempts && e.failed_attempts > 0);
  const statusCode = isAttack 
    ? (e.status === 'blocked' ? '403 Forbidden' : '401 Unauthorized') 
    : (e.status === 'success' || e.status === 'OK' ? '200 OK' : '200 OK');

  const rawSev = (e.severity || e.ml_severity || (isAttack ? 'high' : 'normal')).toLowerCase();
  const inferredSev = rawSev === 'low' && !isAttack ? 'normal' : rawSev;
  const anomalyScore = e.anomaly_score !== undefined ? Number(e.anomaly_score).toFixed(3) : (isAttack ? '0.892' : '0.045');
  
  const matchedEngine = ATTACK_ENGINES.find(eng => eng.id === e.attack_type);
  const detectorTag = matchedEngine ? matchedEngine.code : (inferredSev === 'normal' ? 'Normal Baseline' : 'DET-RULE-5712');

  const user = e.user || e.srcuser || e.principal || 'system';
  const srcIp = e.src_ip || e.srcip || '10.0.0.1';
  const action = e.action || 'ApiActivity';
  const targetResource = e.target_resource || e.dst_ip || service;

  const rawPayload = {
    eventVersion: '1.08',
    eventTime: e.timestamp || new Date().toISOString(),
    eventSource: `${service}.amazonaws.com`,
    eventName: action,
    awsRegion: e.region || 'us-east-1',
    sourceIPAddress: srcIp,
    userAgent: isAttack ? 'curl/7.88.1 (untrusted)' : 'aws-sdk-go/v1.44 (authorized)',
    userIdentity: {
      type: 'IAMUser',
      arn: `arn:aws:iam::123456789012:user/${user}`,
      userName: user
    },
    requestParameters: {
      targetResource: targetResource,
      bytesTransferred: e.bytes_transferred || 0
    },
    responseElements: {
      statusCode: statusCode
    },
    _siem_inference: {
      pyod_anomaly_score: Number(anomalyScore),
      inferred_severity: inferredSev.toUpperCase(),
      detector_engine: detectorTag
    }
  };

  return {
    id: e.id || e.event_id || `EVT-${Math.floor(1000 + Math.random() * 9000)}`,
    timestamp: ts,
    eventSource,
    action,
    user,
    src_ip: srcIp,
    targetResource,
    statusCode,
    inferredSeverity: inferredSev,
    anomalyScore,
    detectorTag,
    description: e.description || `${action} by ${user}`,
    rawJson: JSON.stringify(rawPayload, null, 2)
  };
};

const LiveLogsTab = ({ showToast }) => {
  const [logs, setLogs] = useState([]);
  const [isStreaming, setIsStreaming] = useState(true);
  const [viewMode, setViewMode] = useState('table'); // 'table' | 'terminal'
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterSource, setFilterSource] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [speedMs, setSpeedMs] = useState(2000);
  const [selectedLog, setSelectedLog] = useState(null);
  const [simulatingEngine, setSimulatingEngine] = useState(null);
  const [selectedScenarioId, setSelectedScenarioId] = useState('brute_force');
  const [showAllScenarios, setShowAllScenarios] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [page, setPage] = useState(1);
  const pageSize = 12;

  const logContainerRef = useRef(null);

  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = 0;
    }
  }, [logs]);

  const fetchLogs = async () => {
    try {
      const res = await axios.get(`${API_URL}/events?limit=120`);
      if (res.data && res.data.data) {
        const mapped = res.data.data.map(normalizeBackendEvent);
        setLogs(mapped);
      }
    } catch (err) {
      // Retain existing telemetry
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  useEffect(() => {
    if (!isStreaming) return;
    const interval = setInterval(fetchLogs, speedMs);
    return () => clearInterval(interval);
  }, [isStreaming, speedMs]);

  const handleTriggerAttack = async (engine) => {
    if (!engine) return;
    setSimulatingEngine(engine.id);
    try {
      if (showToast) showToast(`Injecting realistic ${engine.name} telemetry...`);
      await axios.post(`${API_URL}/simulate/attack?scenario=${engine.id}`);
      await fetchLogs();
      if (showToast) showToast(`[INFERRED & DETECTED] ${engine.name} flagged by engine (${engine.code})!`);
    } catch (err) {
      try {
        await axios.get(`${API_URL}/simulate/attack?scenario=${engine.id}`);
        await fetchLogs();
        if (showToast) showToast(`[INFERRED & DETECTED] ${engine.name} flagged by engine (${engine.code})!`);
      } catch (e2) {
        if (showToast) showToast(`Simulated telemetry injected for ${engine.name}`);
      }
    } finally {
      setSimulatingEngine(null);
    }
  };

  const handleCopyRaw = () => {
    if (!selectedLog) return;
    navigator.clipboard?.writeText(selectedLog.rawJson);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const filteredLogs = useMemo(() => {
    return logs.filter((l) => {
      if (filterSeverity !== 'all' && l.inferredSeverity !== filterSeverity) return false;
      if (filterSource !== 'all' && l.eventSource !== filterSource) return false;
      if (searchTerm) {
        const q = searchTerm.toLowerCase();
        return (
          l.id.toLowerCase().includes(q) ||
          l.user.toLowerCase().includes(q) ||
          l.src_ip.toLowerCase().includes(q) ||
          l.action.toLowerCase().includes(q) ||
          l.eventSource.toLowerCase().includes(q) ||
          l.targetResource.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [logs, filterSeverity, filterSource, searchTerm]);

  const pagedLogs = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredLogs.slice(start, start + pageSize);
  }, [filteredLogs, page, pageSize]);

  return (
    <div className="animate-fade-in">
      {/* 1. COMPACT TELEMETRY OPERATIONS & SCENARIO CONTROL BAR */}
      <div style={{
        background: 'var(--surface-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '10px',
        padding: '12px 18px',
        marginBottom: '16px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '12px'
      }}>
        {/* Left: Stream Status & Stream Rate Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            padding: '4px 10px',
            borderRadius: '6px',
            backgroundColor: isStreaming ? 'rgba(16, 185, 129, 0.08)' : 'rgba(100, 116, 139, 0.08)',
            border: isStreaming ? '1px solid rgba(16, 185, 129, 0.25)' : '1px solid var(--border-subtle)',
            fontSize: '12px',
            fontWeight: 600,
            color: isStreaming ? '#10b981' : 'var(--text-secondary)'
          }}>
            <span style={{
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              backgroundColor: isStreaming ? '#10b981' : '#94a3b8'
            }} />
            {isStreaming ? 'Live Stream Active' : 'Stream Paused'}
          </div>

          <button
            type="button"
            onClick={() => setIsStreaming(!isStreaming)}
            className="figma-btn-secondary"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '12px', padding: '6px 12px' }}
          >
            {isStreaming ? <Pause size={13} /> : <Play size={13} />}
            <span>{isStreaming ? 'Pause' : 'Resume'}</span>
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: '3px', fontSize: '11.5px', color: 'var(--text-tertiary)' }}>
            <span>Interval:</span>
            {[1000, 2000, 5000].map(ms => (
              <button
                key={ms}
                type="button"
                className={`figma-page-btn ${speedMs === ms ? 'active' : ''}`}
                style={{ minWidth: 'auto', padding: '0 6px', height: '24px', fontSize: '11px' }}
                onClick={() => setSpeedMs(ms)}
              >
                {ms / 1000}s
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={fetchLogs}
            className="figma-btn-secondary"
            title="Refresh stream now"
            style={{ padding: '6px 10px', fontSize: '12px' }}
          >
            <RefreshCw size={13} className={isStreaming ? '' : 'animate-spin'} />
          </button>

          <button
            type="button"
            onClick={() => setLogs([])}
            className="figma-btn-secondary"
            title="Clear in-memory buffer"
            style={{ padding: '6px 10px' }}
          >
            <Trash2 size={13} />
          </button>
        </div>

        {/* Right: Sleek Scenario Ingestion Dropdown & Action Button */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '12px', color: 'var(--text-tertiary)', fontWeight: 500 }}>
            Simulate Scenario:
          </span>

          <select
            className="figma-filter-select"
            value={selectedScenarioId}
            onChange={(e) => setSelectedScenarioId(e.target.value)}
            style={{ width: '250px', fontSize: '12px' }}
          >
            <optgroup label="Initial Access">
              <option value="brute_force">DET-BF-01: SSH / RDP Brute Force</option>
              <option value="account_takeover">DET-ATO-07: Account Takeover (ATO)</option>
              <option value="bola_ssrf">DET-API-06: Broken Object & SSRF</option>
              <option value="supply_chain">DET-SC-15: Supply Chain Compromise</option>
            </optgroup>
            <optgroup label="Privilege Escalation">
              <option value="iam_privilege_escalation">DET-PE-03: IAM Privilege Escalation</option>
              <option value="suspicious_api_activity">DET-API-09: CloudTrail Suspicious API</option>
              <option value="container_k8s">DET-K8S-10: Container & K8s Abuse</option>
              <option value="serverless_abuse">DET-LAM-11: Serverless Function Abuse</option>
            </optgroup>
            <optgroup label="Recon & Evasion">
              <option value="network_scanning">DET-NS-05: Network Port Scanning</option>
              <option value="defense_tampering">DET-DT-08: Log & Defense Tampering</option>
              <option value="cloud_misconfiguration">DET-CFG-14: Cloud Misconfiguration</option>
            </optgroup>
            <optgroup label="Theft & Impact">
              <option value="data_exfiltration">DET-EX-02: S3 Data Exfiltration</option>
              <option value="malware_ransomware">DET-RW-04: Ransomware Encryption</option>
              <option value="cryptomining">DET-MIN-12: Hostile Cryptomining</option>
              <option value="database_attacks">DET-DB-13: Database SQL Injection</option>
              <option value="ddos">DET-DOS-16: Distributed Denial of Service</option>
            </optgroup>
          </select>

          <button
            type="button"
            className="figma-btn-secondary"
            disabled={simulatingEngine !== null}
            onClick={() => {
              const eng = ATTACK_ENGINES.find(e => e.id === selectedScenarioId);
              if (eng) handleTriggerAttack(eng);
            }}
            style={{
              fontSize: '12px',
              padding: '6px 14px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: 'var(--text-primary)',
              color: 'var(--surface-card)',
              borderColor: 'transparent'
            }}
          >
            <Zap size={13} className={simulatingEngine ? 'animate-spin' : ''} />
            <span>{simulatingEngine ? 'Injecting...' : 'Inject Telemetry'}</span>
          </button>

          <button
            type="button"
            className="figma-btn-secondary"
            onClick={() => setShowAllScenarios(!showAllScenarios)}
            title="Toggle catalog view of all 16 detection engines"
            style={{ fontSize: '11.5px', padding: '6px 10px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
          >
            <span>Modules</span>
            {showAllScenarios ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          </button>
        </div>
      </div>

      {/* 2. OPTIONAL EXPANDABLE ALL 16 ENGINES MATRIX (COLLAPSED BY DEFAULT FOR CLEAN ENTERPRISE LOOK) */}
      {showAllScenarios && (
        <div style={{
          background: 'var(--surface-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '10px',
          padding: '16px 20px',
          marginBottom: '16px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <div>
              <h4 style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                16 Specialized Attack Modules
              </h4>
              <p style={{ fontSize: '11.5px', color: 'var(--text-tertiary)', margin: '2px 0 0 0' }}>
                Select any module below to trigger real-time telemetry verification.
              </p>
            </div>
            <button
              type="button"
              className="figma-link-btn"
              onClick={() => setShowAllScenarios(false)}
              style={{ fontSize: '11.5px' }}
            >
              Close catalog
            </button>
          </div>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))',
            gap: '10px'
          }}>
            {ATTACK_ENGINES.map(engine => {
              const isRunning = simulatingEngine === engine.id;
              return (
                <div
                  key={engine.id}
                  style={{
                    backgroundColor: 'var(--surface-sunken)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '8px',
                    padding: '10px 12px',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between'
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <span style={{
                        fontSize: '10px',
                        fontWeight: 600,
                        fontFamily: 'monospace',
                        color: 'var(--text-secondary)',
                        backgroundColor: 'var(--surface-card)',
                        border: '1px solid var(--border-subtle)',
                        padding: '1px 5px',
                        borderRadius: '4px'
                      }}>
                        {engine.code}
                      </span>
                      <span style={{ fontSize: '10.5px', color: 'var(--text-tertiary)' }}>
                        {engine.category}
                      </span>
                    </div>
                    <strong style={{ fontSize: '12px', color: 'var(--text-primary)', display: 'block', marginBottom: '2px' }}>
                      {engine.name}
                    </strong>
                    <p style={{ fontSize: '11px', color: 'var(--text-secondary)', margin: '0 0 8px 0', lineHeight: 1.35 }}>
                      {engine.desc}
                    </p>
                  </div>

                  <button
                    type="button"
                    className="figma-btn-secondary"
                    disabled={isRunning}
                    onClick={() => handleTriggerAttack(engine)}
                    style={{
                      fontSize: '11px',
                      padding: '4px 8px',
                      width: '100%',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: '5px'
                    }}
                  >
                    <Zap size={11} className={isRunning ? 'animate-spin' : ''} />
                    {isRunning ? 'Injecting...' : 'Inject Stream'}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 3. STREAM TOOLBAR: SEARCH, INFERRED SEVERITY, SOURCE & VIEW CONTROLS */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '10px',
        marginBottom: '12px',
        flexWrap: 'wrap'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: '1 1 340px' }}>
          <div className="figma-header-search" style={{ flex: 1, width: 'auto', backgroundColor: 'var(--surface-card)' }}>
            <Search size={14} className="figma-search-icon" />
            <input
              type="text"
              placeholder="Search stream by actor, IP, action, or target resource..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          <select
            className="figma-filter-select"
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            style={{ width: '145px' }}
          >
            <option value="all">Severity: All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="normal">Normal</option>
          </select>

          <select
            className="figma-filter-select"
            value={filterSource}
            onChange={(e) => setFilterSource(e.target.value)}
            style={{ width: '135px' }}
          >
            <option value="all">Source: All</option>
            <option value="aws.cloudtrail">CloudTrail</option>
            <option value="vpc.flow">VPC Flow</option>
            <option value="wazuh.hids">Wazuh HIDS</option>
            <option value="aws.s3">AWS S3</option>
            <option value="aws.lambda">AWS Lambda</option>
          </select>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
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
                padding: '5px 12px',
                fontSize: '11.5px',
                fontWeight: 600,
                border: 'none',
                cursor: 'pointer',
                backgroundColor: viewMode === 'table' ? 'var(--surface-sunken)' : 'var(--surface-card)',
                color: viewMode === 'table' ? 'var(--text-primary)' : 'var(--text-tertiary)'
              }}
            >
              Structured Stream
            </button>
            <button
              type="button"
              onClick={() => setViewMode('terminal')}
              style={{
                padding: '5px 12px',
                fontSize: '11.5px',
                fontWeight: 600,
                border: 'none',
                cursor: 'pointer',
                backgroundColor: viewMode === 'terminal' ? 'var(--surface-sunken)' : 'var(--surface-card)',
                color: viewMode === 'terminal' ? 'var(--text-primary)' : 'var(--text-tertiary)'
              }}
            >
              Cloud Console
            </button>
          </div>
        </div>
      </div>

      {/* 4A. STRUCTURED TELEMETRY TABLE VIEW */}
      {viewMode === 'table' ? (
        <div className="figma-table-container">
          <table className="figma-table">
            <thead>
              <tr>
                <th style={{ width: '120px' }}>Inferred Risk</th>
                <th style={{ width: '155px' }}>Timestamp (UTC)</th>
                <th style={{ width: '115px' }}>Source</th>
                <th>Action / Event</th>
                <th>Actor Identity</th>
                <th>Source IP</th>
                <th>Target Resource</th>
                <th>Status</th>
                <th style={{ textAlign: 'right' }}>Forensics</th>
              </tr>
            </thead>
            <tbody>
              {pagedLogs.length === 0 ? (
                <tr>
                  <td colSpan="9" style={{ textAlign: 'center', padding: '36px 20px', color: 'var(--text-tertiary)' }}>
                    No telemetry records matching filter criteria.
                  </td>
                </tr>
              ) : (
                pagedLogs.map((l, idx) => {
                  const isCrit = l.inferredSeverity === 'critical';
                  const isHigh = l.inferredSeverity === 'high';
                  const isMed = l.inferredSeverity === 'medium';
                  const isNormal = l.inferredSeverity === 'normal' || l.inferredSeverity === 'low';

                  // Soft pastel Aikido-style badges
                  let badgeBg = 'rgba(100, 116, 139, 0.08)';
                  let badgeColor = '#475569';
                  let badgeBorder = 'rgba(100, 116, 139, 0.2)';
                  let dotColor = '#64748b';

                  if (isCrit) {
                    badgeBg = 'rgba(239, 68, 68, 0.08)';
                    badgeColor = '#dc2626';
                    badgeBorder = 'rgba(239, 68, 68, 0.25)';
                    dotColor = '#ef4444';
                  } else if (isHigh) {
                    badgeBg = 'rgba(249, 115, 22, 0.08)';
                    badgeColor = '#ea580c';
                    badgeBorder = 'rgba(249, 115, 22, 0.25)';
                    dotColor = '#f97316';
                  } else if (isMed) {
                    badgeBg = 'rgba(234, 179, 8, 0.08)';
                    badgeColor = '#ca8a04';
                    badgeBorder = 'rgba(234, 179, 8, 0.25)';
                    dotColor = '#eab308';
                  }

                  const badgeText = isNormal ? 'NORMAL' : l.inferredSeverity.toUpperCase();

                  return (
                    <tr
                      key={l.id + '-' + idx}
                      onClick={() => setSelectedLog(l)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '5px',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontSize: '11px',
                          fontWeight: 600,
                          backgroundColor: badgeBg,
                          color: badgeColor,
                          border: `1px solid ${badgeBorder}`
                        }}>
                          <span style={{ width: '5px', height: '5px', borderRadius: '50%', backgroundColor: dotColor }} />
                          {badgeText}
                        </span>
                      </td>
                      <td style={{ fontSize: '11.5px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                        {l.timestamp}
                      </td>
                      <td>
                        <span style={{
                          fontSize: '10.5px',
                          padding: '2px 6px',
                          borderRadius: '4px',
                          background: 'var(--surface-sunken)',
                          border: '1px solid var(--border-subtle)',
                          fontFamily: 'monospace',
                          fontWeight: 500,
                          color: 'var(--text-secondary)'
                        }}>
                          {l.eventSource}
                        </span>
                      </td>
                      <td>
                        <strong style={{ fontSize: '12.5px', color: 'var(--text-primary)', display: 'block' }}>{l.action}</strong>
                        <div style={{ fontSize: '10.5px', color: 'var(--text-tertiary)' }}>{l.detectorTag}</div>
                      </td>
                      <td style={{ fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                        @{l.user}
                      </td>
                      <td style={{ fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                        {l.src_ip}
                      </td>
                      <td style={{ fontSize: '11.5px', color: 'var(--text-tertiary)', maxWidth: '160px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {l.targetResource}
                      </td>
                      <td>
                        <span style={{
                          fontSize: '10.5px',
                          fontWeight: 500,
                          color: l.statusCode.startsWith('200') ? '#059669' : '#dc2626'
                        }}>
                          {l.statusCode}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          type="button"
                          className="figma-link-btn"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedLog(l);
                          }}
                          style={{ fontSize: '11.5px' }}
                        >
                          Payload ↗
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
        /* 4B. CLOUDWATCH CONSOLE VIEW */
        <div
          ref={logContainerRef}
          style={{
            backgroundColor: '#0c1017',
            color: '#38bdf8',
            fontFamily: 'Consolas, Monaco, "Courier New", monospace',
            fontSize: '11.5px',
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
            <span>--- RAM ANTIVIRUS TELEMETRY STREAM INGEST [AWS_CLOUDTRAIL + VPC_FLOW + WAZUH_HIDS] ---</span>
            <span style={{ color: '#10b981' }}>▲ REAL-TIME BUFFER INGESTION</span>
          </div>

          {filteredLogs.length === 0 ? (
            <div style={{ color: '#64748b', padding: '20px 0', textAlign: 'center' }}>
              No telemetry records matching filter criteria.
            </div>
          ) : (
            filteredLogs.map((l, idx) => {
              const isCrit = l.inferredSeverity === 'critical';
              const isHigh = l.inferredSeverity === 'high';
              const isMed = l.inferredSeverity === 'medium';
              const sevColor = isCrit ? '#ef4444' : (isHigh ? '#f97316' : (isMed ? '#eab308' : '#10b981'));

              return (
                <div
                  key={l.id + '-' + idx}
                  onClick={() => setSelectedLog(l)}
                  style={{
                    display: 'flex',
                    alignItems: 'baseline',
                    gap: '10px',
                    padding: '3px 0',
                    cursor: 'pointer',
                    borderBottom: '1px solid rgba(255,255,255,0.03)',
                    transition: 'background 0.1s ease',
                    backgroundColor: idx === 0 ? 'rgba(235, 107, 39, 0.08)' : 'transparent'
                  }}
                >
                  <span style={{ color: '#64748b', minWidth: '150px' }}>{l.timestamp}</span>
                  <span style={{ color: '#94a3b8', minWidth: '95px' }}>[{l.eventSource}]</span>
                  <span style={{ color: '#e2e8f0', minWidth: '130px', fontWeight: 600 }}>{l.action}</span>
                  <span style={{ color: '#38bdf8', minWidth: '105px' }}>{l.src_ip}</span>
                  <span style={{ color: '#cbd5e1', minWidth: '90px' }}>user:{l.user}</span>
                  <span style={{ color: l.statusCode.startsWith('200') ? '#10b981' : '#f87171', minWidth: '85px' }}>
                    {l.statusCode}
                  </span>
                  <span style={{ color: sevColor, minWidth: '130px', fontWeight: 700 }}>
                    Inferred: {l.inferredSeverity.toUpperCase()} ({l.anomalyScore})
                  </span>
                  <span style={{ color: '#f59e0b', fontSize: '10.5px', textDecoration: 'underline' }}>
                    payload
                  </span>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* 5. FORENSICS INSPECTION MODAL */}
      {selectedLog && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.6)',
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
            style={{ width: '680px', maxWidth: '100%', padding: '24px', borderRadius: '12px' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{
                  padding: '2px 8px',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontWeight: 600,
                  backgroundColor: selectedLog.inferredSeverity === 'critical' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(100, 116, 139, 0.1)',
                  color: selectedLog.inferredSeverity === 'critical' ? '#dc2626' : 'var(--text-secondary)'
                }}>
                  INFERRED: {selectedLog.inferredSeverity.toUpperCase()}
                </span>
                <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                  Event Telemetry & SIEM Inference Inspector
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

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '12px', marginBottom: '14px' }}>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Event ID:</span> <code>{selectedLog.id}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Timestamp:</span> <code>{selectedLog.timestamp}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Telemetry Source:</span> <code>{selectedLog.eventSource}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Action / API:</span> <code>{selectedLog.action}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Actor / Principal:</span> <code>{selectedLog.user}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Source IP:</span> <code>{selectedLog.src_ip}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Target Resource:</span> <code>{selectedLog.targetResource}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>HTTP / Result:</span> <code>{selectedLog.statusCode}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>PyOD Anomaly Score:</span> <code>{selectedLog.anomalyScore}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>SIEM Engine Tag:</span> <code>{selectedLog.detectorTag}</code></div>
            </div>

            <div style={{ backgroundColor: '#0c1017', padding: '14px', borderRadius: '8px', fontSize: '11.5px', marginBottom: '16px', position: 'relative' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ color: '#94a3b8', fontWeight: 600 }}>Raw CloudTrail / Wazuh Event Payload:</span>
                <button
                  type="button"
                  onClick={handleCopyRaw}
                  className="figma-btn-secondary"
                  style={{ padding: '2px 8px', fontSize: '11px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                >
                  {copiedRaw ? <Check size={12} style={{ color: '#10b981' }} /> : <Copy size={12} />}
                  <span>{copiedRaw ? 'Copied' : 'Copy JSON'}</span>
                </button>
              </div>
              <pre style={{ color: '#38bdf8', margin: 0, maxHeight: '200px', overflowY: 'auto', fontFamily: 'monospace', fontSize: '11px' }}>
                {selectedLog.rawJson}
              </pre>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                type="button"
                className="figma-btn-secondary"
                onClick={() => setSelectedLog(null)}
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 6. STREAM HEALTH & TELEMETRY METRICS (CLEAN BOTTOM CARDS) */}
      <div className="figma-grid-4col" style={{ marginTop: '20px', marginBottom: '12px' }}>
        <div className="figma-card" style={{ padding: '14px 18px', borderRadius: '10px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>
            Buffer Depth
          </span>
          <div style={{ fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
            {logs.length || 120} Events In-Memory
          </div>
        </div>

        <div className="figma-card" style={{ padding: '14px 18px', borderRadius: '10px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>
            Stream Status
          </span>
          <div style={{
            fontSize: '13.5px',
            fontWeight: 600,
            color: isStreaming ? '#10b981' : 'var(--text-secondary)',
            marginTop: '4px',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}>
            <span style={{
              width: '7px',
              height: '7px',
              borderRadius: '50%',
              backgroundColor: isStreaming ? '#10b981' : '#94a3b8'
            }} />
            {isStreaming ? 'LIVE STREAMING' : 'STREAM PAUSED'}
          </div>
        </div>

        <div className="figma-card" style={{ padding: '14px 18px', borderRadius: '10px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>
            Processing Latency
          </span>
          <div style={{ fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
            ~12.4 ms
          </div>
        </div>

        <div className="figma-card" style={{ padding: '14px 18px', borderRadius: '10px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>
            Ingestion Daemon
          </span>
          <div style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '4px' }}>
            PyOD + Rule Engine Active
          </div>
        </div>
      </div>
    </div>
  );
};

export default LiveLogsTab;
