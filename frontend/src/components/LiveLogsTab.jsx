import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { Terminal, Play, Pause, RefreshCw, Trash2, ShieldAlert, Filter, Download, Zap, Database, CheckCircle2 } from 'lucide-react';
import { API_URL } from '../config';

const INITIAL_LOGS = [
  { id: 'LOG-7721', timestamp: '10:00:02 UTC', rule_id: 1001, level: 3, severity: 'low', source: 'wazuh', action: 'ListBuckets', user: 'system-monitor', src_ip: '10.0.0.12', service: 's3', status: 'success', raw: 'S3: ListBuckets requested by IAM principal system-monitor' },
  { id: 'LOG-7722', timestamp: '10:00:04 UTC', rule_id: 5500, level: 2, severity: 'low', source: 'cloudtrail', action: 'DescribeInstances', user: 'read-only-auditor', src_ip: '10.0.0.18', service: 'ec2', status: 'success', raw: 'EC2: DescribeInstances queried from VPC peering gateway' },
  { id: 'LOG-7723', timestamp: '10:00:07 UTC', rule_id: 5710, level: 10, severity: 'high', source: 'wazuh', action: 'ConsoleLogin', user: 'admin', src_ip: '103.21.244.18', service: 'iam', status: 'failure', raw: 'IAM: ConsoleLogin failed (incorrect credentials). Attempt #1' },
  { id: 'LOG-7724', timestamp: '10:00:08 UTC', rule_id: 5710, level: 11, severity: 'high', source: 'wazuh', action: 'ConsoleLogin', user: 'admin', src_ip: '103.21.244.18', service: 'iam', status: 'failure', raw: 'IAM: ConsoleLogin failed (incorrect credentials). Attempt #2' },
  { id: 'LOG-7725', timestamp: '10:00:09 UTC', rule_id: 5712, level: 13, severity: 'critical', source: 'wazuh', action: 'ConsoleLogin', user: 'admin', src_ip: '103.21.244.18', service: 'iam', status: 'failure', raw: 'IAM: Rapid authentication failure burst detected (rule 5712 trigger)' },
  { id: 'LOG-7726', timestamp: '10:00:11 UTC', rule_id: 5715, level: 14, severity: 'critical', source: 'wazuh', action: 'ConsoleLogin', user: 'admin', src_ip: '103.21.244.18', service: 'iam', status: 'success', raw: 'IAM: Breach escalation: Successful login after repeated credential failures' },
  { id: 'LOG-7727', timestamp: '10:00:14 UTC', rule_id: 5402, level: 11, severity: 'high', source: 'cloudtrail', action: 'CreatePolicy', user: 'admin', src_ip: '103.21.244.18', service: 'iam', status: 'success', raw: 'IAM: Policy created with AdministratorAccess scope' },
  { id: 'LOG-7728', timestamp: '10:00:16 UTC', rule_id: 8502, level: 14, severity: 'critical', source: 'cloudtrail', action: 'AssumeRole', user: 'admin', src_ip: '103.21.244.18', service: 'sts', status: 'success', raw: 'STS: AssumeRole invoked for arn:aws:iam::prod:role/SuperAdmin' },
  { id: 'LOG-7729', timestamp: '10:00:19 UTC', rule_id: 31101, level: 15, severity: 'critical', source: 'wazuh', action: 'GetObject', user: 'admin', src_ip: '10.0.0.20', service: 's3', status: 'success', raw: 'S3: High-volume egress transfer detected (1.85 GB transferred to 198.51.100.42)' },
];

const LiveLogsTab = ({ showToast }) => {
  const [logs, setLogs] = useState(INITIAL_LOGS);
  const [isStreaming, setIsStreaming] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [speedMs, setSpeedMs] = useState(2000);
  const [selectedLog, setSelectedLog] = useState(null);
  const logContainerRef = useRef(null);

  // Auto-scroll to bottom of log stream if at bottom
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  // Live log generator heartbeat simulation
  useEffect(() => {
    if (!isStreaming) return;

    const interval = setInterval(() => {
      const users = ['demo-admin', 'analyst-jane', 'worker-node-03', 'svc-deployer', 'anonymous'];
      const actions = [
        { action: 'GetObject', service: 's3', level: 2, severity: 'low', rule: 1002, desc: 'S3: Object read by service worker' },
        { action: 'DescribeSecurityGroups', service: 'ec2', level: 3, severity: 'low', rule: 5501, desc: 'EC2: Security group inspection' },
        { action: 'GetSecretValue', service: 'secretsmanager', level: 7, severity: 'medium', rule: 18100, desc: 'SecretsManager: Access to database credential' },
        { action: 'ConsoleLogin', service: 'iam', level: 10, severity: 'high', rule: 5710, desc: 'IAM: Sign-in failure recorded' },
        { action: 'AssumeRole', service: 'sts', level: 12, severity: 'critical', rule: 8502, desc: 'STS: Unmapped cross-account role assumption' },
      ];

      const item = actions[Math.floor(Math.random() * actions.length)];
      const now = new Date();
      const timeStr = `${String(now.getUTCHours()).padStart(2, '0')}:${String(now.getUTCMinutes()).padStart(2, '0')}:${String(now.getUTCSeconds()).padStart(2, '0')} UTC`;
      const idStr = `LOG-${Math.floor(7730 + Math.random() * 9000)}`;

      const newLog = {
        id: idStr,
        timestamp: timeStr,
        rule_id: item.rule,
        level: item.level,
        severity: item.severity,
        source: Math.random() > 0.4 ? 'wazuh' : 'cloudtrail',
        action: item.action,
        user: users[Math.floor(Math.random() * users.length)],
        src_ip: `10.0.${Math.floor(Math.random() * 20)}.${Math.floor(Math.random() * 250)}`,
        service: item.service,
        status: item.severity === 'critical' || item.severity === 'high' ? 'failure' : 'success',
        raw: `${item.desc} (Principal: ${users[0]})`
      };

      setLogs((prev) => [...prev.slice(-120), newLog]);
    }, speedMs);

    return () => clearInterval(interval);
  }, [isStreaming, speedMs]);

  const handleInjectAttackBurst = () => {
    const burst = [
      { id: `BURST-${Date.now()}-1`, timestamp: 'Just now', rule_id: 5710, level: 11, severity: 'high', source: 'wazuh', action: 'ConsoleLogin', user: 'admin', src_ip: '198.51.100.99', service: 'iam', status: 'failure', raw: 'ADVERSARY INJECTION: Rapid brute force attempt 1/3' },
      { id: `BURST-${Date.now()}-2`, timestamp: 'Just now', rule_id: 5712, level: 13, severity: 'critical', source: 'wazuh', action: 'ConsoleLogin', user: 'admin', src_ip: '198.51.100.99', service: 'iam', status: 'failure', raw: 'ADVERSARY INJECTION: Rapid brute force attempt 2/3 (Burst trigger)' },
      { id: `BURST-${Date.now()}-3`, timestamp: 'Just now', rule_id: 5715, level: 14, severity: 'critical', source: 'wazuh', action: 'ConsoleLogin', user: 'admin', src_ip: '198.51.100.99', service: 'iam', status: 'success', raw: 'ADVERSARY INJECTION: Breach escalation confirmed' }
    ];
    setLogs((prev) => [...prev, ...burst]);
    if (showToast) showToast('Injected live adversary event burst into telemetry stream!');
  };

  const filteredLogs = logs.filter((l) => {
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

  return (
    <div className="animate-fade-in">
      {/* 1. ADMIN HEADER BANNER */}
      <div style={{
        background: 'var(--surface-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '8px',
        padding: '20px 24px',
        marginBottom: '20px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <Terminal size={20} style={{ color: 'var(--accent-orange)' }} />
            <h3 style={{ fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              === Live Log Generator === (Admin Telemetry Stream)
            </h3>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: 0 }}>
            Real-time Wazuh OSSEC & AWS CloudTrail raw ingestion daemon · Pipeline latency &lt;15ms
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            onClick={() => setIsStreaming(!isStreaming)}
            className="figma-btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            {isStreaming ? <Pause size={13} /> : <Play size={13} />}
            {isStreaming ? 'Pause Stream' : 'Resume Stream'}
          </button>

          <button
            onClick={handleInjectAttackBurst}
            className="figma-btn-primary"
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <Zap size={13} /> Inject Attack Burst
          </button>

          <button
            onClick={() => setLogs([])}
            className="figma-btn-secondary"
            title="Clear Stream"
            style={{ padding: '8px' }}
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {/* 2. TELEMETRY STATS TICKER */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '14px', marginBottom: '20px' }}>
        <div style={{ padding: '14px 18px', background: 'var(--surface-card)', border: '1px solid var(--border-subtle)', borderRadius: '8px' }}>
          <span style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-tertiary)', fontWeight: 600 }}>Buffer Depth</span>
          <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
            {logs.length} Events In-Memory
          </div>
        </div>
        <div style={{ padding: '14px 18px', background: 'var(--surface-card)', border: '1px solid var(--border-subtle)', borderRadius: '8px' }}>
          <span style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-tertiary)', fontWeight: 600 }}>Stream Status</span>
          <div style={{ fontSize: '18px', fontWeight: 700, color: isStreaming ? 'var(--success-color)' : 'var(--sev-high)', marginTop: '2px' }}>
            {isStreaming ? '● LIVE STREAMING' : '❚❚ PAUSED'}
          </div>
        </div>
        <div style={{ padding: '14px 18px', background: 'var(--surface-card)', border: '1px solid var(--border-subtle)', borderRadius: '8px' }}>
          <span style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-tertiary)', fontWeight: 600 }}>Processing Latency</span>
          <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--accent-orange)', marginTop: '2px' }}>
            ~12.4 ms (Normalized)
          </div>
        </div>
        <div style={{ padding: '14px 18px', background: 'var(--surface-card)', border: '1px solid var(--border-subtle)', borderRadius: '8px' }}>
          <span style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-tertiary)', fontWeight: 600 }}>Ingestion Daemon</span>
          <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
            PyOD + Rule Engine Active
          </div>
        </div>
      </div>

      {/* 3. CONTROLS BAR: SEARCH & SEVERITY FILTER */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '14px',
        flexWrap: 'wrap',
        gap: '12px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <input
            type="text"
            placeholder="Search raw stream (user, IP, action)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="figma-filter-select"
            style={{ minWidth: '280px', padding: '6px 12px', fontSize: '12.5px' }}
          />

          <select
            className="figma-filter-select"
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            style={{ fontSize: '12.5px' }}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical Only</option>
            <option value="high">High Only</option>
            <option value="medium">Medium Only</option>
            <option value="low">Low Only</option>
          </select>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--text-secondary)' }}>
          <span>Stream Interval:</span>
          {[
            { label: 'Fast (1s)', val: 1000 },
            { label: 'Normal (2s)', val: 2000 },
            { label: 'Slow (5s)', val: 5000 }
          ].map((sp) => (
            <button
              key={sp.val}
              onClick={() => setSpeedMs(sp.val)}
              style={{
                background: speedMs === sp.val ? 'var(--accent-orange)' : 'var(--surface-muted)',
                color: speedMs === sp.val ? '#ffffff' : 'var(--text-primary)',
                border: '1px solid var(--border-subtle)',
                padding: '3px 8px',
                borderRadius: '4px',
                fontSize: '11px',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              {sp.label}
            </button>
          ))}
        </div>
      </div>

      {/* 4. REAL-TIME TERMINAL CONSOLE */}
      <div
        ref={logContainerRef}
        style={{
          backgroundColor: '#0a0d12',
          border: '1px solid #1f293d',
          borderRadius: '8px',
          padding: '16px 18px',
          height: '460px',
          overflowY: 'auto',
          fontFamily: 'Consolas, Monaco, "Courier New", monospace',
          fontSize: '12px',
          lineHeight: '1.7',
          color: '#c9d1d9',
          boxShadow: 'inset 0 2px 10px rgba(0,0,0,0.6)'
        }}
      >
        <div style={{ color: '#58a6ff', marginBottom: '8px', borderBottom: '1px dashed #30363d', paddingBottom: '6px' }}>
          === RAM ANTIVIRUS TELEMETRY STREAM INITIALIZED [INGEST PROTOCOL: WAZUH_JSON + CLOUDTRAIL_AUDIT] ===
        </div>

        {filteredLogs.length === 0 ? (
          <div style={{ color: '#8b949e', textAlign: 'center', padding: '40px 0' }}>
            No log events matching active search / severity filter.
          </div>
        ) : (
          filteredLogs.map((log) => {
            const sevColor =
              log.severity === 'critical' ? '#ff7b72' :
              log.severity === 'high' ? '#ffa657' :
              log.severity === 'medium' ? '#d29922' : '#7ee787';

            return (
              <div
                key={log.id}
                onClick={() => setSelectedLog(log)}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '12px',
                  cursor: 'pointer',
                  padding: '2px 4px',
                  borderRadius: '3px',
                  transition: 'background 0.15s ease'
                }}
                onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.05)'}
                onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
              >
                <span style={{ color: '#8b949e', minWidth: '95px' }}>{log.timestamp}</span>
                <span style={{
                  color: sevColor,
                  fontWeight: 700,
                  minWidth: '70px',
                  textTransform: 'uppercase',
                  fontSize: '11px'
                }}>
                  [{log.severity}]
                </span>
                <span style={{ color: '#79c0ff', minWidth: '85px' }}>{log.action}</span>
                <span style={{ color: '#d2a8ff', minWidth: '110px' }}>user:{log.user}</span>
                <span style={{ color: '#a5d6ff', minWidth: '95px' }}>ip:{log.src_ip}</span>
                <span style={{ color: '#c9d1d9', flex: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {log.raw}
                </span>
                <span style={{ color: '#58a6ff', fontSize: '11px', textDecoration: 'underline' }}>inspect</span>
              </div>
            );
          })
        )}
      </div>

      {/* 5. LOG INSPECTION MODAL */}
      {selectedLog && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(3px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '20px'
        }}>
          <div className="figma-card" style={{
            width: '100%',
            maxWidth: '560px',
            padding: '24px',
            backgroundColor: 'var(--surface-card)',
            border: '1px solid var(--border-strong)',
            borderRadius: '10px'
          }}>
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '12px' }}>
              Raw Telemetry Inspection: {selectedLog.id}
            </h3>
            <pre style={{
              background: '#0a0d12',
              color: '#58a6ff',
              padding: '16px',
              borderRadius: '6px',
              fontSize: '12px',
              fontFamily: 'monospace',
              maxHeight: '320px',
              overflowY: 'auto'
            }}>
              {JSON.stringify(selectedLog, null, 2)}
            </pre>
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '16px' }}>
              <button className="figma-btn-primary" onClick={() => setSelectedLog(null)}>
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default LiveLogsTab;
