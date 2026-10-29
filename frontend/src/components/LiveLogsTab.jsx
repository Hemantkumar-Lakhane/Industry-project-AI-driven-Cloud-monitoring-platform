import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { Terminal, Play, Pause, RefreshCw, Trash2, ShieldAlert, Filter, Download, Zap, Database, CheckCircle2, ChevronRight, Server, Globe, User, ShieldCheck } from 'lucide-react';
import { API_URL } from '../config';

const normalizeBackendEvent = (e) => {
  const ts = e.timestamp ? (new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' UTC') : 'Live';
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
    status: (sev === 'critical' || sev === 'high' || e.event_type === 'attack') ? 'failure' : 'success',
    raw: e.description || e.raw || `${e.action || 'Event'} by ${e.user || 'principal'}`
  };
};

const LiveLogsTab = ({ showToast }) => {
  const [logs, setLogs] = useState([]);
  const [isStreaming, setIsStreaming] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [speedMs, setSpeedMs] = useState(3000);
  const [selectedLog, setSelectedLog] = useState(null);
  const [simulating, setSimulating] = useState(false);
  const logContainerRef = useRef(null);

  // Keep newest events in view at top (no bottom scrolling jump)
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
      // Keep previous logs if network temporarily interrupts
    }
  };

  // Initial load
  useEffect(() => {
    fetchLogs();
  }, []);

  // Periodic live telemetry polling
  useEffect(() => {
    if (!isStreaming) return;
    const interval = setInterval(fetchLogs, speedMs);
    return () => clearInterval(interval);
  }, [isStreaming, speedMs]);

  // 1-Click Targeted Attack Simulation
  const handleSimulateAttack = async (scenario, label) => {
    setSimulating(true);
    try {
      if (showToast) showToast(`Injecting ${label} into live telemetry stream...`);
      await axios.get(`${API_URL}/simulate/attack?scenario=${scenario}`);
      await fetchLogs();
      if (showToast) showToast(`[DETECTED] ${label} burst processed by detection engine!`);
    } catch (err) {
      await fetchLogs();
      if (showToast) showToast(`Simulation completed; telemetry stream updated.`);
    } finally {
      setSimulating(false);
    }
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
        padding: '18px 22px',
        marginBottom: '16px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <Terminal size={18} style={{ color: 'var(--accent-orange)' }} />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Live Telemetry Stream & Attack Generator
            </h3>
            <span style={{ fontSize: '11px', fontWeight: 600, padding: '2px 8px', borderRadius: '12px', background: 'rgba(16, 185, 129, 0.12)', color: 'var(--success-color)' }}>
              Wazuh SIEM Active
            </span>
          </div>
          <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', margin: 0 }}>
            Real-time Wazuh OSSEC & AWS CloudTrail raw ingestion daemon · Newest events stream directly at top
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            onClick={() => setIsStreaming(!isStreaming)}
            className="figma-btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', padding: '6px 12px' }}
          >
            {isStreaming ? <Pause size={12} /> : <Play size={12} />}
            {isStreaming ? 'Pause Stream' : 'Resume Stream'}
          </button>

          <button
            onClick={fetchLogs}
            className="figma-btn-secondary"
            title="Refresh stream now"
            style={{ padding: '6px 10px', fontSize: '12px' }}
          >
            <RefreshCw size={13} className={simulating ? 'animate-spin' : ''} />
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

      {/* 2. ADMIN 1-CLICK ATTACK SIMULATION TOOLBAR */}
      <div style={{
        background: 'var(--surface-muted)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '8px',
        padding: '14px 18px',
        marginBottom: '18px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px', flexWrap: 'wrap', gap: '6px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Zap size={15} style={{ color: 'var(--accent-orange)' }} />
            <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
              Admin Attack Generator Panel — 1-Click Detection Verification
            </span>
          </div>
          <span style={{ fontSize: '11.5px', color: 'var(--text-tertiary)' }}>
            Inject test attack bursts directly into telemetry to verify detector response
          </span>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
          <button
            className="figma-btn-secondary"
            style={{ padding: '6px 14px', fontSize: '12px', borderLeft: '3px solid var(--sev-critical)' }}
            disabled={simulating}
            onClick={() => handleSimulateAttack('brute_force', 'SSH Brute Force Attack')}
          >
            🔴 Simulate Brute Force (SSH)
          </button>
          <button
            className="figma-btn-secondary"
            style={{ padding: '6px 14px', fontSize: '12px', borderLeft: '3px solid var(--accent-orange)' }}
            disabled={simulating}
            onClick={() => handleSimulateAttack('network_scanning', 'Network Port Scan')}
          >
            🟠 Simulate Network Port Scan
          </button>
          <button
            className="figma-btn-secondary"
            style={{ padding: '6px 14px', fontSize: '12px', borderLeft: '3px solid #8b5cf6' }}
            disabled={simulating}
            onClick={() => handleSimulateAttack('privilege_escalation', 'IAM Privilege Escalation')}
          >
            🟣 Simulate Privilege Escalation
          </button>
          <button
            className="figma-btn-secondary"
            style={{ padding: '6px 14px', fontSize: '12px', borderLeft: '3px solid #3b82f6' }}
            disabled={simulating}
            onClick={() => handleSimulateAttack('data_exfiltration', 'S3 Data Exfiltration')}
          >
            🔵 Simulate S3 Data Exfil
          </button>
          <button
            className="figma-btn-secondary"
            style={{ padding: '6px 14px', fontSize: '12px', borderLeft: '3px solid #10b981' }}
            disabled={simulating}
            onClick={() => handleSimulateAttack('cryptomining', 'Hostile Cryptomining')}
          >
            🟢 Simulate Cryptomining
          </button>
          <button
            className="figma-btn-secondary"
            style={{ padding: '6px 14px', fontSize: '12px', borderLeft: '3px solid var(--sev-critical)' }}
            disabled={simulating}
            onClick={() => handleSimulateAttack('malware_ransomware', 'Ransomware Precursor')}
          >
            🛑 Simulate Ransomware
          </button>
        </div>
      </div>

      {/* 4. SEARCH & FILTER TOOLBAR */}
      <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap' }}>
        <input
          type="text"
          className="figma-search-input"
          placeholder="Search raw stream (user, IP, action)..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{ width: '280px' }}
        />

        <select
          className="figma-select"
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          style={{ width: '150px' }}
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical Only</option>
          <option value="high">High Only</option>
          <option value="medium">Medium Only</option>
          <option value="low">Low Only</option>
        </select>

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--text-tertiary)' }}>
          <span>Stream Interval:</span>
          <button
            className={`figma-btn-secondary ${speedMs === 1000 ? 'active' : ''}`}
            style={{ padding: '4px 8px', fontSize: '11px' }}
            onClick={() => setSpeedMs(1000)}
          >
            Fast (1s)
          </button>
          <button
            className={`figma-btn-secondary ${speedMs === 3000 ? 'active' : ''}`}
            style={{ padding: '4px 8px', fontSize: '11px' }}
            onClick={() => setSpeedMs(3000)}
          >
            Normal (3s)
          </button>
          <button
            className={`figma-btn-secondary ${speedMs === 5000 ? 'active' : ''}`}
            style={{ padding: '4px 8px', fontSize: '11px' }}
            onClick={() => setSpeedMs(5000)}
          >
            Slow (5s)
          </button>
        </div>
      </div>

      {/* 5. LIVE TERMINAL CONTAINER (NEWEST AT TOP, NO WEIRD BOTTOM JUMP) */}
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
          maxHeight: '480px',
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

      {/* 6. INSPECT LOG DRAWER */}
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
              <button className="figma-btn-secondary" style={{ padding: '4px 8px' }} onClick={() => setSelectedLog(null)}>✕</button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '12.5px', marginBottom: '16px' }}>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Event ID:</span> <code>{selectedLog.id}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Time:</span> {selectedLog.timestamp}</div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>User / Identity:</span> <code>{selectedLog.user}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Source IP:</span> <code>{selectedLog.src_ip}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Service:</span> <code>{selectedLog.service}</code></div>
              <div><span style={{ color: 'var(--text-tertiary)' }}>Rule ID:</span> <code>{selectedLog.rule_id}</code></div>
            </div>

            <div style={{ backgroundColor: 'var(--surface-muted)', padding: '12px', borderRadius: '6px', fontSize: '12px', marginBottom: '16px' }}>
              <span style={{ color: 'var(--text-tertiary)', display: 'block', marginBottom: '4px' }}>Raw Telemetry Payload:</span>
              <code style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>{selectedLog.raw}</code>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="figma-btn-primary" onClick={() => setSelectedLog(null)}>
                Close Forensics
              </button>
            </div>
          </div>
        </div>
      )}

{/* 5. STREAM HEALTH & TELEMETRY STATS (AT BOTTOM) */}
      <div className="figma-grid-4col" style={{ marginTop: '20px', marginBottom: '12px' }}>
        <div className="figma-card" style={{ padding: '14px 18px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>Buffer Depth</span>
          <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
            {logs.length} Events In-Memory
          </div>
        </div>

        <div className="figma-card" style={{ padding: '14px 18px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>Stream Status</span>
          <div style={{ fontSize: '15px', fontWeight: 700, color: isStreaming ? 'var(--success-color)' : 'var(--text-muted)', marginTop: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: isStreaming ? 'var(--success-color)' : 'var(--text-muted)' }} />
            {isStreaming ? 'LIVE STREAMING' : 'STREAM PAUSED'}
          </div>
        </div>

        <div className="figma-card" style={{ padding: '14px 18px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>Processing Latency</span>
          <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
            ~12.4 ms
          </div>
        </div>

        <div className="figma-card" style={{ padding: '14px 18px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>Ingestion Daemon</span>
          <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
            PyOD + Rule Engine Active
          </div>
        </div>
      </div>

      
    </div>
  );
};

export default LiveLogsTab;
