import React, { useState } from 'react';
import { Search, ChevronDown, ArrowUpDown, ArrowRight, ExternalLink, ShieldCheck, X, AlertTriangle } from 'lucide-react';

const AlertsIncidentsTab = ({
  findings = [],
  findingsLoading = false,
  findingsError = null,
  findingsAttackMode = 15,
  fetchFindings,
  onInvestigateFinding
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [sourceFilter, setSourceFilter] = useState('All');
  const [selectedIncident, setSelectedIncident] = useState(null);

  // Map real backend findings directly to table rows
  const activeList = (findings || []).map((f, idx) => {
    const rawTime = f.timestamp || f.created_at;
    const timeFormatted = rawTime ? new Date(rawTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Recent';
    const detectorName = f.detection_method ? f.detection_method.replace(/_/g, ' ') : (f.attack_category ? f.attack_category.replace(/_/g, ' ') : 'detector');

    return {
      id: f.finding_id || `FIND-${String(idx + 1).padStart(4, '0')}`,
      title: f.title || 'Security Finding',
      fixture: `${detectorName} detector`,
      severity: (f.severity || 'high').toLowerCase(),
      resource: `${f.affected_principal || f.affected_resource || 'cloud-resource'} ↗`,
      status: f.status || 'New',
      seen: timeFormatted,
      source: (f.data_source || 'LIVE').toUpperCase(),
      observedFacts: Array.isArray(f.evidence?.observed_facts) && f.evidence.observed_facts.length > 0
        ? f.evidence.observed_facts
        : (f.description ? [f.description] : ['Anomaly matched by security detector engine.']),
      hypothesis: f.evidence?.inferred_hypothesis || `Adversary activity detected matching ${f.attack_category || 'unauthorized behavior'}.`,
      missingEvidence: f.evidence?.missing_evidence || 'Cross-region VPC flow logs and host memory dump.',
      raw: f
    };
  });

  const filtered = activeList.filter(item => {
    const matchesSearch = !searchTerm ||
      item.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.resource.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity = severityFilter === 'All' || item.severity.toLowerCase() === severityFilter.toLowerCase();
    const matchesStatus = statusFilter === 'All' || item.status.toLowerCase() === statusFilter.toLowerCase();
    const matchesSource = sourceFilter === 'All' || item.source.toLowerCase() === sourceFilter.toLowerCase();

    return matchesSearch && matchesSeverity && matchesStatus && matchesSource;
  });

  // Calculate live counts
  const totalFindings = activeList.length;
  const resolvedCount = activeList.filter(f => f.status.toLowerCase() === 'resolved').length;
  const openCount = totalFindings - resolvedCount;
  const criticalCount = activeList.filter(f => f.severity === 'critical').length;
  const highCount = activeList.filter(f => f.severity === 'high').length;
  const mediumCount = activeList.filter(f => f.severity === 'medium').length;
  const lowCount = activeList.filter(f => f.severity === 'low').length;

  const liveCount = activeList.filter(f => f.source === 'LIVE').length;
  const simCount = activeList.filter(f => f.source === 'SIMULATED').length;
  const impCount = activeList.filter(f => f.source === 'IMPORTED').length;
  const provParts = [];
  if (liveCount > 0) provParts.push(`${liveCount} LIVE`);
  if (simCount > 0) provParts.push(`${simCount} SIMULATED`);
  if (impCount > 0) provParts.push(`${impCount} IMPORTED`);
  const provenanceStr = provParts.length > 0 ? provParts.join(' · ') : `${totalFindings} TOTAL`;

  return (
    <div>
      {/* STATS TICKER */}
      <div className="figma-overview-ticker">
        <div className="figma-ticker-left">
          <span className="count-bold">{openCount}</span>
          <span>open findings</span>
          <span style={{ color: 'var(--text-muted)' }}>/ {resolvedCount} resolved</span>
        </div>

        <div className="figma-ticker-severities">
          <span className="figma-sev-crit">{criticalCount} Critical</span>
          <span className="figma-sev-high">{highCount} High</span>
          <span className="figma-sev-med">{mediumCount} Medium</span>
          <span className="figma-sev-low">{lowCount} Low</span>
        </div>

        <div className="figma-ticker-provenance">
          <span>{provenanceStr}</span>
        </div>
      </div>

      {/* FILTER AND SEARCH BAR (MATCHING FIGMA alertandincident.png) */}
      <div className="figma-filter-bar">
        <div className="figma-header-search" style={{ flex: '1 1 300px', width: 'auto', backgroundColor: 'var(--surface-card)' }}>
          <Search size={15} style={{ color: 'var(--text-tertiary)' }} />
          <input
            type="text"
            placeholder="Search findings or resources..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        <select
          className="figma-filter-select"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="All">Severity: All</option>
          <option value="Critical">Severity: Critical</option>
          <option value="High">Severity: High</option>
          <option value="Medium">Severity: Medium</option>
          <option value="Low">Severity: Low</option>
        </select>

        <select
          className="figma-filter-select"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="All">Status: All</option>
          <option value="New">Status: New</option>
          <option value="Investigating">Status: Investigating</option>
          <option value="Resolved">Status: Resolved</option>
        </select>

        <select
          className="figma-filter-select"
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value)}
        >
          <option value="All">Source: All</option>
          <option value="LIVE">Source: LIVE</option>
          <option value="SIMULATED">Source: SIMULATED</option>
          <option value="IMPORTED">Source: IMPORTED</option>
        </select>

        <button className="figma-btn-secondary" style={{ padding: '7px 12px' }}>
          More filters <ChevronDown size={14} />
        </button>
      </div>

      {/* MAIN TABLE MATCHING FIGMA SPEC */}
      <div className="figma-table-container">
        <table className="figma-table">
          <thead>
            <tr>
              <th style={{ width: '40px' }}>
                <input type="checkbox" style={{ cursor: 'pointer' }} />
              </th>
              <th style={{ width: '130px' }}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', cursor: 'pointer' }}>
                  Severity <ArrowUpDown size={12} />
                </span>
              </th>
              <th>Finding</th>
              <th>Resource</th>
              <th>Status</th>
              <th>Seen · UTC</th>
              <th style={{ textAlign: 'right' }}>Details</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)' }}>
                  {findingsLoading ? 'Analyzing live telemetry stream...' : 'No security findings match the selected filters.'}
                </td>
              </tr>
            ) : (
              filtered.map((item, idx) => (
              <tr key={idx}>
                <td>
                  <input type="checkbox" style={{ cursor: 'pointer' }} />
                </td>
                <td>
                  <span className={`figma-dot-badge ${item.severity}`}>
                    {item.severity.charAt(0).toUpperCase() + item.severity.slice(1)}
                  </span>
                </td>
                <td>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                    {item.title}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '2px' }}>
                    <span style={{ fontFamily: 'monospace' }}>{item.id}</span> · {item.source} · {item.fixture}
                  </div>
                </td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  {item.resource}
                </td>
                <td>
                  <span style={{
                    fontSize: '12.5px',
                    fontWeight: 500,
                    color: item.status === 'Resolved' ? 'var(--sev-medium)' : 'var(--text-secondary)'
                  }}>
                    {item.status}
                  </span>
                </td>
                <td style={{ color: 'var(--text-tertiary)', fontSize: '13px' }}>
                  {item.seen}
                </td>
                <td style={{ textAlign: 'right' }}>
                  <button
                    className="figma-link-btn"
                    onClick={() => setSelectedIncident(item)}
                  >
                    Evidence →
                  </button>
                </td>
              </tr>
            )))}
          </tbody>
        </table>
      </div>

      {/* FORENSIC EVIDENCE DRAWER MODAL */}
      {selectedIncident && (
        <div className="figma-drawer-overlay" onClick={() => setSelectedIncident(null)}>
          <div className="figma-drawer-content" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
              <div>
                <span className={`figma-dot-badge ${selectedIncident.severity}`} style={{ marginBottom: '6px' }}>
                  {selectedIncident.severity.toUpperCase()}
                </span>
                <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {selectedIncident.title}
                </h2>
                <span style={{ fontSize: '12px', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                  {selectedIncident.id} · {selectedIncident.source} · {selectedIncident.resource}
                </span>
              </div>
              <button
                className="figma-btn-secondary"
                style={{ padding: '6px 8px', borderRadius: '50%' }}
                onClick={() => setSelectedIncident(null)}
              >
                <X size={16} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* Observed Facts */}
              <div className="figma-card" style={{ padding: '16px' }}>
                <h4 style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <ShieldCheck size={16} style={{ color: 'var(--success-color)' }} /> Observed Facts
                </h4>
                <ul style={{ paddingLeft: '18px', fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  {selectedIncident.observedFacts.map((fact, fi) => (
                    <li key={fi}>{fact}</li>
                  ))}
                </ul>
              </div>

              {/* Inferred Hypothesis */}
              <div className="figma-card" style={{ padding: '16px' }}>
                <h4 style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>
                  Inferred Hypothesis
                </h4>
                <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  {selectedIncident.hypothesis}
                </p>
              </div>

              {/* Missing Evidence */}
              <div className="figma-card" style={{ padding: '16px' }}>
                <h4 style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <AlertTriangle size={16} style={{ color: 'var(--sev-high)' }} /> Missing Evidence
                </h4>
                <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  {selectedIncident.missingEvidence}
                </p>
              </div>

              {/* Response action */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '12px' }}>
                <button
                  className="figma-btn-primary"
                  onClick={() => {
                    const inc = selectedIncident;
                    setSelectedIncident(null);
                    if (onInvestigateFinding) onInvestigateFinding(inc.raw || inc);
                  }}
                >
                  Open in Remediation →
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AlertsIncidentsTab;
