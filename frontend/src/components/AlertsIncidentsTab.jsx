import React, { useState } from 'react';
import {
  Search,
  ChevronDown,
  ArrowUpDown,
  ArrowRight,
  ExternalLink,
  ShieldCheck,
  X,
  AlertTriangle,
  Layers,
  Clock,
  Users,
  Globe,
  Database,
  Tag,
  ChevronRight,
  CheckCircle2
} from 'lucide-react';

const formatDuration = (seconds) => {
  if (!seconds || seconds <= 0) return '< 1 min';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const mins = Math.floor(seconds / 60);
  const remSec = Math.round(seconds % 60);
  if (mins < 60) return remSec > 0 ? `${mins}m ${remSec}s` : `${mins} min`;
  const hours = Math.floor(mins / 60);
  const remMins = mins % 60;
  return `${hours}h ${remMins}m`;
};

const AlertsIncidentsTab = ({
  findings = [],
  findingsLoading = false,
  findingsError = null,
  findingsAttackMode = 15,
  fetchFindings,
  incidents = [],
  incidentsLoading = false,
  incidentsStats = null,
  fetchIncidents,
  onInvestigateFinding
}) => {
  const [viewMode, setViewMode] = useState('incidents'); // 'incidents' | 'findings'
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [selectedIncidentModal, setSelectedIncidentModal] = useState(null);
  const [selectedFindingModal, setSelectedFindingModal] = useState(null);
  const [expandedFindingId, setExpandedFindingId] = useState(null);

  // ── 1. Map raw findings ─────────────────────────────────────────────────────
  const activeFindingsList = (findings || []).map((f, idx) => {
    const rawTime = f.timestamp || f.created_at;
    const timeFormatted = rawTime
      ? new Date(rawTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
      : 'Recent';
    const detectorName = f.detection_method
      ? f.detection_method.replace(/_/g, ' ')
      : (f.attack_category ? f.attack_category.replace(/_/g, ' ') : 'detector');

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

  // ── 2. Correlated Incidents Filtering ───────────────────────────────────────
  const filteredIncidents = (incidents || []).filter(inc => {
    const matchesSearch = !searchTerm ||
      inc.incident_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (inc.principals || []).some(p => p.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (inc.resources || []).some(r => r.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (inc.source_ips || []).some(ip => ip.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesSeverity = severityFilter === 'All' || inc.severity.toLowerCase() === severityFilter.toLowerCase();
    const matchesStatus = statusFilter === 'All' || inc.status.toLowerCase() === statusFilter.toLowerCase();

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  // ── 3. Atomic Findings Filtering ───────────────────────────────────────────
  const filteredFindings = activeFindingsList.filter(item => {
    const matchesSearch = !searchTerm ||
      item.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.resource.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity = severityFilter === 'All' || item.severity.toLowerCase() === severityFilter.toLowerCase();
    const matchesStatus = statusFilter === 'All' || item.status.toLowerCase() === statusFilter.toLowerCase();

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  // Metrics summary
  const totalIncidents = incidents.length;
  const openIncidents = incidents.filter(i => i.status.toLowerCase() === 'open').length;
  const resolvedIncidents = totalIncidents - openIncidents;
  const critIncidents = incidents.filter(i => i.severity.toLowerCase() === 'critical').length;
  const highIncidents = incidents.filter(i => i.severity.toLowerCase() === 'high').length;
  const medIncidents = incidents.filter(i => i.severity.toLowerCase() === 'medium').length;
  const lowIncidents = incidents.filter(i => i.severity.toLowerCase() === 'low').length;

  return (
    <div>
      {/* ── TOP STATS TICKER ──────────────────────────────────────────────── */}
      <div className="figma-overview-ticker" style={{ marginBottom: '16px' }}>
        <div className="figma-ticker-left">
          <span className="count-bold">{openIncidents}</span>
          <span>open incidents</span>
          <span style={{ color: 'var(--text-muted)' }}>/ {totalIncidents} total correlated</span>
        </div>

        <div className="figma-ticker-severities">
          <span className="figma-sev-crit">{critIncidents} Critical</span>
          <span className="figma-sev-high">{highIncidents} High</span>
          <span className="figma-sev-med">{medIncidents} Medium</span>
          <span className="figma-sev-low">{lowIncidents} Low</span>
        </div>

        <div className="figma-ticker-provenance">
          <span>
            {incidentsStats?.avg_findings_per_incident
              ? `${incidentsStats.avg_findings_per_incident} avg findings/incident`
              : `${findings.length} findings grouped into ${totalIncidents} incidents`}
          </span>
        </div>
      </div>

      {/* ── VIEW MODE TOGGLE + SEARCH & FILTERS ────────────────────────────── */}
      <div className="figma-filter-bar" style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center' }}>
        {/* Tab Toggle: Incidents vs Findings */}
        <div style={{
          display: 'inline-flex',
          backgroundColor: 'var(--surface-sunken)',
          borderRadius: '8px',
          padding: '3px',
          border: '1px solid var(--border-subtle)'
        }}>
          <button
            style={{
              padding: '6px 14px',
              fontSize: '13px',
              fontWeight: 600,
              borderRadius: '6px',
              border: 'none',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: viewMode === 'incidents' ? 'var(--surface-card)' : 'transparent',
              color: viewMode === 'incidents' ? 'var(--text-primary)' : 'var(--text-secondary)',
              boxShadow: viewMode === 'incidents' ? '0 1px 3px rgba(0,0,0,0.1)' : 'none'
            }}
            onClick={() => setViewMode('incidents')}
          >
            <Layers size={14} style={{ color: viewMode === 'incidents' ? 'var(--sev-crit)' : 'inherit' }} />
            Correlated Incidents ({incidents.length})
          </button>
          <button
            style={{
              padding: '6px 14px',
              fontSize: '13px',
              fontWeight: 600,
              borderRadius: '6px',
              border: 'none',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: viewMode === 'findings' ? 'var(--surface-card)' : 'transparent',
              color: viewMode === 'findings' ? 'var(--text-primary)' : 'var(--text-secondary)',
              boxShadow: viewMode === 'findings' ? '0 1px 3px rgba(0,0,0,0.1)' : 'none'
            }}
            onClick={() => setViewMode('findings')}
          >
            <Tag size={14} />
            Atomic Findings ({findings.length})
          </button>
        </div>

        {/* Search */}
        <div className="figma-header-search" style={{ flex: '1 1 250px', width: 'auto', backgroundColor: 'var(--surface-card)' }}>
          <Search size={15} style={{ color: 'var(--text-tertiary)' }} />
          <input
            type="text"
            placeholder={viewMode === 'incidents' ? "Search incidents, entities, IPs, stages..." : "Search findings or resources..."}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        {/* Severity Filter */}
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

        {/* Status Filter */}
        <select
          className="figma-filter-select"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="All">Status: All</option>
          <option value="Open">Status: Open</option>
          <option value="Investigating">Status: Investigating</option>
          <option value="Resolved">Status: Resolved</option>
        </select>

        {fetchIncidents && (
          <button
            className="figma-btn-secondary"
            style={{ padding: '7px 12px' }}
            onClick={() => {
              if (fetchIncidents) fetchIncidents();
              if (fetchFindings) fetchFindings(findingsAttackMode);
            }}
          >
            Refresh
          </button>
        )}
      </div>

      {/* ── CORRELATED INCIDENTS VIEW (DEFAULT) ───────────────────────────── */}
      {viewMode === 'incidents' && (
        <div className="figma-table-container">
          <table className="figma-table">
            <thead>
              <tr>
                <th style={{ width: '110px' }}>Incident ID</th>
                <th style={{ width: '100px' }}>Severity</th>
                <th>Campaign & Summary</th>
                <th>Entities & Infrastructure</th>
                <th style={{ width: '160px' }}>Attack Stages</th>
                <th style={{ width: '90px' }}>Duration</th>
                <th style={{ width: '100px', textAlign: 'center' }}>Findings</th>
                <th style={{ textAlign: 'right', width: '130px' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredIncidents.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)' }}>
                    {incidentsLoading ? 'Correlating security findings across telemetry stream...' : 'No correlated incidents match the selected filters.'}
                  </td>
                </tr>
              ) : (
                filteredIncidents.map((inc) => {
                  const entitiesList = [
                    ...(inc.principals || []),
                    ...(inc.source_ips || []),
                    ...(inc.resources || [])
                  ].slice(0, 2).join(' · ');

                  return (
                    <tr
                      key={inc.incident_id}
                      style={{ cursor: 'pointer' }}
                      onClick={() => setSelectedIncidentModal(inc)}
                    >
                      <td>
                        <span style={{ fontFamily: 'monospace', fontWeight: 700, color: 'var(--text-primary)' }}>
                          {inc.incident_id}
                        </span>
                        <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: '2px' }}>
                          Score: {(inc.correlation_score * 100).toFixed(0)}%
                        </div>
                      </td>
                      <td>
                        <span className={`figma-dot-badge ${inc.severity.toLowerCase()}`}>
                          {inc.severity.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '3px' }}>
                          {inc.title}
                        </div>
                        <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                          {inc.description}
                        </div>
                      </td>
                      <td>
                        <div style={{ fontSize: '12.5px', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <Users size={13} style={{ color: 'var(--text-tertiary)', flexShrink: 0 }} />
                          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '200px' }}>
                            {entitiesList || 'System workload'}
                          </span>
                        </div>
                        {inc.source_ips && inc.source_ips.length > 0 && (
                          <div style={{ fontSize: '11.5px', color: 'var(--text-tertiary)', marginTop: '2px', fontFamily: 'monospace' }}>
                            IP: {inc.source_ips.join(', ')}
                          </div>
                        )}
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                          {(inc.attack_stages || []).slice(0, 3).map((stage, si) => (
                            <span
                              key={si}
                              style={{
                                fontSize: '11px',
                                padding: '2px 6px',
                                borderRadius: '4px',
                                backgroundColor: 'var(--surface-sunken)',
                                border: '1px solid var(--border-subtle)',
                                color: 'var(--text-secondary)',
                                whiteSpace: 'nowrap'
                              }}
                            >
                              {stage}
                            </span>
                          ))}
                          {(inc.attack_stages || []).length > 3 && (
                            <span style={{ fontSize: '10.5px', color: 'var(--text-tertiary)' }}>
                              +{inc.attack_stages.length - 3}
                            </span>
                          )}
                        </div>
                      </td>
                      <td style={{ color: 'var(--text-secondary)', fontSize: '12.5px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <Clock size={12} style={{ color: 'var(--text-tertiary)' }} />
                          {formatDuration(inc.duration_seconds)}
                        </div>
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          padding: '3px 8px',
                          borderRadius: '12px',
                          backgroundColor: inc.finding_count > 1 ? 'rgba(239, 68, 68, 0.1)' : 'var(--surface-sunken)',
                          color: inc.finding_count > 1 ? 'var(--sev-crit)' : 'var(--text-secondary)',
                          fontWeight: 700,
                          fontSize: '12px'
                        }}>
                          {inc.finding_count} {inc.finding_count === 1 ? 'finding' : 'findings'}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }} onClick={(e) => e.stopPropagation()}>
                        <button
                          className="figma-link-btn"
                          style={{
                            padding: '6px 10px',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                            fontWeight: 600
                          }}
                          onClick={() => setSelectedIncidentModal(inc)}
                        >
                          View Findings →
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* ── ATOMIC FINDINGS VIEW ─────────────────────────────────────────── */}
      {viewMode === 'findings' && (
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
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)' }}>
                    {findingsLoading ? 'Analyzing live telemetry stream...' : 'No security findings match the selected filters.'}
                  </td>
                </tr>
              ) : (
                filteredFindings.map((item, idx) => (
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
                        onClick={() => setSelectedFindingModal(item)}
                      >
                        Evidence →
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* ── INCIDENT DETAIL DRAWER (SHOWING CORRELATED MEMBER FINDINGS) ────── */}
      {selectedIncidentModal && (
        <div className="figma-drawer-overlay" onClick={() => setSelectedIncidentModal(null)}>
          <div
            className="figma-drawer-content"
            style={{ width: '700px', maxWidth: '95vw', overflowY: 'auto' }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '20px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                  <span className={`figma-dot-badge ${selectedIncidentModal.severity.toLowerCase()}`}>
                    {selectedIncidentModal.severity.toUpperCase()}
                  </span>
                  <span style={{
                    fontFamily: 'monospace',
                    fontSize: '13px',
                    fontWeight: 700,
                    color: 'var(--text-secondary)'
                  }}>
                    {selectedIncidentModal.incident_id}
                  </span>
                  <span style={{
                    fontSize: '11.5px',
                    padding: '2px 8px',
                    borderRadius: '10px',
                    backgroundColor: 'rgba(59, 130, 246, 0.12)',
                    color: '#2563eb',
                    fontWeight: 600
                  }}>
                    Deterministic Score: {(selectedIncidentModal.correlation_score * 100).toFixed(0)}%
                  </span>
                </div>
                <h2 style={{ fontSize: '19px', fontWeight: 700, color: 'var(--text-primary)', margin: '4px 0' }}>
                  {selectedIncidentModal.title}
                </h2>
                <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span>Span: {formatDuration(selectedIncidentModal.duration_seconds)}</span>
                  <span>·</span>
                  <span>{selectedIncidentModal.finding_count} correlated findings</span>
                  <span>·</span>
                  <span>Status: {selectedIncidentModal.status.toUpperCase()}</span>
                </div>
              </div>
              <button
                className="figma-btn-secondary"
                style={{ padding: '6px 8px', borderRadius: '50%' }}
                onClick={() => setSelectedIncidentModal(null)}
              >
                <X size={16} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Correlation Evidence / Reasons */}
              <div className="figma-card" style={{ padding: '16px' }}>
                <h4 style={{
                  fontSize: '13px',
                  fontWeight: 600,
                  color: 'var(--text-primary)',
                  marginBottom: '10px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}>
                  <ShieldCheck size={16} style={{ color: 'var(--success-color)' }} />
                  Deterministic Correlation Evidence
                </h4>
                <ul style={{ paddingLeft: '18px', fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
                  {(selectedIncidentModal.correlation_reasons || []).map((reason, ri) => (
                    <li key={ri}>{reason}</li>
                  ))}
                </ul>
              </div>

              {/* Entities & Infrastructure Signals */}
              <div className="figma-card" style={{ padding: '16px' }}>
                <h4 style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '10px' }}>
                  Correlated Context & Attack Chain
                </h4>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', fontSize: '12px' }}>
                  <div style={{ backgroundColor: 'var(--surface-sunken)', padding: '10px', borderRadius: '6px' }}>
                    <div style={{ color: 'var(--text-tertiary)', marginBottom: '4px', fontWeight: 600 }}>IDENTITIES / PRINCIPALS</div>
                    <div style={{ color: 'var(--text-primary)', fontWeight: 600, wordBreak: 'break-all' }}>
                      {selectedIncidentModal.principals?.join(', ') || 'None identified'}
                    </div>
                  </div>
                  <div style={{ backgroundColor: 'var(--surface-sunken)', padding: '10px', borderRadius: '6px' }}>
                    <div style={{ color: 'var(--text-tertiary)', marginBottom: '4px', fontWeight: 600 }}>SOURCE IPS</div>
                    <div style={{ color: 'var(--text-primary)', fontFamily: 'monospace' }}>
                      {selectedIncidentModal.source_ips?.join(', ') || 'Internal / Cloud Service'}
                    </div>
                  </div>
                  <div style={{ backgroundColor: 'var(--surface-sunken)', padding: '10px', borderRadius: '6px' }}>
                    <div style={{ color: 'var(--text-tertiary)', marginBottom: '4px', fontWeight: 600 }}>TARGET RESOURCES</div>
                    <div style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                      {selectedIncidentModal.resources?.join(', ') || 'Distributed'}
                    </div>
                  </div>
                  <div style={{ backgroundColor: 'var(--surface-sunken)', padding: '10px', borderRadius: '6px' }}>
                    <div style={{ color: 'var(--text-tertiary)', marginBottom: '4px', fontWeight: 600 }}>MITRE ATT&CK STAGES</div>
                    <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                      {selectedIncidentModal.attack_stages?.join(' → ') || 'Unmapped'}
                    </div>
                  </div>
                </div>
              </div>

              {/* Correlated Member Findings */}
              <div className="figma-card" style={{ padding: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                  <h4 style={{
                    fontSize: '13.5px',
                    fontWeight: 700,
                    color: 'var(--text-primary)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}>
                    <Layers size={16} style={{ color: 'var(--sev-crit)' }} />
                    Member Findings Correlated Into This Campaign ({selectedIncidentModal.finding_count})
                  </h4>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Original findings intact
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {(selectedIncidentModal.findings || []).map((finding, fi) => {
                    const fId = finding.finding_id || `FIND-${fi}`;
                    const isExpanded = expandedFindingId === fId;

                    return (
                      <div
                        key={fi}
                        style={{
                          border: '1px solid var(--border-subtle)',
                          borderRadius: '6px',
                          padding: '10px 12px',
                          backgroundColor: 'var(--surface-card)',
                          fontSize: '12.5px'
                        }}
                      >
                        <div
                          style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}
                          onClick={() => setExpandedFindingId(isExpanded ? null : fId)}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span className={`figma-dot-badge ${(finding.severity || 'high').toLowerCase()}`} style={{ fontSize: '10px' }}>
                              {(finding.severity || 'HIGH').toUpperCase()}
                            </span>
                            <span style={{ fontFamily: 'monospace', fontWeight: 600, color: 'var(--text-primary)' }}>
                              {fId}
                            </span>
                            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                              {finding.title}
                            </span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-tertiary)', fontSize: '11.5px' }}>
                            <span>{finding.timestamp ? new Date(finding.timestamp).toLocaleTimeString() : 'Recent'}</span>
                            <ChevronRight size={14} style={{ transform: isExpanded ? 'rotate(90deg)' : 'none', transition: 'transform 0.15s' }} />
                          </div>
                        </div>

                        {/* Collapsed summary snippet */}
                        {!isExpanded && finding.affected_resource && (
                          <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: '4px', marginLeft: '6px' }}>
                            Target: {finding.affected_resource} · Principal: {finding.affected_principal || 'N/A'}
                          </div>
                        )}

                        {/* Expanded details */}
                        {isExpanded && (
                          <div style={{ marginTop: '10px', paddingTop: '8px', borderTop: '1px dashed var(--border-subtle)' }}>
                            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                              <strong>Category:</strong> {finding.attack_category} · <strong>Method:</strong> {finding.detection_method || 'Specialized Rule'}
                            </div>

                            {finding.evidence?.observed_facts && finding.evidence.observed_facts.length > 0 && (
                              <div style={{ marginBottom: '6px' }}>
                                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-tertiary)' }}>OBSERVED FACTS:</div>
                                <ul style={{ margin: '4px 0 0 16px', padding: 0, fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                                  {finding.evidence.observed_facts.map((obs, oi) => (
                                    <li key={oi}>{obs}</li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {finding.evidence?.triggering_event_ids && finding.evidence.triggering_event_ids.length > 0 && (
                              <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                                Events: {finding.evidence.triggering_event_ids.slice(0, 5).join(', ')}
                                {finding.evidence.triggering_event_ids.length > 5 && ` (+${finding.evidence.triggering_event_ids.length - 5} more)`}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Remediation Action Button */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '6px' }}>
                <button
                  className="figma-btn-secondary"
                  onClick={() => setSelectedIncidentModal(null)}
                >
                  Close
                </button>
                <button
                  className="figma-btn-primary"
                  onClick={() => {
                    const inc = selectedIncidentModal;
                    setSelectedIncidentModal(null);
                    if (onInvestigateFinding) {
                      onInvestigateFinding(inc.findings?.[0] || inc);
                    }
                  }}
                >
                  Open in Remediation →
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── ATOMIC FINDING DETAIL DRAWER ─────────────────────────────────── */}
      {selectedFindingModal && (
        <div className="figma-drawer-overlay" onClick={() => setSelectedFindingModal(null)}>
          <div className="figma-drawer-content" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
              <div>
                <span className={`figma-dot-badge ${selectedFindingModal.severity}`} style={{ marginBottom: '6px' }}>
                  {selectedFindingModal.severity.toUpperCase()}
                </span>
                <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {selectedFindingModal.title}
                </h2>
                <span style={{ fontSize: '12px', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                  {selectedFindingModal.id} · {selectedFindingModal.source} · {selectedFindingModal.resource}
                </span>
              </div>
              <button
                className="figma-btn-secondary"
                style={{ padding: '6px 8px', borderRadius: '50%' }}
                onClick={() => setSelectedFindingModal(null)}
              >
                <X size={16} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="figma-card" style={{ padding: '16px' }}>
                <h4 style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <ShieldCheck size={16} style={{ color: 'var(--success-color)' }} /> Observed Facts
                </h4>
                <ul style={{ paddingLeft: '18px', fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  {selectedFindingModal.observedFacts.map((fact, fi) => (
                    <li key={fi}>{fact}</li>
                  ))}
                </ul>
              </div>

              <div className="figma-card" style={{ padding: '16px' }}>
                <h4 style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>
                  Inferred Hypothesis
                </h4>
                <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  {selectedFindingModal.hypothesis}
                </p>
              </div>

              <div className="figma-card" style={{ padding: '16px' }}>
                <h4 style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <AlertTriangle size={16} style={{ color: 'var(--sev-high)' }} /> Missing Evidence
                </h4>
                <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  {selectedFindingModal.missingEvidence}
                </p>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '12px' }}>
                <button
                  className="figma-btn-primary"
                  onClick={() => {
                    const inc = selectedFindingModal;
                    setSelectedFindingModal(null);
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
