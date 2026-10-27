import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { ShieldCheck, Download, RefreshCw, FileText, CheckCircle2, AlertTriangle, X, Info } from 'lucide-react';
import { API_URL } from '../config';

const ComplianceTab = ({ showToast }) => {
  const [activeFrameworkKey, setActiveFrameworkKey] = useState('ISO27001');
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [report, setReport] = useState(null);
  const [generating, setGenerating] = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);

  const frameworkDefinitions = [
    { key: 'ISO27001', label: 'ISO/IEC 27001:2022', desc: 'Information Security Management Systems (ISMS)' },
    { key: 'SOC2', label: 'SOC 2 Type II', desc: 'Trust Services Criteria (Security, Availability, Confidentiality)' },
    { key: 'GDPR', label: 'GDPR', desc: 'General Data Protection Regulation (Article 32 Security of Processing)' }
  ];

  const fetchComplianceDashboard = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await axios.get(`${API_URL}/compliance/dashboard`);
      setDashboardData(res.data?.data || null);
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Failed to fetch compliance dashboard';
      setError(msg);
      if (showToast) showToast(`Compliance data fetch failed: ${msg}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchComplianceDashboard();
  }, []);

  const generateReport = async () => {
    setGenerating(true);
    try {
      const res = await axios.get(`${API_URL}/compliance/report?format=json`);
      setReport(res.data?.data || null);
      setShowReportModal(true);
      if (showToast) showToast('Executive compliance audit report generated!');
    } catch (err) {
      if (showToast) showToast('Report generation failed', 'error');
    } finally {
      setGenerating(false);
    }
  };

  const downloadCSVReport = async () => {
    try {
      const res = await axios.get(`${API_URL}/compliance/report?format=csv`, { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', 'compliance_report.csv');
      document.body.appendChild(link);
      link.click();
      link.remove();
      if (showToast) showToast('CSV Report downloaded to your device!');
    } catch (err) {
      if (showToast) showToast('Download failed', 'error');
    }
  };

  const activeFwData = dashboardData?.frameworks?.[activeFrameworkKey] || null;
  const criticalGaps = activeFwData?.critical_gaps || [];

  return (
    <div className="animate-fade-in">
      {/* 1. INFORMATIONAL HONESTY BADGE */}
      <div
        style={{
          padding: '12px 18px',
          borderRadius: '8px',
          backgroundColor: 'var(--surface-table-head)',
          border: '1px solid var(--border-subtle)',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Info size={16} style={{ color: 'var(--accent-orange)' }} />
          <span style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>
            <strong>Demo Baseline Audit:</strong> Compliance scores and control mappings are computed dynamically by the backend engine from active CSPM configuration audits and CIEM identity findings.
          </span>
        </div>
        <span
          style={{
            fontSize: '11px',
            fontWeight: 600,
            padding: '2px 8px',
            borderRadius: '4px',
            backgroundColor: 'var(--surface-muted)',
            color: 'var(--text-tertiary)',
            border: '1px solid var(--border-subtle)'
          }}
        >
          SEEDED BASELINE EVALUATION
        </span>
      </div>

      {/* 2. FRAMEWORK TABS SELECTOR (FIGMA PILL TABS) */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          borderBottom: '1px solid var(--border-subtle)',
          marginBottom: '24px',
          flexWrap: 'wrap',
          gap: '12px'
        }}
      >
        <div style={{ display: 'flex', gap: '24px' }}>
          {frameworkDefinitions.map((fw) => {
            const isActive = fw.key === activeFrameworkKey;
            return (
              <button
                key={fw.key}
                onClick={() => setActiveFrameworkKey(fw.key)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  borderBottom: isActive ? '2px solid var(--accent-orange)' : '2px solid transparent',
                  padding: '10px 4px',
                  fontSize: '13.5px',
                  fontWeight: isActive ? 600 : 500,
                  color: isActive ? 'var(--accent-orange)' : 'var(--text-secondary)',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  marginBottom: '-1px'
                }}
              >
                {fw.label}
              </button>
            );
          })}
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="figma-btn-secondary" onClick={downloadCSVReport}>
            <Download size={13} /> Export CSV
          </button>
          <button className="figma-btn-primary" onClick={generateReport} disabled={generating}>
            <FileText size={13} className={generating ? 'animate-spin' : ''} />
            {generating ? 'Generating Audit Report...' : 'Generate report'}
          </button>
        </div>
      </div>

      {/* ERROR BANNER */}
      {error && (
        <div
          style={{
            padding: '12px 16px',
            borderRadius: '8px',
            backgroundColor: 'rgba(217, 45, 32, 0.1)',
            border: '1px solid rgba(217, 45, 32, 0.3)',
            marginBottom: '18px',
            color: 'var(--sev-critical)',
            fontSize: '13px'
          }}
        >
          {error}
        </div>
      )}

      {/* 3. THREE DYNAMIC SUMMARY CARDS: ISO, SOC 2, GDPR */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginBottom: '24px' }}>
        {frameworkDefinitions.map((fw, idx) => {
          const fwData = dashboardData?.frameworks?.[fw.key];
          const score = fwData ? `${fwData.score}%` : '—';
          const passFail = fwData ? `${fwData.passing} / ${fwData.failing}` : '— / —';
          const totalControls = fwData ? `${fwData.total} evaluated` : 'Loading...';
          const statusText = fwData?.status ? fwData.status.toUpperCase() : 'AUDITING';

          return (
            <div key={fw.key} className="figma-card">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
                <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                  {fw.label}
                </h3>
                <span style={{ fontSize: '12px', color: 'var(--text-tertiary)', fontWeight: 600 }}>
                  {score}
                </span>
              </div>

              <div
                style={{
                  width: '40px',
                  height: '4px',
                  backgroundColor: fw.key === activeFrameworkKey ? 'var(--accent-orange)' : 'var(--text-muted)',
                  borderRadius: '2px',
                  marginBottom: '16px'
                }}
              />

              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12.5px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                <span>Pass / Fail controls</span>
                <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                  {passFail}
                </span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: 'var(--text-tertiary)' }}>
                <span>{totalControls}</span>
                <span style={{ color: fwData?.status === 'compliant' ? 'var(--success-color)' : 'var(--sev-high)', fontWeight: 600 }}>
                  {statusText}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* 4. POTENTIAL CONTROL GAPS TABLE (LIVE BACKEND DATA) */}
      <div className="figma-card" style={{ padding: '0', overflow: 'hidden', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
            Potential Control Gaps & Mappings
          </h3>
          <span style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
            {activeFwData?.name || activeFrameworkKey} · {criticalGaps.length} Active Gaps
          </span>
        </div>

        <table className="figma-table">
          <thead>
            <tr>
              <th>Control Reference</th>
              <th>Requirement Name</th>
              <th>Source</th>
              <th>Mapped Security Finding</th>
              <th style={{ textAlign: 'right' }}>Review</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={5} style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                  Loading compliance mapping...
                </td>
              </tr>
            ) : criticalGaps.length === 0 ? (
              <tr>
                <td colSpan={5} style={{ textAlign: 'center', padding: '24px', color: 'var(--success-color)' }}>
                  No failing control gaps detected for {activeFwData?.name || activeFrameworkKey}.
                </td>
              </tr>
            ) : (
              criticalGaps.map((gap, idx) => (
                <tr key={idx}>
                  <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                    {gap.control}
                  </td>
                  <td style={{ color: 'var(--text-primary)' }}>
                    {gap.name}
                  </td>
                  <td>
                    <span
                      style={{
                        padding: '2px 6px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: 600,
                        backgroundColor: gap.source === 'CIEM' ? 'rgba(235, 107, 39, 0.12)' : 'rgba(59, 130, 246, 0.12)',
                        color: gap.source === 'CIEM' ? 'var(--accent-orange)' : '#3b82f6'
                      }}
                    >
                      {gap.source}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>
                    {gap.finding || 'Configuration non-compliance detected'}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button className="figma-link-btn" onClick={() => generateReport()}>
                      Evidence →
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        <div style={{ padding: '14px 20px', borderTop: '1px solid var(--border-subtle)', fontSize: '12px', color: 'var(--text-muted)' }}>
          Potential gaps for review, mapped directly by backend engine from CSPM cloud audits and CIEM identity risks.
        </div>
      </div>

      {/* 5. ON-SCREEN GENERATED AUDIT REPORT MODAL */}
      {showReportModal && report && (
        <div
          style={{
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
            padding: '24px'
          }}
        >
          <div
            className="figma-card"
            style={{
              width: '100%',
              maxWidth: '720px',
              maxHeight: '90vh',
              overflowY: 'auto',
              padding: '24px'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>
                Compliance Audit Report ({report.framework || 'All Frameworks'})
              </h3>
              <button
                onClick={() => setShowReportModal(false)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '18px' }}>
              <div><strong>Audit ID:</strong> {report.report_id || 'AUD-REPORT-2026'}</div>
              <div><strong>Overall Compliance Score:</strong> {report.overall_score || report.score || dashboardData?.overall_score}%</div>
              <div><strong>Generated At:</strong> {report.timestamp || new Date().toISOString()}</div>
              <div><strong>Status:</strong> {report.status || 'Compliant'}</div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px' }}>
              <button className="figma-btn-secondary" onClick={() => setShowReportModal(false)}>
                Close
              </button>
              <button className="figma-btn-primary" onClick={downloadCSVReport}>
                <Download size={13} /> Download CSV
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ComplianceTab;
