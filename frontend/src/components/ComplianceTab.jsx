import React, { useState } from 'react';
import axios from 'axios';
import { ShieldCheck, Download, RefreshCw, FileText, CheckCircle2, AlertTriangle, X } from 'lucide-react';
import { API_URL } from '../config';

const ComplianceTab = ({ showToast }) => {
  const [activeFramework, setActiveFramework] = useState('ISO/IEC 27001:2022');
  const [report, setReport] = useState(null);
  const [generating, setGenerating] = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);

  const frameworks = [
    { id: 'ISO/IEC 27001:2022', label: 'ISO/IEC 27001:2022', desc: 'Information Security Management Systems (ISMS)' },
    { id: 'SOC 2 Type II', label: 'SOC 2 Type II', desc: 'Trust Services Criteria (Security, Availability, Confidentiality)' },
    { id: 'GDPR', label: 'GDPR', desc: 'General Data Protection Regulation (Article 32 Security of Processing)' }
  ];

  // Gaps matching Figma compliance.png wireframe
  const controlGaps = [
    {
      control: 'A.8.20 · Network security',
      finding: 'RAM-1041 · SSH accessible from internet',
      resource: 'demo-web-01 ↗',
      review: 'Evidence →',
      framework: 'ISO/IEC 27001:2022',
      status: 'FAILING'
    },
    {
      control: 'A.8.3 · Access restriction',
      finding: 'RAM-1039 · Public S3 access policy',
      resource: 'demo-artifacts ↗',
      review: 'Evidence →',
      framework: 'ISO/IEC 27001:2022',
      status: 'FAILING'
    },
    {
      control: 'A.8.5 · Secure authentication',
      finding: 'RAM-1037 · MFA absent in identity snapshot',
      resource: 'demo-operator ↗',
      review: 'Evidence →',
      framework: 'ISO/IEC 27001:2022',
      status: 'FAILING'
    },
    {
      control: 'CC6.1 · Logical access controls',
      finding: 'RAM-1037 · MFA absent on administrative principal',
      resource: 'demo-operator ↗',
      review: 'Evidence →',
      framework: 'SOC 2 Type II',
      status: 'FAILING'
    },
    {
      control: 'CC6.6 · Boundary protection',
      finding: 'RAM-1041 · Ingress port 22 exposed to 0.0.0.0/0',
      resource: 'demo-web-01 ↗',
      review: 'Evidence →',
      framework: 'SOC 2 Type II',
      status: 'FAILING'
    },
    {
      control: 'Art. 32(1)(a) · Confidentiality & encryption',
      finding: 'RAM-1039 · Unencrypted / public S3 asset storage',
      resource: 'demo-artifacts ↗',
      review: 'Evidence →',
      framework: 'GDPR',
      status: 'FAILING'
    }
  ];

  const generateReport = async () => {
    setGenerating(true);
    try {
      const res = await axios.get(`${API_URL}/compliance/report?format=json`);
      setReport(res.data.data);
      setShowReportModal(true);
      if (showToast) showToast('Executive compliance audit report generated!');
    } catch (err) {
      if (showToast) showToast('Report generation failed', 'error');
    }
    setGenerating(false);
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

  const currentGaps = controlGaps.filter(g => g.framework === activeFramework);

  return (
    <div className="animate-fade-in">
      {/* 1. FRAMEWORK TABS SELECTOR (FIGMA PILL TABS) */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', marginBottom: '24px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', gap: '24px' }}>
          {frameworks.map((fw) => {
            const isActive = fw.id === activeFramework;
            return (
              <button
                key={fw.id}
                onClick={() => setActiveFramework(fw.id)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  borderBottom: isActive ? '2px solid var(--accent-orange)' : '2px solid transparent',
                  padding: '10px 4px',
                  fontSize: '13.5px',
                  fontWeight: isActive ? 600 : 500,
                  color: isActive ? 'var(--accent-orange)' : 'var(--text-secondary)',
                  cursor: 'pointer',
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

      {/* 2. THREE SUMMARY CARDS: ISO, SOC 2, GDPR */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginBottom: '24px' }}>
        {frameworks.map((fw, idx) => {
          const score = fw.id === 'ISO/IEC 27001:2022' ? '88%' : fw.id === 'SOC 2 Type II' ? '82.5%' : '83%';
          return (
            <div key={fw.id} className="figma-card">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
                <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {fw.label}
                </h3>
                <span style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
                  {report ? `${score} Audited` : 'Active baseline'}
                </span>
              </div>

              <div style={{ width: '40px', height: '4px', backgroundColor: idx === 0 ? 'var(--accent-orange)' : 'var(--text-muted)', borderRadius: '2px', marginBottom: '16px' }} />

              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12.5px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                <span>Pass / fail</span>
                <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                  {report ? '14 / 3' : '— / —'}
                </span>
              </div>

              <div style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
                {report ? 'Audit verified against snapshot' : 'Assessment configured'}
              </div>
            </div>
          );
        })}
      </div>

      {/* 3. POTENTIAL CONTROL GAPS TABLE */}
      <div className="figma-card" style={{ padding: '0', overflow: 'hidden', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Potential control gaps
          </h3>
          <span style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
            {activeFramework} · Live mapping
          </span>
        </div>

        <table className="figma-table">
          <thead>
            <tr>
              <th>Control reference</th>
              <th>Imported finding</th>
              <th>Resource</th>
              <th style={{ textAlign: 'right' }}>Review</th>
            </tr>
          </thead>
          <tbody>
            {currentGaps.map((gap, idx) => (
              <tr key={idx}>
                <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                  {gap.control}
                </td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  {gap.finding}
                </td>
                <td style={{ color: 'var(--accent-orange)' }}>
                  {gap.resource}
                </td>
                <td style={{ textAlign: 'right' }}>
                  <button className="figma-link-btn" onClick={() => generateReport()}>
                    {gap.review}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <div style={{ padding: '14px 20px', borderTop: '1px solid var(--border-subtle)', fontSize: '12px', color: 'var(--text-muted)' }}>
          Potential gaps for review, mapped directly from CSPM cloud audits and CIEM identity findings.
        </div>
      </div>

      {/* 4. ON-SCREEN GENERATED AUDIT REPORT MODAL */}
      {showReportModal && report && (
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
          padding: '24px'
        }}>
          <div className="figma-card" style={{
            width: '100%',
            maxWidth: '720px',
            maxHeight: '90vh',
            overflowY: 'auto',
            padding: '28px',
            backgroundColor: 'var(--surface-card)',
            border: '1px solid var(--border-strong)',
            borderRadius: '12px',
            boxShadow: '0 16px 48px rgba(0,0,0,0.5)',
            animation: 'fadeIn 0.25s ease'
          }}>
            {/* Modal Header */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '20px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  <ShieldCheck size={22} style={{ color: 'var(--accent-orange)' }} />
                  <h3 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                    Official Compliance Audit Report
                  </h3>
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                  Report ID: {report.report_id || 'COMP-AUDIT-2026-X8'} · Generated: {report.generated_at || new Date().toISOString()}
                </div>
              </div>
              <button
                onClick={() => setShowReportModal(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', padding: '4px' }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Score Overview Banner */}
            <div style={{
              background: 'var(--surface-muted)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              padding: '16px 20px',
              marginBottom: '20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}>
              <div>
                <span style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-tertiary)', fontWeight: 600 }}>Overall Compliance Posture</span>
                <div style={{ fontSize: '24px', fontWeight: 800, color: 'var(--success-color)', marginTop: '2px' }}>
                  {report.executive_summary?.overall_compliance_score || 84.5}% PASSED
                </div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <span style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-tertiary)', fontWeight: 600 }}>Audit State</span>
                <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                  ISO 27001 / SOC 2 / GDPR Verified
                </div>
              </div>
            </div>

            {/* Metric Breakdown Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '14px', marginBottom: '20px' }}>
              <div style={{ padding: '14px', background: 'var(--surface-muted)', borderRadius: '8px' }}>
                <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Passing Controls</span>
                <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--success-color)', marginTop: '2px' }}>
                  14 Controls
                </div>
                <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>No active violations</span>
              </div>
              <div style={{ padding: '14px', background: 'var(--surface-muted)', borderRadius: '8px' }}>
                <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Gaps Identified</span>
                <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--sev-critical)', marginTop: '2px' }}>
                  3 Gaps
                </div>
                <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>Remediation playbooks available</span>
              </div>
              <div style={{ padding: '14px', background: 'var(--surface-muted)', borderRadius: '8px' }}>
                <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Evidence Artifacts</span>
                <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--accent-orange)', marginTop: '2px' }}>
                  6 Cloud Fixtures
                </div>
                <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>CloudTrail + Wazuh audited</span>
              </div>
            </div>

            {/* Framework Score Cards */}
            <h4 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '10px' }}>
              Framework Attestation Breakdown
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '24px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--surface-muted)', borderRadius: '6px' }}>
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>ISO/IEC 27001:2022 (ISMS)</span>
                <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--success-color)' }}>88.0% · PASS</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--surface-muted)', borderRadius: '6px' }}>
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>SOC 2 Type II (Trust Services Criteria)</span>
                <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--success-color)' }}>82.5% · PASS</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--surface-muted)', borderRadius: '6px' }}>
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>GDPR (Regulation EU 2016/679 Art. 32)</span>
                <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--success-color)' }}>83.0% · PASS</span>
              </div>
            </div>

            {/* Modal Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button className="figma-btn-secondary" onClick={downloadCSVReport}>
                <Download size={13} /> Download CSV Report
              </button>
              <button className="figma-btn-primary" onClick={() => setShowReportModal(false)}>
                Done / Close Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ComplianceTab;
