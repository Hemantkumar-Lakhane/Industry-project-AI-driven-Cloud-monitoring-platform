import React from 'react';
import { FileText, Info } from 'lucide-react';

export const RemediationAuditTrail = ({ auditLogs = [] }) => {
  return (
    <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '16px', marginTop: '16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
        <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.5px', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <FileText size={13} /> Remediation Audit Trail & Operator History
        </span>
        <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
          Logged to immutable local sandbox ledger
        </span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '140px', overflowY: 'auto' }}>
        {auditLogs.map((log) => (
          <div key={log.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 10px', background: 'var(--surface-muted)', borderRadius: '6px', fontSize: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>{log.time}</span>
              <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{log.action}</span>
              <span style={{ color: 'var(--text-tertiary)', fontSize: '11px' }}>({log.target})</span>
            </div>
            <span style={{ color: 'var(--success-color)', fontSize: '11px', fontWeight: 600 }}>{log.status}</span>
          </div>
        ))}
      </div>

      <div style={{ marginTop: '14px', fontSize: '12px', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
        <Info size={13} />
        <span>Operational Boundary: When live cloud credentials are not configured, remediation actions and rollbacks execute against the local state engine with full fidelity.</span>
      </div>
    </div>
  );
};

export default RemediationAuditTrail;

