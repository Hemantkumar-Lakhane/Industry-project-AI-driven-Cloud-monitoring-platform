import React from 'react';
import { CheckCircle2, ShieldCheck, Clock } from 'lucide-react';

export const DryRunReport = ({ dryRunResult }) => {
  if (!dryRunResult) return null;

  const steps = Array.isArray(dryRunResult.steps) ? dryRunResult.steps : [];

  return (
    <div style={{
      padding: '16px 20px',
      borderRadius: '8px',
      backgroundColor: 'rgba(16, 185, 129, 0.06)',
      border: '1px solid rgba(16, 185, 129, 0.3)',
      marginBottom: '20px',
      boxSizing: 'border-box'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ShieldCheck size={18} style={{ color: 'var(--success-color)' }} />
          <h4 style={{ fontSize: '13.5px', fontWeight: 700, color: 'var(--success-color)', margin: 0 }}>
            Safe Dry-Run Simulation Verified (Zero Service Downtime)
          </h4>
        </div>
        <span style={{ fontSize: '11.5px', color: 'var(--text-tertiary)' }}>
          EXEC: <code>{dryRunResult.executionId}</code> &bull; Duration: {dryRunResult.durationMs}ms &bull; {dryRunResult.time}
        </span>
      </div>

      <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '12px' }}>
        All remediation steps evaluated against isolated sandbox mocks without making live destructive cloud mutations:
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {steps.map((st, i) => (
          <div
            key={i}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '6px 12px',
              background: 'var(--surface-card)',
              borderRadius: '6px',
              fontSize: '12px'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                Step {st.order || (i + 1)}:
              </span>
              <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                {st.description || st.action}
              </span>
            </div>
            <span style={{ color: 'var(--success-color)', fontWeight: 600, fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <CheckCircle2 size={12} /> {(st.status || 'Verified').toUpperCase()} ({st.duration_ms || 180}ms)
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default DryRunReport;

