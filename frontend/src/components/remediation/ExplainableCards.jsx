import React from 'react';
import { HelpCircle, AlertOctagon, ListOrdered } from 'lucide-react';

export const ExplainableCards = ({ explainable }) => {
  if (!explainable) return null;

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
      gap: '16px',
      marginBottom: '22px',
      width: '100%',
      boxSizing: 'border-box'
    }}>
      {/* CARD 1: What is this attack? */}
      <div style={{
        padding: '16px',
        borderRadius: '8px',
        backgroundColor: 'var(--surface-muted)',
        border: '1px solid var(--border-subtle)',
        display: 'flex',
        flexDirection: 'column',
        boxSizing: 'border-box'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
          <div style={{
            width: '24px',
            height: '24px',
            borderRadius: '6px',
            backgroundColor: 'rgba(217, 45, 32, 0.12)',
            color: 'var(--sev-critical)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontWeight: 700,
            fontSize: '12px'
          }}>
            1
          </div>
          <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
            1. What is this attack?
          </h4>
        </div>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0, flex: 1 }}>
          {explainable.whatIsAttack}
        </p>
        <div style={{ marginTop: '12px', paddingTop: '8px', borderTop: '1px solid var(--border-subtle)', fontSize: '11.5px', color: 'var(--text-tertiary)' }}>
          Category: <strong style={{ color: 'var(--text-primary)' }}>{explainable.categoryLabel}</strong>
        </div>
      </div>

      {/* CARD 2: Real Root Cause Analysis */}
      <div style={{
        padding: '16px',
        borderRadius: '8px',
        backgroundColor: 'var(--surface-muted)',
        border: '1px solid var(--border-subtle)',
        display: 'flex',
        flexDirection: 'column',
        boxSizing: 'border-box'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
          <div style={{
            width: '24px',
            height: '24px',
            borderRadius: '6px',
            backgroundColor: 'rgba(240, 106, 26, 0.12)',
            color: 'var(--accent-orange)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontWeight: 700,
            fontSize: '12px'
          }}>
            2
          </div>
          <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
            2. Real Root Cause Analysis
          </h4>
        </div>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0, flex: 1 }}>
          {explainable.trueRootCause}
        </p>
        <div style={{ marginTop: '12px', paddingTop: '8px', borderTop: '1px solid var(--border-subtle)', fontSize: '11.5px', color: 'var(--text-tertiary)' }}>
          Tactic: <strong style={{ color: 'var(--accent-orange)' }}>{explainable.mitreTactic}</strong>
        </div>
      </div>

      {/* CARD 3: Automated Response Plan */}
      <div style={{
        padding: '16px',
        borderRadius: '8px',
        backgroundColor: 'var(--surface-muted)',
        border: '1px solid var(--border-subtle)',
        display: 'flex',
        flexDirection: 'column',
        boxSizing: 'border-box'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
          <div style={{
            width: '24px',
            height: '24px',
            borderRadius: '6px',
            backgroundColor: 'rgba(16, 185, 129, 0.12)',
            color: 'var(--success-color)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontWeight: 700,
            fontSize: '12px'
          }}>
            3
          </div>
          <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
            3. Automated Containment Steps
          </h4>
        </div>
        <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.55, flex: 1 }}>
          {(explainable.containmentSteps || []).map((step, idx) => (
            <li key={idx} style={{ marginBottom: '8px' }}>
              {step}
            </li>
          ))}
        </ul>
        <div style={{ marginTop: '12px', paddingTop: '8px', borderTop: '1px solid var(--border-subtle)', fontSize: '11.5px', color: 'var(--text-tertiary)' }}>
          Safety: <strong style={{ color: 'var(--success-color)' }}>Zero Service Downtime</strong>
        </div>
      </div>
    </div>
  );
};

export default ExplainableCards;

