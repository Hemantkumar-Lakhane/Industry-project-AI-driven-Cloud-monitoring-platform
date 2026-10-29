import React from 'react';
import { Shield, Key, Lock, CheckCircle2, Search, Wrench, RotateCcw, AlertCircle } from 'lucide-react';

export const HumanActionCenter = ({
  explainable,
  isHealed,
  currentExecId,
  executing,
  onDryRun,
  onAutoRemediate,
  onRollback,
  onExecuteGranularAction,
  granularState = {}
}) => {
  return (
    <div style={{
      marginBottom: '20px',
      padding: '16px 20px',
      borderRadius: '8px',
      backgroundColor: 'var(--surface-muted)',
      border: '1px solid var(--border-subtle)',
      boxSizing: 'border-box'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', flexWrap: 'wrap', gap: '10px' }}>
        <div>
          <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Shield size={14} style={{ color: 'var(--accent-orange)' }} />
            Human-in-the-Loop Granular Actions
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Take precision actions individually or apply the entire validated remediation playbook.
          </div>
        </div>

        {/* TOP WORKFLOW BUTTONS: DRY RUN & AUTO REMEDIATE */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <button
            className="figma-btn-secondary"
            onClick={onDryRun}
            disabled={executing}
            title="Simulate step-by-step remediation safely in sandbox with zero downtime"
          >
            <Search size={13} />
            {executing ? 'Simulating...' : 'Test Fix (Dry Run)'}
          </button>

          {(currentExecId || isHealed) && (
            <button
              className="figma-btn-secondary"
              onClick={onRollback}
              disabled={executing}
              title="Rollback remediation and restore pre-attack state"
              style={{ borderColor: 'var(--accent-orange)', color: 'var(--accent-orange)' }}
            >
              <RotateCcw size={13} className={executing ? 'animate-spin' : ''} />
              Rollback
            </button>
          )}

          {!isHealed ? (
            <button
              className="figma-btn-primary"
              onClick={onAutoRemediate}
              disabled={executing}
              style={{ padding: '8px 18px' }}
              title="Execute full automated remediation playbook"
            >
              <Wrench size={13} className={executing ? 'animate-spin' : ''} />
              {executing ? 'Remediating...' : 'Apply Automated Remediation'}
            </button>
          ) : (
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 14px',
              borderRadius: '6px',
              backgroundColor: 'var(--success-bg)',
              color: 'var(--success-color)',
              fontWeight: 600,
              fontSize: '13px'
            }}>
              <CheckCircle2 size={15} /> Contained & Secured
            </span>
          )}
        </div>
      </div>

      {/* GRANULAR ACTION CHIPS */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '10px',
        marginTop: '12px'
      }}>
        {(explainable?.granularActions || []).map((action) => {
          const isDone = granularState[action.id];
          return (
            <button
              key={action.id}
              onClick={() => onExecuteGranularAction(action)}
              disabled={executing || isDone}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '8px',
                padding: '10px 12px',
                borderRadius: '6px',
                backgroundColor: isDone ? 'rgba(16, 185, 129, 0.1)' : 'var(--surface-card)',
                border: isDone ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid var(--border-subtle)',
                cursor: isDone ? 'default' : 'pointer',
                textAlign: 'left',
                transition: 'all 0.15s ease'
              }}
              className="figma-action-chip"
              title={action.desc}
            >
              <div style={{ marginTop: '2px' }}>
                {isDone ? (
                  <CheckCircle2 size={14} style={{ color: 'var(--success-color)' }} />
                ) : (
                  <Lock size={14} style={{ color: 'var(--accent-orange)' }} />
                )}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: '12px', fontWeight: 600, color: isDone ? 'var(--success-color)' : 'var(--text-primary)' }}>
                  {action.label}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: '2px' }}>
                  {isDone ? 'Action applied successfully' : action.desc}
                </div>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
};

export default HumanActionCenter;

