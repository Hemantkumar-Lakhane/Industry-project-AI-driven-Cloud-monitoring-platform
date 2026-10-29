import React from 'react';
import { AlertTriangle, Check, ShieldAlert } from 'lucide-react';

export const IncidentSelector = ({
  incidents = [],
  selectedIncidentId,
  onSelectIncident,
  healedIncidents = new Set()
}) => {
  return (
    <div style={{ marginBottom: '20px', width: '100%', minWidth: 0, maxWidth: '100%', boxSizing: 'border-box' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
        <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          Active Threat Incidents ({incidents.length})
        </span>
        <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
          Click any incident to inspect root cause & remediate
        </span>
      </div>

      <div
        style={{
          display: 'flex',
          gap: '12px',
          overflowX: 'auto',
          paddingBottom: '10px',
          width: '100%',
          minWidth: 0,
          maxWidth: '100%',
          WebkitOverflowScrolling: 'touch',
          boxSizing: 'border-box'
        }}
      >
        {incidents.map((inc) => {
          const isSelected = inc.id === selectedIncidentId;
          const incHealed = healedIncidents.has(inc.id);
          const sev = (inc.severity || 'high').toLowerCase();

          return (
            <div
              key={inc.id}
              onClick={() => onSelectIncident(inc.id)}
              style={{
                flex: '0 0 280px',
                padding: '12px 14px',
                borderRadius: '8px',
                backgroundColor: isSelected ? 'var(--surface-card)' : 'var(--surface-muted)',
                border: isSelected
                  ? '2px solid var(--accent-orange)'
                  : incHealed
                  ? '1px solid var(--success-color)'
                  : '1px solid var(--border-subtle)',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
                boxShadow: isSelected ? '0 2px 8px rgba(240, 106, 26, 0.18)' : 'none',
                boxSizing: 'border-box'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span className={`figma-dot-badge ${sev}`}>
                  {sev.toUpperCase()}
                </span>
                {incHealed ? (
                  <span style={{ fontSize: '10.5px', fontWeight: 600, color: 'var(--success-color)', display: 'flex', alignItems: 'center', gap: '3px' }}>
                    <Check size={11} /> Secured
                  </span>
                ) : (
                  <span style={{ fontSize: '10.5px', fontWeight: 600, color: 'var(--sev-critical)' }}>
                    Action needed
                  </span>
                )}
              </div>

              <div style={{ fontSize: '12.5px', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {inc.name || inc.title}
              </div>

              <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>Target: <code>{inc.target || 'Workload'}</code></span>
                <span style={{ fontWeight: 600, color: 'var(--accent-orange)' }}>
                  {inc.isLive ? 'LIVE' : 'DEMO'}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default IncidentSelector;

