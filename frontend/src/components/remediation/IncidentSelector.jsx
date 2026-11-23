import React, { useRef } from 'react';
import { AlertTriangle, Check, ShieldAlert, Radio, ChevronLeft, ChevronRight } from 'lucide-react';

export const IncidentSelector = ({
  incidents = [],
  selectedIncidentId,
  onSelectIncident,
  healedIncidents = new Set()
}) => {
  const scrollContainerRef = useRef(null);

  const scroll = (direction) => {
    if (scrollContainerRef.current) {
      const scrollAmount = 310;
      scrollContainerRef.current.scrollBy({
        left: direction === 'left' ? -scrollAmount : scrollAmount,
        behavior: 'smooth'
      });
    }
  };

  return (
    <div
      className="figma-card"
      style={{
        marginBottom: '20px',
        padding: '16px 20px',
        width: '100%',
        minWidth: 0,
        maxWidth: '100%',
        boxSizing: 'border-box'
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.6px' }}>
            Active Threat Incidents ({incidents.length})
          </span>
          <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
            Select an incident to inspect root cause & trigger containment
          </span>
        </div>

        {incidents.length > 2 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <button
              type="button"
              onClick={() => scroll('left')}
              className="figma-btn-secondary"
              style={{
                padding: '4px 7px',
                borderRadius: '6px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: 'none'
              }}
              title="Scroll left"
              aria-label="Previous incidents"
            >
              <ChevronLeft size={14} />
            </button>
            <button
              type="button"
              onClick={() => scroll('right')}
              className="figma-btn-secondary"
              style={{
                padding: '4px 7px',
                borderRadius: '6px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: 'none'
              }}
              title="Scroll right"
              aria-label="Next incidents"
            >
              <ChevronRight size={14} />
            </button>
          </div>
        )}
      </div>

      <div
        ref={scrollContainerRef}
        onWheel={(e) => {
          if (e.deltaY !== 0 && scrollContainerRef.current) {
            scrollContainerRef.current.scrollLeft += e.deltaY;
          }
        }}
        style={{
          display: 'flex',
          gap: '12px',
          overflowX: 'auto',
          padding: '4px 2px 10px 2px',
          width: '100%',
          minWidth: 0,
          maxWidth: '100%',
          WebkitOverflowScrolling: 'touch',
          boxSizing: 'border-box',
          scrollbarWidth: 'thin',
          scrollbarColor: 'var(--border-subtle) transparent'
        }}
      >
        {incidents.map((inc) => {
          const isSelected = inc.id === selectedIncidentId;
          const incHealed = healedIncidents.has(inc.id);
          const sev = (inc.severity || 'high').toLowerCase();

          return (
            <div
              key={inc.id}
              role="button"
              tabIndex={0}
              onClick={() => onSelectIncident && onSelectIncident(inc.id)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  onSelectIncident && onSelectIncident(inc.id);
                }
              }}
              style={{
                flex: '0 0 295px',
                padding: '13px 15px',
                borderRadius: '8px',
                backgroundColor: isSelected ? 'var(--surface-card)' : 'var(--surface-muted)',
                border: isSelected
                  ? '1px solid var(--accent-orange)'
                  : incHealed
                  ? '1px solid var(--success-color)'
                  : '1px solid var(--border-subtle)',
                boxShadow: isSelected
                  ? '0 0 0 1px var(--accent-orange), 0 2px 8px rgba(240, 106, 26, 0.16)'
                  : 'var(--shadow-xs)',
                cursor: 'pointer',
                transition: 'background-color 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
                boxSizing: 'border-box',
                userSelect: 'none'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span className={`figma-dot-badge ${sev}`}>
                    {sev.toUpperCase()}
                  </span>
                  {isSelected && (
                    <span style={{ fontSize: '10px', fontWeight: 700, color: 'var(--accent-orange)', letterSpacing: '0.4px', textTransform: 'uppercase' }}>
                      Selected
                    </span>
                  )}
                </div>
                {incHealed ? (
                  <span style={{ fontSize: '10.5px', fontWeight: 600, color: 'var(--success-color)', display: 'flex', alignItems: 'center', gap: '3px' }}>
                    <Check size={11} /> Secured
                  </span>
                ) : (
                  <span style={{ fontSize: '10.5px', fontWeight: 600, color: isSelected ? 'var(--accent-orange)' : 'var(--sev-critical)' }}>
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
                  {inc.isLive ? 'LIVE' : 'ACTIVE'}
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
