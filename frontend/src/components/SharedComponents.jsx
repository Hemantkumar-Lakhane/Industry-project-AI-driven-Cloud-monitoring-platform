import React, { useEffect } from 'react';
import { CheckCircle, XCircle, X } from 'lucide-react';
import logoUrl from '../assets/LOGO.png';

export const Badge = ({ children, level }) => {
  const cn = `badge badge-${(level || 'low').toLowerCase()}`;
  return <span className={cn}>{children}</span>;
};

export const BrandMark = ({ size = 44, compact = false }) => (
  <div className="brand-mark" style={{ width: size, height: size, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
    <img
      src={logoUrl}
      alt={compact ? 'Ram Antivirus logo' : 'Ram Antivirus'}
      style={{ width: '100%', height: '100%', objectFit: 'contain', filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.15))' }}
    />
  </div>
);

export const SectionHeader = ({ icon: Icon, title, subtitle, actions }) => (
  <div className="section-header">
    <div className="section-heading">
      {Icon && <Icon size={18} className="section-heading-icon" />}
      <div>
        <h2>{title}</h2>
        {subtitle && <p>{subtitle}</p>}
      </div>
    </div>
    {actions && <div className="section-actions">{actions}</div>}
  </div>
);

export const MetricCard = ({ icon: Icon, label, value, tone = 'default', detail }) => (
  <div className={`metric-card metric-${tone}`}>
    <div className="metric-icon">{Icon && <Icon size={18} />}</div>
    <div>
      <span className="metric-label">{label}</span>
      <strong className="metric-value">{value}</strong>
      {detail && <span className="metric-detail">{detail}</span>}
    </div>
  </div>
);

export const ScoreRing = ({ score, size = 120, color, label }) => {
  const strokeWidth = 8;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const ringColor = color || (score >= 90 ? '#10b981' : score >= 70 ? '#eab308' : '#ef4444');
  return (
    <div className="score-ring-container">
      <div className="score-ring" style={{ width: size, height: size }}>
        <svg width={size} height={size}>
          <circle className="score-ring-bg" cx={size / 2} cy={size / 2} r={radius} />
          <circle className="score-ring-fill" cx={size / 2} cy={size / 2} r={radius}
            stroke={ringColor} strokeDasharray={circumference} strokeDashoffset={offset} />
        </svg>
        <span className="score-ring-value" style={{ color: ringColor }}>{score}%</span>
      </div>
      {label && <span className="score-ring-label">{label}</span>}
    </div>
  );
};

export const Toast = ({ message, type = 'success', onClose }) => {
  useEffect(() => {
    const timer = setTimeout(onClose, 3200);
    return () => clearTimeout(timer);
  }, [onClose]);
  return (
    <div className={`toast toast-${type}`} role="alert">
      <div className="toast-icon">
        {type === 'success' ? (
          <CheckCircle size={15} color="#10b981" />
        ) : (
          <XCircle size={15} color="#ef4444" />
        )}
      </div>
      <div className="toast-content">
        <span className="toast-message">{message}</span>
      </div>
      {onClose && (
        <button
          type="button"
          className="toast-close-btn"
          onClick={onClose}
          aria-label="Dismiss notification"
          title="Dismiss"
        >
          <X size={13} />
        </button>
      )}
    </div>
  );
};

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('ErrorBoundary caught error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '24px', background: 'var(--surface-card)', borderRadius: '12px', border: '1px solid var(--sev-crit, #ef4444)', margin: '20px 0' }}>
          <h3 style={{ color: 'var(--sev-crit, #ef4444)', margin: '0 0 8px 0', fontSize: '16px' }}>Component Error Recovered</h3>
          <p style={{ color: 'var(--text-secondary, #94a3b8)', fontSize: '13px', margin: '0 0 12px 0' }}>
            {this.state.error?.message || 'An unexpected rendering error occurred in this section.'}
          </p>
          <button
            className="figma-btn-primary"
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{ fontSize: '12px', padding: '6px 14px', cursor: 'pointer' }}
          >
            Retry Section
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}


export const Pagination = ({
  currentPage = 1,
  totalItems = 0,
  pageSize = 10,
  onPageChange,
  itemLabel = 'items'
}) => {
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  if (totalItems <= 0) return null;

  const startIdx = (currentPage - 1) * pageSize + 1;
  const endIdx = Math.min(currentPage * pageSize, totalItems);

  const getPageNumbers = () => {
    const pages = [];
    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
      pages.push(1);
      if (currentPage > 3) pages.push('...');
      const start = Math.max(2, currentPage - 1);
      const end = Math.min(totalPages - 1, currentPage + 1);
      for (let i = start; i <= end; i++) {
        if (!pages.includes(i)) pages.push(i);
      }
      if (currentPage < totalPages - 2) pages.push('...');
      if (!pages.includes(totalPages)) pages.push(totalPages);
    }
    return pages;
  };

  return (
    <div className="figma-pagination-container">
      <div className="figma-pagination-info">
        Showing <strong>{startIdx}</strong>–<strong>{endIdx}</strong> of <strong>{totalItems}</strong> {itemLabel}
      </div>
      <div className="figma-pagination-actions">
        <button
          type="button"
          className="figma-page-btn"
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage <= 1}
          aria-label="Previous page"
        >
          Previous
        </button>
        {getPageNumbers().map((page, idx) => (
          page === '...' ? (
            <span key={`ellipsis-${idx}`} style={{ padding: '0 4px', color: 'var(--text-secondary)' }}>…</span>
          ) : (
            <button
              key={page}
              type="button"
              className={`figma-page-btn ${currentPage === page ? 'active' : ''}`}
              onClick={() => onPageChange(page)}
            >
              {page}
            </button>
          )
        ))}
        <button
          type="button"
          className="figma-page-btn"
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage >= totalPages}
          aria-label="Next page"
        >
          Next
        </button>
      </div>
    </div>
  );
};
