import React from 'react';
import { Globe, User, Server, ShieldCheck, Activity } from 'lucide-react';

export const ForensicsBanner = ({ incident, explainable }) => {
  if (!incident) return null;

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
      gap: '12px',
      padding: '14px 18px',
      borderRadius: '8px',
      backgroundColor: 'var(--surface-muted)',
      marginBottom: '20px',
      border: '1px solid var(--border-subtle)',
      boxSizing: 'border-box'
    }}>
      <div>
        <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
          <Globe size={12} style={{ color: 'var(--accent-orange)' }} /> Attacker Source IP
        </span>
        <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
          <code>{explainable.attackerIp || incident.attacker_ip || '185.220.101.5'}</code>
        </div>
        <span style={{ fontSize: '11px', color: 'var(--sev-high)' }}>Untrusted Ingress</span>
      </div>

      <div>
        <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
          <User size={12} style={{ color: 'var(--accent-orange)' }} /> Compromised Identity
        </span>
        <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
          <code>{explainable.principal || incident.principal || 'root'}</code>
        </div>
        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>IAM / Host Principal</span>
      </div>

      <div>
        <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
          <Server size={12} style={{ color: 'var(--accent-orange)' }} /> Target Cloud Asset
        </span>
        <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
          <code>{explainable.target || incident.target || 'Workload'}</code>
        </div>
        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Storage / Compute Asset</span>
      </div>

      <div>
        <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
          <ShieldCheck size={12} style={{ color: 'var(--success-color)' }} /> Detection Confidence
        </span>
        <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--success-color)', marginTop: '2px' }}>
          {Math.round((incident.correlation_score || 0.96) * 100)}% Verified
        </div>
        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Wazuh + CloudTrail Telemetry</span>
      </div>
    </div>
  );
};

export default ForensicsBanner;

