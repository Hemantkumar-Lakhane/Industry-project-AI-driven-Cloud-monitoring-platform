import React from 'react';
import { Settings, Users, Check, Wrench } from 'lucide-react';

export const ConfigFixesSection = ({
  healedConfigs = new Set(),
  revokedEntities = new Set(),
  onAutoFixConfig,
  onRevokeAccess
}) => {
  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
      gap: '20px',
      marginTop: '24px',
      boxSizing: 'border-box'
    }}>
      {/* CSPM Configuration Auto-Fixes */}
      <div className="figma-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Settings size={15} style={{ color: 'var(--text-secondary)' }} />
            Cloud Infrastructure Auto-Fixes (CSPM)
          </h3>
          <span style={{ fontSize: '11.5px', color: 'var(--text-tertiary)' }}>1-Click Security Corrections</span>
        </div>

        <table className="figma-table">
          <tbody>
            <tr>
              <td>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>Close public SSH port 22 on production server</div>
                <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '2px' }}>Target: <code>prod-web-01 &bull; sg-0a1b2c3d</code></div>
              </td>
              <td style={{ textAlign: 'right' }}>
                {healedConfigs.has('VULN-001') ? (
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--success-color)', background: 'var(--success-bg)', padding: '4px 10px', borderRadius: '6px' }}>
                    <Check size={12} /> Closed & Secured
                  </span>
                ) : (
                  <button className="figma-btn-secondary" style={{ padding: '5px 12px', fontSize: '12px' }} onClick={() => onAutoFixConfig('VULN-001')}>
                    <Wrench size={12} /> Auto-Fix
                  </button>
                )}
              </td>
            </tr>
            <tr>
              <td>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>Enable S3 Default Server-Side Encryption (KMS)</div>
                <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '2px' }}>Target: <code>customer-financial-records-bucket</code></div>
              </td>
              <td style={{ textAlign: 'right' }}>
                {healedConfigs.has('VULN-002') ? (
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--success-color)', background: 'var(--success-bg)', padding: '4px 10px', borderRadius: '6px' }}>
                    <Check size={12} /> Encrypted & Secured
                  </span>
                ) : (
                  <button className="figma-btn-secondary" style={{ padding: '5px 12px', fontSize: '12px' }} onClick={() => onAutoFixConfig('VULN-002')}>
                    <Wrench size={12} /> Auto-Fix
                  </button>
                )}
              </td>
            </tr>
            <tr>
              <td>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>Restrict Security Group 0.0.0.0/0 Outbound Rules</div>
                <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '2px' }}>Target: <code>sg-db-private-cluster</code></div>
              </td>
              <td style={{ textAlign: 'right' }}>
                {healedConfigs.has('VULN-003') ? (
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--success-color)', background: 'var(--success-bg)', padding: '4px 10px', borderRadius: '6px' }}>
                    <Check size={12} /> Restricted
                  </span>
                ) : (
                  <button className="figma-btn-secondary" style={{ padding: '5px 12px', fontSize: '12px' }} onClick={() => onAutoFixConfig('VULN-003')}>
                    <Wrench size={12} /> Auto-Fix
                  </button>
                )}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* CIEM Identity Access Controls */}
      <div className="figma-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Users size={15} style={{ color: 'var(--text-secondary)' }} />
            Identity Access Revocation (CIEM)
          </h3>
          <span style={{ fontSize: '11.5px', color: 'var(--text-tertiary)' }}>Least-Privilege Enforcement</span>
        </div>

        <table className="figma-table">
          <tbody>
            <tr>
              <td>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>Revoke unused AdministratorAccess policy from deploy-bot</div>
                <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '2px' }}>Principal: <code>deploy-bot &bull; IAM User &bull; 90+ days inactive</code></div>
              </td>
              <td style={{ textAlign: 'right' }}>
                {revokedEntities.has('deploy-bot') ? (
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--success-color)', background: 'var(--success-bg)', padding: '4px 10px', borderRadius: '6px' }}>
                    <Check size={12} /> Privileges Revoked
                  </span>
                ) : (
                  <button className="figma-btn-secondary" style={{ padding: '5px 12px', fontSize: '12px' }} onClick={() => onRevokeAccess('deploy-bot', 'user', 'critical')}>
                    Revoke Access
                  </button>
                )}
              </td>
            </tr>
            <tr>
              <td>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>Enforce Hardware MFA challenge on intern-alice</div>
                <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '2px' }}>Principal: <code>intern-alice &bull; Cloud Console Access</code></div>
              </td>
              <td style={{ textAlign: 'right' }}>
                {revokedEntities.has('intern-alice') ? (
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--success-color)', background: 'var(--success-bg)', padding: '4px 10px', borderRadius: '6px' }}>
                    <Check size={12} /> MFA Enforced
                  </span>
                ) : (
                  <button className="figma-btn-secondary" style={{ padding: '5px 12px', fontSize: '12px' }} onClick={() => onRevokeAccess('intern-alice', 'user', 'high')}>
                    Enforce MFA
                  </button>
                )}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ConfigFixesSection;
