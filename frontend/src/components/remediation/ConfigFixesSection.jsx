import React from 'react';
import { Settings, Users, Check, Wrench, ShieldCheck } from 'lucide-react';

export const ConfigFixesSection = ({
  cspmFindings = [],
  ciemFindings = [],
  healedConfigs = new Set(),
  revokedEntities = new Set(),
  onAutoFixConfig,
  onRevokeAccess
}) => {
  // If no findings at all, render clean empty posture card
  if (cspmFindings.length === 0 && ciemFindings.length === 0) {
    return (
      <div className="figma-card" style={{ marginTop: '24px', padding: '24px', textAlign: 'center', boxSizing: 'border-box' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: '40px', height: '40px', borderRadius: '50%', backgroundColor: 'var(--surface-muted)', marginBottom: '10px' }}>
          <ShieldCheck size={20} style={{ color: 'var(--success-color, #10b981)' }} />
        </div>
        <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 6px 0' }}>
          Zero Infrastructure & Identity Misconfigurations
        </h4>
        <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', margin: 0 }}>
          No open CSPM misconfigurations or excessive CIEM privileges detected in your cloud environment.
        </p>
      </div>
    );
  }

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

        {cspmFindings.length === 0 ? (
          <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '13px' }}>
            No open infrastructure posture misconfigurations.
          </div>
        ) : (
          <table className="figma-table">
            <tbody>
              {cspmFindings.slice(0, 5).map((f) => {
                const fid = f.finding_id || f.scan_id || f.id || 'CSPM-FIX';
                const isFixed = healedConfigs.has(fid);
                return (
                  <tr key={fid}>
                    <td>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>{f.title}</div>
                      <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '2px' }}>
                        Target: <code>{f.affected_resource || f.resource || 'AWS Resource'}</code>
                      </div>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {isFixed ? (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--success-color)', background: 'var(--success-bg)', padding: '4px 10px', borderRadius: '6px' }}>
                          <Check size={12} /> Corrected
                        </span>
                      ) : (
                        <button className="figma-btn-secondary" style={{ padding: '5px 12px', fontSize: '12px' }} onClick={() => onAutoFixConfig(fid)}>
                          <Wrench size={12} /> Auto-Fix
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
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

        {ciemFindings.length === 0 ? (
          <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '13px' }}>
            No excessive privilege risks or missing MFA policies detected.
          </div>
        ) : (
          <table className="figma-table">
            <tbody>
              {ciemFindings.slice(0, 5).map((f) => {
                const eid = f.affected_principal || f.entity_name || f.finding_id || 'CIEM-FIX';
                const isRevoked = revokedEntities.has(eid);
                return (
                  <tr key={eid}>
                    <td>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>{f.title || `Restrict access for ${eid}`}</div>
                      <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '2px' }}>
                        Principal: <code>{eid} &bull; {f.affected_resource || 'IAM Principal'}</code>
                      </div>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {isRevoked ? (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--success-color)', background: 'var(--success-bg)', padding: '4px 10px', borderRadius: '6px' }}>
                          <Check size={12} /> Access Restricted
                        </span>
                      ) : (
                        <button className="figma-btn-secondary" style={{ padding: '5px 12px', fontSize: '12px' }} onClick={() => onRevokeAccess(eid, 'user', f.severity || 'high')}>
                          Revoke Access
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default ConfigFixesSection;
