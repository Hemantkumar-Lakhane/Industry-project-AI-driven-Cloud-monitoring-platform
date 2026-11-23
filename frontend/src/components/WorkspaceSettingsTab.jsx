import React, { useState } from 'react';
import { Shield, Sun, Moon, Building2, Sliders, CheckCircle2, ShieldCheck, Lock, Activity, Eye, Zap } from 'lucide-react';

const WorkspaceSettingsTab = ({ user, theme, onToggleTheme, showToast }) => {
  const [windowSec, setWindowSec] = useState(60);
  const [failThreshold, setFailThreshold] = useState(5);
  const [anomalyThreshold, setAnomalyThreshold] = useState(70);
  const [safeDryRun, setSafeDryRun] = useState(true);
  const [autoAuditLog, setAutoAuditLog] = useState(true);

  const handleSave = () => {
    if (showToast) showToast('Workspace settings saved successfully', 'success');
  };

  return (
    <div className="animate-fade-in" style={{ maxWidth: '1100px' }}>
      {/* 1. WORKSPACE ORGANIZATION PROFILE */}
      <div className="figma-card" style={{ marginBottom: '24px', padding: '20px 24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div style={{
              width: '46px',
              height: '46px',
              borderRadius: '10px',
              backgroundColor: 'rgba(240, 106, 26, 0.1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-orange)'
            }}>
              <Building2 size={24} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <h3 style={{ fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                  {user?.company_name || 'RAM Security Workspace'}
                </h3>
                <span style={{
                  fontSize: '11px',
                  fontWeight: 600,
                  padding: '2px 8px',
                  borderRadius: '4px',
                  backgroundColor: 'rgba(52, 199, 89, 0.12)',
                  color: 'var(--success-color)'
                }}>
                  ACTIVE & MONITORED
                </span>
              </div>
              <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginTop: '4px', margin: 0 }}>
                Tenant: <code style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{user?.org_id || 'org_main'}</code> · Region: <code style={{ color: 'var(--text-primary)', fontWeight: 600 }}>ap-southeast-2 (Sydney)</code> · User: <code style={{ color: 'var(--text-primary)' }}>{user?.username || 'Security Officer'}</code>
              </p>
            </div>
          </div>

          <button className="figma-btn-primary" onClick={handleSave} style={{ padding: '8px 18px', fontSize: '13px' }}>
            Save changes
          </button>
        </div>
      </div>

      {/* 2. MAIN 2-COLUMN CONFIGURATION GRID */}
      <div className="figma-grid-2col" style={{ gap: '24px' }}>
        {/* Left Column: Detector & Workload Thresholds */}
        <div className="figma-card" style={{ padding: '22px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '18px', paddingBottom: '14px', borderBottom: '1px solid var(--border-subtle)' }}>
            <Sliders size={18} style={{ color: 'var(--accent-orange)' }} />
            <div>
              <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Detection & Sensitivity Thresholds
              </h3>
              <span style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
                Fine-tune continuous inspection parameters across authentication and API streams
              </span>
            </div>
          </div>

          {/* Control 1: Evaluation Window */}
          <div style={{ marginBottom: '22px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <div>
                <label style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Sliding evaluation window
                </label>
                <div style={{ fontSize: '11.5px', color: 'var(--text-tertiary)' }}>
                  Time horizon for aggregating authentication and API telemetry per identity
                </div>
              </div>
              <span style={{
                fontSize: '12px',
                fontWeight: 700,
                color: 'var(--accent-orange)',
                backgroundColor: 'rgba(240, 106, 26, 0.1)',
                padding: '3px 10px',
                borderRadius: '6px'
              }}>
                {windowSec} seconds
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '8px' }}>
              <input
                type="range"
                min="15"
                max="300"
                step="15"
                value={windowSec}
                onChange={(e) => setWindowSec(Number(e.target.value))}
                style={{ flex: 1, accentColor: 'var(--accent-orange)', cursor: 'pointer' }}
              />
              <div style={{ display: 'flex', gap: '6px' }}>
                <button
                  type="button"
                  className="figma-btn-secondary"
                  onClick={() => setWindowSec(Math.max(15, windowSec - 15))}
                  style={{ padding: '2px 8px', fontSize: '12px' }}
                >
                  -
                </button>
                <button
                  type="button"
                  className="figma-btn-secondary"
                  onClick={() => setWindowSec(Math.min(300, windowSec + 15))}
                  style={{ padding: '2px 8px', fontSize: '12px' }}
                >
                  +
                </button>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              <span>15s (Aggressive)</span>
              <span>60s (Recommended)</span>
              <span>300s (Extended)</span>
            </div>
          </div>

          {/* Control 2: Alert Threshold */}
          <div style={{ marginBottom: '22px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <div>
                <label style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Threat alert escalation threshold
                </label>
                <div style={{ fontSize: '11.5px', color: 'var(--text-tertiary)' }}>
                  Minimum anomalous event count required to escalate to high-priority alert
                </div>
              </div>
              <span style={{
                fontSize: '12px',
                fontWeight: 700,
                color: 'var(--accent-orange)',
                backgroundColor: 'rgba(240, 106, 26, 0.1)',
                padding: '3px 10px',
                borderRadius: '6px'
              }}>
                {failThreshold} events
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '8px' }}>
              <input
                type="range"
                min="3"
                max="20"
                step="1"
                value={failThreshold}
                onChange={(e) => setFailThreshold(Number(e.target.value))}
                style={{ flex: 1, accentColor: 'var(--accent-orange)', cursor: 'pointer' }}
              />
              <div style={{ display: 'flex', gap: '6px' }}>
                <button
                  type="button"
                  className="figma-btn-secondary"
                  onClick={() => setFailThreshold(Math.max(3, failThreshold - 1))}
                  style={{ padding: '2px 8px', fontSize: '12px' }}
                >
                  -
                </button>
                <button
                  type="button"
                  className="figma-btn-secondary"
                  onClick={() => setFailThreshold(Math.min(20, failThreshold + 1))}
                  style={{ padding: '2px 8px', fontSize: '12px' }}
                >
                  +
                </button>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              <span>3 events (Strict)</span>
              <span>5 events (Default)</span>
              <span>20 events (High Volume)</span>
            </div>
          </div>

          {/* Control 3: Anomaly Score Cutoff */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <div>
                <label style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Automated containment sensitivity
                </label>
                <div style={{ fontSize: '11.5px', color: 'var(--text-tertiary)' }}>
                  Minimum confidence score to propose automated response playbook
                </div>
              </div>
              <span style={{
                fontSize: '12px',
                fontWeight: 700,
                color: 'var(--accent-orange)',
                backgroundColor: 'rgba(240, 106, 26, 0.1)',
                padding: '3px 10px',
                borderRadius: '6px'
              }}>
                {(anomalyThreshold / 100).toFixed(2)}
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '8px' }}>
              <input
                type="range"
                min="40"
                max="95"
                step="5"
                value={anomalyThreshold}
                onChange={(e) => setAnomalyThreshold(Number(e.target.value))}
                style={{ flex: 1, accentColor: 'var(--accent-orange)', cursor: 'pointer' }}
              />
              <div style={{ display: 'flex', gap: '6px' }}>
                <button
                  type="button"
                  className="figma-btn-secondary"
                  onClick={() => setAnomalyThreshold(Math.max(40, anomalyThreshold - 5))}
                  style={{ padding: '2px 8px', fontSize: '12px' }}
                >
                  -
                </button>
                <button
                  type="button"
                  className="figma-btn-secondary"
                  onClick={() => setAnomalyThreshold(Math.min(95, anomalyThreshold + 5))}
                  style={{ padding: '2px 8px', fontSize: '12px' }}
                >
                  +
                </button>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              <span>0.40 (Sensitive)</span>
              <span>0.70 (Balanced)</span>
              <span>0.95 (High Precision)</span>
            </div>
          </div>
        </div>

        {/* Right Column: Theme & Execution Safeguards */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Appearance Card */}
          <div className="figma-card" style={{ padding: '22px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
              {theme === 'dark' ? <Moon size={18} style={{ color: 'var(--accent-orange)' }} /> : <Sun size={18} style={{ color: 'var(--accent-orange)' }} />}
              <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Appearance & Theme
              </h3>
            </div>
            <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
              Choose your preferred visual console interface styling.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div
                onClick={() => { if (theme !== 'light') onToggleTheme(); }}
                style={{
                  border: theme === 'light' ? '2px solid var(--accent-orange)' : '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  padding: '14px',
                  backgroundColor: theme === 'light' ? 'rgba(240, 106, 26, 0.05)' : 'var(--surface-muted)',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                  transition: 'all 0.15s ease'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)' }}>
                    <Sun size={16} /> Light Theme
                  </div>
                  {theme === 'light' && <CheckCircle2 size={16} style={{ color: 'var(--accent-orange)' }} />}
                </div>
                <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>
                  Clean, high-contrast white & slate interface
                </span>
              </div>

              <div
                onClick={() => { if (theme !== 'dark') onToggleTheme(); }}
                style={{
                  border: theme === 'dark' ? '2px solid var(--accent-orange)' : '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  padding: '14px',
                  backgroundColor: theme === 'dark' ? 'rgba(240, 106, 26, 0.05)' : 'var(--surface-muted)',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                  transition: 'all 0.15s ease'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)' }}>
                    <Moon size={16} /> Dark Theme
                  </div>
                  {theme === 'dark' && <CheckCircle2 size={16} style={{ color: 'var(--accent-orange)' }} />}
                </div>
                <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>
                  Low-glare dark console for SOC workstations
                </span>
              </div>
            </div>
          </div>

          {/* Safety Safeguards Card */}
          <div className="figma-card" style={{ padding: '22px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
              <ShieldCheck size={18} style={{ color: 'var(--accent-orange)' }} />
              <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Response Safeguards & Governance
              </h3>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={safeDryRun}
                  onChange={(e) => setSafeDryRun(e.target.checked)}
                  style={{ accentColor: 'var(--accent-orange)', marginTop: '3px' }}
                />
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    Safe Dry-Run Pre-Execution Simulation
                  </div>
                  <div style={{ fontSize: '11.5px', color: 'var(--text-tertiary)', marginTop: '2px' }}>
                    Simulates all containment playbooks and shows blast-radius diffs before executing changes.
                  </div>
                </div>
              </label>

              <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={autoAuditLog}
                  onChange={(e) => setAutoAuditLog(e.target.checked)}
                  style={{ accentColor: 'var(--accent-orange)', marginTop: '3px' }}
                />
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    Immutable Audit Trail Logging
                  </div>
                  <div style={{ fontSize: '11.5px', color: 'var(--text-tertiary)', marginTop: '2px' }}>
                    Maintains cryptographically verifiable records of all scans, detections, and user approvals.
                  </div>
                </div>
              </label>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WorkspaceSettingsTab;
