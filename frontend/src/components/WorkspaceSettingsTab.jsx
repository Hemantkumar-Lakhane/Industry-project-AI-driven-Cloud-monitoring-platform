import React, { useState } from 'react';
import { AlertCircle, Sliders, Shield, Sun, Moon } from 'lucide-react';

const WorkspaceSettingsTab = ({ theme, onToggleTheme, showToast }) => {
  const [windowSec, setWindowSec] = useState(60);
  const [failThreshold, setFailThreshold] = useState(5);
  const [prodSafeLock, setProdSafeLock] = useState(true);

  const handleSave = () => {
    if (showToast) showToast('Platform settings saved');
  };

  return (
    <div>
      {/* 1. FIGMA NOTICE CALLOUT */}
      <div className="figma-callout">
        <AlertCircle size={18} className="figma-callout-icon" />
        <div className="figma-callout-content">
          <h4>System configuration · Active cluster</h4>
          <p>Controls detection engine sensitivity parameters, display themes, and execution safety locks.</p>
        </div>
      </div>

      {/* 2. 2-COLUMN SETTINGS GRID */}
      <div className="figma-grid-2col">
        {/* Left Column: Detection Parameters */}
        <div className="figma-card">
          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '16px' }}>
            Detector sensitivity parameters
          </h3>

          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
              Sliding evaluation window
            </label>
            <span style={{ fontSize: '12px', color: 'var(--text-tertiary)', display: 'block', marginBottom: '8px' }}>
              Time horizon for aggregating authentication failures per identity (current: {windowSec}s)
            </span>
            <input
              type="range"
              min="15"
              max="300"
              step="15"
              value={windowSec}
              onChange={(e) => setWindowSec(Number(e.target.value))}
              style={{ width: '100%', accentColor: 'var(--accent-orange)' }}
            />
          </div>

          <div style={{ marginBottom: '24px' }}>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
              Failure threshold
            </label>
            <span style={{ fontSize: '12px', color: 'var(--text-tertiary)', display: 'block', marginBottom: '8px' }}>
              Minimum consecutive failed attempts to trigger Category 1 alerts (current: {failThreshold})
            </span>
            <input
              type="range"
              min="3"
              max="20"
              step="1"
              value={failThreshold}
              onChange={(e) => setFailThreshold(Number(e.target.value))}
              style={{ width: '100%', accentColor: 'var(--accent-orange)' }}
            />
          </div>

          <button className="figma-btn-primary" onClick={handleSave}>
            Update detector policy
          </button>
        </div>

        {/* Right Column: Theme & Safeguard Policies */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Appearance card */}
          <div className="figma-card">
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '14px' }}>
              Appearance & theme
            </h3>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
              Select between light theme and obsidian dark theme.
            </p>
            <div className="figma-theme-toggle">
              <button
                className={theme === 'light' ? 'active' : ''}
                onClick={() => { if (theme !== 'light') onToggleTheme(); }}
              >
                Light
              </button>
              <button
                className={theme === 'dark' ? 'active' : ''}
                onClick={() => { if (theme !== 'dark') onToggleTheme(); }}
              >
                Dark
              </button>
            </div>
          </div>

          {/* Safety Safeguards card */}
          <div className="figma-card">
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '14px' }}>
              Execution safeguards
            </h3>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--text-primary)', cursor: 'pointer', marginBottom: '8px' }}>
              <input
                type="checkbox"
                checked={prodSafeLock}
                onChange={(e) => setProdSafeLock(e.target.checked)}
                style={{ accentColor: 'var(--accent-orange)' }}
              />
              Lock production mutations (Dry-run enforced)
            </label>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Prevents unauthorized live cloud resource tampering.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WorkspaceSettingsTab;
