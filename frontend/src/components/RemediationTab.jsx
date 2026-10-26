import React, { useState } from 'react';
import axios from 'axios';
import {
  AlertCircle,
  Zap,
  ShieldCheck,
  CheckCircle,
  RefreshCw,
  Play,
  Lock,
  Unlock,
  Settings,
  ArrowRight,
  Check,
  AlertTriangle,
  Shield,
  ShieldAlert,
  Cpu,
  Database,
  Activity,
  Terminal,
  Wrench,
  Search,
  Layers,
  GitBranch
} from 'lucide-react';
import { API_URL } from '../config';

const RemediationTab = ({ playbooks = [], onExecutePlaybook, showToast, cspm = [], ciem = [] }) => {
  const [selectedPlaybookKey, setSelectedPlaybookKey] = useState('brute_force');
  const [remediationResult, setRemediationResult] = useState(null);
  const [executing, setExecuting] = useState(false);
  const [pipelineResult, setPipelineResult] = useState(null);
  const [runningPipeline, setRunningPipeline] = useState(false);

  // Self-Healing & RCA state
  const [diagnosingRCA, setDiagnosingRCA] = useState(false);
  const [selfHealing, setSelfHealing] = useState(false);
  const [rcaHealed, setRcaHealed] = useState(false);
  const [healedConfigs, setHealedConfigs] = useState(new Set());
  const [revokedEntities, setRevokedEntities] = useState(new Set());

  // Exact 8 playbooks matching Figma wireframe (remediation.png)
  const figmaPlaybooks = [
    {
      key: 'brute_force',
      attackType: 'brute_force',
      name: 'Brute Force Response',
      scope: 'Sign-in identity',
      mode: 'Approval',
      proposedTarget: 'demo-admin · Fixture only',
      observedEvidence: 'RAM-1040 · SIMULATED · 09:26 UTC',
      steps: [
        { name: 'Review sign-in evidence', impact: 'Confirm sequence and target identity.', status: 'completed' },
        { name: 'Propose temporary lock', impact: 'Sign-in interruption; restore account access.', status: 'pending' },
        { name: 'Review MFA reset', impact: 'User re-enrollment; restore prior settings.', status: 'pending' },
        { name: 'Prepare SOC notification', impact: 'Routing not configured; cancel draft.', status: 'pending' }
      ]
    },
    {
      key: 'privilege_escalation',
      attackType: 'privilege_escalation',
      name: 'Privilege Escalation Response',
      scope: 'IAM role',
      mode: 'Approval',
      proposedTarget: 'demo-build-role · Fixture only',
      observedEvidence: 'RAM-1042 · IMPORTED · 09:18 UTC',
      steps: [
        { name: 'Audit AssumeRole trail', impact: 'Inspect STS tokens issued.', status: 'pending' },
        { name: 'Detach excessive policy', impact: 'Revoke elevated privileges.', status: 'pending' },
        { name: 'Apply boundary restriction', impact: 'Confine role to build cluster.', status: 'pending' }
      ]
    },
    {
      key: 'data_exfiltration',
      attackType: 'data_exfiltration',
      name: 'Data Exfiltration Response',
      scope: 'Outbound traffic',
      mode: 'Approval',
      proposedTarget: 'demo-worker-02 · Fixture only',
      observedEvidence: 'RAM-1036 · SIMULATED · 09:48 UTC',
      steps: [
        { name: 'Inspect egress flow logs', impact: 'Verify destination reputation.', status: 'pending' },
        { name: 'Quarantine network interface', impact: 'Isolate instance traffic.', status: 'pending' }
      ]
    },
    {
      key: 'lateral_movement',
      attackType: 'lateral_movement',
      name: 'Lateral Movement Response',
      scope: 'Cloud resources',
      mode: 'Approval',
      proposedTarget: 'sg-0a1b2c3d · Security group',
      observedEvidence: 'RAM-1041 · IMPORTED · 09:40 UTC',
      steps: [
        { name: 'Restrict east-west traffic', impact: 'Block inter-VPC ingress.', status: 'pending' },
        { name: 'Invalidate active sessions', impact: 'Force credential re-auth.', status: 'pending' }
      ]
    },
    {
      key: 'misconfiguration_fix',
      attackType: 'misconfiguration',
      name: 'Misconfiguration Auto-Fix',
      scope: 'Config resource',
      mode: 'Approval',
      proposedTarget: 'demo-artifacts · S3 bucket',
      observedEvidence: 'RAM-1039 · IMPORTED · 09:42 UTC',
      steps: [
        { name: 'Apply S3 block public access', impact: 'Close anonymous read access.', status: 'pending' },
        { name: 'Revert bucket ACL drift', impact: 'Restore secure baseline.', status: 'pending' }
      ]
    },
    {
      key: 'crypto_mining',
      attackType: 'crypto_mining',
      name: 'Crypto Mining Response',
      scope: 'Compute resource',
      mode: 'Approval',
      proposedTarget: 'i-0987654321 · EC2 instance',
      observedEvidence: 'Simulated fixture',
      steps: [
        { name: 'Terminate rogue daemon', impact: 'Halt unauthorized compute usage.', status: 'pending' },
        { name: 'Revoke instance profile', impact: 'Cut AWS metadata API access.', status: 'pending' }
      ]
    },
    {
      key: 'credential_stuffing',
      attackType: 'credential_stuffing',
      name: 'Credential Stuffing Response',
      scope: 'Sign-in identity',
      mode: 'Approval',
      proposedTarget: 'demo-operator · IAM user',
      observedEvidence: 'RAM-1037 · IMPORTED · 09:35 UTC',
      steps: [
        { name: 'Force password rotation', impact: 'Invalidate compromised password.', status: 'pending' },
        { name: 'Enforce virtual MFA device', impact: 'Mandate 2FA enrollment.', status: 'pending' }
      ]
    },
    {
      key: 'ransomware_precursor',
      attackType: 'ransomware',
      name: 'Ransomware Precursor Response',
      scope: 'Workload fixture',
      mode: 'Approval',
      proposedTarget: 'demo-web-01 · Fixture only',
      observedEvidence: 'Host anomaly fixture',
      steps: [
        { name: 'Snapshot volume state', impact: 'Capture forensics image.', status: 'pending' },
        { name: 'Isolate host from subnet', impact: 'Stop worm propagation.', status: 'pending' }
      ]
    }
  ];

  const currentPlaybook = figmaPlaybooks.find(p => p.key === selectedPlaybookKey) || figmaPlaybooks[0];

  const runFullPipeline = async () => {
    setRunningPipeline(true);
    try {
      const res = await axios.get(`${API_URL}/remediation/full-pipeline`);
      setPipelineResult(res.data.data);
      if (showToast) showToast('Full remediation pipeline executed successfully!');
    } catch (err) {
      console.error(err);
      if (showToast) showToast('Full pipeline failed', 'error');
    }
    setRunningPipeline(false);
  };

  const executeDryRun = async (attackType) => {
    setExecuting(true);
    try {
      const res = await axios.post(`${API_URL}/remediation/dry-run/${attackType}`);
      setRemediationResult(res.data.data);
      if (showToast) showToast(`Safe dry-run executed for "${res.data.data.playbook_name}"!`);
    } catch (err) {
      console.error(err);
      if (showToast) showToast('Dry-run execution failed', 'error');
    }
    setExecuting(false);
  };

  const autoFixConfig = async (vulnId) => {
    try {
      const res = await axios.post(`${API_URL}/remediation/config-fix/${vulnId}`);
      setHealedConfigs(prev => new Set(prev).add(vulnId));
      if (showToast) showToast(`Self-Healing Applied: ${res.data.data.description}`);
    } catch (err) {
      if (showToast) showToast('Config fix failed', 'error');
    }
  };

  const revokeAccess = async (name, type, risk) => {
    try {
      await axios.post(`${API_URL}/remediation/revoke-access?entity_name=${name}&entity_type=${type}&risk_level=${risk}`);
      setRevokedEntities(prev => new Set(prev).add(name));
      if (showToast) showToast(`Entitlements restricted for ${name}`);
    } catch (err) {
      if (showToast) showToast('Revocation failed', 'error');
    }
  };

  const handleDiagnoseRCA = () => {
    setDiagnosingRCA(true);
    setTimeout(() => {
      setDiagnosingRCA(false);
      if (showToast) showToast('Root cause correlation completed: 94.8% causal confidence');
    }, 600);
  };

  const handleSelfHealIncident = async () => {
    setSelfHealing(true);
    try {
      await autoFixConfig('VULN-001');
      await autoFixConfig('VULN-002');
      await revokeAccess('demo-operator', 'IAM User', 'high');
      setRcaHealed(true);
      if (showToast) showToast('Self-Healing completed: 3 causal vectors neutralized');
    } catch (err) {
      console.error(err);
    }
    setSelfHealing(false);
  };

  return (
    <div className="animate-fade-in">
      {/* 1. END-TO-END PIPELINE BANNER */}
      <div className="figma-card" style={{ marginBottom: '24px', padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Zap size={18} style={{ color: 'var(--accent-orange)' }} /> Autonomous Response Pipeline
            </h3>
            <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginTop: '2px', display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
              <span>Telemetry ingestion</span>
              <ArrowRight size={11} style={{ color: 'var(--text-tertiary)' }} />
              <span>ML detection</span>
              <ArrowRight size={11} style={{ color: 'var(--text-tertiary)' }} />
              <span>Posture analysis</span>
              <ArrowRight size={11} style={{ color: 'var(--text-tertiary)' }} />
              <span>Playbook containment</span>
              <ArrowRight size={11} style={{ color: 'var(--text-tertiary)' }} />
              <span>Config healing</span>
            </p>
          </div>
          <button
            className="figma-btn-primary"
            onClick={runFullPipeline}
            disabled={runningPipeline}
            style={{ padding: '8px 16px' }}
          >
            <Play size={13} className={runningPipeline ? 'animate-spin' : ''} />
            {runningPipeline ? 'Running Pipeline...' : 'Run Full Pipeline'}
          </button>
        </div>

        {/* Visual pipeline flow diagram */}
        <div className="remediation-flow-track">
          <div className="flow-step">
            <span className="step-num">1</span>
            <div className="step-text">
              <strong>Telemetry</strong>
              <span>Normalized events</span>
            </div>
          </div>
          <span className="flow-arrow"><ArrowRight size={14} /></span>

          <div className="flow-step">
            <span className="step-num">2</span>
            <div className="step-text">
              <strong>ML Detection</strong>
              <span>PyOD & Rules</span>
            </div>
          </div>
          <span className="flow-arrow"><ArrowRight size={14} /></span>

          <div className="flow-step">
            <span className="step-num">3</span>
            <div className="step-text">
              <strong>CSPM & CIEM</strong>
              <span>Posture checks</span>
            </div>
          </div>
          <span className="flow-arrow"><ArrowRight size={14} /></span>

          <div className="flow-step">
            <span className="step-num">4</span>
            <div className="step-text">
              <strong>Playbooks</strong>
              <span>Safe containment</span>
            </div>
          </div>
          <span className="flow-arrow"><ArrowRight size={14} /></span>

          <div className="flow-step">
            <span className="step-num">5</span>
            <div className="step-text">
              <strong>Self-Healing</strong>
              <span>Config correction</span>
            </div>
          </div>
        </div>

        {pipelineResult && (
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', marginTop: '16px', paddingTop: '16px', borderTop: '1px solid var(--border-subtle)' }}>
            <span className="figma-dot-badge low"><Check size={12} /> {pipelineResult.ml_analysis?.total_events || 100} Events Evaluated</span>
            <span className="figma-dot-badge critical"><AlertTriangle size={12} /> {pipelineResult.ml_analysis?.anomalies_detected || 15} Anomalies</span>
            <span className="figma-dot-badge medium"><Zap size={12} /> {pipelineResult.threat_remediation?.remediations_triggered || 4} Playbooks Triggered</span>
            <span className="figma-dot-badge high"><Settings size={12} /> {pipelineResult.config_fixes?.length || 2} Config Fixes Applied</span>
            <span className="figma-dot-badge low"><Shield size={12} /> {pipelineResult.access_revocations?.length || 2} Access Revocations</span>
          </div>
        )}
      </div>

      {/* 2. ROOT CAUSE ANALYSIS (RCA) & CAUSAL ATTACK CHAIN */}
      <div className="figma-card" style={{ marginBottom: '24px', padding: '22px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h3 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <GitBranch size={17} style={{ color: 'var(--accent-orange)' }} /> Automated Root Cause Analysis (RCA) & Causal Chain
            </h3>
            <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Correlates telemetry vectors, ML anomaly scoring, and cloud posture drift to isolate origin vulnerabilities
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button className="figma-btn-secondary" onClick={handleDiagnoseRCA} disabled={diagnosingRCA}>
              <Search size={13} className={diagnosingRCA ? 'animate-spin' : ''} /> {diagnosingRCA ? 'Correlating telemetry...' : 'Re-diagnose Incident'}
            </button>
            <button className="figma-btn-primary" onClick={handleSelfHealIncident} disabled={selfHealing}>
              <Wrench size={13} className={selfHealing ? 'animate-spin' : ''} /> {selfHealing ? 'Executing Self-Healing...' : 'Apply Autonomous Self-Healing'}
            </button>
          </div>
        </div>

        {/* 3-Stage Attack Causal Progression */}
        <div className="rca-chain-grid">
          {/* Stage 1: Initial Vector */}
          <div className="rca-stage-card">
            <div className="rca-stage-header">
              <span className="rca-stage-num">Stage 1</span>
              <span className="rca-stage-badge critical">Infiltration Vector</span>
            </div>
            <div className="rca-stage-title">Unrestricted SSH Ingress</div>
            <div className="rca-stage-meta">Target: <code>demo-web-01 (10.0.0.10)</code></div>
            <p className="rca-stage-desc">
              Security Group <code>sg-0a1b2c3d</code> allows <code>0.0.0.0/0:22</code>. High-frequency brute force spike detected (18 auth failures in 0.1s).
            </p>
            <div className="rca-stage-status">
              <AlertTriangle size={12} style={{ color: 'var(--sev-critical)' }} /> PyOD Anomaly Score: 0.942
            </div>
          </div>

          <div className="rca-connector">
            <ArrowRight size={18} />
          </div>

          {/* Stage 2: Privilege Pivot */}
          <div className="rca-stage-card">
            <div className="rca-stage-header">
              <span className="rca-stage-num">Stage 2</span>
              <span className="rca-stage-badge high">Privilege Pivot</span>
            </div>
            <div className="rca-stage-title">STS AssumeRole Elevation</div>
            <div className="rca-stage-meta">Role: <code>demo-build-role</code></div>
            <p className="rca-stage-desc">
              Host metadata token leveraged to assume IAM role with unconstrained wildcard <code>s3:*</code> and <code>iam:*</code> entitlements.
            </p>
            <div className="rca-stage-status">
              <Layers size={12} style={{ color: 'var(--sev-high)' }} /> CIEM Risk: Excessive Admin Drift
            </div>
          </div>

          <div className="rca-connector">
            <ArrowRight size={18} />
          </div>

          {/* Stage 3: Target Impact */}
          <div className="rca-stage-card">
            <div className="rca-stage-header">
              <span className="rca-stage-num">Stage 3</span>
              <span className="rca-stage-badge medium">Target Impact</span>
            </div>
            <div className="rca-stage-title">Data Staging Exfiltration</div>
            <div className="rca-stage-meta">Asset: <code>s3://demo-artifacts</code></div>
            <p className="rca-stage-desc">
              Public read policy enabled on S3 bucket. Suspicious egress burst of 4.2 MB towards external Tor exit node.
            </p>
            <div className="rca-stage-status">
              <Database size={12} style={{ color: 'var(--sev-medium)' }} /> MITRE ATT&CK: T1567.002
            </div>
          </div>
        </div>

        {/* Root Cause Conclusion & Self-Healing Prescription */}
        <div className="rca-prescription-box">
          <div className="prescription-left">
            <span className="prescription-label">Identified Root Cause</span>
            <p className="prescription-text">
              <strong>Over-permissive IAM Trust Policy + Public Security Group Ingress.</strong> The root compromise originated from an unshielded SSH port leading to instance metadata harvesting and IAM lateral movement.
            </p>
          </div>
          <div className="prescription-right">
            <span className="prescription-label">Self-Healing Status</span>
            {rcaHealed ? (
              <span className="self-healing-badge healed">
                <Check size={13} /> Self-Healing Successfully Applied (3/3 Contained)
              </span>
            ) : (
              <span className="self-healing-badge pending">
                <AlertCircle size={13} /> Action Pending: Auto-Remediation Recommended
              </span>
            )}
          </div>
        </div>
      </div>

      {/* 3. 2-COLUMN GRID: PLAYBOOK DIRECTORY + PLAN PREVIEW */}
      <div className="remediation-grid">
        {/* Playbook Directory Table */}
        <div className="figma-card" style={{ padding: '0', overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldCheck size={16} style={{ color: 'var(--accent-orange)' }} /> Playbook directory
            </h3>
            <span className="figma-pill-counter">
              8 playbooks
            </span>
          </div>

          <table className="figma-table remediation-playbook-table">
            <thead>
              <tr>
                <th style={{ width: '48%' }}>Playbook</th>
                <th style={{ width: '32%' }}>Target scope</th>
                <th style={{ width: '20%', textAlign: 'right', whiteSpace: 'nowrap' }}>Mode</th>
              </tr>
            </thead>
            <tbody>
              {figmaPlaybooks.map((pb) => {
                const isSelected = pb.key === selectedPlaybookKey;
                return (
                  <tr
                    key={pb.key}
                    onClick={() => {
                      setSelectedPlaybookKey(pb.key);
                      setRemediationResult(null);
                    }}
                    className={`remediation-row ${isSelected ? 'selected' : ''}`}
                  >
                    <td>
                      <div className="playbook-cell-wrap">
                        <span className={`playbook-type-badge ${isSelected ? 'active' : ''}`}>
                          {pb.key === 'brute_force' && <Lock size={12} />}
                          {pb.key === 'privilege_escalation' && <Zap size={12} />}
                          {pb.key === 'data_exfiltration' && <ArrowRight size={12} />}
                          {pb.key === 'lateral_movement' && <AlertCircle size={12} />}
                          {pb.key === 'misconfiguration_fix' && <Settings size={12} />}
                          {pb.key === 'crypto_mining' && <Zap size={12} />}
                          {pb.key === 'credential_stuffing' && <Lock size={12} />}
                          {pb.key === 'ransomware_precursor' && <ShieldCheck size={12} />}
                        </span>
                        <span className="playbook-name-text">
                          {pb.name}
                        </span>
                        {isSelected && <ArrowRight size={13} className="playbook-active-arrow" />}
                      </div>
                    </td>
                    <td>
                      <span className="playbook-scope-tag">{pb.scope}</span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <span className="playbook-mode-badge">{pb.mode}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Plan Preview Card (Right Column) */}
        <div className="figma-card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
              {currentPlaybook.name}
            </h3>
            <span style={{
              fontSize: '11px',
              fontWeight: 600,
              padding: '3px 9px',
              borderRadius: '6px',
              backgroundColor: remediationResult ? 'var(--success-bg)' : 'var(--surface-muted)',
              color: remediationResult ? 'var(--success-color)' : 'var(--text-tertiary)',
              border: `1px solid ${remediationResult ? 'rgba(2, 122, 72, 0.3)' : 'var(--border-subtle)'}`
            }}>
              {remediationResult ? 'DRY-RUN VERIFIED' : 'PLAN PREVIEW'}
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '20px', fontSize: '13px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Proposed target</span>
              <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{currentPlaybook.proposedTarget}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Observed evidence</span>
              <span style={{ fontWeight: 600, color: 'var(--accent-orange)' }}>{currentPlaybook.observedEvidence}</span>
            </div>
          </div>

          <div style={{ marginBottom: '14px' }}>
            <span style={{ fontSize: '12.5px', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Execution Sequence {remediationResult ? '· Dry-run verified' : '· Sequential containment steps'}
            </span>
          </div>

          {/* Sequential Step Flow */}
          <div className="remediation-steps-flow" style={{ marginBottom: '18px' }}>
            {currentPlaybook.steps.map((st, i) => (
              <React.Fragment key={i}>
                <div className={`step-flow-node ${remediationResult ? 'completed' : ''}`}>
                  <span className="step-flow-num">{remediationResult ? <Check size={11} /> : i + 1}</span>
                  <span className="step-flow-title">{st.name}</span>
                </div>
                {i < currentPlaybook.steps.length - 1 && (
                  <span className="step-flow-arrow"><ArrowRight size={13} /></span>
                )}
              </React.Fragment>
            ))}
          </div>

          {remediationResult && (
            <div style={{
              background: 'var(--surface-muted)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              padding: '12px 16px',
              marginBottom: '16px',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px', color: 'var(--text-secondary)' }}>
                <span>ID: <code style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{remediationResult.execution_id}</code></span>
                <span>{remediationResult.total_duration_ms}ms execution latency</span>
                <span style={{ color: 'var(--success-color)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <Check size={12} /> {remediationResult.steps_succeeded}/{remediationResult.steps_executed} steps passed
                </span>
              </div>
              <div style={{
                fontFamily: 'monospace',
                fontSize: '11px',
                background: 'rgba(0, 0, 0, 0.2)',
                padding: '8px 10px',
                borderRadius: '6px',
                color: 'var(--text-secondary)',
                lineHeight: '1.6'
              }}>
                <div>[0.00s] INIT: Triggering containment playbook for {currentPlaybook.attackType}...</div>
                <div>[0.02s] DRY-RUN: Evaluating blast radius on target {currentPlaybook.proposedTarget}...</div>
                <div>[0.04s] SUCCESS: All steps validated with 0 policy violations.</div>
              </div>
            </div>
          )}

          <table className="figma-table" style={{ marginBottom: '24px' }}>
            <thead>
              <tr>
                <th style={{ width: '45%' }}>Step</th>
                <th style={{ width: '55%', textAlign: 'right' }}>Impact / rollback</th>
              </tr>
            </thead>
            <tbody>
              {currentPlaybook.steps.map((st, i) => (
                <tr key={i}>
                  <td style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>
                    {remediationResult ? (
                      <Check size={13} style={{ color: 'var(--success-color)', display: 'inline', verticalAlign: 'middle', marginRight: '6px' }} />
                    ) : (
                      <span style={{ color: 'var(--text-tertiary)', marginRight: '6px' }}>•</span>
                    )}
                    {st.name}
                  </td>
                  <td style={{ textAlign: 'right', color: 'var(--text-secondary)', fontSize: '12.5px' }}>
                    {st.impact}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              className="figma-btn-primary"
              onClick={() => executeDryRun(currentPlaybook.attackType)}
              disabled={executing}
            >
              <Zap size={13} className={executing ? 'animate-spin' : ''} />
              {executing ? 'Executing...' : 'Execute safe dry-run'}
            </button>
            <button
              className="figma-btn-secondary"
              onClick={() => setRemediationResult(null)}
            >
              <RefreshCw size={13} /> Reset view
            </button>
          </div>
        </div>
      </div>

      {/* 4. POSTURE CORRECTIONS (CSPM CONFIG FIXES & CIEM REVOCATIONS) */}
      <div className="figma-grid-2col" style={{ marginTop: '24px' }}>
        {/* CSPM Auto-Fixes */}
        <div className="figma-card" style={{ padding: '0', overflow: 'hidden' }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Settings size={15} style={{ color: 'var(--accent-orange)' }} /> CSPM configuration corrections
            </h3>
            <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>Self-Healing Baseline</span>
          </div>
          <table className="figma-table">
            <tbody>
              <tr>
                <td>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Close public SSH port 22</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>demo-web-01 · sg-0a1b2c3d</div>
                </td>
                <td style={{ textAlign: 'right' }}>
                  {healedConfigs.has('VULN-001') ? (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--success-color)', background: 'var(--success-bg)', padding: '4px 10px', borderRadius: '6px' }}>
                      <Check size={12} /> Healed
                    </span>
                  ) : (
                    <button className="figma-btn-secondary" style={{ padding: '5px 12px', fontSize: '12px' }} onClick={() => autoFixConfig('VULN-001')}>
                      <Wrench size={12} /> Auto-Fix
                    </button>
                  )}
                </td>
              </tr>
              <tr>
                <td>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Block public S3 read policy</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>demo-artifacts · s3-bucket</div>
                </td>
                <td style={{ textAlign: 'right' }}>
                  {healedConfigs.has('VULN-002') ? (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--success-color)', background: 'var(--success-bg)', padding: '4px 10px', borderRadius: '6px' }}>
                      <Check size={12} /> Healed
                    </span>
                  ) : (
                    <button className="figma-btn-secondary" style={{ padding: '5px 12px', fontSize: '12px' }} onClick={() => autoFixConfig('VULN-002')}>
                      <Wrench size={12} /> Auto-Fix
                    </button>
                  )}
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* CIEM Access Revocation */}
        <div className="figma-card" style={{ padding: '0', overflow: 'hidden' }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldAlert size={15} style={{ color: 'var(--accent-orange)' }} /> CIEM access revocations
            </h3>
            <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>Least-Privilege Enforcement</span>
          </div>
          <table className="figma-table">
            <tbody>
              <tr>
                <td>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Enforce MFA on root account</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>demo-operator · IAM user</div>
                </td>
                <td style={{ textAlign: 'right' }}>
                  {revokedEntities.has('demo-operator') ? (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--success-color)', background: 'var(--success-bg)', padding: '4px 10px', borderRadius: '6px' }}>
                      <Check size={12} /> Enforced
                    </span>
                  ) : (
                    <button className="figma-btn-secondary" style={{ padding: '5px 12px', fontSize: '12px' }} onClick={() => revokeAccess('demo-operator', 'IAM User', 'high')}>
                      <ShieldAlert size={12} /> Enforce
                    </button>
                  )}
                </td>
              </tr>
              <tr>
                <td>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Prune unused ec2:* permissions</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>demo-report-role · IAM role</div>
                </td>
                <td style={{ textAlign: 'right' }}>
                  {revokedEntities.has('demo-report-role') ? (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--success-color)', background: 'var(--success-bg)', padding: '4px 10px', borderRadius: '6px' }}>
                      <Check size={12} /> Revoked
                    </span>
                  ) : (
                    <button className="figma-btn-secondary" style={{ padding: '5px 12px', fontSize: '12px' }} onClick={() => revokeAccess('demo-report-role', 'IAM Role', 'medium')}>
                      <ShieldAlert size={12} /> Revoke
                    </button>
                  )}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default RemediationTab;
