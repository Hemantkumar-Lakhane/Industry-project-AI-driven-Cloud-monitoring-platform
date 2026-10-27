import React, { useState } from 'react';
import axios from 'axios';
import {
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
  Database,
  Activity,
  Wrench,
  Search,
  Layers,
  AlertCircle,
  HelpCircle,
  RotateCcw,
  Info
} from 'lucide-react';
import { API_URL } from '../config';

// Fallback demo scenarios available for dry-run simulation when in clean baseline
const DEMO_PREVIEWS = [
  {
    id: 'DEMO-BF-01',
    attackType: 'brute_force',
    name: 'SSH Password Brute Force Attack',
    severity: 'critical',
    target: 'prod-web-01 (10.0.1.25)',
    source: 'Wazuh SIEM Host Agent',
    time: 'Demo Baseline',
    whatIsAttack: 'Automated credential stuffing and dictionary attack guessing administrative credentials rapidly against exposed SSH endpoint.',
    whyDidItArrive: 'Public SSH Port Left Open: Server port 22 allows inbound traffic from 0.0.0.0/0 without rate limiting or IP allowlisting.',
    howIsItFixed: [
      'Blacklists hostile source IP address at perimeter security group and edge firewall.',
      'Restricts administrative SSH access exclusively to corporate private VPN CIDR.',
      'Temporarily locks targeted account and triggers mandatory MFA reset challenge.'
    ],
    status: 'open',
    isLive: false
  },
  {
    id: 'DEMO-EX-02',
    attackType: 'data_exfiltration',
    name: 'Unauthorized Data Exfiltration from Cloud Storage',
    severity: 'high',
    target: 'prod-financial-records (S3)',
    source: 'AWS CloudTrail & VPC Flow Logs',
    time: 'Demo Baseline',
    whatIsAttack: 'Abnormal volume of sensitive financial archives transferred to untrusted external destination IP.',
    whyDidItArrive: 'Over-Permissive Storage Access: Workload IAM role configured with unconstrained s3:* read wildcard.',
    howIsItFixed: [
      'Terminates active egress network flows towards untrusted destination address.',
      'Revokes active STS temporary credentials and rotates IAM access keys.',
      'Applies AWS S3 Block Public Access and restricts bucket policy to internal VPC endpoint.'
    ],
    status: 'open',
    isLive: false
  },
  {
    id: 'DEMO-PE-03',
    attackType: 'privilege_escalation',
    name: 'IAM Privilege Escalation Attempt',
    severity: 'high',
    target: 'SuperAdminExecutionRole',
    source: 'IAM Policy Engine & Wazuh',
    time: 'Demo Baseline',
    whatIsAttack: 'Worker role attempted to elevate privileges to Super Administrator through unconstrained AssumeRole trust relationship.',
    whyDidItArrive: 'Missing Permission Boundary: Role lacked explicit permission boundaries, enabling administrative elevation.',
    howIsItFixed: [
      'Revokes active STS temporary credentials generated during elevation attempt.',
      'Detaches unauthorized administrative policy from compromised role.',
      'Enforces immutable IAM permission boundary restricting actions strictly to local workload.'
    ],
    status: 'open',
    isLive: false
  },
  {
    id: 'DEMO-NS-04',
    attackType: 'network_scanning',
    name: 'Hostile Network Port Scanning',
    severity: 'medium',
    target: 'Production VPC Ingress (sg-0442ab91c890f11)',
    source: 'VPC Flow Log Inspection',
    time: 'Demo Baseline',
    whatIsAttack: 'Adversary scanning exposed network ports across subnet to identify unpatched databases and open ingress services.',
    whyDidItArrive: 'Exposed Edge Ports: Development ports directly exposed to public internet without ingress filtering.',
    howIsItFixed: [
      'Drops inbound SYN packet bursts originating from scanning IP CIDR.',
      'Moves backend database and cache services to private subnets without public route tables.',
      'Enables automated edge rate-limiting to throttle aggressive port discovery.'
    ],
    status: 'open',
    isLive: false
  }
];

const RemediationTab = ({
  playbooks = [],
  onExecutePlaybook,
  showToast,
  cspm = [],
  ciem = [],
  findings = [],
  incidents = [],
  onRefreshData
}) => {
  // Transform live incidents from backend API
  const liveIncidents = (incidents || []).map((inc) => {
    const rawAttackType = (inc.attack_categories && inc.attack_categories[0]) || 'brute_force';
    const target =
      (inc.resources && inc.resources[0]) ||
      (inc.principals && inc.principals[0]) ||
      (inc.source_ips && inc.source_ips[0]) ||
      'Production Cloud Asset';
    const source = (inc.correlation_reasons && inc.correlation_reasons[0]) || 'Multi-Signal Correlation Engine';
    const timeFormatted = inc.start_time
      ? new Date(inc.start_time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' UTC'
      : 'Live Telemetry';

    // Tailored fix steps based on attack type
    const defaultFixSteps = [
      'Isolate compromised network flows and block source IP address at perimeter firewall.',
      'Invalidate active STS temporary credentials and revoke elevated session tokens.',
      'Re-apply least-privilege IAM policy and enforce immediate MFA re-authentication.'
    ];

    return {
      id: inc.incident_id,
      rawId: inc.incident_id,
      attackType: rawAttackType,
      name: inc.title,
      severity: (inc.severity || 'high').toLowerCase(),
      target,
      source,
      time: timeFormatted,
      whatIsAttack: inc.description || `Correlated security campaign involving ${inc.attack_categories?.join(', ') || 'anomalous signals'}.`,
      whyDidItArrive:
        inc.correlation_reasons && inc.correlation_reasons.length > 0
          ? inc.correlation_reasons.join('. ')
          : 'Deterministic detection signatures triggered across monitored telemetry.',
      howIsItFixed: defaultFixSteps,
      status: inc.status || 'open',
      isLive: true
    };
  });

  const hasLiveIncidents = liveIncidents.length > 0;
  const displayIncidents = hasLiveIncidents ? liveIncidents : DEMO_PREVIEWS;

  const [selectedIncidentId, setSelectedIncidentId] = useState(displayIncidents[0]?.id || 'DEMO-BF-01');
  const [healedIncidents, setHealedIncidents] = useState(new Set());
  const [dryRunResults, setDryRunResults] = useState({});
  const [lastExecutionId, setLastExecutionId] = useState({});
  const [executing, setExecuting] = useState(false);
  const [runningPipeline, setRunningPipeline] = useState(false);
  const [healedConfigs, setHealedConfigs] = useState(new Set());
  const [revokedEntities, setRevokedEntities] = useState(new Set());
  const [actionError, setActionError] = useState(null);

  const currentIncident = displayIncidents.find((inc) => inc.id === selectedIncidentId) || displayIncidents[0];
  const isHealed = healedIncidents.has(currentIncident.id);
  const currentExecId = lastExecutionId[currentIncident.id];

  // 1. Dry Run Simulation (Never mutate, dry_run=True)
  const handleDryRun = async () => {
    setExecuting(true);
    setActionError(null);
    try {
      const res = await axios.post(`${API_URL}/remediation/execute/${currentIncident.attackType}?dry_run=true`);
      const data = res.data?.data || {};
      const execId = data.execution_id;

      if (execId) {
        setLastExecutionId((prev) => ({ ...prev, [currentIncident.id]: execId }));
      }

      setDryRunResults((prev) => ({
        ...prev,
        [currentIncident.id]: {
          verified: true,
          executionId: execId,
          plan: data.steps_executed?.map((s) => s.description) || [
            'Firewall rule validated',
            'Identity session isolated',
            'MFA verified'
          ],
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' UTC'
        }
      }));

      if (showToast) showToast('Safe dry-run simulation succeeded in sandbox! Safe to apply.');
    } catch (err) {
      const msg = err.response?.data?.detail || err.response?.data?.message || err.message || 'Dry run simulation failed';
      setActionError(`Dry-run failed: ${msg}`);
      if (showToast) showToast(`Dry-run failed: ${msg}`, 'error');
    } finally {
      setExecuting(false);
    }
  };

  // 2. Apply Remediation (dry_run=False)
  const handleAutoRemediate = async () => {
    setExecuting(true);
    setActionError(null);
    try {
      const res = await axios.post(`${API_URL}/remediation/execute/${currentIncident.attackType}?dry_run=false`);
      const data = res.data?.data || {};
      const execId = data.execution_id;

      if (execId) {
        setLastExecutionId((prev) => ({ ...prev, [currentIncident.id]: execId }));
      }

      setHealedIncidents((prev) => new Set(prev).add(currentIncident.id));
      if (onRefreshData) onRefreshData();

      if (showToast) {
        showToast(`Remediation executed (Simulated Sandbox): "${currentIncident.name}" contained!`);
      }
    } catch (err) {
      const msg = err.response?.data?.detail || err.response?.data?.message || err.message || 'Remediation failed';
      setActionError(`Remediation failed: ${msg}`);
      if (showToast) showToast(`Remediation failed: ${msg}`, 'error');
    } finally {
      setExecuting(false);
    }
  };

  // 3. Rollback Executed Remediation via POST /api/remediation/rollback
  const handleRollback = async () => {
    if (!currentExecId) {
      if (showToast) showToast('No recorded execution ID for this incident to rollback.', 'warning');
      return;
    }

    setExecuting(true);
    setActionError(null);
    try {
      const res = await axios.post(`${API_URL}/remediation/rollback`, {
        execution_id: currentExecId
      });

      // Remove from healed set to reflect restored 'open' state
      setHealedIncidents((prev) => {
        const next = new Set(prev);
        next.delete(currentIncident.id);
        return next;
      });

      if (onRefreshData) onRefreshData();

      const rollbackMsg = res.data?.data?.message || `Execution ${currentExecId} rolled back successfully.`;
      if (showToast) showToast(rollbackMsg);
    } catch (err) {
      const msg = err.response?.data?.detail || err.response?.data?.message || err.message || 'Rollback failed';
      setActionError(`Rollback error: ${msg}`);
      if (showToast) showToast(`Rollback failed: ${msg}`, 'error');
    } finally {
      setExecuting(false);
    }
  };

  // 4. Run End-to-End Pipeline
  const handleRunFullPipeline = async () => {
    setRunningPipeline(true);
    setActionError(null);
    try {
      await axios.get(`${API_URL}/remediation/full-pipeline`);
      setHealedIncidents(new Set(displayIncidents.map((i) => i.id)));
      setHealedConfigs(new Set(['VULN-001', 'VULN-002']));
      setRevokedEntities(new Set(['secops-operator', 'prod-ci-role']));
      if (onRefreshData) onRefreshData();
      if (showToast) showToast('Autonomous response executed across all telemetry vectors.');
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Pipeline execution failed';
      setActionError(`Pipeline failed: ${msg}`);
      if (showToast) showToast(`Pipeline execution failed: ${msg}`, 'error');
    } finally {
      setRunningPipeline(false);
    }
  };

  // 5. Auto-Fix Individual Config (CSPM)
  const autoFixConfig = async (vulnId) => {
    try {
      await axios.post(`${API_URL}/remediation/config-fix/${vulnId}`);
      setHealedConfigs((prev) => new Set(prev).add(vulnId));
      if (showToast) showToast('Security configuration updated and baseline healed!');
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Configuration fix failed';
      setActionError(`Config fix failed: ${msg}`);
      if (showToast) showToast(`Config fix failed: ${msg}`, 'error');
    }
  };

  // 6. Revoke IAM Access (CIEM)
  const revokeAccess = async (name, type, risk) => {
    try {
      await axios.post(`${API_URL}/remediation/revoke-access?entity_name=${name}&entity_type=${type}&risk_level=${risk}`);
      setRevokedEntities((prev) => new Set(prev).add(name));
      if (showToast) showToast(`Privileges revoked and MFA enforced for ${name}`);
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Access revocation failed';
      setActionError(`Access revocation failed: ${msg}`);
      if (showToast) showToast(`Access revocation failed: ${msg}`, 'error');
    }
  };

  return (
    <div className="animate-fade-in">
      {/* 1. TOP PIPELINE STATUS & QUICK ACTIONS */}
      <div className="figma-card" style={{ marginBottom: '20px', padding: '18px 22px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldCheck size={18} style={{ color: 'var(--accent-orange)' }} />
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                Security Incident Remediation & Rollback Console
              </h3>
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px', margin: 0 }}>
              Live telemetry correlation isolating attack vectors, root cause analysis, automated sandbox containment, and verified rollbacks.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
              {healedIncidents.size} of {displayIncidents.length} Threats Secured
            </span>
            <button
              className="figma-btn-primary"
              onClick={handleRunFullPipeline}
              disabled={runningPipeline || executing}
              style={{ padding: '8px 16px' }}
            >
              <Play size={13} className={runningPipeline ? 'animate-spin' : ''} />
              {runningPipeline ? 'Remediating...' : 'Auto-Remediate All'}
            </button>
          </div>
        </div>
      </div>

      {/* 2. BASELINE STATUS BANNER / ACTIVE INCIDENT STATUS */}
      {!hasLiveIncidents ? (
        <div
          style={{
            padding: '14px 18px',
            borderRadius: '8px',
            backgroundColor: 'var(--surface-table-head)',
            border: '1px solid var(--border-subtle)',
            marginBottom: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '12px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <CheckCircle size={18} style={{ color: 'var(--success-color)' }} />
            <div>
              <div style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Clean Baseline — Zero Active Live Incidents
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                No active threats detected. Displaying verified demo playbooks below for dry-run simulation and safe evaluation.
              </div>
            </div>
          </div>
          <span
            style={{
              padding: '4px 10px',
              borderRadius: '6px',
              fontSize: '11px',
              fontWeight: 700,
              backgroundColor: 'var(--surface-muted)',
              color: 'var(--text-tertiary)',
              border: '1px solid var(--border-subtle)'
            }}
          >
            DEMO PLAYBOOK PREVIEW MODE
          </span>
        </div>
      ) : (
        <div
          style={{
            padding: '14px 18px',
            borderRadius: '8px',
            backgroundColor: 'rgba(217, 45, 32, 0.08)',
            border: '1px solid rgba(217, 45, 32, 0.25)',
            marginBottom: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '12px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertTriangle size={18} style={{ color: 'var(--sev-critical)' }} />
            <div>
              <div style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--sev-critical)' }}>
                Active Incident Correlation Detected ({liveIncidents.length} Live Campaign{liveIncidents.length > 1 ? 's' : ''})
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                Incidents generated from active telemetry signals. Recommended playbooks ready for dry-run or sandbox containment.
              </div>
            </div>
          </div>
          <span
            style={{
              padding: '4px 10px',
              borderRadius: '6px',
              fontSize: '11px',
              fontWeight: 700,
              backgroundColor: 'rgba(217, 45, 32, 0.15)',
              color: 'var(--sev-critical)'
            }}
          >
            LIVE TELEMETRY INCIDENTS
          </span>
        </div>
      )}

      {/* ERROR BANNER IF ACTION FAILED */}
      {actionError && (
        <div
          style={{
            padding: '12px 16px',
            borderRadius: '8px',
            backgroundColor: 'rgba(217, 45, 32, 0.1)',
            border: '1px solid rgba(217, 45, 32, 0.3)',
            marginBottom: '18px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--sev-critical)', fontSize: '13px' }}>
            <AlertCircle size={16} />
            <span>{actionError}</span>
          </div>
          <button
            onClick={() => setActionError(null)}
            style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '12px' }}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* 3. INCIDENT SELECTOR BUTTONS */}
      <div style={{ display: 'grid', gridTemplateColumns: `repeat(${displayIncidents.length}, 1fr)`, gap: '10px', marginBottom: '20px' }}>
        {displayIncidents.map((inc) => {
          const isSelected = inc.id === currentIncident.id;
          const incHealed = healedIncidents.has(inc.id);
          return (
            <div
              key={inc.id}
              onClick={() => setSelectedIncidentId(inc.id)}
              style={{
                padding: '12px 14px',
                borderRadius: '8px',
                border: isSelected ? '1.5px solid var(--accent-orange)' : '1px solid var(--border-subtle)',
                backgroundColor: isSelected ? 'var(--accent-orange-subtle)' : 'var(--surface-card)',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                <span className={`figma-dot-badge ${inc.severity}`}>
                  {inc.severity.toUpperCase()}
                </span>
                {incHealed ? (
                  <span style={{ fontSize: '11px', color: 'var(--success-color)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '3px' }}>
                    <Check size={12} /> Contained
                  </span>
                ) : (
                  <span style={{ fontSize: '11px', color: 'var(--sev-high)', fontWeight: 500 }}>
                    Action needed
                  </span>
                )}
              </div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {inc.name}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: '2px', display: 'flex', justifyContent: 'space-between' }}>
                <span>Target: {inc.target.split(' ')[0]}</span>
                {inc.isLive && <span style={{ color: 'var(--accent-orange)', fontWeight: 600 }}>LIVE</span>}
              </div>
            </div>
          );
        })}
      </div>

      {/* 4. INCIDENT REMEDIATION CONSOLE */}
      <div className="figma-card" style={{ marginBottom: '24px', padding: '24px' }}>
        {/* Incident Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '16px', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className={`figma-dot-badge ${currentIncident.severity}`}>
                {currentIncident.severity.toUpperCase()} SEVERITY
              </span>
              <h2 style={{ fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                {currentIncident.name}
              </h2>
              {currentIncident.isLive ? (
                <span style={{ fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px', background: 'rgba(235, 107, 39, 0.15)', color: 'var(--accent-orange)' }}>
                  LIVE CORRELATION
                </span>
              ) : (
                <span style={{ fontSize: '11px', fontWeight: 600, padding: '2px 8px', borderRadius: '4px', background: 'var(--surface-muted)', color: 'var(--text-tertiary)' }}>
                  DEMO PLAYBOOK
                </span>
              )}
            </div>
            <div style={{ fontSize: '12.5px', color: 'var(--text-tertiary)', marginTop: '6px' }}>
              Target Asset: <strong style={{ color: 'var(--text-primary)' }}>{currentIncident.target}</strong> · Source: {currentIncident.source} · Time: {currentIncident.time}
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            {isHealed ? (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 14px', borderRadius: '6px', backgroundColor: 'var(--success-bg)', color: 'var(--success-color)', fontWeight: 600, fontSize: '13px' }}>
                <Check size={15} /> Contained (Sandbox)
              </span>
            ) : (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 14px', borderRadius: '6px', backgroundColor: 'var(--sev-high-bg)', color: 'var(--sev-high)', fontWeight: 600, fontSize: '13px' }}>
                <AlertCircle size={15} /> Unresolved Threat
              </span>
            )}

            {/* Test Fix (Dry Run Simulation) */}
            <button
              className="figma-btn-secondary"
              onClick={handleDryRun}
              disabled={executing}
              title="Test the remediation playbook safely in sandbox without mutating resources"
            >
              <Search size={13} />
              {executing ? 'Evaluating...' : 'Test Fix (Dry Run)'}
            </button>

            {/* Rollback button (Available if an execution exists or if marked healed) */}
            {(currentExecId || isHealed) && (
              <button
                className="figma-btn-secondary"
                onClick={handleRollback}
                disabled={executing}
                title="Rollback previous remediation action using backend /api/remediation/rollback"
                style={{ borderColor: 'var(--accent-orange)', color: 'var(--accent-orange)' }}
              >
                <RotateCcw size={13} className={executing ? 'animate-spin' : ''} />
                Rollback ({currentExecId || 'Active'})
              </button>
            )}

            {/* Apply Automated Fix */}
            {!isHealed && (
              <button
                className="figma-btn-primary"
                onClick={handleAutoRemediate}
                disabled={executing}
                style={{ padding: '8px 18px' }}
                title="Execute remediation playbook in sandbox runtime"
              >
                <Wrench size={13} className={executing ? 'animate-spin' : ''} />
                {executing ? 'Securing...' : 'Apply Fix (Simulated Sandbox)'}
              </button>
            )}
          </div>
        </div>

        {/* 3 Structured Columns: Attack Vector -> Root Cause -> Remediation Plan */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '18px', marginBottom: '20px' }}>
          {/* Card 1: Attack Vector & Behavior */}
          <div style={{ padding: '16px', borderRadius: '8px', backgroundColor: 'var(--surface-muted)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
              <div style={{ width: '24px', height: '24px', borderRadius: '6px', backgroundColor: 'rgba(217, 45, 32, 0.1)', color: 'var(--sev-critical)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '12px' }}>
                1
              </div>
              <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                1. Attack Vector & Behavior
              </h4>
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.55, margin: 0 }}>
              {currentIncident.whatIsAttack}
            </p>
          </div>

          {/* Card 2: Root Cause Analysis */}
          <div style={{ padding: '16px', borderRadius: '8px', backgroundColor: 'var(--surface-muted)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
              <div style={{ width: '24px', height: '24px', borderRadius: '6px', backgroundColor: 'rgba(181, 71, 8, 0.1)', color: 'var(--sev-high)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '12px' }}>
                2
              </div>
              <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                2. Root Cause Analysis
              </h4>
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.55, margin: 0 }}>
              {currentIncident.whyDidItArrive}
            </p>
          </div>

          {/* Card 3: Containment & Remediation Plan */}
          <div style={{ padding: '16px', borderRadius: '8px', backgroundColor: 'var(--surface-muted)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
              <div style={{ width: '24px', height: '24px', borderRadius: '6px', backgroundColor: 'rgba(2, 122, 72, 0.1)', color: 'var(--success-color)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '12px' }}>
                3
              </div>
              <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                3. Automated Remediation Plan
              </h4>
            </div>
            <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              {currentIncident.howIsItFixed.map((step, idx) => (
                <li key={idx} style={{ marginBottom: '6px' }}>
                  {step}
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Dry Run / Action Output Box */}
        {dryRunResults[currentIncident.id] && (
          <div style={{ padding: '14px 18px', borderRadius: '8px', backgroundColor: 'var(--surface-table-head)', border: '1px solid var(--border-subtle)', marginTop: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ fontSize: '12.5px', fontWeight: 600, color: 'var(--success-color)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Check size={14} /> Safe Dry-Run Simulation Passed (Zero Service Interruption)
              </span>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                EXEC: {dryRunResults[currentIncident.id].executionId || 'SIMULATED'} · {dryRunResults[currentIncident.id].time}
              </span>
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Validated containment steps: {dryRunResults[currentIncident.id].plan.join(' → ')}
            </div>
          </div>
        )}

        <div style={{ marginTop: '14px', fontSize: '12px', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Info size={13} />
          <span>Operational Boundary: When live cloud infrastructure credentials are not configured, remediation actions and rollbacks execute against the local simulation state engine.</span>
        </div>
      </div>

      {/* 5. CLOUD CONFIGURATION & IDENTITY AUTO-FIXES (CSPM & CIEM) */}
      <div className="figma-grid-2col">
        {/* CSPM Configuration Auto-Fixes */}
        <div className="figma-card" style={{ padding: '0', overflow: 'hidden' }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: '14.5px', fontWeight: 600, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
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
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '2px' }}>Target: <code>prod-web-01 · sg-0a1b2c3d</code></div>
                </td>
                <td style={{ textAlign: 'right' }}>
                  {healedConfigs.has('VULN-001') ? (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--success-color)', background: 'var(--success-bg)', padding: '4px 10px', borderRadius: '6px' }}>
                      <Check size={12} /> Closed & Secured
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
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>Enable S3 Block Public Access on customer data bucket</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '2px' }}>Target: <code>prod-customer-bucket · s3-storage</code></div>
                </td>
                <td style={{ textAlign: 'right' }}>
                  {healedConfigs.has('VULN-002') ? (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--success-color)', background: 'var(--success-bg)', padding: '4px 10px', borderRadius: '6px' }}>
                      <Check size={12} /> Public Access Blocked
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

        {/* CIEM Identity & Access Corrections */}
        <div className="figma-card" style={{ padding: '0', overflow: 'hidden' }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: '14.5px', fontWeight: 600, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldAlert size={15} style={{ color: 'var(--text-secondary)' }} />
              Identity Access Controls & MFA (CIEM)
            </h3>
            <span style={{ fontSize: '11.5px', color: 'var(--text-tertiary)' }}>Least-Privilege Enforcement</span>
          </div>

          <table className="figma-table">
            <tbody>
              <tr>
                <td>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>Enforce Multi-Factor Authentication (MFA) on root user</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '2px' }}>Target: <code>secops-operator · IAM Administrator</code></div>
                </td>
                <td style={{ textAlign: 'right' }}>
                  {revokedEntities.has('secops-operator') ? (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--success-color)', background: 'var(--success-bg)', padding: '4px 10px', borderRadius: '6px' }}>
                      <Check size={12} /> MFA Enforced
                    </span>
                  ) : (
                    <button className="figma-btn-secondary" style={{ padding: '5px 12px', fontSize: '12px' }} onClick={() => revokeAccess('secops-operator', 'IAM User', 'high')}>
                      <Shield size={12} /> Enforce MFA
                    </button>
                  )}
                </td>
              </tr>
              <tr>
                <td>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>Prune unused wildcard permissions (s3:* / ec2:*)</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '2px' }}>Target: <code>prod-ci-role · IAM Role</code></div>
                </td>
                <td style={{ textAlign: 'right' }}>
                  {revokedEntities.has('prod-ci-role') ? (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 600, color: 'var(--success-color)', background: 'var(--success-bg)', padding: '4px 10px', borderRadius: '6px' }}>
                      <Check size={12} /> Excess Access Revoked
                    </span>
                  ) : (
                    <button className="figma-btn-secondary" style={{ padding: '5px 12px', fontSize: '12px' }} onClick={() => revokeAccess('prod-ci-role', 'IAM Role', 'medium')}>
                      <Shield size={12} /> Prune Access
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
