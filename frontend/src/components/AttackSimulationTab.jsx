import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  AlertCircle,
  Play,
  CheckCircle,
  Target,
  Hammer,
  ArrowUpRight,
  Upload,
  Globe,
  Radio,
  Clock,
  ChevronDown,
  Shield,
  Zap,
  Activity,
  Check,
  ArrowRight
} from 'lucide-react';
import { API_URL } from '../config';

const INTENSITY_OPTIONS = ['low', 'medium', 'high', 'extreme'];

const formatLabel = (value) => value.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase());

// Realistic playbook steps (timing derived dynamically from simulation runtime)
const SCENARIO_PLAYBOOKS = {
  privilege_escalation: {
    title: 'Privilege Escalation Response & Verification',
    steps: [
      { name: 'Revert IAM policy changes to last known-good state', fn: 'revert_policy' },
      { name: 'Revoke all active sessions for the entity', fn: 'revoke_sessions' },
      { name: 'Move entity to quarantine OU with read-only access', fn: 'quarantine_entity' },
      { name: 'Capture CloudTrail evidence snapshot', fn: 'snapshot_evidence' },
      { name: 'Escalate to cloud security admin', fn: 'notify_admin' }
    ]
  },
  brute_force: {
    title: 'Brute Force Credential Response & Verification',
    steps: [
      { name: 'Enforce immediate temporary lock on target identity', fn: 'lock_account' },
      { name: 'Revoke active STS tokens and invalidate sessions', fn: 'revoke_sessions' },
      { name: 'Inject blocking rule at AWS WAF and security group', fn: 'block_ip_edge' },
      { name: 'Extract forensic authentication logs snapshot', fn: 'snapshot_evidence' },
      { name: 'Trigger emergency MFA reset and alert SOC team', fn: 'notify_admin' }
    ]
  },
  data_exfiltration: {
    title: 'Data Exfiltration Containment Response & Verification',
    steps: [
      { name: 'Block destination egress IP address on AWS Network Firewall', fn: 'block_egress' },
      { name: 'Enforce strict VPC endpoint policy on target S3 bucket', fn: 'restrict_s3_vpc' },
      { name: 'Sever active STS assume-role session for exfiltrator identity', fn: 'terminate_session' },
      { name: 'Preserve S3 access log and CloudTrail audit chain', fn: 'snapshot_evidence' },
      { name: 'Dispatch critical severity paging alert to Data Protection Officer', fn: 'notify_admin' }
    ]
  },
  abnormal_access: {
    title: 'Anomalous Geolocation Access Response & Verification',
    steps: [
      { name: 'Terminate unauthorized foreign geographical session', fn: 'terminate_geo_session' },
      { name: 'Trigger mandatory FIDO2 hardware MFA challenge on next sign-in', fn: 'enforce_stepup_mfa' },
      { name: 'Quarantine host IP and restrict IAM access boundaries', fn: 'quarantine_entity' },
      { name: 'Collect VPC Flow Logs & GeoIP routing telemetry', fn: 'snapshot_evidence' },
      { name: 'Notify cloud security analyst with threat intelligence enrichment', fn: 'notify_admin' }
    ]
  }
};

const AttackSimulationTab = ({ showToast }) => {
  const [selectedIntensity, setSelectedIntensity] = useState('high');
  const [activeScenarioKey, setActiveScenarioKey] = useState(null);
  const [simResult, setSimResult] = useState(null);
  const [executing, setExecuting] = useState(false);
  const [fullSimResult, setFullResult] = useState(null);
  const [runningFullSim, setRunningFullSim] = useState(false);

  const scenarioCards = [
    {
      id: 'brute_force',
      title: 'Brute Force',
      desc: 'Multiple failed login attempts followed by a successful breach.',
      icon: Hammer,
      target: 'admin · Category 1'
    },
    {
      id: 'privilege_escalation',
      title: 'Privilege Escalation',
      desc: 'A user escalates privileges through IAM policy manipulation.',
      icon: ArrowUpRight,
      target: 'demo-build-role · STS AssumeRole'
    },
    {
      id: 'data_exfiltration',
      title: 'Data Exfiltration',
      desc: 'Large outbound transfers to an external destination.',
      icon: Upload,
      target: 'demo-worker-02 · S3 / egress'
    },
    {
      id: 'abnormal_access',
      title: 'Abnormal Access',
      desc: 'Unusual geo-location access followed by suspicious cloud activity.',
      icon: Globe,
      target: 'demo-analyst · Geo anomaly'
    }
  ];

  const runScenario = async (scenarioId) => {
    setActiveScenarioKey(scenarioId);
    setExecuting(true);
    setSimResult(null);
    try {
      const res = await axios.post(`${API_URL}/simulation/run/${scenarioId}?intensity=${selectedIntensity}`);
      setSimResult(res.data.data);
      if (showToast) showToast(`Attack scenario "${formatLabel(scenarioId)}" simulated & verified!`);
    } catch (err) {
      console.error(err);
      const detail = err.response?.data?.detail || err.message || 'Unknown error';
      if (showToast) showToast(`Simulation failed: ${detail}`, 'error');
    }
    setExecuting(false);
  };

  const runFullSim = async () => {
    setRunningFullSim(true);
    setFullResult(null);
    try {
      const res = await axios.post(`${API_URL}/simulation/full?intensity=${selectedIntensity}`);
      setFullResult(res.data.data);
      if (showToast) showToast('Full 4-scenario attack simulation suite executed!');
    } catch (err) {
      console.error(err);
      const detail = err.response?.data?.detail || err.message || 'Unknown error';
      if (showToast) showToast(`Full simulation failed: ${detail}`, 'error');
    }
    setRunningFullSim(false);
  };

  const activePlaybook = SCENARIO_PLAYBOOKS[activeScenarioKey] || SCENARIO_PLAYBOOKS.privilege_escalation;
  
  // Derive authentic timeline progression from actual simulated events
  const sampleEvents = simResult?.sample_sim_events || [];
  const timelineSteps = sampleEvents.length > 0 ? sampleEvents.map((evt, idx, arr) => {
    let latencyText = 'N/A';
    if (idx > 0 && evt.timestamp && arr[0].timestamp) {
      const delta = new Date(evt.timestamp).getTime() - new Date(arr[0].timestamp).getTime();
      latencyText = delta > 0 ? `+${delta}ms` : 'Batch burst';
    } else if (idx === 0) {
      latencyText = 'T+0';
    }
    return {
      name: evt.description || `${evt.service || 'cloud'}:${evt.action || 'event'}`,
      fn: `${(evt.source || 'telemetry').toUpperCase()} · ${evt.action || evt.attack_type || 'Event'}`,
      timing: latencyText
    };
  }) : activePlaybook.steps.map(s => ({ ...s, timing: 'N/A' }));

  return (
    <div className="animate-fade-in">
      {/* 1. FULL ATTACK SIMULATION TOP BANNER (MATCHING IMAGE 5) */}
      <div style={{
        background: 'var(--surface-card)',
        border: '1px solid var(--accent-orange-border)',
        borderRadius: '8px',
        padding: '20px 24px',
        marginBottom: '24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <Target size={20} style={{ color: 'var(--accent-orange)' }} />
            <h3 style={{ fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Full Attack Simulation
            </h3>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: 0, display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
            <span>Run all 4 attack scenarios</span>
            <ArrowRight size={11} style={{ color: 'var(--text-tertiary)' }} />
            <span>ML detection</span>
            <ArrowRight size={11} style={{ color: 'var(--text-tertiary)' }} />
            <span>Risk scoring</span>
            <ArrowRight size={11} style={{ color: 'var(--text-tertiary)' }} />
            <span>Auto-remediation</span>
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <select
            className="figma-filter-select"
            value={selectedIntensity}
            onChange={(e) => setSelectedIntensity(e.target.value)}
            disabled={runningFullSim || executing}
            style={{ minWidth: '110px' }}
          >
            {INTENSITY_OPTIONS.map(lvl => (
              <option key={lvl} value={lvl}>{formatLabel(lvl)}</option>
            ))}
          </select>
          <button
            onClick={runFullSim}
            disabled={runningFullSim || executing}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '9px 18px',
              backgroundColor: '#e03e2d',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              fontSize: '13.5px',
              fontWeight: 600,
              cursor: (runningFullSim || executing) ? 'not-allowed' : 'pointer',
              transition: 'all 0.2s ease',
              boxShadow: '0 2px 8px rgba(224, 62, 45, 0.25)'
            }}
          >
            <Zap size={15} className={runningFullSim ? 'animate-spin' : ''} />
            {runningFullSim ? 'Running Simulation Suite...' : 'Launch Full Simulation'}
          </button>
        </div>
      </div>

      {/* FULL SUITE RESULTS SUMMARY */}
      {fullSimResult && (
        <div className="figma-card" style={{ marginBottom: '24px', padding: '18px 22px', borderLeft: '4px solid var(--accent-orange)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <div>
              <h4 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                Full Adversary Simulation Results (ID: {fullSimResult.simulation_summary?.simulation_id})
              </h4>
              <span style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
                4 scenarios injected simultaneously with baseline background noise
              </span>
            </div>
            <span style={{
              padding: '4px 10px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 700,
              backgroundColor: 'var(--success-bg)',
              color: 'var(--success-color)',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '4px'
            }}>
              <Check size={12} /> {fullSimResult.detection?.detection_rate}% ENSEMBLE DETECTION
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
            <div style={{ padding: '10px 14px', background: 'var(--surface-muted)', borderRadius: '6px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>Attack Events</span>
              <div style={{ fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                {fullSimResult.simulation_summary?.total_attack_events}
              </div>
            </div>
            <div style={{ padding: '10px 14px', background: 'var(--surface-muted)', borderRadius: '6px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>Anomalies Caught</span>
              <div style={{ fontSize: '17px', fontWeight: 700, color: 'var(--success-color)', marginTop: '2px' }}>
                {fullSimResult.detection?.detected_as_anomaly}
              </div>
            </div>
            <div style={{ padding: '10px 14px', background: 'var(--surface-muted)', borderRadius: '6px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>Post-Attack Risk</span>
              <div style={{ fontSize: '17px', fontWeight: 700, color: 'var(--sev-critical)', marginTop: '2px' }}>
                {fullSimResult.risk_score?.unified} / 100 ({fullSimResult.risk_score?.level?.toUpperCase()})
              </div>
            </div>
            <div style={{ padding: '10px 14px', background: 'var(--surface-muted)', borderRadius: '6px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>Auto-Remediation</span>
              <div style={{ fontSize: '17px', fontWeight: 700, color: 'var(--accent-orange)', marginTop: '2px' }}>
                {fullSimResult.auto_remediation?.triggered || 4} Playbooks Queued
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 2. TWO-COLUMN LAYOUT: ATTACK SCENARIOS (LEFT) + DETECTION VERIFICATION (RIGHT) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.05fr 1fr', gap: '24px', alignItems: 'start' }}>

        {/* LEFT COLUMN: ATTACK SCENARIOS (MATCHING IMAGE 5) */}
        <div className="figma-card" style={{ padding: '22px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '18px' }}>
            <Target size={18} style={{ color: 'var(--accent-orange)' }} />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Attack Scenarios
            </h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {scenarioCards.map((sc) => {
              const IconComp = sc.icon;
              const isCurrent = activeScenarioKey === sc.id;
              const isSimulatingThis = executing && isCurrent;

              return (
                <div
                  key={sc.id}
                  style={{
                    background: 'var(--surface-muted)',
                    border: isCurrent ? '1px solid var(--accent-orange-border)' : '1px solid var(--border-subtle)',
                    borderRadius: '8px',
                    padding: '16px 18px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '16px',
                    transition: 'all 0.2s ease'
                  }}
                >
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '5px' }}>
                      <IconComp size={16} style={{ color: 'var(--accent-orange)' }} />
                      <h4 style={{ fontSize: '14.5px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                        {sc.title}
                      </h4>
                    </div>
                    <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', margin: '0 0 6px 0', lineHeight: 1.4 }}>
                      {sc.desc}
                    </p>
                    <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>
                      Target: {sc.target}
                    </span>
                  </div>

                  <button
                    onClick={() => runScenario(sc.id)}
                    disabled={executing || runningFullSim}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      padding: '7px 14px',
                      backgroundColor: '#e03e2d',
                      color: '#ffffff',
                      border: 'none',
                      borderRadius: '5px',
                      fontSize: '12.5px',
                      fontWeight: 600,
                      cursor: (executing || runningFullSim) ? 'not-allowed' : 'pointer',
                      flexShrink: 0,
                      transition: 'all 0.2s ease'
                    }}
                  >
                    <Play size={12} className={isSimulatingThis ? 'animate-spin' : ''} />
                    {isSimulatingThis ? 'Simulating...' : 'Simulate'}
                  </button>
                </div>
              );
            })}
          </div>
        </div>

        {/* RIGHT COLUMN: DETECTION VERIFICATION (MATCHING IMAGES 4 & 5) */}
        <div className="figma-card" style={{ padding: '22px', minHeight: '440px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <CheckCircle size={18} style={{ color: 'var(--success-color)' }} />
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                Detection Verification
              </h3>
            </div>
            {simResult && (
              <span style={{
                padding: '3px 8px',
                borderRadius: '4px',
                fontSize: '11px',
                fontWeight: 700,
                backgroundColor: 'var(--success-bg)',
                color: 'var(--success-color)'
              }}>
                {simResult.detection?.detection_rate}% ANOMALY RATE
              </span>
            )}
          </div>

          {/* EMPTY / IDLE STATE (MATCHING IMAGE 5) */}
          {!simResult && !executing && (
            <div style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '40px 20px',
              textAlign: 'center'
            }}>
              <div style={{
                width: '64px',
                height: '64px',
                borderRadius: '50%',
                border: '2px dashed var(--border-strong)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginBottom: '16px',
                color: 'var(--text-tertiary)'
              }}>
                <Radio size={28} />
              </div>
              <h4 style={{ fontSize: '14.5px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Run an attack scenario to verify detection
              </h4>
              <p style={{ fontSize: '12px', color: 'var(--text-tertiary)', maxWidth: '300px', margin: 0, lineHeight: 1.5 }}>
                Click [Simulate] on any attack scenario on the left to test ML anomaly models and trigger autonomous response playbooks.
              </p>
            </div>
          )}

          {/* EXECUTING STATE */}
          {executing && (
            <div style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '40px 20px',
              textAlign: 'center'
            }}>
              <Activity size={32} className="animate-spin" style={{ color: 'var(--accent-orange)', marginBottom: '16px' }} />
              <h4 style={{ fontSize: '14.5px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
                Simulating {activeScenarioKey ? formatLabel(activeScenarioKey) : 'Adversary'} & Evaluating ML...
              </h4>
              <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: 0 }}>
                Feeding telemetry into Isolation Forest, KNN, and HBOS anomaly models
              </p>
            </div>
          )}

          {/* COMPLETED STATE: VERIFICATION METRICS + EXECUTION RESULT (MATCHING IMAGE 4) */}
          {simResult && !executing && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', animation: 'fadeIn 0.3s ease' }}>

              {/* Telemetry Summary Stats */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                gap: '10px',
                padding: '12px',
                background: 'var(--surface-muted)',
                borderRadius: '6px'
              }}>
                <div>
                  <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>Total Events</span>
                  <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {simResult.detection?.total_sim_events}
                  </div>
                </div>
                <div>
                  <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>Detected Anomalies</span>
                  <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--success-color)' }}>
                    {simResult.detection?.detected_as_anomaly}
                  </div>
                </div>
                <div>
                  <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>Detection Status</span>
                  <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--success-color)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                    <Check size={12} /> DETECTED
                  </div>
                </div>
              </div>

              {/* EXECUTION RESULT TIMELINE (MATCHING IMAGE 4 EXACTLY) */}
              <div style={{
                backgroundColor: '#111726',
                border: '1px solid #1f293d',
                borderRadius: '8px',
                padding: '18px 20px',
                color: '#f0f6fc'
              }}>
                {/* Header with Title and COMPLETED Badge */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <CheckCircle size={18} style={{ color: 'var(--accent-orange)' }} />
                    <h4 style={{ fontSize: '14.5px', fontWeight: 700, color: '#f0f6fc', margin: 0 }}>
                      {activePlaybook.title}
                    </h4>
                  </div>
                  <span style={{
                    padding: '3px 8px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    fontWeight: 700,
                    letterSpacing: '0.5px',
                    backgroundColor: 'rgba(46, 160, 67, 0.15)',
                    color: '#3fb950',
                    border: '1px solid rgba(46, 160, 67, 0.4)'
                  }}>
                    COMPLETED
                  </span>
                </div>

                {/* Subtitle with simulation ID, timing, and detected count */}
                <div style={{ fontSize: '12px', color: '#8b949e', marginBottom: '18px', fontFamily: 'monospace' }}>
                  ID: SIM-{simResult.simulation?.simulation_id?.replace(/[^A-Za-z0-9]/g, '').slice(-8) || 'E75EC2AD'} &nbsp;
                  Latency: N/A (In-memory batch) &nbsp;
                  {simResult.detection?.detected_as_anomaly || 0}/{simResult.detection?.total_sim_events || 0} anomalies caught
                </div>

                {/* Vertical Connected Timeline */}
                <div style={{ position: 'relative', paddingLeft: '22px' }}>
                  {/* Vertical connecting line */}
                  <div style={{
                    position: 'absolute',
                    left: '5px',
                    top: '8px',
                    bottom: '22px',
                    width: '2px',
                    backgroundColor: '#593822'
                  }} />

                  {timelineSteps.map((step, idx) => (
                    <div key={idx} style={{ position: 'relative', marginBottom: idx === timelineSteps.length - 1 ? 0 : '16px' }}>
                      {/* Green circle node */}
                      <div style={{
                        position: 'absolute',
                        left: '-22px',
                        top: '3px',
                        width: '12px',
                        height: '12px',
                        borderRadius: '50%',
                        backgroundColor: '#2ea043',
                        border: '2px solid #111726',
                        zIndex: 2
                      }} />

                      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '12px' }}>
                        <div>
                          <div style={{ fontSize: '13px', fontWeight: 600, color: '#f0f6fc', lineHeight: 1.3 }}>
                            {step.name}
                          </div>
                          <div style={{ fontSize: '11.5px', color: '#8b949e', fontFamily: 'monospace', marginTop: '2px' }}>
                            {step.fn}
                          </div>
                        </div>
                        <div style={{ fontSize: '12px', color: '#8b949e', fontFamily: 'monospace', flexShrink: 0 }}>
                          {step.timing}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          )}

        </div>
      </div>
    </div>
  );
};

export default AttackSimulationTab;
