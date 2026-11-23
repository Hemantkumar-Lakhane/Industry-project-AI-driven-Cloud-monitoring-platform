import React, { useState, useEffect } from 'react';
import { Play, ShieldAlert, Cpu, CheckCircle2, AlertTriangle, ArrowRight, Activity, Terminal } from 'lucide-react';
import LatticeLoader from './LatticeLoader';
import './LiveThreatSimulation.css';

const SCENARIOS = [
  {
    id: 'det-bf-01',
    name: 'SSH Brute Force Swarm',
    mitre: 'T1110.001',
    detector: 'DET-BF-01',
    severity: 'HIGH',
    vector: 'Wazuh Host Telemetry (Linux auth.log)',
    target: 'bastion-prod-01 (10.0.4.12)',
    anomalyScore: '0.94 / 1.00',
    description: '142 failed authentication attempts across 8 non-standard usernames from 3 distributed IP subnets within 45 seconds.',
    remediation: 'AUTOMATED_IP_BAN + SSHD_MFA_ENFORCE',
    findingsCount: 4,
    campaignId: 'CMP-2026-BF09'
  },
  {
    id: 'det-pe-03',
    name: 'IAM AssumeRole Privilege Jump',
    mitre: 'T1078.004',
    detector: 'DET-PE-03',
    severity: 'CRITICAL',
    vector: 'AWS CloudTrail Management Events',
    target: 'arn:aws:iam::123456789012:role/DevReadOnly -> AdminFull',
    anomalyScore: '0.98 / 1.00',
    description: 'Dev service principal elevated permissions by attaching AdministratorAccess policy without ticketing approval.',
    remediation: 'REVOKE_ACTIVE_SESSIONS + DETACH_POLICY + ALERT_SOC',
    findingsCount: 6,
    campaignId: 'CMP-2026-IAM88'
  },
  {
    id: 'det-leak-05',
    name: 'S3 Sensitive Data Exfiltration',
    mitre: 'T1530',
    detector: 'DET-LEAK-05',
    severity: 'CRITICAL',
    vector: 'VPC Flow Logs & S3 Data Events',
    target: 's3://prod-customer-vault-backup',
    anomalyScore: '0.91 / 1.00',
    description: 'Anomalous 48.2 GB outbound transfer to unclassified external IP with modified public ACL bucket policy.',
    remediation: 'BLOCK_PUBLIC_ACCESS + ISOLATE_VPC_ENDPOINT',
    findingsCount: 3,
    campaignId: 'CMP-2026-S3X01'
  },
  {
    id: 'det-crypto-11',
    name: 'Cryptominer Flow Anomaly',
    mitre: 'T1496',
    detector: 'DET-CRYPTO-11',
    severity: 'HIGH',
    vector: 'PyOD 9D Flow Ensemble (iForest+KNN)',
    target: 'i-09f48ac23789b (gpu-compute-02)',
    anomalyScore: '0.89 / 1.00',
    description: 'Sustained stratum+tcp protocol outbound bursts to known mining pools with 100% CPU core saturation.',
    remediation: 'ISOLATE_SECURITY_GROUP + SNAPSHOT_VOLUMES',
    findingsCount: 5,
    campaignId: 'CMP-2026-MINER4'
  }
];

export default function LiveThreatSimulation({ onLaunchConsole }) {
  const [selectedId, setSelectedId] = useState(SCENARIOS[0].id);
  const [status, setStatus] = useState('working');
  const [currentStep, setCurrentStep] = useState(0);
  const [loaderLabel, setLoaderLabel] = useState('Ingesting Telemetry');

  const activeScenario = SCENARIOS.find(s => s.id === selectedId) || SCENARIOS[0];

  const runSimulation = () => {
    setStatus('working');
    setCurrentStep(1);
    setLoaderLabel('Ingesting Telemetry Streams...');

    setTimeout(() => {
      setCurrentStep(2);
      setLoaderLabel('PyOD ML Anomaly Ensemble Scoring...');
    }, 900);

    setTimeout(() => {
      setCurrentStep(3);
      setLoaderLabel('Disjoint Set Graph Correlation...');
    }, 1800);

    setTimeout(() => {
      setCurrentStep(4);
      setStatus('done');
    }, 2800);
  };

  useEffect(() => {
    runSimulation();
  }, [selectedId]);

  return (
    <div className="threat-sim-container">
      {/* Scenario Selector Tabs */}
      <div className="threat-sim-tabs" role="tablist">
        {SCENARIOS.map((scenario) => (
          <button
            key={scenario.id}
            role="tab"
            aria-selected={scenario.id === selectedId}
            className={`threat-sim-tab-btn ${scenario.id === selectedId ? 'active' : ''}`}
            onClick={() => setSelectedId(scenario.id)}
          >
            <ShieldAlert size={15} />
            <span>{scenario.name}</span>
          </button>
        ))}
      </div>

      {/* Main Interactive Stage */}
      <div className="threat-sim-panel">
        <div className="threat-sim-meta">
          <div className="threat-sim-header">
            <span className="threat-mitre-tag">
              <Cpu size={12} /> {activeScenario.detector} · MITRE {activeScenario.mitre}
            </span>
            <span
              style={{
                fontSize: '11px',
                fontWeight: 700,
                color: activeScenario.severity === 'CRITICAL' ? '#f87171' : '#fb923c',
                padding: '3px 8px',
                borderRadius: '4px',
                background: activeScenario.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(249, 115, 22, 0.15)',
                border: `1px solid ${activeScenario.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(249, 115, 22, 0.3)'}`
              }}
            >
              {activeScenario.severity} SEVERITY
            </span>
          </div>

          <p className="threat-sim-desc">{activeScenario.description}</p>

          <div className="threat-sim-attributes">
            <div className="threat-attr-item">
              <span className="threat-attr-label">Target Asset</span>
              <span className="threat-attr-val">{activeScenario.target}</span>
            </div>
            <div className="threat-attr-item">
              <span className="threat-attr-label">Telemetry Ingest</span>
              <span className="threat-attr-val">{activeScenario.vector}</span>
            </div>
            <div className="threat-attr-item">
              <span className="threat-attr-label">PyOD ML Score</span>
              <span className="threat-attr-val" style={{ color: '#f97316' }}>{activeScenario.anomalyScore}</span>
            </div>
            <div className="threat-attr-item">
              <span className="threat-attr-label">Correlated Campaign</span>
              <span className="threat-attr-val" style={{ color: '#38bdf8' }}>{activeScenario.campaignId} ({activeScenario.findingsCount} findings)</span>
            </div>
          </div>

          <div className="threat-sim-actions">
            <button
              type="button"
              className="threat-sim-run-btn"
              onClick={runSimulation}
              disabled={status === 'working'}
            >
              <Play size={15} /> Re-run Simulation
            </button>
            {onLaunchConsole && (
              <button
                type="button"
                className="threat-sim-tab-btn"
                style={{ background: 'transparent' }}
                onClick={() => onLaunchConsole('demo')}
              >
                Inspect in Security Console <ArrowRight size={14} />
              </button>
            )}
          </div>
        </div>

        {/* Live Execution & LatticeLoader Stream */}
        <div className="threat-sim-output-card">
          <div className="threat-sim-output-header">
            <div className="terminal-dots">
              <span className="terminal-dot red" />
              <span className="terminal-dot yellow" />
              <span className="terminal-dot green" />
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Terminal size={13} color="#94a3b8" />
              <span style={{ fontSize: '11px', color: '#94a3b8' }}>RAM AI Sentinel Core v2.4</span>
            </div>
          </div>

          {/* Integrated React Bits LatticeLoader */}
          <div style={{ padding: '12px 0 16px 0', borderBottom: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <LatticeLoader
              status={status}
              label={loaderLabel}
              doneLabel="Threat Neutralized in"
              errorLabel="Analysis Interrupted"
              pattern={currentStep === 2 ? 'orbit' : currentStep === 3 ? 'spiral' : 'dots'}
              grid={3}
              shape="round"
              color="#fb923c"
              doneColor="#10b981"
              errorColor="#ef4444"
              cellSize={6}
              gap={3}
              fontSize={13}
              step={85}
              glow={true}
              glowColor="rgba(249, 115, 22, 0.6)"
              showTimer={true}
            />
          </div>

          {/* Live Step Progression Feed */}
          <div className="threat-live-feed" style={{ marginTop: '14px' }}>
            <div className={`feed-step ${currentStep >= 1 ? 'alert' : ''}`}>
              <span className="feed-step-badge">INGEST</span>
              <span>Normalized 50 raw telemetry events from {activeScenario.vector}.</span>
            </div>

            {currentStep >= 2 && (
              <div className="feed-step alert">
                <span className="feed-step-badge">PYOD-ML</span>
                <span>Ensemble alert: iForest (0.96) + KNN (0.92) tagged vector as anomalous (score {activeScenario.anomalyScore}).</span>
              </div>
            )}

            {currentStep >= 3 && (
              <div className="feed-step alert">
                <span className="feed-step-badge">GRAPH</span>
                <span>Union-Find clustered {activeScenario.findingsCount} findings into campaign <strong>{activeScenario.campaignId}</strong>.</span>
              </div>
            )}

            {currentStep >= 4 && (
              <div className="feed-step success">
                <span className="feed-step-badge">AUTO-PLAYBOOK</span>
                <span>Autonomous Dry-Run passed: <strong>{activeScenario.remediation}</strong> executed successfully. Threat isolated.</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
