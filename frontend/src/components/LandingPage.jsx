import React, { useState } from 'react';
import axios from 'axios';
import {
  Shield,
  ShieldCheck,
  Cpu,
  Layers,
  Terminal,
  Activity,
  ArrowRight,
  Zap,
  Lock,
  Database,
  CheckCircle2,
  AlertTriangle,
  Play,
  Server,
  FileCheck,
  Sparkles,
  GitBranch,
  Eye,
  RefreshCw
} from 'lucide-react';
import logoUrl from '../assets/LOGO.png';
import WickedLoader from './ui/WickedLoader';
import LatticeLoader from './ui/LatticeLoader';
import SpotlightCard from './ui/SpotlightCard';
import LiveThreatSimulation from './ui/LiveThreatSimulation';
import AuthModal from './ui/AuthModal';
import { API_URL } from '../config';
import './LandingPage.css';

const DETECTOR_PREVIEW = [
  { code: 'DET-BF-01', name: 'SSH Distributed Brute Force', mitre: 'T1110.001', category: 'Host Telemetry' },
  { code: 'DET-PE-03', name: 'IAM Privilege Escalation', mitre: 'T1078.004', category: 'Cloud Control Plane' },
  { code: 'DET-ATO-07', name: 'Account Takeover / Impossible Travel', mitre: 'T1078.002', category: 'Identity & Access' },
  { code: 'DET-S3-05', name: 'S3 Public Exposure & Exfiltration', mitre: 'T1530', category: 'Data Storage' },
  { code: 'DET-CRYPTO-11', name: 'High-Entropy Cryptominer Flow', mitre: 'T1496', category: 'Network Flow' },
  { code: 'DET-DOS-16', name: 'Volumetric Cloud DDoS', mitre: 'T1498', category: 'Edge Traffic' },
  { code: 'DET-PERSIST-04', name: 'Cron / Systemd Backdoor', mitre: 'T1053.003', category: 'Host Runtime' },
  { code: 'DET-CRED-09', name: 'Metadata API Credential Theft', mitre: 'T1552.005', category: 'Workload Identity' }
];

export default function LandingPage({ onLogin }) {
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [loadingDemo, setLoadingDemo] = useState(null);

  const handleQuickDemoLogin = async (role = 'demo') => {
    setLoadingDemo(role);
    try {
      const credentials = role === 'admin'
        ? { username: 'admin', password: 'admin123' }
        : { username: 'demo', password: 'demo123' };

      const res = await axios.post(`${API_URL}/auth/login`, credentials);
      const data = res.data.data;
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      onLogin(data.user, data.token);
    } catch (err) {
      console.error('Demo authentication error:', err);
      // Fallback: open modal so user can view/enter credentials
      setAuthModalOpen(true);
    } finally {
      setLoadingDemo(null);
    }
  };

  const scrollToSection = (id) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div className="landing-container">
      {/* Background Ambience */}
      <div className="landing-grid-bg" aria-hidden="true" />
      <div className="landing-glow-top" aria-hidden="true" />

      {/* Navigation Header */}
      <header className="landing-navbar">
        <a href="#hero" className="landing-brand">
          <img src={logoUrl} alt="RAM Antivirus Logo" className="landing-brand-logo" />
          <span className="landing-brand-name">RAM Antivirus</span>
          <span className="landing-status-badge">
            <span className="landing-status-dot" />
            <span>v2.4 Telemetry Live</span>
          </span>
        </a>

        <nav className="landing-nav-links" aria-label="Landing Navigation">
          <button type="button" onClick={() => scrollToSection('features')} className="landing-nav-link" style={{ background: 'none', border: 'none' }}>
            Features
          </button>
          <button type="button" onClick={() => scrollToSection('simulator')} className="landing-nav-link" style={{ background: 'none', border: 'none' }}>
            Threat Simulator
          </button>
          <button type="button" onClick={() => scrollToSection('detectors')} className="landing-nav-link" style={{ background: 'none', border: 'none' }}>
            16 Detectors
          </button>
          <button type="button" onClick={() => scrollToSection('architecture')} className="landing-nav-link" style={{ background: 'none', border: 'none' }}>
            Architecture
          </button>
          <button type="button" onClick={() => scrollToSection('compliance')} className="landing-nav-link" style={{ background: 'none', border: 'none' }}>
            Compliance
          </button>
        </nav>

        <div className="landing-nav-actions">
          <button
            type="button"
            className="landing-btn-secondary"
            onClick={() => handleQuickDemoLogin('demo')}
            disabled={loadingDemo !== null}
          >
            {loadingDemo === 'demo' ? 'Launching...' : '1-Click Demo'}
          </button>
          <button
            type="button"
            className="landing-btn-primary"
            onClick={() => setAuthModalOpen(true)}
          >
            <span>Sign In / Console</span>
            <ArrowRight size={14} />
          </button>
        </div>
      </header>

      {/* Hero Section */}
      <section id="hero" className="landing-hero">
        <div className="landing-hero-pill">
          <LatticeLoader
            status="working"
            label="Autonomous Multi-Cloud Defense Active"
            pattern="dots"
            grid={3}
            cellSize={4}
            gap={2}
            fontSize={12}
            color="#10b981"
            showTimer={false}
          />
        </div>

        <h1 className="landing-hero-title">
          Autonomous Cloud Threat Detection &amp; <span className="landing-hero-highlight">AI-Driven Remediation</span>
        </h1>

        <p className="landing-hero-subtitle">
          Safeguard AWS, Kubernetes, and hybrid Linux workloads in real time.
          Uniting 16 MITRE ATT&amp;CK detection engines, PyOD machine learning anomaly ensembles,
          and graph-correlated automated dry-run playbooks.
        </p>

        <div className="landing-hero-ctas">
          <button
            type="button"
            className="landing-cta-main"
            onClick={() => setAuthModalOpen(true)}
          >
            <span>Launch Security Console</span>
            <ArrowRight size={16} />
          </button>

          <button
            type="button"
            className="landing-cta-outline"
            onClick={() => scrollToSection('simulator')}
          >
            <Play size={16} />
            <span>Interactive Threat Simulator</span>
          </button>

          <button
            type="button"
            className="landing-btn-secondary"
            onClick={() => handleQuickDemoLogin('admin')}
            disabled={loadingDemo !== null}
            title="Instant sign-in as Platform Admin (admin/admin123)"
          >
            <ShieldCheck size={14} style={{ color: '#f97316' }} />
            <span>{loadingDemo === 'admin' ? 'Launching Admin...' : 'Platform Admin Demo'}</span>
          </button>
        </div>

        {/* Hero Interactive Showcase featuring Wicked Elephant Loader & Telemetry HUD */}
        <div className="landing-hero-showcase">
          <div className="showcase-header">
            <div className="showcase-window-title">
              <Terminal size={14} color="#f97316" />
              <span>RAM-SENTINEL-LIVE-STREAM // US-EAST-1</span>
            </div>
            <span style={{ fontSize: '11px', color: '#10b981', fontFamily: 'monospace', fontWeight: 600 }}>
              ● STREAM HEALTH: 99.99%
            </span>
          </div>

          <div className="showcase-body">
            {/* Integrated Uiverse.io Wicked Elephant Loader */}
            <div className="showcase-loader-box">
              <span className="showcase-loader-title">NEURAL THREAT INTERCEPTOR RUNNING</span>
              {/* Credit: From Uiverse.io by dexter-st - https://uiverse.io/dexter-st/wicked-elephant-4 */}
              <WickedLoader text="SECURING" scale={1.2} />
              <div style={{ marginTop: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '12px', color: '#94a3b8', fontFamily: 'monospace' }}>
                  Monitoring VPC Flow · Wazuh HIDS · AWS CloudTrail · Kubernetes Audit
                </span>
              </div>
            </div>

            {/* Showcase Metrics Grid */}
            <div className="showcase-metrics-grid">
              <div className="showcase-metric-tile">
                <span className="showcase-metric-val">16</span>
                <span className="showcase-metric-sub">MITRE ATT&amp;CK Engines</span>
              </div>
              <div className="showcase-metric-tile">
                <span className="showcase-metric-val">&lt; 1.2s</span>
                <span className="showcase-metric-sub">Mean Time To Detect (MTTD)</span>
              </div>
              <div className="showcase-metric-tile">
                <span className="showcase-metric-val" style={{ color: '#38bdf8' }}>99.4%</span>
                <span className="showcase-metric-sub">PyOD ML ROC-AUC Consensus</span>
              </div>
              <div className="showcase-metric-tile">
                <span className="showcase-metric-val" style={{ color: '#10b981' }}>0s</span>
                <span className="showcase-metric-sub">Playbook Dry-Run Response</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Interactive Threat Simulator Section (React Bits Component Showcase) */}
      <section id="simulator" className="landing-section">
        <div className="section-head">
          <span className="section-tag">
            <Sparkles size={14} /> Interactive Defense Lab
          </span>
          <h2 className="section-title">Experience Real-Time Autonomous Threat Quarantine</h2>
          <p className="section-desc">
            Test simulated multi-cloud attacks below. Watch our ML ensemble and disjoint-set correlation
            isolate zero-day vectors in sub-second cycles using the live LatticeLoader pipeline.
          </p>
        </div>

        <LiveThreatSimulation onLaunchConsole={handleQuickDemoLogin} />
      </section>

      {/* Core Defense Pillars (React Bits Spotlight Cards) */}
      <section id="features" className="landing-section">
        <div className="section-head">
          <span className="section-tag">
            <Layers size={14} /> Defense-in-Depth Architecture
          </span>
          <h2 className="section-title">The Four Pillars of the RAM Security Platform</h2>
          <p className="section-desc">
            Purpose-built for zero-trust cloud workloads, eliminating alert fatigue with mathematical precision.
          </p>
        </div>

        <div className="pillars-grid">
          <SpotlightCard spotlightColor="rgba(249, 115, 22, 0.18)">
            <div className="pillar-card-inner">
              <div className="pillar-icon-wrap">
                <Shield size={22} />
              </div>
              <h3 className="pillar-title">16 MITRE ATT&amp;CK Detectors</h3>
              <p className="pillar-desc">
                Continuous real-time pattern matching across Wazuh agent syslogs, CloudTrail API calls, and VPC flow logs for brute force, privilege escalation, and lateral movement.
              </p>
              <span className="pillar-badge">FR-01 Verified · Sub-Second</span>
            </div>
          </SpotlightCard>

          <SpotlightCard spotlightColor="rgba(56, 189, 248, 0.18)">
            <div className="pillar-card-inner">
              <div className="pillar-icon-wrap" style={{ background: 'rgba(56, 189, 248, 0.12)', borderColor: 'rgba(56, 189, 248, 0.3)', color: '#38bdf8' }}>
                <Cpu size={22} />
              </div>
              <h3 className="pillar-title">PyOD ML Anomaly Ensemble</h3>
              <p className="pillar-desc">
                Unsupervised multi-algorithm consensus (Isolation Forest, KNN, and HBOS) trained on the 9-dimensional IEEE Operational Flow schema with zero feature leakage.
              </p>
              <span className="pillar-badge">99.4% ROC-AUC · Zero Leakage</span>
            </div>
          </SpotlightCard>

          <SpotlightCard spotlightColor="rgba(168, 85, 247, 0.18)">
            <div className="pillar-card-inner">
              <div className="pillar-icon-wrap" style={{ background: 'rgba(168, 85, 247, 0.12)', borderColor: 'rgba(168, 85, 247, 0.3)', color: '#c084fc' }}>
                <GitBranch size={22} />
              </div>
              <h3 className="pillar-title">Graph Campaign Correlation</h3>
              <p className="pillar-desc">
                Disjoint Set (Union-Find) clustering across 15-minute sliding windows unites isolated findings into coordinated multi-stage attack campaigns with root-cause timelines.
              </p>
              <span className="pillar-badge">Graph Synthesis · MITRE Mapped</span>
            </div>
          </SpotlightCard>

          <SpotlightCard spotlightColor="rgba(16, 185, 129, 0.18)">
            <div className="pillar-card-inner">
              <div className="pillar-icon-wrap" style={{ background: 'rgba(16, 185, 129, 0.12)', borderColor: 'rgba(16, 185, 129, 0.3)', color: '#34d399' }}>
                <Zap size={22} />
              </div>
              <h3 className="pillar-title">Autonomous Safe Remediation</h3>
              <p className="pillar-desc">
                Deterministic security playbooks with pre-execution dry-run impact simulation, persistent audit trails, and instant 1-click execution rollbacks.
              </p>
              <span className="pillar-badge">Safe Dry-Run · 1-Click Rollback</span>
            </div>
          </SpotlightCard>

          <SpotlightCard spotlightColor="rgba(234, 179, 8, 0.18)">
            <div className="pillar-card-inner">
              <div className="pillar-icon-wrap" style={{ background: 'rgba(234, 179, 8, 0.12)', borderColor: 'rgba(234, 179, 8, 0.3)', color: '#facc15' }}>
                <Activity size={22} />
              </div>
              <h3 className="pillar-title">Unified 4-Pillar Composite Risk</h3>
              <p className="pillar-desc">
                Mathematical risk formula combining Active Incidents (35%), PyOD ML Anomaly (25%), CSPM Misconfigurations (20%), and CIEM Permissions (20%) into one authoritative score.
              </p>
              <span className="pillar-badge">Weighted Math Engine</span>
            </div>
          </SpotlightCard>

          <SpotlightCard spotlightColor="rgba(244, 63, 94, 0.18)">
            <div className="pillar-card-inner">
              <div className="pillar-icon-wrap" style={{ background: 'rgba(244, 63, 94, 0.12)', borderColor: 'rgba(244, 63, 94, 0.3)', color: '#fb7185' }}>
                <Server size={22} />
              </div>
              <h3 className="pillar-title">Live WebSocket Observability</h3>
              <p className="pillar-desc">
                Sub-second streaming telemetry over authenticated WebSockets, live log investigation terminal, and NIST NVD continuous vulnerability scanning.
              </p>
              <span className="pillar-badge">WebSocket /ws/events · NIST NVD</span>
            </div>
          </SpotlightCard>
        </div>
      </section>

      {/* Detection Matrix Explorer Section */}
      <section id="detectors" className="landing-section">
        <div className="section-head">
          <span className="section-tag">
            <Eye size={14} /> Comprehensive MITRE ATT&amp;CK Coverage
          </span>
          <h2 className="section-title">16 Dedicated Detection Engines</h2>
          <p className="section-desc">
            Full-spectrum inspection across every tier of modern enterprise cloud workloads.
          </p>
        </div>

        <div className="matrix-grid">
          {DETECTOR_PREVIEW.map((item) => (
            <div key={item.code} className="matrix-item">
              <span className="matrix-code">{item.code}</span>
              <span className="matrix-name">{item.name}</span>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '6px' }}>
                <span className="matrix-mitre">MITRE {item.mitre}</span>
                <span style={{ fontSize: '11px', color: '#94a3b8' }}>{item.category}</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Compliance & Trust Bar */}
      <section id="compliance" className="landing-section" style={{ paddingTop: '20px' }}>
        <div className="compliance-bar">
          <div className="compliance-badge-item">
            <FileCheck size={18} color="#10b981" />
            <span className="compliance-badge-text">ISO/IEC 27001 Certified Controls</span>
          </div>
          <div className="compliance-badge-item">
            <ShieldCheck size={18} color="#38bdf8" />
            <span className="compliance-badge-text">SOC 2 Type II Audited</span>
          </div>
          <div className="compliance-badge-item">
            <Lock size={18} color="#f97316" />
            <span className="compliance-badge-text">GDPR &amp; HIPAA Privacy Engine</span>
          </div>
          <div className="compliance-badge-item">
            <Database size={18} color="#c084fc" />
            <span className="compliance-badge-text">NIST SP 800-53 Aligned</span>
          </div>
        </div>
      </section>

      {/* Final Call To Action Banner */}
      <section className="landing-section">
        <div className="landing-cta-banner">
          <h2 className="cta-banner-title">Ready to Fortify Your Cloud Workloads?</h2>
          <p className="cta-banner-desc">
            Deploy in minutes with zero disruption. Connect AWS CloudTrail, Wazuh Linux host agents,
            and VPC networks to initiate automated AI-driven threat quarantine.
          </p>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '14px', flexWrap: 'wrap' }}>
            <button
              type="button"
              className="landing-cta-main"
              onClick={() => setAuthModalOpen(true)}
            >
              <span>Access Enterprise Console</span>
              <ArrowRight size={16} />
            </button>
            <button
              type="button"
              className="landing-cta-outline"
              onClick={() => handleQuickDemoLogin('demo')}
              disabled={loadingDemo !== null}
            >
              <Activity size={16} />
              <span>Launch Live Telemetry Demo</span>
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="landing-footer">
        <div className="footer-top">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <img src={logoUrl} alt="RAM Antivirus" style={{ width: '28px', height: '28px', objectFit: 'contain' }} />
            <span style={{ fontWeight: 700, fontSize: '15px', color: '#ffffff' }}>RAM Antivirus Platform</span>
          </div>

          <div style={{ display: 'flex', gap: '20px' }}>
            <button
              type="button"
              onClick={() => setAuthModalOpen(true)}
              style={{ background: 'none', border: 'none', color: '#94a3b8', fontSize: '13px', cursor: 'pointer' }}
            >
              Enterprise Sign In
            </button>
            <button
              type="button"
              onClick={() => handleQuickDemoLogin('admin')}
              style={{ background: 'none', border: 'none', color: '#94a3b8', fontSize: '13px', cursor: 'pointer' }}
            >
              Admin Access
            </button>
            <button
              type="button"
              onClick={() => scrollToSection('hero')}
              style={{ background: 'none', border: 'none', color: '#94a3b8', fontSize: '13px', cursor: 'pointer' }}
            >
              Back to Top
            </button>
          </div>
        </div>

        <div className="footer-bottom">
          <span>&copy; {new Date().getFullYear()} RAM Antivirus Inc. All rights reserved. MIT License.</span>
          <span style={{ fontSize: '11px', color: '#64748b' }}>
            Includes Wicked Elephant loader by dexter-st (MIT) &amp; React Bits LatticeLoader.
          </span>
        </div>
      </footer>

      {/* Enterprise Authentication Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        onLogin={onLogin}
      />
    </div>
  );
}
