import React, { useState } from 'react';
import axios from 'axios';
import {
  Shield,
  ShieldCheck,
  Cpu,
  Layers,
  Activity,
  ArrowRight,
  Zap,
  Lock,
  Database,
  CheckCircle2,
  AlertTriangle,
  Server,
  FileCheck,
  Check,
  Key,
  Eye,
  RefreshCw
} from 'lucide-react';
import logoUrl from '../assets/LOGO.png';
import AuthModal from './ui/AuthModal';
import { API_URL } from '../config';
import './LandingPage.css';

const CAPABILITIES = [
  {
    icon: <Shield size={24} style={{ color: 'var(--accent-orange)' }} />,
    title: 'Cloud Security Posture (CSPM)',
    desc: 'Continuous real-time auditing across AWS S3 buckets, EC2 security groups, RDS databases, and CloudTrail logging to prevent public exposure and configuration drift.',
    badge: 'Continuous Audit'
  },
  {
    icon: <Key size={24} style={{ color: 'var(--accent-orange)' }} />,
    title: 'Identity & Access Governance (CIEM)',
    desc: 'Zero-trust entitlement analysis identifying overly permissive AdministratorAccess policies, accounts lacking MFA, stale 90-day credentials, and wildcard permissions.',
    badge: 'Least-Privilege'
  },
  {
    icon: <Activity size={24} style={{ color: 'var(--accent-orange)' }} />,
    title: 'Live Telemetry & Anomaly Ingestion',
    desc: 'Direct ingestion of live AWS CloudTrail management events with automated normalization, entity extraction, and multi-vector behavioral anomaly evaluation.',
    badge: 'Real-Time Stream'
  },
  {
    icon: <Zap size={24} style={{ color: 'var(--accent-orange)' }} />,
    title: 'Autonomous Safe Remediation',
    desc: 'Deterministic containment playbooks with mandatory pre-execution dry-run impact simulation, persistent audit logs, and instantaneous 1-click rollback.',
    badge: 'Safe Dry-Run'
  }
];

const COMPLIANCE_STANDARDS = [
  { name: 'CIS AWS Foundations Benchmark', code: 'CIS v3.0', coverage: '98% Controls', desc: 'S3 public access, IAM credential rotation, root account protection, and CloudWatch retention.' },
  { name: 'ISO/IEC 27001:2022', code: 'ISO 27001', coverage: 'Annex A Controls', desc: 'Organizational information security controls, access restriction, and incident management.' },
  { name: 'SOC 2 Type II', code: 'AICPA SOC-2', coverage: 'Trust Criteria', desc: 'Security, availability, and confidentiality audit trail verification and continuous evidence logging.' },
  { name: 'GDPR Article 32', code: 'GDPR Art. 32', coverage: 'Data Protection', desc: 'Security of processing, encryption of sensitive data stores, and continuous access control evaluation.' }
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
    <div className="landing-corporate-container">
      {/* Top Corporate Navigation */}
      <header className="landing-corporate-nav">
        <div className="landing-nav-inner">
          <a href="#hero" className="landing-brand-wrap">
            <img src={logoUrl} alt="RAM Antivirus Logo" className="landing-brand-img" />
            <span className="landing-brand-text">RAM Antivirus</span>
            <span className="landing-live-badge">
              <span className="landing-live-dot" />
              <span>Live Cloud Security</span>
            </span>
          </a>

          <nav className="landing-nav-menu" aria-label="Main Navigation">
            <button type="button" onClick={() => scrollToSection('capabilities')} className="landing-nav-item">
              Platform
            </button>
            <button type="button" onClick={() => scrollToSection('architecture')} className="landing-nav-item">
              Architecture
            </button>
            <button type="button" onClick={() => scrollToSection('compliance')} className="landing-nav-item">
              Compliance
            </button>
          </nav>

          <div className="landing-nav-buttons">
            <button
              type="button"
              className="landing-btn-login"
              onClick={() => setAuthModalOpen(true)}
            >
              Sign In
            </button>
            <button
              type="button"
              className="landing-btn-primary"
              onClick={() => handleQuickDemoLogin('demo')}
              disabled={loadingDemo !== null}
            >
              {loadingDemo === 'demo' ? 'Launching...' : 'Open Console'}
            </button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section id="hero" className="landing-hero-section">
        <div className="landing-hero-content">
          <div className="landing-badge-pill">
            <ShieldCheck size={14} style={{ color: 'var(--accent-orange)' }} />
            <span>Autonomous Cloud Workload Security & Posture Management</span>
          </div>

          <h1 className="landing-hero-headline">
            Continuous Cloud Defense &amp; <br />
            <span className="landing-headline-highlight">Automated Security Posture</span>
          </h1>

          <p className="landing-hero-subhead">
            Continuous threat detection across AWS CloudTrail, IAM identities, and cloud infrastructure.
            Identify misconfigurations, correlate multi-signal attack campaigns, and execute automated
            containment playbooks with dry-run verification.
          </p>

          <div className="landing-cta-row">
            <button
              type="button"
              className="landing-btn-hero-primary"
              onClick={() => setAuthModalOpen(true)}
            >
              <span>Access Security Console</span>
              <ArrowRight size={16} />
            </button>

            <button
              type="button"
              className="landing-btn-hero-secondary"
              onClick={() => handleQuickDemoLogin('demo')}
              disabled={loadingDemo !== null}
            >
              <Activity size={16} style={{ color: 'var(--accent-orange)' }} />
              <span>Explore Live Workspace</span>
            </button>
          </div>

          {/* Quick Metrics Bar */}
          <div className="landing-kpi-bar">
            <div className="landing-kpi-item">
              <span className="landing-kpi-num">16</span>
              <span className="landing-kpi-lbl">MITRE ATT&amp;CK Detectors</span>
            </div>
            <div className="landing-kpi-divider" />
            <div className="landing-kpi-item">
              <span className="landing-kpi-num">24/7</span>
              <span className="landing-kpi-lbl">CloudTrail API Stream</span>
            </div>
            <div className="landing-kpi-divider" />
            <div className="landing-kpi-item">
              <span className="landing-kpi-num">100%</span>
              <span className="landing-kpi-lbl">Dry-Run Safe Remediation</span>
            </div>
            <div className="landing-kpi-divider" />
            <div className="landing-kpi-item">
              <span className="landing-kpi-num">4</span>
              <span className="landing-kpi-lbl">Compliance Benchmarks</span>
            </div>
          </div>
        </div>
      </section>

      {/* Core Platform Capabilities Section */}
      <section id="capabilities" className="landing-section-wrap">
        <div className="landing-section-header">
          <span className="landing-section-eyebrow">Enterprise Protection Modules</span>
          <h2 className="landing-section-heading">Purpose-Built for Cloud Infrastructure</h2>
          <p className="landing-section-sub">
            Continuous visibility, behavioral analysis, and automated guardrails for zero-trust cloud operations.
          </p>
        </div>

        <div className="landing-cards-grid">
          {CAPABILITIES.map((cap, idx) => (
            <div key={idx} className="landing-feature-card">
              <div className="landing-feature-icon-wrap">
                {cap.icon}
              </div>
              <div className="landing-feature-badge">{cap.badge}</div>
              <h3 className="landing-feature-title">{cap.title}</h3>
              <p className="landing-feature-desc">{cap.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Architecture & Telemetry Pipeline */}
      <section id="architecture" className="landing-section-wrap landing-bg-alt">
        <div className="landing-section-header">
          <span className="landing-section-eyebrow">Pipeline Architecture</span>
          <h2 className="landing-section-heading">From Ingestion to Containment</h2>
          <p className="landing-section-sub">
            Deterministic 4-stage pipeline delivering sub-second anomaly isolation without false-positive fatigue.
          </p>
        </div>

        <div className="landing-pipeline-grid">
          <div className="landing-pipeline-step">
            <div className="landing-step-num">01</div>
            <h4 className="landing-step-title">Ingestion &amp; Parsing</h4>
            <p className="landing-step-text">
              Real-time polling of AWS CloudTrail, STS session tokens, and IAM entity definitions normalized to standard schema.
            </p>
          </div>

          <div className="landing-pipeline-step">
            <div className="landing-step-num">02</div>
            <h4 className="landing-step-title">Continuous Posture Audit</h4>
            <p className="landing-step-text">
              Automated evaluation against S3 bucket policies, EC2 security groups, RDS storage encryption, and credential hygiene.
            </p>
          </div>

          <div className="landing-pipeline-step">
            <div className="landing-step-num">03</div>
            <h4 className="landing-step-title">Graph Correlation</h4>
            <p className="landing-step-text">
              Disjoint-set clustering links disparate authentication anomalies, IP indicators, and resource mutations into unified incidents.
            </p>
          </div>

          <div className="landing-pipeline-step">
            <div className="landing-step-num">04</div>
            <h4 className="landing-step-title">Safe Containment</h4>
            <p className="landing-step-text">
              Autonomous remediation executes dry-run simulation, isolates identities, closes security groups, and logs immutable audit trails.
            </p>
          </div>
        </div>
      </section>

      {/* Compliance Frameworks Section */}
      <section id="compliance" className="landing-section-wrap">
        <div className="landing-section-header">
          <span className="landing-section-eyebrow">Regulatory &amp; Security Standards</span>
          <h2 className="landing-section-heading">Automated Compliance Assessment</h2>
          <p className="landing-section-sub">
            Real-time control mapping and downloadable executive audit reports for security leadership.
          </p>
        </div>

        <div className="landing-compliance-grid">
          {COMPLIANCE_STANDARDS.map((std, idx) => (
            <div key={idx} className="landing-compliance-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <span className="landing-compliance-tag">{std.code}</span>
                <span className="landing-compliance-coverage">{std.coverage}</span>
              </div>
              <h4 className="landing-compliance-title">{std.name}</h4>
              <p className="landing-compliance-desc">{std.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* CTA Banner */}
      <section className="landing-cta-banner">
        <div className="landing-cta-box">
          <h2 className="landing-cta-headline">Secure Your Cloud Workloads Today</h2>
          <p className="landing-cta-sub">
            Connect your AWS environment in minutes with read-only IAM credentials or explore the live interactive console.
          </p>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '14px', flexWrap: 'wrap' }}>
            <button
              type="button"
              className="landing-btn-hero-primary"
              onClick={() => setAuthModalOpen(true)}
            >
              <span>Access Console</span>
              <ArrowRight size={16} />
            </button>
            <button
              type="button"
              className="landing-btn-hero-secondary"
              onClick={() => handleQuickDemoLogin('demo')}
              disabled={loadingDemo !== null}
            >
              <span>Launch Demo</span>
            </button>
          </div>
        </div>
      </section>

      {/* Clean Corporate Footer */}
      <footer className="landing-corporate-footer">
        <div className="landing-footer-inner">
          <div className="landing-footer-brand">
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <img src={logoUrl} alt="RAM Antivirus" style={{ width: '28px', height: '28px', objectFit: 'contain' }} />
              <span style={{ fontWeight: 700, fontSize: '15px', color: '#0f172a' }}>RAM Antivirus</span>
            </div>
            <p style={{ fontSize: '12px', color: '#64748b', marginTop: '6px' }}>
              Autonomous Cloud Workload Security &amp; Compliance Posture Platform.
            </p>
          </div>

          <div className="landing-footer-links">
            <button type="button" onClick={() => setAuthModalOpen(true)}>Sign In</button>
            <button type="button" onClick={() => handleQuickDemoLogin('admin')}>Admin Access</button>
            <button type="button" onClick={() => scrollToSection('hero')}>Back to Top</button>
          </div>
        </div>

        <div className="landing-footer-copy">
          <span>&copy; {new Date().getFullYear()} RAM Antivirus. All rights reserved.</span>
          <span>Official Corporate Cloud Platform</span>
        </div>
      </footer>

      {/* Authentication Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        onLogin={onLogin}
      />
    </div>
  );
}
