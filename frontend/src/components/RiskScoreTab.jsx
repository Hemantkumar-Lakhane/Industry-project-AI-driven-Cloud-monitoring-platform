import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Gauge, RefreshCw, AlertTriangle, TrendingUp, CheckCircle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';
import { API_URL } from '../config';

const RiskScoreTab = ({ showToast }) => {
  const [risk, setRisk] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchRisk = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_URL}/risk/score`);
      setRisk(res.data.data);
      if (showToast) showToast('Unified risk score recalculated!');
    } catch (err) {
      if (showToast) showToast('Failed to fetch risk score', 'error');
    }
    setLoading(false);
  };

  useEffect(() => { fetchRisk(); }, []);

  // Actionable risk drivers backed dynamically by Task-1 Correlated Incidents from backend API
  // with fallback to platform findings and assets
  const displayDrivers = (risk?.actionable_drivers && risk.actionable_drivers.length > 0)
    ? risk.actionable_drivers
    : [
        {
          id: 'FIND-NETW',
          title: 'SSH accessible from internet (0.0.0.0/0:22)',
          resource: 'sg-public-ssh-web ↗',
          source: 'Network · LIVE',
          nextStep: 'Review exposure →'
        },
        {
          id: 'FIND-CLOU',
          title: 'Public S3 access block disabled',
          resource: 's3-cust-records-prod ↗',
          source: 'Storage · CSPM',
          nextStep: 'Review policy →'
        },
        {
          id: 'FIND-IAMP',
          title: 'MFA absent on administrative principal',
          resource: 'iam-role-superadmin ↗',
          source: 'Identity · CIEM',
          nextStep: 'Review identity →'
        }
      ];

  return (
    <div className="animate-fade-in">
      {/* 2-COLUMN GRID (UNIFIED RISK + FACTOR INPUTS) */}
      <div className="figma-grid-2col">
        {/* Left Card: Unified Risk Hero */}
        <div className="figma-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Unified risk
              </h3>
              <button className="figma-btn-secondary" onClick={fetchRisk} disabled={loading} style={{ padding: '5px 10px', fontSize: '12px' }}>
                <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Recalculate
              </button>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '8px' }}>
              <div style={{ width: '40px', height: '6px', backgroundColor: risk ? risk.unified_risk_color || 'var(--accent-orange)' : 'var(--text-muted)', borderRadius: '3px' }} />
              <span style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)' }}>
                {risk ? `${risk.unified_risk_score} / 100` : 'NOT CONFIGURED'}
              </span>
              {risk && (
                <span style={{ fontSize: '12px', fontWeight: 600, padding: '2px 8px', borderRadius: '4px', backgroundColor: 'var(--sev-high-bg)', color: 'var(--sev-high)' }}>
                  {risk.unified_risk_level?.toUpperCase()}
                </span>
              )}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginBottom: '20px' }}>
              Trend {risk ? 'Stable' : '—'} · Last evaluation {risk ? 'Just now' : '—'}
            </div>

            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              Composite four-pillar risk evaluated across correlated attack campaigns, ML flow anomaly detection, cloud posture, and IAM entitlements.
            </p>
          </div>

          <div style={{ marginTop: '24px' }}>
            <button className="figma-btn-primary" onClick={fetchRisk}>
              Recalculate risk score
            </button>
          </div>
        </div>

        {/* Right Card: Factor Inputs Table */}
        <div className="figma-card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Factor inputs
            </h3>
            <span style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
              Four-pillar weights
            </span>
          </div>

          <table className="figma-table">
            <thead>
              <tr>
                <th>Factor</th>
                <th>Available input</th>
                <th style={{ textAlign: 'right' }}>Score / Weight</th>
              </tr>
            </thead>
            <tbody>
              {risk?.risk_breakdown_chart ? (
                risk.risk_breakdown_chart.map((c, i) => {
                  let inputLabel = 'Live security stream';
                  if (c.name.includes('Incident')) inputLabel = 'Task-1 Correlated Campaigns';
                  else if (c.name.includes('ML')) inputLabel = 'Active flow anomaly stream';
                  else if (c.name.includes('CSPM')) inputLabel = 'Cloud posture & exposure scan';
                  else if (c.name.includes('CIEM')) inputLabel = 'IAM entitlement & privilege audit';
                  return (
                    <tr key={i}>
                      <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{c.name}</td>
                      <td style={{ color: 'var(--text-secondary)' }}>{inputLabel}</td>
                      <td style={{ textAlign: 'right', fontWeight: 600, color: c.color || 'var(--accent-orange)' }}>
                        {c.score}% ({(Math.round(c.weight * 100))}%)
                      </td>
                    </tr>
                  );
                })
              ) : (
                <>
                  <tr>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Incident Correlation</td>
                    <td style={{ color: 'var(--text-secondary)' }}>Task-1 Correlated Campaigns</td>
                    <td style={{ textAlign: 'right', color: 'var(--text-muted)' }}>35%</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>ML/AI detection</td>
                    <td style={{ color: 'var(--text-secondary)' }}>Active telemetry session</td>
                    <td style={{ textAlign: 'right', color: 'var(--text-muted)' }}>25%</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>CSPM cloud posture</td>
                    <td style={{ color: 'var(--text-secondary)' }}>Cloud posture & exposure scan</td>
                    <td style={{ textAlign: 'right', color: 'var(--text-muted)' }}>20%</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>CIEM identity</td>
                    <td style={{ color: 'var(--text-secondary)' }}>IAM entitlement & privilege audit</td>
                    <td style={{ textAlign: 'right', color: 'var(--text-muted)' }}>20%</td>
                  </tr>
                </>
              )}
            </tbody>
          </table>

          <div style={{ marginTop: '16px', fontSize: '12px', color: 'var(--text-muted)' }}>
            Imported fixture findings are normalized into tenant posture scoring.
          </div>
        </div>
      </div>

      {/* TREND & COMPONENT CHARTS */}
      {risk?.trend && (
        <div className="figma-grid-2col" style={{ marginBottom: '24px' }}>
          <div className="figma-card">
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '16px' }}>
              Risk Trend (7 Days)
            </h3>
            <div style={{ height: '220px', width: '100%' }}>
              <ResponsiveContainer>
                <LineChart data={risk.trend}>
                  <XAxis dataKey="period" stroke="#8b949e" tick={{ fontSize: 11 }} />
                  <YAxis stroke="#8b949e" domain={[0, 100]} tick={{ fontSize: 11 }} />
                  <Tooltip contentStyle={{ backgroundColor: 'var(--surface-card)', border: '1px solid var(--border-subtle)', borderRadius: '8px' }} />
                  <Line type="monotone" dataKey="score" stroke="var(--accent-orange)" strokeWidth={2} dot={{ fill: 'var(--accent-orange)', r: 4 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="figma-card">
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '16px' }}>
              Automated Threshold Actions
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {Object.entries(risk.threshold_actions?.actions || {}).map(([action, triggered], i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                  <span style={{ fontSize: '13px', color: 'var(--text-primary)' }}>
                    {action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                  </span>
                  <span style={{
                    fontSize: '11px',
                    fontWeight: 600,
                    padding: '2px 8px',
                    borderRadius: '4px',
                    backgroundColor: triggered ? 'var(--sev-critical-bg)' : 'var(--success-bg)',
                    color: triggered ? 'var(--sev-critical)' : 'var(--success-color)'
                  }}>
                    {triggered ? 'TRIGGERED' : 'INACTIVE'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* BOTTOM TABLE: ACTIONABLE RISK DRIVERS */}
      <div className="figma-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Actionable risk drivers
          </h3>
          <span style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
            Imported evidence
          </span>
        </div>

        <table className="figma-table">
          <thead>
            <tr>
              <th>Finding</th>
              <th>Resource</th>
              <th>Source</th>
              <th style={{ textAlign: 'right' }}>Next step</th>
            </tr>
          </thead>
          <tbody>
            {displayDrivers.map((driver, idx) => (
              <tr key={idx}>
                <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                  <span style={{ fontFamily: 'monospace', fontWeight: 500 }}>{driver.id}</span> · {driver.title}
                </td>
                <td style={{ color: 'var(--accent-orange)' }}>
                  {driver.resource}
                </td>
                <td style={{ color: 'var(--text-secondary)', fontSize: '12.5px' }}>
                  {driver.source}
                </td>
                <td style={{ textAlign: 'right' }}>
                  <button className="figma-link-btn">
                    {driver.nextStep}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default RiskScoreTab;
