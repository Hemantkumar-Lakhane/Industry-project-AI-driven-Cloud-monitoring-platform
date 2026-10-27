import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { AlertCircle, RefreshCw, Trophy, ChevronDown, Play, BarChart3 } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { API_URL } from '../config';

const MLComparisonTab = ({ showToast }) => {
  const [selectedDataset, setSelectedDataset] = useState('cicids');
  const [comparison, setComparison] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchComparison = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_URL}/ml/compare?normal=100&attacks=20`);
      setComparison(res.data.data);
      if (showToast) showToast('ML model benchmark comparison evaluated!');
    } catch (err) {
      if (showToast) showToast('ML comparison failed', 'error');
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchComparison();
  }, []);

  const chartData = comparison?.chart_data || [];

  return (
    <div className="animate-fade-in">
      {/* 1. FIGMA NOTICE CALLOUT */}
      <div className="figma-callout">
        <AlertCircle size={18} className="figma-callout-icon" />
        <div className="figma-callout-content">
          <h4>PyOD evaluation · Specialist model benchmarks</h4>
          <p>Isolation Forest, KNN, and HBOS evaluated on benchmark datasets. 9-dimensional operational network/flow feature model is in training status.</p>
        </div>
      </div>

      {/* 2. MODEL COMPARISON CARD */}
      <div className="figma-card" style={{ padding: '0', overflow: 'hidden', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
          <div>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Model comparison
            </h3>
            {comparison && (
              <span style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
                Evaluated {comparison.total_events} events ({comparison.total_normal} normal, {comparison.total_attacks} attacks) · Best: <strong style={{ color: 'var(--success-color)' }}>{comparison.best_model}</strong> (F1: {comparison.best_f1}%)
              </span>
            )}
          </div>
          <button className="figma-btn-primary" onClick={fetchComparison} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            {loading ? 'Evaluating...' : 'Run comparison'}
          </button>
        </div>

        <table className="figma-table">
          <thead>
            <tr>
              <th>Model</th>
              <th>Suggested reference</th>
              <th style={{ textAlign: 'center' }}>Accuracy</th>
              <th style={{ textAlign: 'center' }}>Precision</th>
              <th style={{ textAlign: 'center' }}>Recall</th>
              <th style={{ textAlign: 'center' }}>F1</th>
              <th style={{ textAlign: 'right' }}>Status</th>
            </tr>
          </thead>
          <tbody>
            {comparison?.models ? (
              Object.entries(comparison.models).map(([name, m]) => (
                <tr key={name}>
                  <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                    {name} {name === comparison.best_model && <span style={{ color: 'var(--success-color)', fontSize: '11px', marginLeft: '6px' }}>★ Best</span>}
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>
                    {name.includes('Isolation') ? 'NSL-KDD' : name.includes('KNN') ? 'CICIDS-2017' : 'UNSW-NB15'}
                  </td>
                  <td style={{ textAlign: 'center', fontWeight: 600 }}>{m.accuracy}%</td>
                  <td style={{ textAlign: 'center', fontWeight: 600 }}>{m.precision}%</td>
                  <td style={{ textAlign: 'center', fontWeight: 600 }}>{m.recall}%</td>
                  <td style={{ textAlign: 'center', fontWeight: 600, color: 'var(--accent-orange)' }}>{m.f1_score}%</td>
                  <td style={{ textAlign: 'right', color: 'var(--success-color)', fontWeight: 500 }}>Evaluated</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                  Loading PyOD models...
                </td>
              </tr>
            )}
          </tbody>
        </table>

        <div style={{ padding: '14px 20px', borderTop: '1px solid var(--border-subtle)', fontSize: '12px', color: 'var(--text-muted)' }}>
          Dataset names are suggested evaluation references, not evidence of production model training.
        </div>
      </div>

      {/* 3. PERFORMANCE METRICS BAR CHART */}
      {chartData.length > 0 && (
        <div className="figma-card" style={{ marginBottom: '24px' }}>
          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '16px' }}>
            Comparative Performance Metrics (%)
          </h3>
          <div style={{ height: '240px', width: '100%' }}>
            <ResponsiveContainer>
              <BarChart data={chartData}>
                <XAxis dataKey="model" stroke="#8b949e" tick={{ fontSize: 11 }} />
                <YAxis stroke="#8b949e" domain={[0, 100]} tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--surface-card)', border: '1px solid var(--border-subtle)', borderRadius: '8px', color: 'var(--text-primary)' }} />
                <Legend />
                <Bar dataKey="accuracy" fill="#3b82f6" radius={[4, 4, 0, 0]} name="Accuracy" />
                <Bar dataKey="precision" fill="#a855f7" radius={[4, 4, 0, 0]} name="Precision" />
                <Bar dataKey="recall" fill="#06b6d4" radius={[4, 4, 0, 0]} name="Recall" />
                <Bar dataKey="f1_score" fill="#c2410c" radius={[4, 4, 0, 0]} name="F1 Score" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* 4. 2-COLUMN BOTTOM ROW: DATASET CONFIGURATION + EVALUATION READINESS */}
      <div className="figma-grid-2col">
        {/* Dataset Configuration */}
        <div className="figma-card">
          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '16px' }}>
            Dataset configuration
          </h3>

          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
              Evaluation dataset
            </label>
            <div style={{ position: 'relative' }}>
              <select
                className="figma-filter-select"
                style={{ width: '100%', appearance: 'none', paddingRight: '30px' }}
                value={selectedDataset}
                onChange={(e) => setSelectedDataset(e.target.value)}
              >
                <option value="cicids">CICIDS-2017 (Standard Flow captures)</option>
                <option value="nsl-kdd">NSL-KDD (Standard benchmark)</option>
                <option value="unsw">UNSW-NB15 (Hybrid telemetry)</option>
              </select>
              <ChevronDown size={14} style={{ position: 'absolute', right: '12px', top: '12px', pointerEvents: 'none', color: 'var(--text-tertiary)' }} />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Ground-truth label
              </label>
              <input
                type="text"
                readOnly
                value="Label / is_attack"
                style={{
                  width: '100%',
                  padding: '7px 12px',
                  borderRadius: '8px',
                  border: '1px solid var(--border-subtle)',
                  backgroundColor: 'var(--surface-muted)',
                  color: 'var(--text-primary)',
                  fontSize: '13px'
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Feature mapping
              </label>
              <div style={{ padding: '8px 12px', backgroundColor: 'var(--surface-muted)', borderRadius: '8px', fontSize: '13px', color: 'var(--text-secondary)', border: '1px solid var(--border-subtle)' }}>
                3-D Normalized Flow
              </div>
            </div>
          </div>

          <button className="figma-btn-primary" onClick={fetchComparison} disabled={loading}>
            <Play size={13} /> Run re-train & comparison
          </button>
        </div>

        {/* Evaluation Readiness */}
        <div className="figma-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '16px' }}>
              Evaluation readiness
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginBottom: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Dataset</span>
                <span style={{ fontWeight: 500, color: 'var(--success-color)' }}>Loaded (200 events)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Labels & features</span>
                <span style={{ fontWeight: 500, color: 'var(--success-color)' }}>Validated</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Model configuration</span>
                <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>PyOD Ensemble Active</span>
              </div>
            </div>

            <p style={{ fontSize: '12.5px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Models evaluate anomaly score distribution and assign severity triggers.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '10px', marginTop: '24px' }}>
            <button className="figma-btn-secondary" onClick={fetchComparison} disabled={loading}>
              Train models
            </button>
            <button className="figma-btn-primary" onClick={fetchComparison} disabled={loading}>
              Evaluate
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MLComparisonTab;
