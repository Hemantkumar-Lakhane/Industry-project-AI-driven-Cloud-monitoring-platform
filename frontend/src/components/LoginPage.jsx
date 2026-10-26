import React, { useState } from 'react';
import axios from 'axios';
import { Lock, User, Mail, KeyRound, Eye, EyeOff, Shield, Activity, Sparkles, ArrowRight, Loader2 } from 'lucide-react';
import { BrandMark } from './SharedComponents';
import { API_URL } from '../config';

const LoginPage = ({ onLogin }) => {
  const [isRegister, setIsRegister] = useState(false);
  const [form, setForm] = useState({ username: '', password: '', email: '', role: 'viewer', full_name: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeDemo, setActiveDemo] = useState(null);
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (isRegister) {
        await axios.post(`${API_URL}/auth/register`, form);
        setIsRegister(false);
        setError('');
        setForm(f => ({ ...f, email: '', role: 'viewer', full_name: '' }));
      } else {
        const res = await axios.post(`${API_URL}/auth/login`, {
          username: form.username, password: form.password
        });
        const data = res.data.data;
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        onLogin(data.user, data.token);
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Authentication failed. Please check your credentials.');
    }
    setLoading(false);
  };

  const demoLogin = async (roleName, username, password) => {
    setActiveDemo(roleName);
    setForm(f => ({ ...f, username, password }));
    setLoading(true);
    setError('');
    try {
      const res = await axios.post(`${API_URL}/auth/login`, { username, password });
      const data = res.data.data;
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      onLogin(data.user, data.token);
    } catch (err) {
      setError(err.response?.data?.detail || 'Demo login failed');
    }
    setLoading(false);
    setActiveDemo(null);
  };

  return (
    <div className="login-page">
      <div className="login-container animate-fade-in">
        <div className="login-header">
          <div className="login-brand-wrapper">
            <BrandMark size={76} />
          </div>
          <h1>Ram Antivirus</h1>
          <p className="login-subtitle">Cloud Security AI Platform</p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          <div className="login-form-title-wrap">
            <h2>{isRegister ? 'Create an Account' : 'Sign In'}</h2>
            <p className="login-form-desc">
              {isRegister ? 'Set up credentials for your workspace' : 'Enter your organization credentials'}
            </p>
          </div>

          {error && (
            <div className="login-error animate-fade-in">
              <span>{error}</span>
            </div>
          )}

          <div className="form-group">
            <User size={16} className="form-icon" />
            <input
              type="text"
              placeholder="Username"
              value={form.username}
              onChange={e => setForm({ ...form, username: e.target.value })}
              required
              autoFocus
            />
          </div>

          <div className="form-group">
            <Lock size={16} className="form-icon" />
            <input
              type={showPassword ? 'text' : 'password'}
              placeholder="Password"
              value={form.password}
              onChange={e => setForm({ ...form, password: e.target.value })}
              required
            />
            <button
              type="button"
              className="toggle-pass"
              onClick={() => setShowPassword(!showPassword)}
              aria-label="Toggle password visibility"
            >
              {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>

          {isRegister && (
            <>
              <div className="form-group">
                <Mail size={16} className="form-icon" />
                <input
                  type="email"
                  placeholder="Email"
                  value={form.email}
                  onChange={e => setForm({ ...form, email: e.target.value })}
                  required
                />
              </div>
              <div className="form-group">
                <User size={16} className="form-icon" />
                <input
                  type="text"
                  placeholder="Full Name"
                  value={form.full_name}
                  onChange={e => setForm({ ...form, full_name: e.target.value })}
                />
              </div>
              <div className="form-group">
                <KeyRound size={16} className="form-icon" />
                <select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}>
                  <option value="viewer">Viewer — Read-Only Executive</option>
                  <option value="analyst">Analyst — SOC Operations</option>
                  <option value="admin">Admin — Full Platform Access</option>
                </select>
              </div>
            </>
          )}

          <button type="submit" className="login-btn-primary" disabled={loading}>
            {loading && !activeDemo ? (
              <>
                <Loader2 size={16} className="animate-spin" /> Authenticating...
              </>
            ) : (
              <>
                {isRegister ? 'Register Account' : 'Sign In'} <ArrowRight size={15} />
              </>
            )}
          </button>

          <div className="toggle-mode">
            <span>{isRegister ? 'Already have an account?' : "Don't have an account?"}</span>
            <button
              type="button"
              onClick={() => { setIsRegister(!isRegister); setError(''); }}
              className="toggle-mode-btn"
            >
              {isRegister ? 'Sign In' : 'Register'}
            </button>
          </div>
        </form>

        <div className="demo-accounts">
          <div className="demo-accounts-header">
            <Sparkles size={14} className="demo-sparkle-icon" />
            <span>Quick Demo Login</span>
          </div>
          <div className="demo-btns">
            <button
              type="button"
              className={`demo-role-card demo-admin ${activeDemo === 'admin' ? 'loading' : ''}`}
              onClick={() => demoLogin('admin', 'admin', 'admin123')}
              disabled={loading}
            >
              <div className="demo-role-icon">
                {activeDemo === 'admin' ? <Loader2 size={14} className="animate-spin" /> : <Shield size={14} />}
              </div>
              <div className="demo-role-info">
                <span className="demo-role-name">Admin</span>
                <span className="demo-role-sub">Full Access</span>
              </div>
            </button>

            <button
              type="button"
              className={`demo-role-card demo-analyst ${activeDemo === 'analyst' ? 'loading' : ''}`}
              onClick={() => demoLogin('analyst', 'analyst1', 'analyst123')}
              disabled={loading}
            >
              <div className="demo-role-icon">
                {activeDemo === 'analyst' ? <Loader2 size={14} className="animate-spin" /> : <Activity size={14} />}
              </div>
              <div className="demo-role-info">
                <span className="demo-role-name">Analyst</span>
                <span className="demo-role-sub">SOC Team</span>
              </div>
            </button>

            <button
              type="button"
              className={`demo-role-card demo-viewer ${activeDemo === 'viewer' ? 'loading' : ''}`}
              onClick={() => demoLogin('viewer', 'viewer1', 'viewer123')}
              disabled={loading}
            >
              <div className="demo-role-icon">
                {activeDemo === 'viewer' ? <Loader2 size={14} className="animate-spin" /> : <Eye size={14} />}
              </div>
              <div className="demo-role-info">
                <span className="demo-role-name">Viewer</span>
                <span className="demo-role-sub">Audit View</span>
              </div>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
