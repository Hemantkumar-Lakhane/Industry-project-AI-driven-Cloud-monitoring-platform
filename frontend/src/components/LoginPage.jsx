import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Lock, User, Mail, Building, Eye, EyeOff, Shield, Activity, ShieldCheck, ArrowRight, Loader2, ChevronDown, ChevronUp } from 'lucide-react';
import { BrandMark } from './SharedComponents';
import { API_URL } from '../config';

const GOOGLE_CLIENT_ID = "935815727495-8a34omegvgel2s6q99u7kn6t4j2a4o0k.apps.googleusercontent.com";

const LoginPage = ({ onLogin }) => {
  const [isRegister, setIsRegister] = useState(false);
  const [showDemoLogins, setShowDemoLogins] = useState(false);
  const [form, setForm] = useState({ 
    username: '', 
    password: '', 
    email: '', 
    company_name: '', 
    full_name: '' 
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeDemo, setActiveDemo] = useState(null);
  const [showPassword, setShowPassword] = useState(false);

  const handleGoogleCallback = async (response) => {
    if (!response || !response.credential) return;
    setLoading(true);
    setError('');
    try {
      const res = await axios.post(`${API_URL}/auth/google`, {
        credential: response.credential
      });
      const data = res.data.data;
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      onLogin(data.user, data.token);
    } catch (err) {
      setError(err.response?.data?.detail || 'Google sign-in failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const renderGoogleBtn = () => {
      if (window.google?.accounts?.id) {
        window.google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: handleGoogleCallback,
          auto_select: false
        });
        const container = document.getElementById('google-btn-container');
        if (container) {
          container.innerHTML = '';
          window.google.accounts.id.renderButton(container, {
            theme: 'outline',
            size: 'large',
            width: 360,
            text: isRegister ? 'signup_with' : 'signin_with',
            shape: 'rectangular',
            logo_alignment: 'left'
          });
        }
      }
    };

    if (window.google?.accounts?.id) {
      renderGoogleBtn();
    } else {
      const timer = setInterval(() => {
        if (window.google?.accounts?.id) {
          clearInterval(timer);
          renderGoogleBtn();
        }
      }, 300);
      return () => clearInterval(timer);
    }
  }, [isRegister]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (isRegister) {
        // Real self-serve enterprise company onboarding
        const cleanName = (form.full_name && form.full_name.trim().toLowerCase() !== form.password.trim().toLowerCase() && !form.full_name.toLowerCase().includes('password'))
          ? form.full_name.trim()
          : `${form.company_name.trim()} Admin`;

        const res = await axios.post(`${API_URL}/auth/register-company`, {
          company_name: form.company_name.trim(),
          admin_name: cleanName,
          email: form.email.trim(),
          password: form.password,
          username: form.username || form.email.split('@')[0]
        });
        const data = res.data.data;
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        localStorage.setItem('first_time_setup', 'true');
        onLogin(data.user, data.token);
      } else {
        const res = await axios.post(`${API_URL}/auth/login`, {
          username: form.username, 
          password: form.password
        });
        const data = res.data.data;
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        onLogin(data.user, data.token);
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Authentication failed. Please verify credentials.');
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
      setError(err.response?.data?.detail || 'Sign in failed');
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
          <h1>RAM Antivirus</h1>
          <p className="login-subtitle">Cloud Workload Security & Posture Platform</p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          <div className="login-form-title-wrap">
            <h2>{isRegister ? 'Register Organization' : 'Enterprise Sign In'}</h2>
            <p className="login-form-desc">
              {isRegister ? 'Set up your cloud security workspace' : 'Enter your organization credentials'}
            </p>
          </div>

          {error && (
            <div className="login-error animate-fade-in">
              <span>{error}</span>
            </div>
          )}

          {isRegister ? (
            <>
              <div className="form-group">
                <Building size={16} className="form-icon" />
                <input
                  type="text"
                  name="company_name"
                  autoComplete="organization"
                  placeholder="Organization / Company Name (e.g. Acme Cloud)"
                  value={form.company_name}
                  onChange={e => setForm({ ...form, company_name: e.target.value })}
                  required
                  autoFocus
                />
              </div>

              <div className="form-group">
                <User size={16} className="form-icon" />
                <input
                  type="text"
                  name="full_name"
                  autoComplete="name"
                  placeholder="Administrator Full Name (e.g. Hemant Lakhane)"
                  value={form.full_name}
                  onChange={e => setForm({ ...form, full_name: e.target.value })}
                  required
                />
              </div>

              <div className="form-group">
                <Mail size={16} className="form-icon" />
                <input
                  type="email"
                  name="email"
                  autoComplete="email"
                  placeholder="Work Business Email"
                  value={form.email}
                  onChange={e => setForm({ ...form, email: e.target.value })}
                  required
                />
              </div>

              <div className="form-group">
                <Lock size={16} className="form-icon" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  name="password"
                  autoComplete="new-password"
                  placeholder="Master Security Password (min 6 characters)"
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
            </>
          ) : (
            <>
              <div className="form-group">
                <User size={16} className="form-icon" />
                <input
                  type="text"
                  placeholder="Username or Email"
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
            </>
          )}

          <button type="submit" className="login-btn-primary" disabled={loading}>
            {loading && !activeDemo ? (
              <>
                <Loader2 size={16} className="animate-spin" /> Authenticating...
              </>
            ) : (
              <>
                {isRegister ? 'Create Organization & Connect Cloud' : 'Sign In'} <ArrowRight size={15} />
              </>
            )}
          </button>

          <div style={{ display: 'flex', alignItems: 'center', margin: '14px 0', gap: '10px' }}>
            <div style={{ flex: 1, height: '1px', backgroundColor: 'var(--border-subtle)' }} />
            <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', fontWeight: 600, letterSpacing: '0.5px' }}>
              OR CONTINUE WITH GOOGLE
            </span>
            <div style={{ flex: 1, height: '1px', backgroundColor: 'var(--border-subtle)' }} />
          </div>

          <div
            id="google-btn-container"
            style={{ minHeight: '44px', display: 'flex', justifyContent: 'center', marginBottom: '14px' }}
          />

          <div className="toggle-mode">
            <span>{isRegister ? 'Already have an organization workspace?' : "Need to onboard a new organization?"}</span>
            <button
              type="button"
              onClick={() => { setIsRegister(!isRegister); setError(''); }}
              className="toggle-mode-btn"
            >
              {isRegister ? 'Sign In' : 'Register Organization'}
            </button>
          </div>
        </form>

        {/* QUICK 1-CLICK TEST LOGINS (ADMIN & DEMO USER) */}
        <div style={{ marginTop: '16px', borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
          <button
            type="button"
            onClick={() => setShowDemoLogins(!showDemoLogins)}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-secondary)',
              fontSize: '12px',
              fontWeight: 500,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px',
              width: '100%',
              padding: '4px'
            }}
          >
            <ShieldCheck size={13} style={{ color: 'var(--brand-primary, #6366f1)' }} />
            <span>{showDemoLogins ? 'Hide quick access accounts' : 'Quick Test Accounts (Admin & Demo)'}</span>
            {showDemoLogins ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          </button>

          {showDemoLogins && (
            <div className="demo-btns" style={{ marginTop: '10px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              <button
                type="button"
                className={`demo-role-card demo-admin ${activeDemo === 'admin' ? 'loading' : ''}`}
                onClick={() => demoLogin('admin', 'admin', 'admin123')}
                disabled={loading}
                style={{ padding: '8px 12px' }}
              >
                <div className="demo-role-icon">
                  {activeDemo === 'admin' ? <Loader2 size={14} className="animate-spin" /> : <Shield size={14} />}
                </div>
                <div className="demo-role-info" style={{ textAlign: 'left' }}>
                  <span className="demo-role-name" style={{ fontWeight: 600 }}>Master Admin</span>
                  <span className="demo-role-sub" style={{ fontSize: '10.5px' }}>admin / admin123</span>
                </div>
              </button>

              <button
                type="button"
                className={`demo-role-card demo-analyst ${activeDemo === 'demo' ? 'loading' : ''}`}
                onClick={() => demoLogin('demo', 'demo', 'demo123')}
                disabled={loading}
                style={{ padding: '8px 12px' }}
              >
                <div className="demo-role-icon">
                  {activeDemo === 'demo' ? <Loader2 size={14} className="animate-spin" /> : <Activity size={14} />}
                </div>
                <div className="demo-role-info" style={{ textAlign: 'left' }}>
                  <span className="demo-role-name" style={{ fontWeight: 600 }}>Demo User</span>
                  <span className="demo-role-sub" style={{ fontSize: '10.5px' }}>demo / demo123</span>
                </div>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
