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
              OR SIGN IN WITH ENTERPRISE IDENTITY
            </span>
            <div style={{ flex: 1, height: '1px', backgroundColor: 'var(--border-subtle)' }} />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '14px' }}>
            {/* Google Identity Services Container */}
            <div
              id="google-btn-container"
              style={{ minHeight: '44px', display: 'flex', justifyContent: 'center' }}
            />

            {/* Custom Google Branded Fallback Button */}
            <button
              type="button"
              onClick={() => {
                if (window.google?.accounts?.id) {
                  window.google.accounts.id.prompt();
                } else {
                  setError('Google Identity Service is loading. Ensure http://localhost:5173 is added to Authorized Origins in Google Cloud Console.');
                }
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '10px',
                width: '100%',
                padding: '10px 16px',
                borderRadius: '8px',
                border: '1px solid var(--border-subtle, #e2e8f0)',
                backgroundColor: 'var(--surface-primary, #ffffff)',
                color: 'var(--text-primary, #1e293b)',
                fontSize: '13px',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)'
              }}
            >
              <svg width="18" height="18" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
              </svg>
              <span>{isRegister ? 'Sign up with Google' : 'Sign in with Google'}</span>
            </button>

            {/* AWS Cloud & IAM Compatibility Chip */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              padding: '6px 10px',
              borderRadius: '6px',
              backgroundColor: 'rgba(255, 153, 0, 0.08)',
              border: '1px solid rgba(255, 153, 0, 0.22)',
              color: '#d97706',
              fontSize: '11.5px',
              fontWeight: 500,
              marginTop: '4px'
            }}>
              <span style={{ fontWeight: 700, letterSpacing: '0.5px' }}>AWS</span>
              <span>Cloud & Workload Telemetry Ready</span>
            </div>
          </div>

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
                  <span className="demo-role-sub" style={{ fontSize: '10.5px' }}>admin / admin123 (Live Cloud)</span>
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
                  <span className="demo-role-name" style={{ fontWeight: 600 }}>Demo Showcase</span>
                  <span className="demo-role-sub" style={{ fontSize: '10.5px' }}>demo / demo123 (Wazuh Logs)</span>
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
