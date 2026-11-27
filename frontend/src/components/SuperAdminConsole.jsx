import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import {
  Shield, Building2, Users, Activity, FileText, RefreshCw, Plus,
  CheckCircle, AlertTriangle, Ban, PlayCircle, LogOut, Search,
  Server, Cloud, Lock, Sun, Moon, X, KeyRound
} from 'lucide-react';
import { API_URL } from '../config';
import { BrandMark } from './SharedComponents';

const SuperAdminConsole = ({ user, onLogout, showToast, theme, onToggleTheme }) => {
  const [activeSection, setActiveSection] = useState('fleet');
  const [fleet, setFleet] = useState(null);
  const [orgs, setOrgs] = useState([]);
  const [users, setUsers] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(false);

  // Filters & modals
  const [orgSearch, setOrgSearch] = useState('');
  const [userSearch, setUserSearch] = useState('');
  const [userOrgFilter, setUserOrgFilter] = useState('');
  const [auditActionFilter, setAuditActionFilter] = useState('');
  const [showCreateOrg, setShowCreateOrg] = useState(false);
  const [newOrg, setNewOrg] = useState({ name: '', industry: 'Cloud Infrastructure', plan: 'enterprise' });
  const [submitting, setSubmitting] = useState(false);

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [fleetRes, orgsRes, usersRes, auditRes] = await Promise.all([
        axios.get(`${API_URL}/admin/fleet/overview`),
        axios.get(`${API_URL}/admin/organizations`),
        axios.get(`${API_URL}/admin/users`, {
          params: {
            ...(userOrgFilter ? { org_id: userOrgFilter } : {}),
            ...(userSearch ? { search: userSearch } : {}),
          }
        }),
        axios.get(`${API_URL}/admin/audit-logs`, {
          params: {
            limit: 100,
            ...(auditActionFilter ? { action: auditActionFilter } : {}),
          }
        })
      ]);
      setFleet(fleetRes.data?.data || null);
      setOrgs(orgsRes.data?.data || []);
      setUsers(usersRes.data?.data || []);
      setAuditLogs(auditRes.data?.data || []);
    } catch (err) {
      const msg = err.response?.data?.detail || 'Failed to load fleet telemetry';
      if (showToast) showToast(msg, 'error');
    } finally {
      setLoading(false);
    }
  }, [userOrgFilter, userSearch, auditActionFilter, showToast]);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  const handleCreateOrg = async (e) => {
    e.preventDefault();
    if (!newOrg.name.trim()) return;
    setSubmitting(true);
    try {
      const res = await axios.post(`${API_URL}/admin/organizations`, newOrg);
      if (showToast) showToast(`Organization "${res.data?.data?.name}" provisioned`);
      setNewOrg({ name: '', industry: 'Cloud Infrastructure', plan: 'enterprise' });
      setShowCreateOrg(false);
      await loadAll();
    } catch (err) {
      if (showToast) showToast(err.response?.data?.detail || 'Failed to create organization', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const handleToggleOrgStatus = async (org) => {
    const nextStatus = (org.status || 'active').toLowerCase() === 'suspended' ? 'active' : 'suspended';
    try {
      await axios.put(`${API_URL}/admin/organizations/${org.org_id}/status`, { status: nextStatus });
      if (showToast) showToast(`Organization "${org.name}" is now ${nextStatus}`);
      await loadAll();
    } catch (err) {
      if (showToast) showToast(err.response?.data?.detail || 'Failed to update status', 'error');
    }
  };

  const handleTerminateSessions = async (targetUser) => {
    try {
      await axios.post(`${API_URL}/admin/users/${targetUser.user_id}/terminate-sessions`);
      if (showToast) showToast(`All active sessions revoked for ${targetUser.username}`);
      await loadAll();
    } catch (err) {
      if (showToast) showToast(err.response?.data?.detail || 'Failed to revoke sessions', 'error');
    }
  };

  const filteredOrgs = orgs.filter((o) => {
    if (!orgSearch.trim()) return true;
    const q = orgSearch.toLowerCase();
    return (
      (o.name || '').toLowerCase().includes(q) ||
      (o.org_id || '').toLowerCase().includes(q) ||
      (o.external_id || '').toLowerCase().includes(q)
    );
  });

  const navItems = [
    { id: 'fleet', label: 'Fleet Command', icon: <Activity size={16} /> },
    { id: 'orgs', label: `Organizations (${orgs.length})`, icon: <Building2 size={16} /> },
    { id: 'users', label: `Global Users (${users.length})`, icon: <Users size={16} /> },
    { id: 'audit', label: `Audit Ledger (${auditLogs.length})`, icon: <FileText size={16} /> },
  ];

  const kpis = fleet?.fleet || {};
  const threats = fleet?.threats || {};
  const infra = fleet?.infrastructure || {};

  return (
    <div style={{ minHeight: '100vh', display: 'flex', backgroundColor: 'var(--bg-color)', color: 'var(--text-primary)' }}>
      {/* Dedicated Super Admin Sidebar */}
      <aside style={{
        width: '260px',
        backgroundColor: 'var(--surface-sidebar)',
        borderRight: '1px solid var(--border-subtle)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        padding: '18px 14px',
        flexShrink: 0
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '4px 8px 16px', borderBottom: '1px solid var(--border-subtle)' }}>
            <BrandMark size={30} />
            <div>
              <div style={{ fontWeight: 700, fontSize: '14px', letterSpacing: '-0.2px', color: 'var(--text-primary)' }}>RAM Antivirus</div>
              <div style={{
                fontSize: '11px',
                fontWeight: 600,
                color: 'var(--text-tertiary)'
              }}>
                Super Admin
              </div>
            </div>
          </div>

          <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {navItems.map((item) => {
              const active = activeSection === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveSection(item.id)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                    width: '100%',
                    padding: '10px 12px',
                    borderRadius: '8px',
                    border: active ? '1px solid var(--border-subtle)' : '1px solid transparent',
                    backgroundColor: active ? 'var(--surface-muted)' : 'transparent',
                    color: active ? 'var(--accent-orange)' : 'var(--text-secondary)',
                    fontWeight: active ? 600 : 500,
                    fontSize: '13px',
                    cursor: 'pointer',
                    textAlign: 'left'
                  }}
                >
                  {item.icon}
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Super Admin Identity Card */}
        <div style={{
          padding: '12px',
          borderRadius: '10px',
          border: '1px solid var(--border-subtle)',
          backgroundColor: 'var(--surface-muted)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{
              width: '28px',
              height: '28px',
              borderRadius: '50%',
              backgroundColor: 'var(--accent-orange)',
              color: '#fff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '11px',
              fontWeight: 700,
              flexShrink: 0
            }}>
              SA
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: '12.5px', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {user?.full_name || user?.username}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>
                {user?.org_id} · super_admin
              </div>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Super Admin Workspace */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, backgroundColor: 'var(--bg-color)' }}>
        {/* Top Bar */}
        <header style={{
          height: '60px',
          borderBottom: '1px solid var(--border-subtle)',
          backgroundColor: 'var(--surface-header)',
          padding: '0 24px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Shield size={18} style={{ color: 'var(--accent-orange)' }} />
            <span style={{ fontWeight: 700, fontSize: '15px', color: 'var(--text-primary)' }}>Fleet Administration</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              className="figma-btn-secondary"
              onClick={loadAll}
              disabled={loading}
              style={{ padding: '6px 12px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
              Refresh Fleet
            </button>
            <button
              className="figma-btn-secondary"
              onClick={onToggleTheme}
              style={{ padding: '6px 10px' }}
              title="Toggle Theme"
            >
              {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
            </button>
            <button
              className="figma-btn-secondary"
              onClick={onLogout}
              style={{ padding: '6px 12px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px', color: '#ef4444' }}
            >
              <LogOut size={14} />
              Sign Out
            </button>
          </div>
        </header>

        {/* Content Area */}
        <main style={{ flex: 1, padding: '24px', overflowY: 'auto' }}>
          {/* 1. FLEET COMMAND OVERVIEW */}
          {activeSection === 'fleet' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <div>
                  <h1 style={{ fontSize: '22px', fontWeight: 700, margin: 0 }}>Platform Fleet Overview</h1>
                  <p style={{ fontSize: '13px', color: 'var(--text-tertiary)', margin: '4px 0 0' }}>
                    Real-time multi-tenant health, cloud connector coverage, and global audit posture
                  </p>
                </div>
                <button
                  className="figma-btn-primary"
                  onClick={() => { setActiveSection('orgs'); setShowCreateOrg(true); }}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px', backgroundColor: '#2563eb' }}
                >
                  <Plus size={15} /> Provision Organization
                </button>
              </div>

              {/* KPI Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginBottom: '24px' }}>
                <div className="figma-card" style={{ padding: '18px' }}>
                  <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Organizations</div>
                  <div style={{ fontSize: '28px', fontWeight: 800, marginTop: '6px', color: '#3b82f6' }}>
                    {kpis.total_organizations ?? orgs.length}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
                    {kpis.active_organizations ?? 0} active · {kpis.suspended_organizations ?? 0} suspended
                  </div>
                </div>

                <div className="figma-card" style={{ padding: '18px' }}>
                  <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Platform Users</div>
                  <div style={{ fontSize: '28px', fontWeight: 800, marginTop: '6px' }}>
                    {kpis.total_users ?? users.length}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
                    {kpis.active_users ?? 0} active accounts across tenants
                  </div>
                </div>

                <div className="figma-card" style={{ padding: '18px' }}>
                  <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Connected Clouds</div>
                  <div style={{ fontSize: '28px', fontWeight: 800, marginTop: '6px', color: '#10b981' }}>
                    {kpis.connected_cloud_accounts ?? 0}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
                    Live AWS CloudTrail &amp; CSPM streams
                  </div>
                </div>

                <div className="figma-card" style={{ padding: '18px' }}>
                  <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Fleet Open Threats</div>
                  <div style={{ fontSize: '28px', fontWeight: 800, marginTop: '6px', color: '#f06a1a' }}>
                    {threats.open_findings_across_fleet ?? 0}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
                    {threats.open_incidents_across_fleet ?? 0} open correlated incidents
                  </div>
                </div>
              </div>

              {/* Infrastructure & Recent Audit Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.4fr', gap: '20px' }}>
                <div className="figma-card" style={{ padding: '20px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
                    <Server size={17} style={{ color: '#3b82f6' }} />
                    <h3 style={{ fontSize: '15px', fontWeight: 700, margin: 0 }}>Infrastructure Health</h3>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 12px', borderRadius: '8px', backgroundColor: 'var(--surface-muted)' }}>
                      <span style={{ color: 'var(--text-secondary)' }}>Primary Database Engine</span>
                      <strong>{infra.database_engine || 'PostgreSQL'}</strong>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 12px', borderRadius: '8px', backgroundColor: 'var(--surface-muted)' }}>
                      <span style={{ color: 'var(--text-secondary)' }}>Database Status</span>
                      <span style={{ color: '#10b981', fontWeight: 700 }}>{(infra.database_status || 'healthy').toUpperCase()}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 12px', borderRadius: '8px', backgroundColor: 'var(--surface-muted)' }}>
                      <span style={{ color: 'var(--text-secondary)' }}>Control Plane API</span>
                      <span style={{ color: '#10b981', fontWeight: 700 }}>{(infra.api_status || 'operational').toUpperCase()}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 12px', borderRadius: '8px', backgroundColor: 'var(--surface-muted)' }}>
                      <span style={{ color: 'var(--text-secondary)' }}>Immutable Audit Records</span>
                      <strong>{infra.audit_ledger_events ?? auditLogs.length}</strong>
                    </div>
                  </div>
                </div>

                <div className="figma-card" style={{ padding: '20px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Lock size={17} style={{ color: '#3b82f6' }} />
                      <h3 style={{ fontSize: '15px', fontWeight: 700, margin: 0 }}>Recent Platform Audit Events</h3>
                    </div>
                    <button className="figma-link-btn" onClick={() => setActiveSection('audit')}>
                      View full ledger →
                    </button>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {auditLogs.slice(0, 5).map((log) => (
                      <div key={log.log_id} style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        padding: '10px 12px',
                        borderRadius: '8px',
                        backgroundColor: 'var(--surface-muted)',
                        fontSize: '12.5px'
                      }}>
                        <div>
                          <span style={{ fontWeight: 700, color: '#3b82f6', fontFamily: 'monospace' }}>{log.action}</span>
                          <span style={{ color: 'var(--text-secondary)', marginLeft: '8px' }}>
                            by <strong>{log.actor_username}</strong> → {log.target_id}
                          </span>
                        </div>
                        <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>
                          {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : ''}
                        </span>
                      </div>
                    ))}
                    {auditLogs.length === 0 && (
                      <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '13px' }}>
                        No platform audit events recorded yet.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* 2. ORGANIZATIONS MANAGER */}
          {activeSection === 'orgs' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
                <div>
                  <h1 style={{ fontSize: '20px', fontWeight: 700, margin: 0 }}>Tenant Organizations</h1>
                  <p style={{ fontSize: '13px', color: 'var(--text-tertiary)', margin: '4px 0 0' }}>
                    Provision customer workspaces, inspect AWS connection posture, or suspend/reactivate access
                  </p>
                </div>
                <button
                  className="figma-btn-primary"
                  onClick={() => setShowCreateOrg(!showCreateOrg)}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px', backgroundColor: '#2563eb' }}
                >
                  <Plus size={15} /> {showCreateOrg ? 'Close Form' : 'Provision Organization'}
                </button>
              </div>

              {showCreateOrg && (
                <form onSubmit={handleCreateOrg} className="figma-card" style={{ padding: '18px', marginBottom: '18px', border: '1px solid rgba(59, 130, 246, 0.35)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <strong style={{ fontSize: '14px' }}>Provision New Customer Organization</strong>
                    <button type="button" onClick={() => setShowCreateOrg(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-tertiary)' }}>
                      <X size={16} />
                    </button>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr 1fr auto', gap: '10px', alignItems: 'end' }}>
                    <div>
                      <label style={{ fontSize: '11px', fontWeight: 600, display: 'block', marginBottom: '4px' }}>Organization Name</label>
                      <input
                        type="text"
                        required
                        placeholder="e.g., Acme Financial Systems"
                        value={newOrg.name}
                        onChange={(e) => setNewOrg({ ...newOrg, name: e.target.value })}
                        className="figma-input"
                        style={{ width: '100%', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--border-subtle)', backgroundColor: 'var(--surface-muted)', color: 'var(--text-primary)' }}
                      />
                    </div>
                    <div>
                      <label style={{ fontSize: '11px', fontWeight: 600, display: 'block', marginBottom: '4px' }}>Industry</label>
                      <input
                        type="text"
                        value={newOrg.industry}
                        onChange={(e) => setNewOrg({ ...newOrg, industry: e.target.value })}
                        style={{ width: '100%', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--border-subtle)', backgroundColor: 'var(--surface-muted)', color: 'var(--text-primary)' }}
                      />
                    </div>
                    <div>
                      <label style={{ fontSize: '11px', fontWeight: 600, display: 'block', marginBottom: '4px' }}>Plan Tier</label>
                      <select
                        value={newOrg.plan}
                        onChange={(e) => setNewOrg({ ...newOrg, plan: e.target.value })}
                        style={{ width: '100%', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--border-subtle)', backgroundColor: 'var(--surface-muted)', color: 'var(--text-primary)' }}
                      >
                        <option value="standard">Standard</option>
                        <option value="pro">Pro</option>
                        <option value="enterprise">Enterprise</option>
                      </select>
                    </div>
                    <button type="submit" disabled={submitting} className="figma-btn-primary" style={{ backgroundColor: '#2563eb', padding: '9px 16px' }}>
                      {submitting ? 'Creating...' : 'Create Tenant'}
                    </button>
                  </div>
                </form>
              )}

              <div className="figma-card" style={{ padding: '0', overflow: 'hidden' }}>
                <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <Search size={15} style={{ color: 'var(--text-tertiary)' }} />
                  <input
                    type="text"
                    placeholder="Search organizations by name, org_id, or external ID..."
                    value={orgSearch}
                    onChange={(e) => setOrgSearch(e.target.value)}
                    style={{ border: 'none', outline: 'none', background: 'transparent', width: '100%', fontSize: '13px', color: 'var(--text-primary)' }}
                  />
                </div>
                <table className="figma-table">
                  <thead>
                    <tr>
                      <th>Organization</th>
                      <th>External ID</th>
                      <th>Plan</th>
                      <th>Cloud Connector</th>
                      <th>Users</th>
                      <th>Findings / Incidents</th>
                      <th>Status</th>
                      <th style={{ textAlign: 'right' }}>Governance</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredOrgs.map((org) => {
                      const isSuspended = (org.status || 'active').toLowerCase() === 'suspended';
                      const isMaster = org.org_id === 'org_master_admin';
                      return (
                        <tr key={org.org_id}>
                          <td>
                            <div style={{ fontWeight: 600 }}>{org.name}</div>
                            <div style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--text-tertiary)' }}>{org.org_id}</div>
                          </td>
                          <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{org.external_id}</td>
                          <td>
                            <span style={{
                              fontSize: '11px', fontWeight: 600, padding: '2px 8px', borderRadius: '5px',
                              backgroundColor: 'var(--surface-muted)', textTransform: 'uppercase'
                            }}>
                              {org.plan || 'standard'}
                            </span>
                          </td>
                          <td>
                            {org.cloud_connected ? (
                              <span style={{ color: '#10b981', fontSize: '12px', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                                <Cloud size={13} /> AWS {org.aws_account_id}
                              </span>
                            ) : (
                              <span style={{ color: 'var(--text-tertiary)', fontSize: '12px' }}>Not connected</span>
                            )}
                          </td>
                          <td>{org.user_count}</td>
                          <td>{org.open_findings} / {org.open_incidents}</td>
                          <td>
                            <span style={{
                              fontSize: '11px', fontWeight: 700, padding: '3px 8px', borderRadius: '999px',
                              backgroundColor: isSuspended ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.14)',
                              color: isSuspended ? '#ef4444' : '#10b981'
                            }}>
                              {isSuspended ? 'SUSPENDED' : 'ACTIVE'}
                            </span>
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            {isMaster ? (
                              <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>Master Org Protected</span>
                            ) : (
                              <button
                                className="figma-btn-secondary"
                                onClick={() => handleToggleOrgStatus(org)}
                                style={{
                                  padding: '5px 10px',
                                  fontSize: '11.5px',
                                  color: isSuspended ? '#10b981' : '#ef4444',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '5px'
                                }}
                              >
                                {isSuspended ? <PlayCircle size={13} /> : <Ban size={13} />}
                                {isSuspended ? 'Reactivate' : 'Suspend'}
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* 3. GLOBAL USER DIRECTORY */}
          {activeSection === 'users' && (
            <div>
              <div style={{ marginBottom: '18px' }}>
                <h1 style={{ fontSize: '20px', fontWeight: 700, margin: 0 }}>Global User Directory &amp; Session Control</h1>
                <p style={{ fontSize: '13px', color: 'var(--text-tertiary)', margin: '4px 0 0' }}>
                  Inspect user identities across all tenants and immediately revoke active JWT sessions
                </p>
              </div>

              <div className="figma-card" style={{ padding: '14px 18px', marginBottom: '16px', display: 'flex', gap: '12px', alignItems: 'center' }}>
                <Search size={15} style={{ color: 'var(--text-tertiary)' }} />
                <input
                  type="text"
                  placeholder="Search by username, email, or name..."
                  value={userSearch}
                  onChange={(e) => setUserSearch(e.target.value)}
                  style={{ flex: 1, border: 'none', outline: 'none', background: 'transparent', fontSize: '13px', color: 'var(--text-primary)' }}
                />
                <select
                  value={userOrgFilter}
                  onChange={(e) => setUserOrgFilter(e.target.value)}
                  style={{ padding: '6px 10px', borderRadius: '6px', border: '1px solid var(--border-subtle)', backgroundColor: 'var(--surface-muted)', color: 'var(--text-primary)', fontSize: '12px' }}
                >
                  <option value="">All Organizations</option>
                  {orgs.map((o) => (
                    <option key={o.org_id} value={o.org_id}>{o.name}</option>
                  ))}
                </select>
              </div>

              <div className="figma-card" style={{ padding: '0', overflow: 'hidden' }}>
                <table className="figma-table">
                  <thead>
                    <tr>
                      <th>User</th>
                      <th>Organization</th>
                      <th>Role</th>
                      <th>Status</th>
                      <th>Last Login</th>
                      <th style={{ textAlign: 'right' }}>Session Control</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((u) => (
                      <tr key={u.user_id}>
                        <td>
                          <div style={{ fontWeight: 600 }}>{u.full_name || u.username}</div>
                          <div style={{ fontSize: '11.5px', color: 'var(--text-tertiary)' }}>
                            @{u.username} · {u.email}
                          </div>
                        </td>
                        <td>
                          <div>{u.company_name || 'Unassigned'}</div>
                          <div style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--text-tertiary)' }}>{u.org_id || '—'}</div>
                        </td>
                        <td>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            padding: '2px 8px',
                            borderRadius: '5px',
                            backgroundColor: u.role === 'super_admin' ? 'rgba(59, 130, 246, 0.15)' : 'var(--surface-muted)',
                            color: u.role === 'super_admin' ? '#3b82f6' : 'var(--text-primary)'
                          }}>
                            {u.role}
                          </span>
                        </td>
                        <td>
                          {u.is_active ? (
                            <span style={{ color: '#10b981', fontSize: '12px', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                              <CheckCircle size={13} /> Active
                            </span>
                          ) : (
                            <span style={{ color: '#ef4444', fontSize: '12px', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                              <AlertTriangle size={13} /> Disabled
                            </span>
                          )}
                        </td>
                        <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                          {u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            className="figma-btn-secondary"
                            onClick={() => handleTerminateSessions(u)}
                            style={{ padding: '5px 10px', fontSize: '11.5px', display: 'inline-flex', alignItems: 'center', gap: '5px', color: '#f06a1a' }}
                          >
                            <KeyRound size={12} /> Revoke Sessions
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* 4. IMMUTABLE AUDIT LEDGER */}
          {activeSection === 'audit' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
                <div>
                  <h1 style={{ fontSize: '20px', fontWeight: 700, margin: 0 }}>Immutable Platform Audit Ledger</h1>
                  <p style={{ fontSize: '13px', color: 'var(--text-tertiary)', margin: '4px 0 0' }}>
                    Tamper-evident log of all Super Admin governance actions across the platform
                  </p>
                </div>
                <select
                  value={auditActionFilter}
                  onChange={(e) => setAuditActionFilter(e.target.value)}
                  style={{ padding: '7px 12px', borderRadius: '6px', border: '1px solid var(--border-subtle)', backgroundColor: 'var(--surface-card)', color: 'var(--text-primary)', fontSize: '12.5px' }}
                >
                  <option value="">All Actions</option>
                  <option value="TENANT_CREATED">TENANT_CREATED</option>
                  <option value="TENANT_SUSPENDED">TENANT_SUSPENDED</option>
                  <option value="TENANT_REACTIVATED">TENANT_REACTIVATED</option>
                  <option value="USER_SESSIONS_REVOKED">USER_SESSIONS_REVOKED</option>
                  <option value="FLEET_TELEMETRY_VIEWED">FLEET_TELEMETRY_VIEWED</option>
                </select>
              </div>

              <div className="figma-card" style={{ padding: '0', overflow: 'hidden' }}>
                <table className="figma-table">
                  <thead>
                    <tr>
                      <th>Log ID</th>
                      <th>Timestamp (UTC)</th>
                      <th>Actor</th>
                      <th>Action</th>
                      <th>Target</th>
                      <th>Source IP</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.map((log) => (
                      <tr key={log.log_id}>
                        <td style={{ fontFamily: 'monospace', fontSize: '11.5px' }}>{log.log_id}</td>
                        <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                          {log.timestamp ? new Date(log.timestamp).toISOString().replace('T', ' ').slice(0, 19) : ''}
                        </td>
                        <td>
                          <strong>{log.actor_username}</strong>{' '}
                          <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>({log.actor_role})</span>
                        </td>
                        <td>
                          <span style={{ fontFamily: 'monospace', fontSize: '11.5px', fontWeight: 700, color: '#3b82f6' }}>
                            {log.action}
                          </span>
                        </td>
                        <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>
                          {log.target_type}: {log.target_id}
                        </td>
                        <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{log.ip_address}</td>
                        <td>
                          <span style={{
                            fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '999px',
                            backgroundColor: 'rgba(16, 185, 129, 0.14)', color: '#10b981'
                          }}>
                            {(log.status || 'success').toUpperCase()}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

export default SuperAdminConsole;
