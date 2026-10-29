import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { AlertCircle, Search, UserCheck, UserX, Plus, Shield, RefreshCw } from 'lucide-react';
import { API_URL } from '../config';
import { Pagination } from './SharedComponents';

const UserManagementTab = ({ token, showToast }) => {
  const [users, setUsers] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [roleFilter, setRoleFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [page, setPage] = useState(1);
  const pageSize = 8;
  
  // Real Invite Form State
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteName, setInviteName] = useState('');
  const [inviteRole, setInviteRole] = useState('analyst');
  const [invitePassword, setInvitePassword] = useState('SecurePass123!');
  const [submitting, setSubmitting] = useState(false);
  const [loading, setLoading] = useState(false);

  const headers = token ? { Authorization: `Bearer ${token}` } : {};

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_URL}/auth/users`, { headers });
      setUsers(res.data.data || []);
    } catch (err) {
      console.error('Failed to fetch real users:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, [token]);

  const toggleUserStatus = async (username, currentActive) => {
    const action = currentActive ? 'deactivate' : 'reactivate';
    try {
      await axios.post(`${API_URL}/auth/users/${username}/${action}`, {}, { headers });
      if (showToast) showToast(`User @${username} ${action}d successfully`);
      fetchUsers();
    } catch (err) {
      if (showToast) showToast(`Failed to ${action} user`, 'error');
    }
  };

  // REAL INVITE / REGISTER HANDLER
  const handleInvite = async (e) => {
    e.preventDefault();
    if (!inviteEmail) return;

    setSubmitting(true);
    const generatedUsername = (inviteEmail.split('@')[0] || 'user').toLowerCase().replace(/[^a-z0-9_]/g, '_');
    
    try {
      await axios.post(
        `${API_URL}/auth/register`,
        {
          username: generatedUsername,
          password: invitePassword || 'SecurePass123!',
          email: inviteEmail,
          role: inviteRole,
          full_name: inviteName || generatedUsername
        },
        { headers }
      );

      if (showToast) {
        showToast(`User @${generatedUsername} (${inviteRole}) registered! Temp password: ${invitePassword || 'SecurePass123!'}`);
      }

      setInviteEmail('');
      setInviteName('');
      setInvitePassword('SecurePass123!');
      await fetchUsers();
    } catch (err) {
      const detail = err.response?.data?.detail || err.message || 'Registration failed';
      if (showToast) showToast(`Registration failed: ${detail}`, 'error');
    } finally {
      setSubmitting(false);
    }
  };

  // Only display real users from SQLite database - NO FAKE FALLBACK USERS
  const displayUsers = (users || []).map(u => ({
    name: u.full_name || u.username,
    username: u.username,
    role: u.role ? u.role.charAt(0).toUpperCase() + u.role.slice(1) : 'Analyst',
    team: u.role === 'admin' ? 'Security Operations' : (u.role === 'analyst' ? 'Cloud Infra' : 'Compliance'),
    status: u.is_active ? 'Active' : 'Deactivated',
    isActive: u.is_active
  }));

  const filtered = displayUsers.filter(u => {
    const matchesSearch = !searchTerm ||
      u.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      u.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      u.role.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesRole = roleFilter === 'All' || u.role.toLowerCase() === roleFilter.toLowerCase();
    const matchesStatus = statusFilter === 'All' || u.status === statusFilter;

    return matchesSearch && matchesRole && matchesStatus;
  });

  const permissionsMatrix = [
    { perm: 'View findings & evidence', admin: 'Full View', analyst: 'Full View', viewer: 'Read Only' },
    { perm: 'Run attack simulation suite', admin: 'Execute', analyst: 'Execute', viewer: 'Restricted' },
    { perm: 'Approve & apply remediation', admin: 'Approve & Execute', analyst: 'Dry-Run Only', viewer: 'Restricted' },
    { perm: 'Directory & RBAC management', admin: 'Full Control', analyst: 'Restricted', viewer: 'Restricted' }
  ];

  return (
    <div className="animate-fade-in">
      {/* 1. HEADER CALLOUT */}
      <div className="figma-callout">
        <AlertCircle size={18} className="figma-callout-icon" />
        <div className="figma-callout-content">
          <h4>Directory — Role-based access control</h4>
          <p>Real-time operator permissions, authentication credentials, and active identities stored in production database.</p>
        </div>
      </div>

      {/* 2. SEARCH & FILTER BAR */}
      <div style={{ marginBottom: '16px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
          <label style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
            Search directory
          </label>
          <button
            className="figma-btn-secondary"
            onClick={fetchUsers}
            disabled={loading}
            style={{ padding: '4px 10px', fontSize: '11.5px', display: 'flex', alignItems: 'center', gap: '5px' }}
          >
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            Refresh Directory
          </button>
        </div>

        <div className="figma-filter-bar" style={{ margin: 0 }}>
          <div className="figma-header-search" style={{ flex: '1 1 300px', width: 'auto', backgroundColor: 'var(--surface-card)' }}>
            <Search size={14} className="figma-search-icon" />
            <input
              type="text"
              placeholder="Filter users by name, username, or role..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          <select
            className="figma-filter-select"
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
          >
            <option value="All">Role: All</option>
            <option value="Admin">Admin</option>
            <option value="Analyst">Analyst</option>
            <option value="Viewer">Viewer</option>
          </select>

          <select
            className="figma-filter-select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="All">Status: All</option>
            <option value="Active">Active</option>
            <option value="Deactivated">Deactivated</option>
          </select>
        </div>
      </div>

      {/* 3. WORKSPACE DIRECTORY TABLE */}
      <div className="figma-card" style={{ padding: '0', overflow: 'hidden', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
            User directory
          </h3>
          <span style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
            {filtered.length} verified operator{filtered.length === 1 ? '' : 's'}
          </span>
        </div>

        <table className="figma-table">
          <thead>
            <tr>
              <th>Name & Username</th>
              <th>Role</th>
              <th>Team</th>
              <th>Status</th>
              <th style={{ textAlign: 'right' }}>Manage</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', padding: '36px 20px', color: 'var(--text-tertiary)' }}>
                  {loading ? 'Loading user directory from database...' : 'No users found matching current filters.'}
                </td>
              </tr>
            ) : (
              filtered.slice((page - 1) * pageSize, page * pageSize).map((u, idx) => (
                <tr key={u.username || idx}>
                  <td>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{u.name}</div>
                    <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>@{u.username}</div>
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>
                    <span style={{
                      fontSize: '11px',
                      fontWeight: 600,
                      padding: '2px 8px',
                      borderRadius: '4px',
                      backgroundColor: u.role === 'Admin' ? 'var(--sev-critical-bg)' : u.role === 'Analyst' ? 'var(--sev-high-bg)' : 'var(--surface-muted)',
                      color: u.role === 'Admin' ? 'var(--sev-critical)' : u.role === 'Analyst' ? 'var(--accent-orange)' : 'var(--text-secondary)'
                    }}>
                      {u.role}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-muted)' }}>{u.team}</td>
                  <td>
                    <span style={{
                      fontSize: '12.5px',
                      fontWeight: 500,
                      color: u.isActive ? 'var(--success-color)' : 'var(--sev-critical)'
                    }}>
                      {u.status}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      className="figma-link-btn"
                      onClick={() => toggleUserStatus(u.username, u.isActive)}
                    >
                      {u.isActive ? 'Deactivate' : 'Reactivate'}
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
        {filtered.length > 0 && (
          <Pagination
            currentPage={page}
            totalItems={filtered.length}
            pageSize={pageSize}
            onPageChange={setPage}
            itemLabel="users"
          />
        )}
      </div>

      {/* 4. 2-COLUMN BOTTOM: ROLE PERMISSIONS MATRIX + INVITATION FORM */}
      <div className="figma-grid-2col">
        {/* Role Permissions Matrix */}
        <div className="figma-card" style={{ padding: '0', overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Role permissions
            </h3>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-tertiary)', letterSpacing: '0.5px' }}>
              ENFORCED POLICY
            </span>
          </div>

          <table className="figma-table">
            <thead>
              <tr>
                <th>Permission</th>
                <th style={{ textAlign: 'center' }}>Admin</th>
                <th style={{ textAlign: 'center' }}>Analyst</th>
                <th style={{ textAlign: 'center' }}>Viewer</th>
              </tr>
            </thead>
            <tbody>
              {permissionsMatrix.map((pm, idx) => (
                <tr key={idx}>
                  <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{pm.perm}</td>
                  <td style={{ textAlign: 'center', color: 'var(--text-secondary)', fontSize: '12px' }}>{pm.admin}</td>
                  <td style={{ textAlign: 'center', color: 'var(--text-secondary)', fontSize: '12px' }}>{pm.analyst}</td>
                  <td style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>{pm.viewer}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Real Invitation Card */}
        <div className="figma-card">
          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '16px' }}>
            Invite team member
          </h3>

          <form onSubmit={handleInvite}>
            <div style={{ marginBottom: '12px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                Full Name
              </label>
              <input
                type="text"
                placeholder="e.g. Alex Johnson"
                value={inviteName}
                onChange={(e) => setInviteName(e.target.value)}
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  border: '1px solid var(--border-subtle)',
                  backgroundColor: 'var(--surface-card)',
                  color: 'var(--text-primary)',
                  fontSize: '13px'
                }}
              />
            </div>

            <div style={{ marginBottom: '12px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                Email address *
              </label>
              <input
                type="email"
                placeholder="colleague@company.com"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                required
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  border: '1px solid var(--border-subtle)',
                  backgroundColor: 'var(--surface-card)',
                  color: 'var(--text-primary)',
                  fontSize: '13px'
                }}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  Role assignment
                </label>
                <select
                  className="figma-filter-select"
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value)}
                  style={{ width: '100%' }}
                >
                  <option value="analyst">Security Analyst</option>
                  <option value="admin">Administrator</option>
                  <option value="viewer">Auditor Viewer</option>
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  Temporary Password
                </label>
                <input
                  type="text"
                  value={invitePassword}
                  onChange={(e) => setInvitePassword(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-subtle)',
                    backgroundColor: 'var(--surface-card)',
                    color: 'var(--text-primary)',
                    fontSize: '13px'
                  }}
                />
              </div>
            </div>

            <button
              type="submit"
              className="figma-btn-primary"
              disabled={submitting}
              style={{ width: '100%', justifyContent: 'center', padding: '9px 16px' }}
            >
              <Plus size={14} className={submitting ? 'animate-spin' : ''} />
              {submitting ? 'Creating account...' : 'Create & Invite Operator'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default UserManagementTab;
